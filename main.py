import os
import json
import re
import time
import hashlib
import secrets
import json as _json
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Header, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from typing import List
from pydantic import BaseModel, EmailStr, Field
import requests
import firebase_admin
try:  # the messaging module is what FCM needs; absent, push simply stays off
    from firebase_admin import messaging
except Exception:  # pragma: no cover
    messaging = None
from firebase_admin import credentials, auth, firestore, db as rtdb

# 1. Initialize Firebase Admin SDK (Realtime Database + Cloud Firestore)
RTDB_URL = os.environ.get(
    "FIREBASE_DATABASE_URL",
    "https://eyemail-c3398-default-rtdb.asia-southeast1.firebasedatabase.app"
).rstrip("/")

if not firebase_admin._apps:
    sa_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")
    if sa_json:
        cred_dict = json.loads(sa_json)
        cred = credentials.Certificate(cred_dict)
    elif os.path.exists("serviceAccountKey.json"):
        cred = credentials.Certificate("serviceAccountKey.json")
    else:
        raise RuntimeError("Missing FIREBASE_SERVICE_ACCOUNT_JSON environment variable.")
    firebase_admin.initialize_app(cred, {"databaseURL": RTDB_URL})

fs_db = firestore.client()

# 2. FastAPI App Setup
app = FastAPI(title="Eyemail Dual-DB Backend API", version="4.0.0")

ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "https://eyemail.in,https://www.eyemail.in,https://eyemail.indoworkspace.in,https://sankalpteam.github.io,https://indoworkspace.github.io,http://localhost:5500,http://127.0.0.1:5500"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in ALLOWED_ORIGINS if origin.strip()],
    allow_origin_regex=r"https://.*\.github\.io",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
INTERNAL_API_SECRET = os.environ.get("INTERNAL_API_SECRET", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
DOMAIN_NAME = "eyemail.in"
FREE_STORAGE_LIMIT_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB Free Storage
FREE_DAILY_EXTERNAL_LIMIT = int(os.environ.get("DAILY_EXTERNAL_LIMIT", "50"))
PAID_DAILY_EXTERNAL_LIMIT = 500
OTP_EXPIRY_SECONDS = 300  # 5 minutes
SIGNUP_OTP_EXPIRY_SECONDS = 600  # 10 minutes to enter the signup code
SIGNUP_VERIFIED_TTL_SECONDS = 900  # 15 minutes to finish registration after verifying

RESERVED_USERNAMES = {
    "admin", "administrator", "support", "help", "info", "contact",
    "noreply", "no-reply", "welcome", "security", "billing", "postmaster",
    "abuse", "eyemail", "founder", "developer", "team", "mail", "root", "system"
}


class RegisterMailboxRequest(BaseModel):
    username: str
    name: str
    recovery_email: EmailStr


class VerifyLoginOtpRequest(BaseModel):
    otp: str


class SignupOtpRequest(BaseModel):
    recovery_email: EmailStr


class VerifySignupOtpRequest(BaseModel):
    otp: str


class ForgotPasswordRequest(BaseModel):
    eyemail: str


class AddBusinessDomainRequest(BaseModel):
    domain: str


class SendEmailRequest(BaseModel):
    to: EmailStr
    subject: str
    body: str
    cc: List[EmailStr] = Field(default_factory=list)
    bcc: List[EmailStr] = Field(default_factory=list)


class DeleteMessagesRequest(BaseModel):
    ids: List[str]


class RecoveryEmailRequest(BaseModel):
    recovery_email: EmailStr


class OtpOnlyRequest(BaseModel):
    otp: str


class PublicSignupRequest(BaseModel):
    username: str
    name: str = ""
    recovery_email: EmailStr
    password: str


class InternalSendMailRequest(BaseModel):
    to: EmailStr
    subject: str
    body: str
    sender_name: str = "Indoworkspace Security"


def verify_firebase_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split("Bearer ")[1].strip()
    try:
        return auth.verify_id_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired Firebase token")


def verify_internal_secret(x_api_key: str = Header(None)):
    if not INTERNAL_API_SECRET or not x_api_key or not secrets.compare_digest(x_api_key, INTERNAL_API_SECRET):
        raise HTTPException(status_code=403, detail="Unauthorized internal service request")
    return True


def validate_username_format(raw_username: str) -> str:
    username = raw_username.strip().lower()
    if "@" in username:
        username = username.split("@")[0]
    if not re.match(r"^[a-z0-9][a-z0-9._]{1,28}[a-z0-9]$", username) or ".." in username:
        raise HTTPException(
            status_code=400,
            detail="Username must be 3-30 characters (letters, numbers, dots, underscores)."
        )
    if username in RESERVED_USERNAMES:
        raise HTTPException(status_code=400, detail="This username is reserved.")
    return username


def rtdb_safe_key(text: str) -> str:
    return text.strip().lower().replace(".", ",")


def user_node(uid: str) -> str:
    """Realtime Database keys cannot contain dots, so users/<email> is stored as
    users/<email with , instead of .>. The uid itself stays the plain address."""
    return rtdb_safe_key(uid)


def resolve_uid(value) -> str:
    """usernames/<name> now holds only the uid string; older entries held a dict."""
    if isinstance(value, str):
        return value.strip().lower()
    if isinstance(value, dict):
        return str(value.get("uid") or "").strip().lower()
    return ""


def send_via_brevo(sender_name: str, sender_email: str, to_email: str, subject: str, body: str,
                   cc: List[str] | None = None, bcc: List[str] | None = None):
    if not BREVO_API_KEY:
        raise HTTPException(status_code=500, detail="BREVO_API_KEY is not configured on server.")
    brevo_payload = {
        "sender": {"name": sender_name, "email": sender_email},
        "to": [{"email": to_email}],
        "subject": subject,
        "textContent": body,
    }
    if cc:
        brevo_payload["cc"] = [{"email": addr} for addr in cc]
    if bcc:
        brevo_payload["bcc"] = [{"email": addr} for addr in bcc]
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json",
    }
    resp = requests.post("https://api.brevo.com/v3/smtp/email", json=brevo_payload, headers=headers, timeout=15)
    if resp.status_code not in (200, 201, 202):
        raise HTTPException(status_code=502, detail=f"Brevo delivery failed: {resp.text}")


class RateLimited(Exception):
    """Raised inside a transaction to abort a write when a limit is reached."""

    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = max(1, int(retry_after_seconds))
        super().__init__("rate limited")


def take_slot(path: str, max_count: int, window_seconds: int) -> None:
    """Count one request in the current window, atomically, or refuse it.

    The counter lives at `path` as {windowStart, count}. The transaction is what
    makes it safe: two requests arriving together cannot both read the same
    count and both write count+1.
    """
    now = int(time.time())
    window_start = now - (now % window_seconds)
    ref = rtdb.reference(path)

    def bump(current):
        current = current or {}
        if int(current.get("windowStart", 0)) != window_start:
            return {"windowStart": window_start, "count": 1}
        count = int(current.get("count", 0))
        if count >= max_count:
            raise RateLimited(window_start + window_seconds - now)
        return {"windowStart": window_start, "count": count + 1}

    try:
        ref.transaction(bump)
    except RateLimited as limited:
        raise HTTPException(
            status_code=429,
            detail=(f"Free plan: a short pause between sends. Try again in "
                    f"{limited.retry_after_seconds}s. This keeps one account from flooding another."),
        )
    except Exception:
        # A counter that cannot be written must not take the service down.
        print(f"[limit] could not record {path}", flush=True)


def count_daily(path: str, daily_limit: int) -> int:
    """Add one to today's counter, or refuse when the day is full."""
    ref = rtdb.reference(path)

    def bump(current):
        current = current or {}
        used = int(current.get("externalSent", 0))
        if used >= daily_limit:
            raise RateLimited(60)
        return {"externalSent": used + 1}

    try:
        ref.transaction(bump)
    except RateLimited:
        raise HTTPException(
            status_code=429,
            detail=(f"Free plan: {daily_limit} outside mails a day. The limit exists to keep the "
                    f"service clear of spam and abuse, not because mail is short."),
        )
    except Exception:
        print(f"[limit] could not record {path}", flush=True)
    return 0


SPAM_WORDS = (
    "viagra", "casino", "lottery", "you have won", "claim your prize", "crypto giveaway",
    "work from home", "100% free", "risk free", "act now", "limited time offer",
    "click here to claim", "wire transfer", "inheritance", "bitcoin investment",
    "no credit check", "guaranteed loan", "make money fast", "unclaimed funds",
)
SPAM_THRESHOLD = 3


def spam_score(subject: str, body: str) -> tuple:
    """A deliberately simple first filter: (score, reasons).

    It reads the subject and body only, because the worker hands us plain text.
    It is a net for obvious junk, not a spam engine.
    """
    subject = subject or ""
    text = f"{subject}\n{body or ''}".lower()
    score = 0
    reasons = []

    for word in SPAM_WORDS:
        if word in text:
            score += 1
            reasons.append(f"phrase:{word}")

    links = len(re.findall(r"https?://", text))
    if links >= 5:
        score += 2
        reasons.append(f"links:{links}")

    if re.search(r"\b(free|winner|urgent|guaranteed)\b", subject.lower()):
        score += 1
        reasons.append("subject-claim")

    letters = [c for c in subject if c.isalpha()]
    if len(letters) >= 8 and sum(1 for c in letters if c.isupper()) / len(letters) > 0.7:
        score += 1
        reasons.append("shouting")

    if subject.count("!") >= 2:
        score += 1
        reasons.append("exclaim")

    return score, reasons


def storage_state(profile: dict) -> tuple:
    """(used, limit, is_full) for a profile node."""
    used = int((profile or {}).get("storageUsedBytes", 0) or 0)
    limit = int((profile or {}).get("storageLimitBytes", FREE_STORAGE_LIMIT_BYTES) or FREE_STORAGE_LIMIT_BYTES)
    return used, limit, used >= limit


def mask_email(addr: str) -> str:
    if "@" not in addr:
        return addr
    local, dom = addr.split("@", 1)
    prefix = local[:2] if len(local) >= 2 else local[:1]
    return f"{prefix}***@{dom}"


@app.get("/health")
def health_check():
    """UptimeRobot ping endpoint to keep Render awake 24/7"""
    return {"status": "ok", "service": "eyemail-dual-db-backend", "timestamp": datetime.now(timezone.utc).isoformat()}


# ==============================================================================
# 1. REALTIME DATABASE USER REGISTRATION & PROFILE
# ==============================================================================
@app.get("/api/check-username/{raw_username}")
def check_username(raw_username: str):
    username = validate_username_format(raw_username)
    safe_user = rtdb_safe_key(username)
    existing = rtdb.reference(f"usernames/{safe_user}").get()
    return {
        "username": username,
        "email": f"{username}@{DOMAIN_NAME}",
        "available": existing is None
    }


@app.post("/api/auth/register-mailbox")
def register_mailbox(payload: RegisterMailboxRequest, user=Depends(verify_firebase_user)):
    uid = user["uid"]
    username = validate_username_format(payload.username)
    safe_user = rtdb_safe_key(username)
    eyemail_address = f"{username}@{DOMAIN_NAME}"
    clean_name = payload.name.strip() or username
    recovery_email = payload.recovery_email.strip().lower()
    now_iso = datetime.now(timezone.utc).isoformat()

    node = user_node(uid)
    user_ref = rtdb.reference(f"users/{node}")
    existing_user = user_ref.get()
    if existing_user:
        return {"status": "exists", "profile": existing_user}

    # The recovery address must be proven before the mailbox is created.
    verified = rtdb.reference(f"signup_verified/{user_node(uid)}").get()
    if not verified:
        raise HTTPException(status_code=403, detail="Verify your recovery email first.")
    if int(time.time()) > int(verified.get("expiresAt", 0)):
        rtdb.reference(f"signup_verified/{user_node(uid)}").delete()
        raise HTTPException(status_code=403, detail="Verification expired. Please verify again.")
    if (verified.get("recoveryEmail") or "").lower() != recovery_email:
        raise HTTPException(status_code=400, detail="Recovery email does not match the one you verified.")

    username_ref = rtdb.reference(f"usernames/{safe_user}")
    taken = username_ref.get()
    if taken is not None and resolve_uid(taken) != uid:
        raise HTTPException(status_code=409, detail=f"{eyemail_address} is already taken.")

    # The index holds one line: the uid. Nothing else is duplicated here.
    username_ref.set(uid)

    # Save user profile & quota in Realtime Database
    # Only what the mail product needs. The address is the uid, so it is stored
    # once as email; the local part is derived, never copied. Nothing about a
    # person's identity beyond this belongs here.
    profile_data = {
        "name": clean_name,
        "email": eyemail_address,
        "recoveryEmail": recovery_email,
        "recoveryVerified": True,
        "plan": "free",
        "storageUsedBytes": 512,
        "storageLimitBytes": FREE_STORAGE_LIMIT_BYTES,
        "createdAt": now_iso,
    }
    user_ref.set(profile_data)

    # Save Welcome Email in Cloud Firestore
    fs_db.collection("users").document(uid).collection("emails").add({
        "from": f"welcome@{DOMAIN_NAME}",
        "fromName": "Eyemail Team",
        "to": eyemail_address,
        "subject": f"Welcome to Eyemail, {clean_name}!",
        "body": (
            f"Hi {clean_name},\n\n"
            f"Your {eyemail_address} mailbox is active with 2FA OTP protection and 1 GB free storage.\n\n"
            f"You can send and receive emails with Gmail, Yahoo, and other Eyemail users instantly.\n\n"
            f"— Team Eyemail"
        ),
        "snippet": f"Hi {clean_name}, your {eyemail_address} mailbox is now active.",
        "folder": "inbox",
        "read": False,
        "starred": True,
        "timestamp": firestore.SERVER_TIMESTAMP,
        "createdAt": now_iso,
    })

    rtdb.reference(f"signup_verified/{user_node(uid)}").delete()

    return {"status": "created", "profile": profile_data}


def purge_old_trash(uid: str, days: int = 30, max_docs: int = 25) -> int:
    """Delete Trash mail older than `days`. Runs a slice at a time, on read."""
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    removed = 0
    try:
        coll = fs_db.collection("users").document(uid).collection("emails")
        for doc in coll.where("folder", "==", "trash").stream():
            data = doc.to_dict() or {}
            stamp = data.get("createdAt") or ""
            try:
                when = datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).timestamp()
            except Exception:
                continue
            if when < cutoff:
                doc.reference.delete()
                removed += 1
                if removed >= max_docs:
                    break
    except Exception as error:
        print(f"[trash] purge skipped for {uid}: {error}", flush=True)
    return removed


@app.get("/api/user/profile")
def get_user_profile(user=Depends(verify_firebase_user)):
    uid = user["uid"]
    purge_old_trash(uid)
    profile = rtdb.reference(f"users/{user_node(uid)}").get()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found in Realtime Database")
    return {"profile": profile}


# ==============================================================================
# 1a. SIGNUP: THE ACCOUNT IS CREATED HERE, WITH THE ADDRESS AS THE UID
# ==============================================================================
@app.post("/api/auth/signup")
def public_signup(payload: PublicSignupRequest):
    """Create the Firebase account with uid = username@eyemail.in, then mail a code.

    The uid has to be chosen by the server: a client signup gets a random uid, and
    we want one identifier for the login, the profile and the mailbox.
    """
    username = validate_username_format(payload.username)
    eyemail_address = f"{username}@{DOMAIN_NAME}"
    clean_name = (payload.name or "").strip() or username
    recovery_email = (payload.recovery_email or "").strip().lower()
    password = payload.password or ""

    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")
    if len(password) > 128:
        raise HTTPException(status_code=400, detail="Password is too long.")

    safe_user = rtdb_safe_key(username)
    if rtdb.reference(f"usernames/{safe_user}").get() is not None:
        raise HTTPException(status_code=409, detail=f"{eyemail_address} is already taken.")

    try:
        auth.get_user(eyemail_address)
        raise HTTPException(status_code=409, detail=f"{eyemail_address} already has a login. Sign in instead.")
    except auth.UserNotFoundError:
        pass
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Could not check the address.")

    try:
        auth.create_user(
            uid=eyemail_address,
            email=eyemail_address,
            password=password,
            display_name=clean_name,
            email_verified=True,
        )
    except auth.EmailAlreadyExistsError:
        raise HTTPException(status_code=409, detail=f"{eyemail_address} already has a login. Sign in instead.")
    except auth.UidAlreadyExistsError:
        raise HTTPException(status_code=409, detail=f"{eyemail_address} already has a login. Sign in instead.")
    except Exception:
        raise HTTPException(status_code=500, detail="Could not create the account.")

    now = int(time.time())
    otp_code = f"{secrets.randbelow(900000) + 100000}"
    otp_ref = rtdb.reference(f"signup_otps/{user_node(eyemail_address)}")
    otp_ref.set({
        "otp": otp_code,
        "recoveryEmail": recovery_email,
        "expiresAt": now + SIGNUP_OTP_EXPIRY_SECONDS,
        "attempts": 0,
        "sentAt": now,
    })

    body = (
        f"Welcome to Eyemail.\n\n"
        f"Your verification code is:\n\n"
        f"{otp_code}\n\n"
        f"Enter it on the signup page to activate {eyemail_address}. It expires in 10 minutes.\n\n"
        f"— Team Eyemail"
    )
    send_via_brevo("Eyemail", f"security@{DOMAIN_NAME}", recovery_email,
                   f"{otp_code} is your Eyemail verification code", body)

    return {
        "status": "otp_sent",
        "email": eyemail_address,
        "maskedRecoveryEmail": mask_email(recovery_email),
        "expiresInSeconds": SIGNUP_OTP_EXPIRY_SECONDS,
    }


# ==============================================================================
# 1b. SIGNUP: VERIFY THE RECOVERY EMAIL BEFORE THE MAILBOX IS CREATED
# ==============================================================================
@app.post("/api/auth/send-signup-otp")
def send_signup_otp(payload: SignupOtpRequest, user=Depends(verify_firebase_user)):
    uid = user["uid"]

    if rtdb.reference(f"users/{user_node(uid)}").get():
        raise HTTPException(status_code=409, detail="This account is already registered. Please sign in.")

    recovery_email = payload.recovery_email.strip().lower()
    otp_ref = rtdb.reference(f"signup_otps/{user_node(uid)}")
    previous = otp_ref.get() or {}
    now = int(time.time())

    last_sent = int(previous.get("sentAt", 0))
    if last_sent and now - last_sent < 60:
        raise HTTPException(status_code=429, detail=f"Please wait {60 - (now - last_sent)}s before asking for another code.")
    take_slot(f"limits/otp/{user_node(uid)}", max_count=10, window_seconds=3600)

    otp_code = f"{secrets.randbelow(900000) + 100000}"
    otp_ref.set({
        "otp": otp_code,
        "recoveryEmail": recovery_email,
        "expiresAt": now + SIGNUP_OTP_EXPIRY_SECONDS,
        "attempts": 0,
        "sentAt": now,
    })

    body = (
        f"Welcome to Eyemail.\n\n"
        f"Your verification code is:\n\n"
        f"{otp_code}\n\n"
        f"Enter it on the signup page to activate your mailbox. It expires in 10 minutes.\n\n"
        f"— Team Eyemail"
    )
    send_via_brevo("Eyemail", f"security@{DOMAIN_NAME}", recovery_email,
                   f"{otp_code} is your Eyemail verification code", body)

    return {
        "status": "otp_sent",
        "maskedRecoveryEmail": mask_email(recovery_email),
        "expiresInSeconds": SIGNUP_OTP_EXPIRY_SECONDS,
    }


@app.post("/api/auth/verify-signup-otp")
def verify_signup_otp(payload: VerifySignupOtpRequest, user=Depends(verify_firebase_user)):
    uid = user["uid"]
    entered = payload.otp.strip()
    otp_ref = rtdb.reference(f"signup_otps/{user_node(uid)}")
    record = otp_ref.get()

    if not record:
        raise HTTPException(status_code=400, detail="No active code found. Please request a new one.")
    if int(time.time()) > int(record.get("expiresAt", 0)):
        otp_ref.delete()
        raise HTTPException(status_code=400, detail="Code expired. Please request a new one.")

    attempts = int(record.get("attempts", 0))
    if attempts >= 5:
        otp_ref.delete()
        raise HTTPException(status_code=429, detail="Too many wrong attempts. Request a new code.")

    if not secrets.compare_digest(entered, str(record.get("otp", ""))):
        otp_ref.update({"attempts": attempts + 1})
        raise HTTPException(status_code=400, detail="That code is not correct.")

    now = int(time.time())
    rtdb.reference(f"signup_verified/{user_node(uid)}").set({
        "recoveryEmail": record.get("recoveryEmail", ""),
        "verifiedAt": now,
        "expiresAt": now + SIGNUP_VERIFIED_TTL_SECONDS,
    })
    otp_ref.delete()

    return {"status": "verified", "expiresInSeconds": SIGNUP_VERIFIED_TTL_SECONDS}


# ==============================================================================
# 2. OPTIONAL LOGIN 2FA OTP (kept for later use, not required to sign in)
# ==============================================================================
@app.post("/api/auth/send-login-otp")
def send_login_otp(user=Depends(verify_firebase_user)):
    uid = user["uid"]
    profile = rtdb.reference(f"users/{user_node(uid)}").get()
    if not profile:
        raise HTTPException(status_code=404, detail="User profile not found.")

    recovery_email = (profile.get("recoveryEmail") or "").strip().lower()
    eyemail_addr = profile.get("email", "")
    user_name = profile.get("name", "User")

    if not recovery_email or "@" not in recovery_email:
        raise HTTPException(status_code=400, detail="No recovery email linked to this account.")

    otp_code = f"{secrets.randbelow(900000) + 100000}"
    expires_at = int(time.time()) + OTP_EXPIRY_SECONDS

    # Save OTP in Realtime Database
    rtdb.reference(f"login_otps/{uid}").set({
        "otp": otp_code,
        "expiresAt": expires_at,
        "attempts": 0
    })

    body = (
        f"Hi {user_name},\n\n"
        f"Your Eyemail login verification code for {eyemail_addr} is:\n\n"
        f"{otp_code}\n\n"
        f"This code expires in 5 minutes. Never share this OTP with anyone.\n\n"
        f"— Eyemail Security Team"
    )
    send_via_brevo("Eyemail Security", f"security@{DOMAIN_NAME}", recovery_email, f"{otp_code} is your Eyemail Login OTP", body)

    return {
        "status": "otp_sent",
        "maskedRecoveryEmail": mask_email(recovery_email),
        "expiresInSeconds": OTP_EXPIRY_SECONDS
    }


@app.post("/api/auth/verify-login-otp")
def verify_login_otp(payload: VerifyLoginOtpRequest, user=Depends(verify_firebase_user)):
    uid = user["uid"]
    entered_otp = payload.otp.strip()
    otp_ref = rtdb.reference(f"login_otps/{uid}")
    record = otp_ref.get()

    if not record:
        raise HTTPException(status_code=400, detail="No active OTP found. Please request a new OTP.")

    if int(time.time()) > int(record.get("expiresAt", 0)):
        otp_ref.delete()
        raise HTTPException(status_code=400, detail="OTP has expired. Please request a new one.")

    attempts = int(record.get("attempts", 0))
    if attempts >= 5:
        otp_ref.delete()
        raise HTTPException(status_code=429, detail="Too many wrong attempts. Request a new OTP.")

    if not secrets.compare_digest(entered_otp, str(record.get("otp", ""))):
        otp_ref.update({"attempts": attempts + 1})
        raise HTTPException(status_code=400, detail="Invalid OTP code. Please try again.")

    otp_ref.delete()
    rtdb.reference(f"users/{user_node(uid)}/lastLoginAt").set(datetime.now(timezone.utc).isoformat())
    return {"status": "verified"}


# ==============================================================================
# 2b. SETTINGS: CHANGE THE RECOVERY EMAIL, SIGN OUT EVERYWHERE, DELETE THE ACCOUNT
# ==============================================================================
@app.post("/api/auth/send-recovery-otp")
def send_recovery_otp(payload: RecoveryEmailRequest, user=Depends(verify_firebase_user)):
    """Mail a code to the new recovery address before we believe it."""
    uid = user["uid"]
    profile = rtdb.reference(f"users/{user_node(uid)}").get()
    if not profile:
        raise HTTPException(status_code=404, detail="Mailbox not found.")

    new_email = payload.recovery_email.strip().lower()
    if new_email == (profile.get("recoveryEmail") or "").strip().lower():
        raise HTTPException(status_code=400, detail="That is already your recovery email.")

    take_slot(f"limits/recovery/{user_node(uid)}", max_count=3, window_seconds=3600)

    now = int(time.time())
    code = f"{secrets.randbelow(900000) + 100000}"
    rtdb.reference(f"recovery_otps/{user_node(uid)}").set({
        "otp": code, "recoveryEmail": new_email,
        "expiresAt": now + SIGNUP_OTP_EXPIRY_SECONDS, "attempts": 0,
    })

    body = (
        f"Confirm this address for your Eyemail account.\n\n"
        f"Your code is:\n\n{code}\n\n"
        f"It expires in 10 minutes. If you did not ask for this, ignore this mail.\n\n"
        f"— Team Eyemail"
    )
    send_via_brevo("Eyemail", f"security@{DOMAIN_NAME}", new_email,
                   f"{code} is your Eyemail confirmation code", body)

    return {"status": "otp_sent", "maskedRecoveryEmail": mask_email(new_email),
            "expiresInSeconds": SIGNUP_OTP_EXPIRY_SECONDS}


@app.post("/api/auth/verify-recovery-otp")
def verify_recovery_otp(payload: OtpOnlyRequest, user=Depends(verify_firebase_user)):
    uid = user["uid"]
    ref = rtdb.reference(f"recovery_otps/{user_node(uid)}")
    record = ref.get() or {}
    if not record:
        raise HTTPException(status_code=400, detail="Ask for a code first.")
    if int(time.time()) > int(record.get("expiresAt", 0)):
        ref.delete()
        raise HTTPException(status_code=400, detail="That code has expired. Ask for a new one.")

    attempts = int(record.get("attempts", 0))
    if attempts >= 5:
        ref.delete()
        raise HTTPException(status_code=429, detail="Too many wrong codes. Ask for a new one.")

    if not secrets.compare_digest(str(payload.otp).strip(), str(record.get("otp", ""))):
        ref.update({"attempts": attempts + 1})
        raise HTTPException(status_code=400, detail="That code is not correct.")

    new_email = record.get("recoveryEmail")
    rtdb.reference(f"users/{user_node(uid)}").update({
        "recoveryEmail": new_email,
        "recoveryVerified": True,
    })
    ref.delete()
    return {"status": "updated", "recoveryEmail": new_email}


@app.post("/api/auth/sign-out-all")
def sign_out_all(user=Depends(verify_firebase_user)):
    """Revoke every refresh token; each device must sign in again."""
    uid = user["uid"]
    try:
        auth.revoke_refresh_tokens(uid)
    except Exception:
        raise HTTPException(status_code=500, detail="Could not end the other sessions.")
    return {"status": "signed_out_all"}


@app.post("/api/auth/delete-account")
def delete_account(user=Depends(verify_firebase_user)):
    """Remove the mailbox, its mail, its address and the login. Not reversible."""
    uid = user["uid"]
    profile = rtdb.reference(f"users/{user_node(uid)}").get()
    if not profile:
        raise HTTPException(status_code=404, detail="Mailbox not found.")

    username = (profile.get("username") or profile.get("email", "").split("@")[0] or "").lower()

    deleted = 0
    try:
        coll = fs_db.collection("users").document(uid).collection("emails")
        for doc in coll.stream():
            doc.reference.delete()
            deleted += 1
    except Exception as error:
        print(f"[account] mail delete failed uid={uid} {error}", flush=True)
        raise HTTPException(status_code=500, detail="Mail could not be deleted. Nothing was removed.")

    try:
        auth.delete_user(uid)
    except auth.UserNotFoundError:
        pass
    except Exception:
        raise HTTPException(status_code=500, detail="The login could not be removed.")

    if username:
        rtdb.reference(f"usernames/{rtdb_safe_key(username)}").delete()
    rtdb.reference(f"users/{user_node(uid)}").delete()
    rtdb.reference(f"signup_verified/{user_node(uid)}").delete()

    return {"status": "deleted", "messages": deleted}


# ==============================================================================
# 3. FORGOT PASSWORD VIA RECOVERY EMAIL
# ==============================================================================
@app.post("/api/auth/forgot-password")
def forgot_password(payload: ForgotPasswordRequest):
    raw = payload.eyemail.strip().lower()
    username = raw.split("@")[0] if "@" in raw else raw
    eyemail_address = f"{username}@{DOMAIN_NAME}"
    safe_user = rtdb_safe_key(username)

    uid = resolve_uid(rtdb.reference(f"usernames/{safe_user}").get())
    if not uid:
        raise HTTPException(status_code=404, detail=f"No Eyemail account found for {eyemail_address}")

    take_slot(f"limits/forgot/{user_node(uid)}", max_count=3, window_seconds=3600)

    profile = rtdb.reference(f"users/{user_node(uid)}").get() or {}
    recovery_email = (profile.get("recoveryEmail") or "").strip().lower()

    if not recovery_email or "@" not in recovery_email:
        raise HTTPException(status_code=400, detail="No recovery email linked to this account.")

    try:
        reset_link = auth.generate_password_reset_link(eyemail_address)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not generate reset link: {str(exc)}")

    body = (
        f"Hi {profile.get('name', username)},\n\n"
        f"Click the secure link below to reset your password for {eyemail_address}:\n"
        f"{reset_link}\n\n"
        f"If you did not request this, please ignore this email.\n\n"
        f"— Eyemail Security Team"
    )
    send_via_brevo("Eyemail Security", f"security@{DOMAIN_NAME}", recovery_email, f"Reset password for {eyemail_address}", body)

    return {"status": "sent", "maskedRecoveryEmail": mask_email(recovery_email)}


# ==============================================================================
# 4. BUSINESS CUSTOM DOMAIN & DNS RECORDS STORAGE (Realtime Database)
# ==============================================================================
@app.post("/api/domains/add")
def add_business_domain(payload: AddBusinessDomainRequest, user=Depends(verify_firebase_user)):
    uid = user["uid"]
    domain = payload.domain.strip().lower()
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain) or domain == DOMAIN_NAME:
        raise HTTPException(status_code=400, detail="Enter a valid custom domain (e.g. yourcompany.in)")

    safe_dom = rtdb_safe_key(domain)
    dom_ref = rtdb.reference(f"domains/{safe_dom}")
    if dom_ref.get() is not None:
        raise HTTPException(status_code=409, detail="This domain is already registered.")

    verify_token = f"eyemail-verify={secrets.token_hex(8)}"
    now_iso = datetime.now(timezone.utc).isoformat()

    domain_record = {
        "domain": domain,
        "ownerUid": uid,
        "verified": False,
        "createdAt": now_iso,
        "dnsRecords": [
            {"type": "TXT", "host": "@", "value": verify_token, "status": "pending"},
            {"type": "MX", "host": "@", "value": "route1.mx.cloudflare.net", "priority": 10, "status": "pending"},
            {"type": "TXT", "host": "@", "value": "v=spf1 include:spf.brevo.com ~all", "status": "pending"}
        ]
    }
    dom_ref.set(domain_record)
    rtdb.reference(f"users/{user_node(uid)}/domains/{safe_dom}").set({"domain": domain, "verified": False})

    return {"status": "added", "domainInfo": domain_record}


# ==============================================================================
# 5. SEND EMAIL (Firestore Emails + Realtime DB Quota & Routing)
# ==============================================================================
@app.post("/api/send-email")
def send_email(payload: SendEmailRequest, user=Depends(verify_firebase_user)):
    uid = user["uid"]
    user_ref = rtdb.reference(f"users/{user_node(uid)}")
    user_data = user_ref.get()

    if not user_data:
        raise HTTPException(status_code=404, detail="Sender Eyemail profile not found")

    sender_email = user_data.get("email", "").lower()
    sender_name = user_data.get("name", sender_email.split("@")[0])
    user_plan = user_data.get("plan", "free")
    current_used = int(user_data.get("storageUsedBytes", 0))

    to_email = payload.to.strip().lower()
    subject = payload.subject.strip() or "(No Subject)"
    body = payload.body.strip()

    if not body:
        raise HTTPException(status_code=400, detail="Email body cannot be empty")

    # Cc and Bcc, cleaned, de-duplicated and never the sender itself
    def clean_addrs(items):
        out, seen = [], set()
        for raw in items:
            addr = str(raw).strip().lower()
            if not addr or addr in seen or addr == sender_email:
                continue
            seen.add(addr)
            out.append(addr)
        return out

    cc_list = clean_addrs(payload.cc)
    bcc_list = clean_addrs(payload.bcc)
    if to_email in cc_list or to_email in bcc_list:
        cc_list = [a for a in cc_list if a != to_email]
        bcc_list = [a for a in bcc_list if a != to_email]

    all_recipients = [to_email] + cc_list + bcc_list
    if len(all_recipients) > 20:
        raise HTTPException(status_code=400, detail="Too many recipients (max 20).")

    now_iso = datetime.now(timezone.utc).isoformat()
    snippet = re.sub(r"\s+", " ", body)[:120]
    msg_size = len(body.encode("utf-8")) + len(subject.encode("utf-8")) + 256

    def store_message(owner_uid: str, folder: str, is_read: bool, recipient: str):
        fs_db.collection("users").document(owner_uid).collection("emails").add({
            "from": sender_email,
            "fromName": sender_name,
            "to": recipient,
            "cc": cc_list,
            "bcc": bcc_list if folder == "sent" else [],
            "subject": subject,
            "body": body,
            "snippet": snippet,
            "folder": folder,
            "read": is_read,
            "starred": False,
            "timestamp": firestore.SERVER_TIMESTAMP,
            "createdAt": now_iso,
        })

    sender_used, sender_limit, sender_full = storage_state(user_data)
    if sender_full:
        raise HTTPException(
            status_code=507,
            detail=("Free plan storage is full. Empty Trash or delete some mail, "
                    "and sending works again."),
        )

    # CASE A: every recipient is @eyemail.in -> deliver inside, no Brevo call
    if all(addr.endswith(f"@{DOMAIN_NAME}") for addr in all_recipients):
        for addr in all_recipients:
            target_username = rtdb_safe_key(addr.split("@")[0])
            target_uid = resolve_uid(rtdb.reference(f"usernames/{target_username}").get())
            if not target_uid:
                raise HTTPException(status_code=404, detail=f"Address {addr} does not exist.")

            target_user_ref = rtdb.reference(f"users/{user_node(target_uid)}")
            target_used = int((target_user_ref.get() or {}).get("storageUsedBytes", 0))

            store_message(target_uid, "inbox", False, addr)
            target_user_ref.update({"storageUsedBytes": target_used + msg_size})

        store_message(uid, "sent", True, to_email)
        user_ref.update({"storageUsedBytes": current_used + msg_size})

        return {"status": "sent", "delivery": "internal", "to": to_email,
                "cc": cc_list, "bcc": bcc_list}

    # CASE B: at least one external recipient -> Brevo
    daily_limit = PAID_DAILY_EXTERNAL_LIMIT if user_plan != "free" else FREE_DAILY_EXTERNAL_LIMIT
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    # One person cannot send faster than this, whatever the daily allowance.
    take_slot(f"limits/send/{user_node(uid)}", max_count=30, window_seconds=60)
    count_daily(f"usage/{user_node(uid)}/{today_str}", daily_limit)

    send_via_brevo(sender_name, sender_email, to_email, subject, body, cc=cc_list, bcc=bcc_list)

    store_message(uid, "sent", True, to_email)
    user_ref.update({"storageUsedBytes": current_used + msg_size})

    return {"status": "sent", "delivery": "brevo", "to": to_email,
            "cc": cc_list, "bcc": bcc_list}


# ==============================================================================
# 5b. PERMANENT DELETE (server side, frees the storage counter too)
# ==============================================================================
@app.post("/api/messages/delete")
def delete_messages(payload: DeleteMessagesRequest, user=Depends(verify_firebase_user)):
    uid = user["uid"]
    ids = [str(i).strip() for i in payload.ids if str(i).strip()]

    if not ids:
        raise HTTPException(status_code=400, detail="No messages selected.")
    if len(ids) > 100:
        raise HTTPException(status_code=400, detail="Delete at most 100 messages at a time.")

    coll = fs_db.collection("users").document(uid).collection("emails")
    freed = 0
    deleted = 0

    for message_id in ids:
        ref = coll.document(message_id)
        snapshot = ref.get()
        if not snapshot.exists:
            continue
        data = snapshot.to_dict() or {}
        freed += len((data.get("body") or "").encode("utf-8"))
        freed += len((data.get("subject") or "").encode("utf-8")) + 256
        ref.delete()
        deleted += 1

    if freed:
        user_ref = rtdb.reference(f"users/{user_node(uid)}")
        used = int((user_ref.get() or {}).get("storageUsedBytes", 0))
        user_ref.update({"storageUsedBytes": max(0, used - freed)})

    return {"status": "deleted", "deleted": deleted, "freedBytes": freed}


# ==============================================================================
# 5c. EMPTY TRASH IN ONE CALL
# ==============================================================================
@app.post("/api/messages/empty-trash")
def empty_trash(user=Depends(verify_firebase_user)):
    """Delete everything in Trash and give the space back."""
    uid = user["uid"]
    coll = fs_db.collection("users").document(uid).collection("emails")

    try:
        docs = list(coll.where("folder", "==", "trash").stream())
    except Exception:
        raise HTTPException(status_code=500, detail="Could not read Trash.")

    freed = 0
    deleted = 0
    for doc in docs:
        data = doc.to_dict() or {}
        freed += len((data.get("body") or "").encode()) + len((data.get("subject") or "").encode()) + 256
        try:
            doc.reference.delete()
            deleted += 1
        except Exception as error:
            print(f"[trash] could not delete {doc.id}: {error}", flush=True)

    if freed:
        user_ref = rtdb.reference(f"users/{user_node(uid)}")
        current = int((user_ref.get() or {}).get("storageUsedBytes", 0))
        user_ref.update({"storageUsedBytes": max(0, current - freed)})

    return {"status": "emptied", "deleted": deleted, "freedBytes": freed}


# ==============================================================================
# 6. CLOUDFLARE INBOUND EMAIL WEBHOOK (External Gmail/Yahoo -> Firestore Inbox)
# ==============================================================================
@app.post("/webhook/inbound")
async def inbound_email_webhook(request: Request, x_webhook_secret: str = Header(None)):
    """Receives incoming emails forwarded by Cloudflare Email Worker."""
    data = await request.json()
    incoming_secret = (x_webhook_secret or data.get("secret") or "").strip()

    if not WEBHOOK_SECRET or not incoming_secret or not secrets.compare_digest(incoming_secret, WEBHOOK_SECRET):
        raise HTTPException(status_code=403, detail="Unauthorized inbound webhook request")

    from_raw = data.get("from") or data.get("sender") or ""
    to_raw = data.get("to") or data.get("recipient") or ""
    raw_email = data.get("raw", "")

    _, sender_email = parseaddr(from_raw)
    sender_email = (sender_email or from_raw).strip().lower()
    sender_name = sender_email.split("@")[0] if "@" in sender_email else sender_email

    _, to_email = parseaddr(to_raw)
    to_email = (to_email or to_raw).strip().lower()

    subject = (data.get("subject") or "(No Subject)").strip()
    body = (data.get("text") or data.get("body") or "").strip()

    if raw_email:
        try:
            msg = Parser(policy=policy.default).parsestr(raw_email)
            hdr_name, hdr_addr = parseaddr(msg.get("From", ""))
            if hdr_name:
                sender_name = hdr_name.strip()
            if hdr_addr and not sender_email:
                sender_email = hdr_addr.strip().lower()
            if msg.get("Subject"):
                subject = msg.get("Subject").strip() or subject

            extracted_text = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain" and not part.get_filename():
                        extracted_text = part.get_content().strip()
                        if extracted_text:
                            break
            elif msg.get_content_type() == "text/plain":
                extracted_text = msg.get_content().strip()

            if extracted_text:
                body = extracted_text
        except Exception:
            pass

    if not body:
        body = "(Empty message)"

    if not to_email or not to_email.endswith(f"@{DOMAIN_NAME}"):
        raise HTTPException(status_code=400, detail="Invalid recipient domain")

    target_username = rtdb_safe_key(to_email.split("@")[0])
    target_uid = resolve_uid(rtdb.reference(f"usernames/{target_username}").get())

    if not target_uid:
        raise HTTPException(status_code=404, detail=f"Mailbox {to_email} does not exist")

    target_user_ref = rtdb.reference(f"users/{user_node(target_uid)}")
    target_profile = target_user_ref.get() or {}
    _used, _limit, target_full = storage_state(target_profile)
    if target_full:
        # The sender is told the mailbox is full instead of losing the mail quietly.
        raise HTTPException(status_code=507, detail=f"Mailbox {to_email} is full.")
    target_used = int(target_profile.get("storageUsedBytes", 0) or 0)

    now_iso = datetime.now(timezone.utc).isoformat()
    snippet = re.sub(r"\s+", " ", body)[:120]
    msg_size = len(body.encode("utf-8")) + len(subject.encode("utf-8")) + 256

    score, reasons = spam_score(subject, body)
    target_folder = "spam" if score >= SPAM_THRESHOLD else "inbox"

    fs_db.collection("users").document(target_uid).collection("emails").add({
        "from": sender_email,
        "fromName": sender_name or sender_email,
        "to": to_email,
        "subject": subject,
        "body": body,
        "snippet": snippet,
        "folder": target_folder,
        "read": False,
        "starred": False,
        "timestamp": firestore.SERVER_TIMESTAMP,
        "createdAt": now_iso,
        **({"spamScore": score, "spamReasons": reasons} if target_folder == "spam" else {}),
    })
    target_user_ref.update({"storageUsedBytes": target_used + msg_size})

    # A notification, but only for real mail, never for something filed as junk.
    if target_folder == "inbox":
        try:
            send_web_push(
                target_uid,
                sender_name or sender_email,
                subject or "(no subject)",
            )
            send_fcm(
                target_uid,
                sender_name or sender_email,
                subject or "(no subject)",
            )
        except Exception:
            # A failed notification must never cost the mail itself.
            pass

    return {"status": "received", "to": to_email}


# ==============================================================================
# 6b. WEB PUSH (a notification when mail arrives, app closed)
# ==============================================================================
VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "").strip()
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "").strip()
VAPID_SUBJECT = os.getenv("VAPID_SUBJECT", "mailto:hello@eyemail.in").strip()


class PushSubscriptionRequest(BaseModel):
    endpoint: str
    p256dh: str
    auth: str


def push_enabled() -> bool:
    return bool(VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY)


def _push_key(uid: str) -> str:
    return hashlib.sha256(uid.encode("utf-8")).hexdigest()[:32]


def send_web_push(uid: str, title: str, body: str, url: str = "/web/app.html") -> int:
    """One notification to every browser this account subscribed. Returns how many went."""
    if not push_enabled():
        return 0
    try:
        from pywebpush import webpush, WebPushException
    except Exception:
        return 0

    node = user_node(uid)
    stored = rtdb.reference(f"push/{_push_key(uid)}").get() or {}
    if not isinstance(stored, dict) or not stored:
        return 0

    payload = _json.dumps({"title": title, "body": body, "url": url})
    sent = 0
    for key, sub in list(stored.items()):
        if not isinstance(sub, dict):
            continue
        info = {
            "endpoint": sub.get("endpoint", ""),
            "keys": {"p256dh": sub.get("p256dh", ""), "auth": sub.get("auth", "")},
        }
        if not info["endpoint"] or not info["keys"]["p256dh"]:
            continue
        try:
            webpush(
                subscription_info=info,
                data=payload,
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims={"sub": VAPID_SUBJECT},
            )
            sent += 1
        except WebPushException as exc:
            # 404 or 410 means the browser threw the subscription away; stop keeping it.
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status in (404, 410):
                try:
                    rtdb.reference(f"push/{_push_key(uid)}/{key}").delete()
                except Exception:
                    pass
        except Exception:
            continue
    return sent


class FcmTokenRequest(BaseModel):
    token: str


def send_fcm(uid: str, title: str, body: str) -> int:
    """One notification to every phone this account registered. Returns how many went."""
    if messaging is None:
        return 0
    tokens = rtdb.reference(f"fcm/{_push_key(uid)}").get() or {}
    if not isinstance(tokens, dict) or not tokens:
        return 0
    sent = 0
    for key, token in list(tokens.items()):
        if not isinstance(token, str) or not token:
            continue
        try:
            messaging.send(
                messaging.Message(
                    token=token,
                    notification=messaging.Notification(title=title, body=body),
                    data={"title": title, "body": body},
                    android=messaging.AndroidConfig(priority="high"),
                )
            )
            sent += 1
        except Exception as exc:
            text = str(exc)
            # A token the phone threw away should not be kept forever.
            if "not registered" in text.lower() or "invalid" in text.lower():
                try:
                    rtdb.reference(f"fcm/{_push_key(uid)}/{key}").delete()
                except Exception:
                    pass
    return sent


@app.post("/api/push/fcm-subscribe")
def fcm_subscribe(payload: FcmTokenRequest, user=Depends(verify_firebase_user)):
    token = payload.token.strip()
    if not token:
        raise HTTPException(status_code=400, detail="No token was sent.")
    key = hashlib.sha256(token.encode("utf-8")).hexdigest()[:24]
    rtdb.reference(f"fcm/{_push_key(user['uid'])}/{key}").set(token)
    return {"status": "subscribed"}


@app.post("/api/push/fcm-test")
def fcm_test(user=Depends(verify_firebase_user)):
    """Send one notification to the caller's own phones, and say exactly what happened."""
    if messaging is None:
        return {"tokens": 0, "sent": 0, "error": "This server has no messaging library."}
    tokens = rtdb.reference(f"fcm/{_push_key(user['uid'])}").get() or {}
    if not isinstance(tokens, dict) or not tokens:
        return {"tokens": 0, "sent": 0, "error": "No phone registered for this account."}

    sent = 0
    error = ""
    for key, token in list(tokens.items()):
        if not isinstance(token, str) or not token:
            continue
        try:
            messaging.send(
                messaging.Message(
                    token=token,
                    notification=messaging.Notification(
                        title="Eyemail test",
                        body="If you can read this, push works on this phone.",
                    ),
                    data={"title": "Eyemail test", "body": "Push works on this phone."},
                    android=messaging.AndroidConfig(priority="high"),
                )
            )
            sent += 1
        except Exception as exc:
            error = str(exc)[:300]
    return {"tokens": len(tokens), "sent": sent, "error": error}


@app.post("/api/push/fcm-unsubscribe")
def fcm_unsubscribe(payload: FcmTokenRequest, user=Depends(verify_firebase_user)):
    key = hashlib.sha256(payload.token.strip().encode("utf-8")).hexdigest()[:24]
    rtdb.reference(f"fcm/{_push_key(user['uid'])}/{key}").delete()
    return {"status": "unsubscribed"}


@app.get("/api/push/public-key")
def push_public_key():
    """The browser needs this to subscribe. It is public by design."""
    if not push_enabled():
        raise HTTPException(status_code=503, detail="Push is not configured on the server yet.")
    return {"key": VAPID_PUBLIC_KEY}


@app.post("/api/push/subscribe")
def push_subscribe(payload: PushSubscriptionRequest, user=Depends(verify_firebase_user)):
    if not push_enabled():
        raise HTTPException(status_code=503, detail="Push is not configured on the server yet.")
    if not payload.endpoint.startswith("https://"):
        raise HTTPException(status_code=400, detail="That subscription does not look right.")
    key = hashlib.sha256(payload.endpoint.encode("utf-8")).hexdigest()[:24]
    rtdb.reference(f"push/{_push_key(user['uid'])}/{key}").set(
        {"endpoint": payload.endpoint, "p256dh": payload.p256dh, "auth": payload.auth}
    )
    return {"status": "subscribed"}


@app.post("/api/push/unsubscribe")
def push_unsubscribe(payload: PushSubscriptionRequest, user=Depends(verify_firebase_user)):
    key = hashlib.sha256(payload.endpoint.encode("utf-8")).hexdigest()[:24]
    rtdb.reference(f"push/{_push_key(user['uid'])}/{key}").delete()
    return {"status": "unsubscribed"}


# ==============================================================================
# 7. INTERNAL OTP BRIDGE (For other Indoworkspace Apps to send OTPs via Eyemail)
# ==============================================================================
@app.post("/api/internal/send-mail")
def internal_send_mail(payload: InternalSendMailRequest, _=Depends(verify_internal_secret)):
    """Allows other Indoworkspace apps to send OTPs/alerts without sharing user accounts."""
    to_email = payload.to.strip().lower()
    subject = payload.subject.strip()
    body = payload.body.strip()
    sender_name = payload.sender_name.strip() or "Indoworkspace Security"
    now_iso = datetime.now(timezone.utc).isoformat()
    snippet = re.sub(r"\s+", " ", body)[:120]

    # A runaway caller on your side must not be able to flood a mailbox.
    take_slot("limits/internal", max_count=120, window_seconds=60)

    if to_email.endswith(f"@{DOMAIN_NAME}"):
        username = rtdb_safe_key(to_email.split("@")[0])
        target_uid = resolve_uid(rtdb.reference(f"usernames/{username}").get())
        if not target_uid:
            raise HTTPException(status_code=404, detail="Eyemail recipient does not exist")

        target_profile = rtdb.reference(f"users/{user_node(target_uid)}").get() or {}
        _used, _limit, target_full = storage_state(target_profile)
        if target_full:
            raise HTTPException(status_code=507, detail="Recipient mailbox is full.")
        stored = fs_db.collection("users").document(target_uid).collection("emails").add({
            "from": f"noreply@{DOMAIN_NAME}",
            "fromName": sender_name,
            "to": to_email,
            "subject": subject,
            "body": body,
            "snippet": snippet,
            "folder": "inbox",
            "read": False,
            "starred": False,
            "timestamp": firestore.SERVER_TIMESTAMP,
            "createdAt": now_iso,
        })
        return {"status": "sent", "delivery": "internal_free"}

    send_via_brevo(sender_name, f"noreply@{DOMAIN_NAME}", to_email, subject, body)
    return {"status": "sent", "delivery": "brevo_free"}
