import os
import json
import re
import time
import secrets
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import List
from pydantic import BaseModel, EmailStr, Field
import requests
import firebase_admin
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

    user_ref = rtdb.reference(f"users/{uid}")
    existing_user = user_ref.get()
    if existing_user:
        return {"status": "exists", "profile": existing_user}

    # The recovery address must be proven before the mailbox is created.
    verified = rtdb.reference(f"signup_verified/{uid}").get()
    if not verified:
        raise HTTPException(status_code=403, detail="Verify your recovery email first.")
    if int(time.time()) > int(verified.get("expiresAt", 0)):
        rtdb.reference(f"signup_verified/{uid}").delete()
        raise HTTPException(status_code=403, detail="Verification expired. Please verify again.")
    if (verified.get("recoveryEmail") or "").lower() != recovery_email:
        raise HTTPException(status_code=400, detail="Recovery email does not match the one you verified.")

    username_ref = rtdb.reference(f"usernames/{safe_user}")
    if username_ref.get() is not None:
        raise HTTPException(status_code=409, detail=f"{eyemail_address} is already taken.")

    # Save username mapping in Realtime Database
    username_ref.set({
        "uid": uid,
        "username": username,
        "email": eyemail_address,
        "createdAt": now_iso
    })

    # Save user profile & quota in Realtime Database
    profile_data = {
        "uid": uid,
        "name": clean_name,
        "username": username,
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

    rtdb.reference(f"signup_verified/{uid}").delete()

    return {"status": "created", "profile": profile_data}


@app.get("/api/user/profile")
def get_user_profile(user=Depends(verify_firebase_user)):
    uid = user["uid"]
    profile = rtdb.reference(f"users/{uid}").get()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found in Realtime Database")
    return {"profile": profile}


# ==============================================================================
# 1b. SIGNUP: VERIFY THE RECOVERY EMAIL BEFORE THE MAILBOX IS CREATED
# ==============================================================================
@app.post("/api/auth/send-signup-otp")
def send_signup_otp(payload: SignupOtpRequest, user=Depends(verify_firebase_user)):
    uid = user["uid"]

    if rtdb.reference(f"users/{uid}").get():
        raise HTTPException(status_code=409, detail="This account is already registered. Please sign in.")

    recovery_email = payload.recovery_email.strip().lower()
    otp_ref = rtdb.reference(f"signup_otps/{uid}")
    previous = otp_ref.get() or {}
    now = int(time.time())

    last_sent = int(previous.get("sentAt", 0))
    if last_sent and now - last_sent < 60:
        raise HTTPException(status_code=429, detail=f"Please wait {60 - (now - last_sent)}s before asking for another code.")

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
    otp_ref = rtdb.reference(f"signup_otps/{uid}")
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
    rtdb.reference(f"signup_verified/{uid}").set({
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
    profile = rtdb.reference(f"users/{uid}").get()
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
    rtdb.reference(f"users/{uid}/lastLoginAt").set(datetime.now(timezone.utc).isoformat())
    return {"status": "verified"}


# ==============================================================================
# 3. FORGOT PASSWORD VIA RECOVERY EMAIL
# ==============================================================================
@app.post("/api/auth/forgot-password")
def forgot_password(payload: ForgotPasswordRequest):
    raw = payload.eyemail.strip().lower()
    username = raw.split("@")[0] if "@" in raw else raw
    eyemail_address = f"{username}@{DOMAIN_NAME}"
    safe_user = rtdb_safe_key(username)

    user_lookup = rtdb.reference(f"usernames/{safe_user}").get()
    if not user_lookup:
        raise HTTPException(status_code=404, detail=f"No Eyemail account found for {eyemail_address}")

    uid = user_lookup.get("uid")
    profile = rtdb.reference(f"users/{uid}").get() or {}
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
    rtdb.reference(f"users/{uid}/domains/{safe_dom}").set({"domain": domain, "verified": False})

    return {"status": "added", "domainInfo": domain_record}


# ==============================================================================
# 5. SEND EMAIL (Firestore Emails + Realtime DB Quota & Routing)
# ==============================================================================
@app.post("/api/send-email")
def send_email(payload: SendEmailRequest, user=Depends(verify_firebase_user)):
    uid = user["uid"]
    user_ref = rtdb.reference(f"users/{uid}")
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

    # CASE A: every recipient is @eyemail.in -> deliver inside, no Brevo call
    if all(addr.endswith(f"@{DOMAIN_NAME}") for addr in all_recipients):
        for addr in all_recipients:
            target_username = rtdb_safe_key(addr.split("@")[0])
            username_data = rtdb.reference(f"usernames/{target_username}").get()
            if not username_data:
                raise HTTPException(status_code=404, detail=f"Address {addr} does not exist.")

            target_uid = username_data.get("uid")
            target_user_ref = rtdb.reference(f"users/{target_uid}")
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
    usage_ref = rtdb.reference(f"usage/{uid}/{today_str}")
    sent_today = int((usage_ref.get() or {}).get("externalSent", 0))

    if sent_today >= daily_limit:
        raise HTTPException(
            status_code=429,
            detail=f"Daily external limit ({daily_limit} emails/day) reached."
        )

    send_via_brevo(sender_name, sender_email, to_email, subject, body, cc=cc_list, bcc=bcc_list)
    usage_ref.update({"externalSent": sent_today + 1})

    store_message(uid, "sent", True, to_email)
    user_ref.update({"storageUsedBytes": current_used + msg_size})

    return {"status": "sent", "delivery": "brevo", "to": to_email,
            "cc": cc_list, "bcc": bcc_list}


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
    username_data = rtdb.reference(f"usernames/{target_username}").get()

    if not username_data:
        raise HTTPException(status_code=404, detail=f"Mailbox {to_email} does not exist")

    target_uid = username_data.get("uid")
    target_user_ref = rtdb.reference(f"users/{target_uid}")
    target_used = int((target_user_ref.get() or {}).get("storageUsedBytes", 0))

    now_iso = datetime.now(timezone.utc).isoformat()
    snippet = re.sub(r"\s+", " ", body)[:120]
    msg_size = len(body.encode("utf-8")) + len(subject.encode("utf-8")) + 256

    fs_db.collection("users").document(target_uid).collection("emails").add({
        "from": sender_email,
        "fromName": sender_name or sender_email,
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
    target_user_ref.update({"storageUsedBytes": target_used + msg_size})

    return {"status": "received", "to": to_email}


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

    if to_email.endswith(f"@{DOMAIN_NAME}"):
        username = rtdb_safe_key(to_email.split("@")[0])
        user_lookup = rtdb.reference(f"usernames/{username}").get()
        if not user_lookup:
            raise HTTPException(status_code=404, detail="Eyemail recipient does not exist")

        target_uid = user_lookup.get("uid")
        fs_db.collection("users").document(target_uid).collection("emails").add({
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
