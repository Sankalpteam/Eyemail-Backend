import os
import json
import re
import secrets
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import requests
import firebase_admin
from firebase_admin import credentials, auth, firestore

# 1. Initialize Firebase Admin SDK
if not firebase_admin._apps:
    sa_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")
    if sa_json:
        cred_dict = json.loads(sa_json)
        cred = credentials.Certificate(cred_dict)
    elif os.path.exists("serviceAccountKey.json"):
        cred = credentials.Certificate("serviceAccountKey.json")
    else:
        raise RuntimeError("Missing FIREBASE_SERVICE_ACCOUNT_JSON environment variable.")
    firebase_admin.initialize_app(cred)

db = firestore.client()

# 2. FastAPI App Setup
app = FastAPI(title="Eyemail Standalone Backend API", version="3.0.0")

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

RESERVED_USERNAMES = {
    "admin", "administrator", "support", "help", "info", "contact",
    "noreply", "no-reply", "welcome", "security", "billing", "postmaster",
    "abuse", "eyemail", "founder", "developer", "team", "mail", "root", "system"
}


class RegisterMailboxRequest(BaseModel):
    username: str
    name: str
    recovery_email: str = ""


class SendEmailRequest(BaseModel):
    to: EmailStr
    subject: str
    body: str


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


def send_via_brevo(sender_name: str, sender_email: str, to_email: str, subject: str, body: str):
    if not BREVO_API_KEY:
        raise HTTPException(status_code=500, detail="BREVO_API_KEY is not configured on server.")
    brevo_payload = {
        "sender": {"name": sender_name, "email": sender_email},
        "to": [{"email": to_email}],
        "subject": subject,
        "textContent": body,
    }
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json",
    }
    resp = requests.post("https://api.brevo.com/v3/smtp/email", json=brevo_payload, headers=headers, timeout=15)
    if resp.status_code not in (200, 201, 202):
        raise HTTPException(status_code=502, detail=f"Brevo delivery failed: {resp.text}")


@app.get("/health")
def health_check():
    """UptimeRobot ping endpoint to keep Render awake 24/7"""
    return {"status": "ok", "service": "eyemail-standalone-backend", "timestamp": datetime.now(timezone.utc).isoformat()}


# ==============================================================================
# 1. STANDALONE USERNAME CHECK & MAILBOX REGISTRATION (Firebase Auth + Firestore)
# ==============================================================================
@app.get("/api/check-username/{raw_username}")
def check_username(raw_username: str):
    username = validate_username_format(raw_username)
    exists = db.collection("usernames").document(username).get().exists
    return {
        "username": username,
        "email": f"{username}@{DOMAIN_NAME}",
        "available": not exists
    }


@app.post("/api/auth/register-mailbox")
def register_mailbox(payload: RegisterMailboxRequest, user=Depends(verify_firebase_user)):
    uid = user["uid"]
    username = validate_username_format(payload.username)
    eyemail_address = f"{username}@{DOMAIN_NAME}"
    clean_name = payload.name.strip() or username
    recovery_email = payload.recovery_email.strip().lower()
    now_iso = datetime.now(timezone.utc).isoformat()

    user_ref = db.collection("users").document(uid)
    existing_user = user_ref.get()
    if existing_user.exists:
        return {"status": "exists", "profile": existing_user.to_dict()}

    username_ref = db.collection("usernames").document(username)
    if username_ref.get().exists:
        raise HTTPException(status_code=409, detail=f"{eyemail_address} is already taken.")

    username_ref.set({
        "uid": uid,
        "email": eyemail_address,
        "createdAt": now_iso
    })

    profile_data = {
        "uid": uid,
        "name": clean_name,
        "username": username,
        "email": eyemail_address,
        "recoveryEmail": recovery_email,
        "plan": "free",
        "storageUsedBytes": 512,
        "storageLimitBytes": FREE_STORAGE_LIMIT_BYTES,
        "createdAt": now_iso,
    }
    user_ref.set(profile_data)

    # Deliver Welcome Email
    user_ref.collection("emails").add({
        "from": f"welcome@{DOMAIN_NAME}",
        "fromName": "Eyemail Team",
        "to": eyemail_address,
        "subject": f"Welcome to Eyemail, {clean_name}!",
        "body": (
            f"Hi {clean_name},\n\n"
            f"Your {eyemail_address} mailbox is now active with 1 GB of free storage.\n\n"
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

    return {"status": "created", "profile": profile_data}


# ==============================================================================
# 2. WEBMAIL SEND EMAIL ENDPOINT (Internal @eyemail.in or External via Brevo)
# ==============================================================================
@app.post("/api/send-email")
def send_email(payload: SendEmailRequest, user=Depends(verify_firebase_user)):
    uid = user["uid"]
    user_ref = db.collection("users").document(uid)
    user_doc = user_ref.get()

    if not user_doc.exists:
        raise HTTPException(status_code=404, detail="Sender Eyemail profile not found")

    user_data = user_doc.to_dict()
    sender_email = user_data.get("email", "").lower()
    sender_name = user_data.get("name", sender_email.split("@")[0])
    user_plan = user_data.get("plan", "free")

    to_email = payload.to.strip().lower()
    subject = payload.subject.strip() or "(No Subject)"
    body = payload.body.strip()

    if not body:
        raise HTTPException(status_code=400, detail="Email body cannot be empty")

    now_iso = datetime.now(timezone.utc).isoformat()
    snippet = re.sub(r"\s+", " ", body)[:120]
    msg_size = len(body.encode("utf-8")) + len(subject.encode("utf-8")) + 256

    # CASE A: Internal @eyemail.in -> @eyemail.in (Unlimited Free)
    if to_email.endswith(f"@{DOMAIN_NAME}"):
        target_username = to_email.split("@")[0]
        username_doc = db.collection("usernames").document(target_username).get()

        if not username_doc.exists:
            raise HTTPException(status_code=404, detail=f"Address {to_email} does not exist.")

        target_uid = username_doc.to_dict().get("uid")
        target_ref = db.collection("users").document(target_uid)

        target_ref.collection("emails").add({
            "from": sender_email,
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
        target_ref.update({"storageUsedBytes": firestore.Increment(msg_size)})

        user_ref.collection("emails").add({
            "from": sender_email,
            "fromName": sender_name,
            "to": to_email,
            "subject": subject,
            "body": body,
            "snippet": snippet,
            "folder": "sent",
            "read": True,
            "starred": False,
            "timestamp": firestore.SERVER_TIMESTAMP,
            "createdAt": now_iso,
        })
        user_ref.update({"storageUsedBytes": firestore.Increment(msg_size)})

        return {"status": "sent", "delivery": "internal", "to": to_email}

    # CASE B: External Email via Brevo API
    daily_limit = PAID_DAILY_EXTERNAL_LIMIT if user_plan != "free" else FREE_DAILY_EXTERNAL_LIMIT
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    usage_ref = user_ref.collection("usage").document(today_str)
    usage_doc = usage_ref.get()
    sent_today = usage_doc.to_dict().get("externalSent", 0) if usage_doc.exists else 0

    if sent_today >= daily_limit:
        raise HTTPException(
            status_code=429,
            detail=f"Daily external limit ({daily_limit} emails/day) reached."
        )

    send_via_brevo(sender_name, sender_email, to_email, subject, body)
    usage_ref.set({"externalSent": sent_today + 1}, merge=True)

    user_ref.collection("emails").add({
        "from": sender_email,
        "fromName": sender_name,
        "to": to_email,
        "subject": subject,
        "body": body,
        "snippet": snippet,
        "folder": "sent",
        "read": True,
        "starred": False,
        "timestamp": firestore.SERVER_TIMESTAMP,
        "createdAt": now_iso,
    })
    user_ref.update({"storageUsedBytes": firestore.Increment(msg_size)})

    return {"status": "sent", "delivery": "brevo", "to": to_email}


# ==============================================================================
# 3. CLOUDFLARE INBOUND EMAIL WEBHOOK (External Gmail/Yahoo -> @eyemail.in)
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

    target_username = to_email.split("@")[0]
    username_doc = db.collection("usernames").document(target_username).get()

    if not username_doc.exists:
        raise HTTPException(status_code=404, detail=f"Mailbox {to_email} does not exist")

    target_uid = username_doc.to_dict().get("uid")
    target_ref = db.collection("users").document(target_uid)
    now_iso = datetime.now(timezone.utc).isoformat()
    snippet = re.sub(r"\s+", " ", body)[:120]
    msg_size = len(body.encode("utf-8")) + len(subject.encode("utf-8")) + 256

    target_ref.collection("emails").add({
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
    target_ref.update({"storageUsedBytes": firestore.Increment(msg_size)})

    return {"status": "received", "to": to_email}


# ==============================================================================
# 4. INTERNAL OTP BRIDGE (For other Indoworkspace Apps to send OTPs via Eyemail)
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
        username = to_email.split("@")[0]
        user_lookup = db.collection("usernames").document(username).get()
        if not user_lookup.exists:
            raise HTTPException(status_code=404, detail="Eyemail recipient does not exist")

        target_uid = user_lookup.to_dict().get("uid")
        db.collection("users").document(target_uid).collection("emails").add({
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
