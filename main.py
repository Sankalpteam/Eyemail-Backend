import os
import json
import re
import secrets
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Header, Depends
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
app = FastAPI(title="Eyemail Backend API", version="2.0.0")

ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "https://eyemail.in,https://www.eyemail.in,https://indoworkspace.github.io,http://localhost:5500,http://127.0.0.1:5500"
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
INDO_ACCOUNT_API_URL = os.environ.get("INDO_ACCOUNT_API_URL", "").rstrip("/")
DOMAIN_NAME = "eyemail.in"
DAILY_EXTERNAL_LIMIT_PER_USER = int(os.environ.get("DAILY_EXTERNAL_LIMIT", "15"))


class SendEmailRequest(BaseModel):
    to: EmailStr
    subject: str
    body: str


class SsoExchangeRequest(BaseModel):
    code: str
    code_verifier: str
    device: str = "Web Browser"


class RegisterMailboxRequest(BaseModel):
    uid: str
    email: EmailStr
    name: str


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


def ensure_mailbox_exists(uid: str, email: str, name: str):
    """Creates Firestore username mapping, user profile, and welcome email if not yet created."""
    clean_email = email.strip().lower()
    clean_uid = uid.strip()
    clean_name = name.strip() or clean_email.split("@")[0]
    username = clean_email.split("@")[0]
    now_iso = datetime.now(timezone.utc).isoformat()

    db.collection("usernames").document(username).set(
        {"uid": clean_uid, "email": clean_email},
        merge=True
    )

    user_ref = db.collection("users").document(clean_uid)
    user_snap = user_ref.get()

    if not user_snap.exists:
        user_ref.set({
            "uid": clean_uid,
            "name": clean_name,
            "username": username,
            "email": clean_email,
            "createdAt": now_iso,
        })
        user_ref.collection("emails").add({
            "from": f"welcome@{DOMAIN_NAME}",
            "fromName": "Eyemail Team",
            "to": clean_email,
            "subject": f"Welcome to Eyemail, {clean_name}!",
            "body": (
                f"Hi {clean_name},\n\n"
                f"Your {clean_email} mailbox is now active and linked to your Indoworkspace Account.\n\n"
                f"You can send and receive emails with Gmail, Yahoo, and other Eyemail users instantly.\n\n"
                f"— Team Eyemail"
            ),
            "snippet": f"Hi {clean_name}, your {clean_email} mailbox is now active.",
            "folder": "inbox",
            "read": False,
            "starred": True,
            "timestamp": firestore.SERVER_TIMESTAMP,
            "createdAt": now_iso,
        })
    else:
        user_ref.set({"name": clean_name, "email": clean_email, "username": username}, merge=True)


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
    return {"status": "ok", "service": "eyemail-backend", "timestamp": datetime.now(timezone.utc).isoformat()}


# ==============================================================================
# 1. CENTRAL ACCOUNT PKCE SSO EXCHANGE (Flow A)
# ==============================================================================
@app.post("/api/auth/sso-exchange")
def sso_exchange(payload: SsoExchangeRequest):
    if not INDO_ACCOUNT_API_URL:
        raise HTTPException(status_code=500, detail="INDO_ACCOUNT_API_URL is not configured on server.")

    # Exchange one-time PKCE authorization code with Central Account API
    resp = requests.post(
        f"{INDO_ACCOUNT_API_URL}/api/v1/app/session",
        json={
            "app": "EYEMAIL",
            "code": payload.code.strip(),
            "code_verifier": payload.code_verifier.strip(),
            "device": payload.device[:80],
        },
        headers={"Content-Type": "application/json"},
        timeout=15,
    )

    if resp.status_code not in (200, 201):
        detail = "Central account sign-in failed"
        try:
            detail = resp.json().get("detail", detail)
        except Exception:
            pass
        raise HTTPException(status_code=resp.status_code, detail=detail)

    session_data = resp.json()
    app_token = session_data.get("token")
    identity = session_data.get("identity", {})

    uid = identity.get("user_id", "").strip()
    eyemail_address = identity.get("indo_id", "").strip().lower()
    full_name = identity.get("full_name", "").strip() or eyemail_address.split("@")[0]

    if not uid or not eyemail_address.endswith(f"@{DOMAIN_NAME}"):
        raise HTTPException(status_code=400, detail="Account does not have a valid @eyemail.in address.")

    # Ensure Firestore mailbox & username routing exist
    ensure_mailbox_exists(uid=uid, email=eyemail_address, name=full_name)

    # Mint Firebase Custom Token for real-time Firestore inbox access
    firebase_custom_token = auth.create_custom_token(uid).decode("utf-8")

    return {
        "firebaseCustomToken": firebase_custom_token,
        "appToken": app_token,
        "profile": {
            "uid": uid,
            "email": eyemail_address,
            "name": full_name,
        },
    }


# ==============================================================================
# 2. INTERNAL WEBHOOKS CALLED BY DYNAMODB CENTRAL ACCOUNT LAMBDA
# ==============================================================================
@app.post("/api/internal/register-mailbox")
def internal_register_mailbox(payload: RegisterMailboxRequest, _=Depends(verify_internal_secret)):
    email = payload.email.strip().lower()
    if not email.endswith(f"@{DOMAIN_NAME}"):
        raise HTTPException(status_code=400, detail="Email must end with @eyemail.in")

    ensure_mailbox_exists(uid=payload.uid, email=email, name=payload.name)
    return {"status": "registered", "email": email}


@app.post("/api/internal/send-mail")
def internal_send_mail(payload: InternalSendMailRequest, _=Depends(verify_internal_secret)):
    """Delivers OTPs & security alerts from Central Account API for ₹0 (replaces AWS SES)."""
    to_email = payload.to.strip().lower()
    subject = payload.subject.strip()
    body = payload.body.strip()
    sender_name = payload.sender_name.strip() or "Indoworkspace Security"
    now_iso = datetime.now(timezone.utc).isoformat()
    snippet = re.sub(r"\s+", " ", body)[:120]

    # Free internal delivery if recipient is @eyemail.in
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

    # Free external delivery via Brevo if recipient is Gmail/Yahoo/etc.
    send_via_brevo(sender_name, f"noreply@{DOMAIN_NAME}", to_email, subject, body)
    return {"status": "sent", "delivery": "brevo_free"}


# ==============================================================================
# 3. WEBMAIL SEND EMAIL ENDPOINT (User -> Internal or External)
# ==============================================================================
@app.post("/api/send-email")
def send_email(payload: SendEmailRequest, user=Depends(verify_firebase_user)):
    uid = user["uid"]
    user_doc = db.collection("users").document(uid).get()

    if not user_doc.exists:
        raise HTTPException(status_code=404, detail="Sender Eyemail profile not found")

    user_data = user_doc.to_dict()
    sender_email = user_data.get("email", "").lower()
    sender_name = user_data.get("name", sender_email.split("@")[0])

    to_email = payload.to.strip().lower()
    subject = payload.subject.strip() or "(No Subject)"
    body = payload.body.strip()

    if not body:
        raise HTTPException(status_code=400, detail="Email body cannot be empty")

    now_iso = datetime.now(timezone.utc).isoformat()
    snippet = re.sub(r"\s+", " ", body)[:120]

    # CASE A: Internal @eyemail.in -> @eyemail.in (Unlimited Free)
    if to_email.endswith(f"@{DOMAIN_NAME}"):
        target_username = to_email.split("@")[0]
        username_doc = db.collection("usernames").document(target_username).get()

        if not username_doc.exists:
            raise HTTPException(status_code=404, detail=f"Address {to_email} does not exist.")

        target_uid = username_doc.to_dict().get("uid")

        db.collection("users").document(target_uid).collection("emails").add({
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

        db.collection("users").document(uid).collection("emails").add({
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

        return {"status": "sent", "delivery": "internal", "to": to_email}

    # CASE B: External Email via Brevo API
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    usage_ref = db.collection("users").document(uid).collection("usage").document(today_str)
    usage_doc = usage_ref.get()
    sent_today = usage_doc.to_dict().get("externalSent", 0) if usage_doc.exists else 0

    if sent_today >= DAILY_EXTERNAL_LIMIT_PER_USER:
        raise HTTPException(
            status_code=429,
            detail=f"Daily external limit ({DAILY_EXTERNAL_LIMIT_PER_USER} emails/day) reached."
        )

    send_via_brevo(sender_name, sender_email, to_email, subject, body)
    usage_ref.set({"externalSent": sent_today + 1}, merge=True)

    db.collection("users").document(uid).collection("emails").add({
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

    return {"status": "sent", "delivery": "brevo", "to": to_email}
