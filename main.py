import os
import json
import re
import secrets
from datetime import datetime, timezone, timedelta
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
app = FastAPI(title="Eyemail Backend API", version="1.1.0")

ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "https://eyemail.in,https://www.eyemail.in,http://localhost:5500,http://127.0.0.1:5500"
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
DOMAIN_NAME = "eyemail.in"
DAILY_EXTERNAL_LIMIT_PER_USER = int(os.environ.get("DAILY_EXTERNAL_LIMIT", "15"))


class SendEmailRequest(BaseModel):
    to: EmailStr
    subject: str
    body: str


class OtpSendRequest(BaseModel):
    email: EmailStr
    app_name: str = "Indoworkspace"


class OtpVerifyRequest(BaseModel):
    email: EmailStr
    otp: str


class SsoSessionRequest(BaseModel):
    uid: str
    email: EmailStr
    name: str


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
    """UptimeRobot ping endpoint to keep Render server awake 24/7"""
    return {"status": "ok", "service": "eyemail-backend", "timestamp": datetime.now(timezone.utc).isoformat()}


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

    # CASE A: Internal @eyemail.in -> @eyemail.in (100% Free & Unlimited)
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

    # CASE B: External Email (Gmail, Yahoo, etc.) via Brevo API
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


# ==============================================================================
# FREE OTP SERVICE FOR ALL 4 APPS (Replaces AWS SES)
# ==============================================================================
@app.post("/api/send-otp")
def send_otp(payload: OtpSendRequest, _=Depends(verify_internal_secret)):
    target_email = payload.email.strip().lower()
    otp_code = str(secrets.randbelow(900000) + 100000)
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(minutes=5)).isoformat()

    db.collection("otp_codes").document(target_email).set({
        "otp": otp_code,
        "expiresAt": expires_at,
        "attempts": 0,
    })

    subject = f"{otp_code} is your {payload.app_name} verification code"
    body = (
        f"Your {payload.app_name} verification code is: {otp_code}\n\n"
        f"This code expires in 5 minutes. Do not share this code with anyone."
    )

    if target_email.endswith(f"@{DOMAIN_NAME}"):
        username = target_email.split("@")[0]
        user_lookup = db.collection("usernames").document(username).get()
        if not user_lookup.exists:
            raise HTTPException(status_code=404, detail="Eyemail address does not exist")
        target_uid = user_lookup.to_dict().get("uid")
        db.collection("users").document(target_uid).collection("emails").add({
            "from": f"noreply@{DOMAIN_NAME}",
            "fromName": f"{payload.app_name} Security",
            "to": target_email,
            "subject": subject,
            "body": body,
            "snippet": f"Your verification code is {otp_code}",
            "folder": "inbox",
            "read": False,
            "starred": False,
            "timestamp": firestore.SERVER_TIMESTAMP,
            "createdAt": now.isoformat(),
        })
        return {"status": "sent", "delivery": "internal_free"}

    send_via_brevo(f"{payload.app_name} Security", f"noreply@{DOMAIN_NAME}", target_email, subject, body)
    return {"status": "sent", "delivery": "brevo_free"}


@app.post("/api/verify-otp")
def verify_otp(payload: OtpVerifyRequest, _=Depends(verify_internal_secret)):
    target_email = payload.email.strip().lower()
    doc_ref = db.collection("otp_codes").document(target_email)
    doc_snap = doc_ref.get()

    if not doc_snap.exists:
        raise HTTPException(status_code=400, detail="No active OTP found for this email")

    data = doc_snap.to_dict()
    if data.get("attempts", 0) >= 5:
        doc_ref.delete()
        raise HTTPException(status_code=429, detail="Too many wrong attempts. Request a new OTP.")

    if datetime.now(timezone.utc) > datetime.fromisoformat(data["expiresAt"]):
        doc_ref.delete()
        raise HTTPException(status_code=400, detail="OTP has expired")

    if not secrets.compare_digest(str(data["otp"]), payload.otp.strip()):
        doc_ref.update({"attempts": data.get("attempts", 0) + 1})
        raise HTTPException(status_code=400, detail="Invalid OTP code")

    doc_ref.delete()
    return {"status": "verified", "email": target_email}


# ==============================================================================
# DYNAMODB CENTRAL ACCOUNT SSO BRIDGE (For connecting your DynamoDB agent later)
# ==============================================================================
@app.post("/api/sso/create-session")
def create_sso_session(payload: SsoSessionRequest, _=Depends(verify_internal_secret)):
    email = payload.email.strip().lower()
    if not email.endswith(f"@{DOMAIN_NAME}"):
        raise HTTPException(status_code=400, detail="SSO email must end with @eyemail.in")

    username = email.split("@")[0]
    uid = payload.uid.strip()

    db.collection("usernames").document(username).set({"uid": uid, "email": email}, merge=True)
    db.collection("users").document(uid).set({
        "uid": uid,
        "name": payload.name.strip(),
        "username": username,
        "email": email,
    }, merge=True)

    custom_token = auth.create_custom_token(uid).decode("utf-8")
    return {"customToken": custom_token, "email": email}
