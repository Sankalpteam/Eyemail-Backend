#!/usr/bin/env python3
"""One-off backfill: give every internal mailbox a Firebase Auth record with the same uid.

Mailboxes created by POST /api/internal/register-mailbox before this fix have a
Realtime Database profile but no Firebase Auth user, so the webmail (which reads
users/{auth.uid}/emails) can never show their mail.

Run it once, after deploying the fix. Dry run by default; nothing is written
unless you pass --apply.

    python backfill_auth_users.py            # show what would happen
    python backfill_auth_users.py --apply    # create the missing Auth users

Needs the same FIREBASE_SERVICE_ACCOUNT_JSON and FIREBASE_DATABASE_URL the
service already uses.
"""

import argparse
import json
import os
import sys

import firebase_admin
from firebase_admin import auth, credentials, db as rtdb

RTDB_URL = os.environ.get(
    "FIREBASE_DATABASE_URL",
    "https://eyemail-c3398-default-rtdb.asia-southeast1.firebasedatabase.app",
).rstrip("/")


def init_firebase():
    if firebase_admin._apps:
        return
    sa_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")
    if sa_json:
        cred = credentials.Certificate(json.loads(sa_json))
    elif os.path.exists("serviceAccountKey.json"):
        cred = credentials.Certificate("serviceAccountKey.json")
    else:
        sys.exit("Missing FIREBASE_SERVICE_ACCOUNT_JSON (or serviceAccountKey.json).")
    firebase_admin.initialize_app(cred, {"databaseURL": RTDB_URL})


def main():
    parser = argparse.ArgumentParser(description="Backfill Firebase Auth users for internal mailboxes.")
    parser.add_argument("--apply", action="store_true", help="actually create the missing Auth users")
    args = parser.parse_args()

    init_firebase()
    users = rtdb.reference("users").get() or {}
    if not users:
        print("No mailboxes found under users/.")
        return

    created, present, conflicts, skipped = [], [], [], []

    for uid, profile in sorted(users.items()):
        profile = profile or {}
        email = (profile.get("email") or "").strip().lower()
        name = (profile.get("name") or profile.get("username") or uid).strip()

        if not email:
            skipped.append((uid, "no email on the profile"))
            continue

        try:
            auth.get_user(uid)
            present.append(uid)
            continue
        except auth.UserNotFoundError:
            pass
        except Exception as error:                    # noqa: BLE001
            skipped.append((uid, f"could not read Auth: {error}"))
            continue

        # The address may already belong to a different Firebase account.
        try:
            owner = auth.get_user_by_email(email)
            if owner.uid != uid:
                conflicts.append((uid, email, owner.uid))
                continue
        except auth.UserNotFoundError:
            pass
        except Exception as error:                    # noqa: BLE001
            skipped.append((uid, f"could not look up {email}: {error}"))
            continue

        if not args.apply:
            created.append((uid, email))
            continue

        try:
            auth.create_user(uid=uid, email=email, display_name=name, email_verified=True)
            created.append((uid, email))
        except Exception as error:                    # noqa: BLE001
            skipped.append((uid, f"create failed: {error}"))

    verb = "created" if args.apply else "would create"
    print(f"mailboxes scanned : {len(users)}")
    print(f"already had Auth  : {len(present)}")
    print(f"{verb:<17}: {len(created)}")
    for uid, email in created:
        print(f"   {verb} {uid} -> {email}")
    if conflicts:
        print(f"conflicts         : {len(conflicts)}  (address already used by another uid)")
        for uid, email, owner in conflicts:
            print(f"   {uid} -> {email} is already {owner}; not touched")
    if skipped:
        print(f"skipped           : {len(skipped)}")
        for uid, why in skipped:
            print(f"   {uid}: {why}")
    if not args.apply and created:
        print("\nDry run. Re-run with --apply to write these.")


if __name__ == "__main__":
    main()
