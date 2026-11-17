#!/usr/bin/env python3
"""One-off cleanup: remove the old usr_... nodes left over from the internal bridge.

Before the uid became the mailbox address, mailboxes were stored as
users/usr_04e4b810217449b898 with an index entry usernames/<name> = {uid: ...}.
Nothing references them any more. This script removes them.

Dry run by default; nothing is deleted unless you pass --apply.

    python cleanup_legacy_nodes.py            # show what would be removed
    python cleanup_legacy_nodes.py --apply    # remove it

What it touches, and only this:
  users/<node>            where the profile uid or the node key has no "@"
  usernames/<name>        where the stored uid has no "@"
  signup_verified/<node>  for the same legacy keys
  signup_otps/<node>      for the same legacy keys

Mail under users/<uid>/emails in Firestore is left alone: a legacy uid has no
Firestore mailbox in the new layout, so there is nothing to delete there.

Needs FIREBASE_SERVICE_ACCOUNT_JSON and FIREBASE_DATABASE_URL.
"""

import argparse
import json
import os
import sys

import firebase_admin
from firebase_admin import credentials, db as rtdb

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


def stored_uid(value):
    if isinstance(value, str):
        return value.strip().lower()
    if isinstance(value, dict):
        return str(value.get("uid") or "").strip().lower()
    return ""


def is_legacy(uid):
    """A uid is legacy when it is not a mailbox address."""
    return bool(uid) and "@" not in uid


def main():
    parser = argparse.ArgumentParser(description="Remove legacy usr_... nodes.")
    parser.add_argument("--apply", action="store_true", help="actually delete")
    args = parser.parse_args()

    init_firebase()

    users = rtdb.reference("users").get() or {}
    usernames = rtdb.reference("usernames").get() or {}
    verified = rtdb.reference("signup_verified").get() or {}
    otps = rtdb.reference("signup_otps").get() or {}

    legacy_user_nodes = []
    for node, profile in users.items():
        uid = stored_uid(profile) or node
        if is_legacy(uid) or is_legacy(node):
            legacy_user_nodes.append((node, uid))

    legacy_usernames = []
    for name, value in usernames.items():
        uid = stored_uid(value)
        if is_legacy(uid):
            legacy_usernames.append((name, uid))

    legacy_verified = [k for k in verified if is_legacy(k)]
    legacy_otps = [k for k in otps if is_legacy(k)]

    print(f"users scanned            : {len(users)}")
    print(f"legacy users/<node>      : {len(legacy_user_nodes)}")
    for node, uid in legacy_user_nodes:
        print(f"   users/{node}  (uid {uid or 'missing'})")
    print(f"legacy usernames entries : {len(legacy_usernames)}")
    for name, uid in legacy_usernames:
        print(f"   usernames/{name} -> {uid}")
    print(f"legacy signup_verified   : {len(legacy_verified)}")
    print(f"legacy signup_otps       : {len(legacy_otps)}")

    total = len(legacy_user_nodes) + len(legacy_usernames) + len(legacy_verified) + len(legacy_otps)
    if not total:
        print("\nNothing to clean up.")
        return

    if not args.apply:
        print(f"\nDry run: {total} node(s) would be removed. Re-run with --apply to do it.")
        return

    for node, _uid in legacy_user_nodes:
        rtdb.reference(f"users/{node}").delete()
    for name, _uid in legacy_usernames:
        rtdb.reference(f"usernames/{name}").delete()
    for key in legacy_verified:
        rtdb.reference(f"signup_verified/{key}").delete()
    for key in legacy_otps:
        rtdb.reference(f"signup_otps/{key}").delete()

    print(f"\nRemoved {total} node(s).")


if __name__ == "__main__":
    main()
