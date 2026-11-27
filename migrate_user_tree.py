#!/usr/bin/env python3
"""Move every scattered record into the person it belongs to.

Before this, one account was spread over eight top level branches:
    fcm/, push/, pushlog/, usage/, limits/, domains/  plus users/ and usernames/
so opening one user showed a fragment, and the same fact could exist twice.

After it, everything about a person lives under users/<uid>/, and the two top level
branches that remain hold one line each, as pointers:
    usernames/<name>   -> uid
    domains/<domain>   -> { ownerUid }

Run it with no arguments to see what it would do. Add --apply to actually move things.
Nothing is deleted until it has been written to the new place and read back.
"""
import argparse
import sys

import firebase_admin
from firebase_admin import credentials, db as rtdb
import os
import json

DRY = True


def key_of(uid: str) -> str:
    """Realtime Database keys cannot contain dots."""
    return uid.replace(".", ",").replace("#", "_").replace("$", "_").replace("[", "(").replace("]", ")")


def main() -> None:
    global DRY
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="write the changes, not just print them")
    args = parser.parse_args()
    DRY = not args.apply

    raw = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
    if not raw:
        print("FIREBASE_SERVICE_ACCOUNT_JSON is not set.", file=sys.stderr)
        raise SystemExit(2)
    creds = credentials.Certificate(json.loads(raw))
    if not firebase_admin._apps:
        firebase_admin.initialize_app(creds, {"databaseURL": os.getenv("FIREBASE_DATABASE_URL")})

    moved = 0

    def put(path: str, value) -> None:
        nonlocal moved
        if DRY:
            print(f"would write {path}")
        else:
            rtdb.reference(path).set(value)
            print(f"wrote {path}")
        moved += 1

    def drop(path: str) -> None:
        if DRY:
            print(f"would delete {path}")
        else:
            rtdb.reference(path).delete()
            print(f"deleted {path}")

    # 1. notification registrations, keyed by a hash of the uid. The user node carries
    #    the uid itself, so the hash is only a lookup. Read it back from users/.
    for branch, into in (("fcm", "push/fcm"), ("push", "push/web"), ("pushlog", "push/last")):
        data = rtdb.reference(branch).get() or {}
        if not isinstance(data, dict):
            continue
        for hashed, value in data.items():
            owner = find_owner_by_hash(hashed)
            if not owner:
                print(f"skip {branch}/{hashed}: no user found for that hash")
                continue
            put(f"users/{owner}/{into}" + (f"/{hashed}" if into != "push/last" else ""), value)
            drop(f"{branch}/{hashed}")

    # 2. daily counts and rate counters
    for branch, into in (("usage", "usage/daily"), ("limits", "usage/limits")):
        data = rtdb.reference(branch).get() or {}
        if not isinstance(data, dict):
            continue
        for name, value in data.items():
            if branch == "limits" and name == "internal":
                continue                      # the OTP bridge counter is not per user
            if branch == "limits":
                for uid_key, counter in (value or {}).items():
                    put(f"users/{uid_key}/usage/limits/{name}", counter)
                    drop(f"limits/{name}/{uid_key}")
                continue
            put(f"users/{name}/{into}", value)
            drop(f"usage/{name}")

    # 2b. the two old signup staging branches become one
    otps = rtdb.reference("signup_otps").get() or {}
    if isinstance(otps, dict):
        for uid_key, value in otps.items():
            put(f"pending/{uid_key}/otp", value)
            drop(f"signup_otps/{uid_key}")
    verified = rtdb.reference("signup_verified").get() or {}
    if isinstance(verified, dict):
        for uid_key, value in verified.items():
            put(f"pending/{uid_key}/verified", value)
            drop(f"signup_verified/{uid_key}")

    # 2c. the OTP bridge ceiling is global, but not a branch of its own
    internal = rtdb.reference("limits/internal").get()
    if internal is not None:
        put("system/limits/internal", internal)
        drop("limits/internal")

    # 3. domains: the record moves into the owner, the top level keeps the owner only
    domains = rtdb.reference("domains").get() or {}
    if isinstance(domains, dict):
        for dom_key, record in domains.items():
            if not isinstance(record, dict):
                continue
            owner = record.get("ownerUid") or ""
            if not owner:
                print(f"skip domains/{dom_key}: no owner recorded")
                continue
            put(f"users/{key_of(owner)}/domains/{dom_key}", record)
            put(f"domains/{dom_key}", {"ownerUid": owner})

    print()
    print(f"{'Would change' if DRY else 'Changed'} {moved} records.")
    if DRY:
        print("Nothing was written. Run with --apply when the list above looks right.")


def find_owner_by_hash(hashed: str) -> str:
    """The hash was sha256(uid)[:32]. Walk the users and find whose hash it is."""
    import hashlib
    users = rtdb.reference("users").get() or {}
    if not isinstance(users, dict):
        return ""
    for uid_key in users.keys():
        candidate = uid_key.replace(",", ".")
        if hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:32] == hashed:
            return uid_key
    return ""


if __name__ == "__main__":
    main()
