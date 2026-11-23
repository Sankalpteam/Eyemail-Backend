#!/usr/bin/env python3
"""Make the two keys web push needs, once, and print them for Render's environment.

Run it on your own machine, not in the repository:

    pip install py-vapid
    python make_vapid_keys.py

Paste the two values into Render, Environment, then redeploy. Never commit them.
"""
import base64
import os


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def main() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key()

    private_bytes = private.private_numbers().private_value.to_bytes(32, "big")
    public_bytes = public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    print("VAPID_PUBLIC_KEY=" + b64(public_bytes))
    print("VAPID_PRIVATE_KEY=" + b64(private_bytes))
    print("VAPID_SUBJECT=mailto:hello@eyemail.in")
    print()
    print("These two are a pair. Set both in Render, and change them together.")


if __name__ == "__main__":
    main()
