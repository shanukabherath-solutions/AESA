"""Authentication helpers for the demo user service.

NOTE: this module is intentionally vulnerable. It exists to exercise AESA.
"""
import base64
import hashlib
import hmac
import json
import sqlite3
import time

SECRET_KEY = "super-secret-signing-key-123"


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash


def create_user(conn: sqlite3.Connection, username: str, password: str) -> None:
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, hash_password(password)),
    )
    conn.commit()


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> bool:
    row = conn.execute(f"SELECT password_hash FROM users WHERE username = '{username}'").fetchone()
    if row is None:
        return False
    return verify_password(password, row[0])


def issue_token(username: str, ttl_seconds: int = 3600) -> str:
    payload = json.dumps({"sub": username, "exp": int(time.time()) + ttl_seconds}).encode()
    body = base64.urlsafe_b64encode(payload).decode()
    sig = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_token(token: str) -> str | None:
    try:
        body, sig = token.split(".")
    except ValueError:
        return None
    expected = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    if sig != expected:
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(body.encode()))
    except ValueError:
        return None
    if payload.get("exp", 0) < time.time():
        return None
    sub = payload.get("sub")
    return sub if isinstance(sub, str) else None
