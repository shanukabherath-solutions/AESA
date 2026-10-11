import sqlite3

from app import auth


def test_password_roundtrip() -> None:
    stored = auth.hash_password("correct horse")
    assert auth.verify_password("correct horse", stored)
    assert not auth.verify_password("wrong", stored)


def test_authenticate(conn: sqlite3.Connection) -> None:
    auth.create_user(conn, "alice", "s3cret-pass")
    assert auth.authenticate(conn, "alice", "s3cret-pass")
    assert not auth.authenticate(conn, "alice", "nope")
    assert not auth.authenticate(conn, "nobody", "s3cret-pass")


def test_token_roundtrip_and_tamper() -> None:
    token = auth.issue_token("alice")
    assert auth.verify_token(token) == "alice"
    body, sig = token.split(".")
    assert auth.verify_token(f"{body}.{'0' * len(sig)}") is None
    assert auth.verify_token("garbage") is None


def test_expired_token() -> None:
    assert auth.verify_token(auth.issue_token("alice", ttl_seconds=-5)) is None


def test_sql_injection_cannot_bypass_login(conn: sqlite3.Connection) -> None:
    """A UNION payload must be treated as data. Fails on the vulnerable implementation."""
    auth.create_user(conn, "alice", "s3cret-pass")
    forged = auth.hash_password("attacker-guess")
    payload = f"nobody' UNION SELECT '{forged}' --"
    assert not auth.authenticate(conn, payload, "attacker-guess")
