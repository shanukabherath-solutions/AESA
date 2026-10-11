from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.config import Settings
from app.models.enums import Role

_ph = PasswordHasher()


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, stored: str) -> bool:
    try:
        return _ph.verify(stored, password)
    except (VerificationError, InvalidHashError):
        return False


class Permission(str, Enum):
    READ_DASHBOARD = "read:dashboard"
    READ_LOGS = "read:logs"
    INSPECT_REPO = "inspect:repo"
    CREATE_TASK = "task:create"
    APPROVE_PATCH = "approve:patch"
    APPROVE_DEPLOY = "approve:deploy"
    MANAGE_REPOS = "manage:repos"
    MANAGE_POLICY = "manage:policy"
    MANAGE_USERS = "manage:users"


_VIEW = {Permission.READ_DASHBOARD, Permission.READ_LOGS}
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.VIEWER: set(_VIEW),
    Role.DEVELOPER: _VIEW | {Permission.INSPECT_REPO, Permission.CREATE_TASK},
    # approvers review and approve, but deliberately cannot create agent tasks (separation of duties)
    Role.APPROVER: _VIEW | {Permission.INSPECT_REPO, Permission.APPROVE_PATCH, Permission.APPROVE_DEPLOY},
    Role.ADMIN: set(Permission),
}


def has_permission(role: str, perm: Permission) -> bool:
    try:
        return perm in ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return False


def create_token(settings: Settings, user_id: int, username: str, role: str) -> tuple[str, str]:
    jti = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user_id), "username": username, "role": role, "jti": jti,
               "iat": now, "exp": now + timedelta(minutes=settings.jwt_ttl_minutes)}
    return jwt.encode(payload, settings.effective_jwt_secret, algorithm=settings.jwt_algorithm), jti


def decode_token(settings: Settings, token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.effective_jwt_secret, algorithms=[settings.jwt_algorithm])


class LoginLimiter:
    """In-memory brute-force throttle (per username+ip). Use a shared store behind multiple workers."""

    def __init__(self) -> None:
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def blocked(self, key: str, settings: Settings) -> bool:
        with self._lock:
            now = time.time()
            recent = [t for t in self._fails.get(key, []) if now - t < settings.login_lockout_seconds]
            self._fails[key] = recent
            return len(recent) >= settings.login_max_failures

    def fail(self, key: str) -> None:
        with self._lock:
            self._fails.setdefault(key, []).append(time.time())

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)


limiter = LoginLimiter()
