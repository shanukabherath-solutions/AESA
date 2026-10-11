from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.auth.security import Permission, decode_token, has_permission
from app.config import get_settings
from app.db import get_db
from app.models import User

bearer = HTTPBearer(auto_error=False)


@dataclass
class Principal:
    user: User
    session_id: str
    ip: str | None

    @property
    def username(self) -> str:
        return self.user.username


def get_principal(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer),
                  db: Session = Depends(get_db)) -> Principal:
    unauth = HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    if creds is None:
        raise unauth
    try:
        claims = decode_token(get_settings(), creds.credentials)
    except jwt.PyJWTError:
        raise unauth from None
    user = db.get(User, int(claims["sub"]))
    if user is None or not user.is_active:
        raise unauth
    return Principal(user, claims.get("jti", ""), request.client.host if request.client else None)


def require(perm: Permission) -> Callable[..., Principal]:
    def dep(p: Principal = Depends(get_principal)) -> Principal:
        if not has_permission(p.user.role, perm):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Role {p.user.role} lacks permission {perm.value}")
        return p

    return dep
