from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.serializers import user_out
from app.audit import logger as audit
from app.auth.deps import Principal, get_principal, require
from app.auth.security import Permission, create_token, hash_password, limiter, verify_password
from app.config import get_settings
from app.db import get_db
from app.models import User
from app.models.enums import Role

router = APIRouter(prefix="/api", tags=["auth"])
_DUMMY = hash_password("dummy-password-for-timing")


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@router.post("/auth/login")
def login(body: LoginBody, request: Request, db: Session = Depends(get_db)) -> dict:
    s, ip = get_settings(), request.client.host if request.client else "unknown"
    key = f"{body.username.lower()}|{ip}"
    if limiter.blocked(key, s):
        audit.record(db, action="login_blocked", user=body.username[:64], status="DENIED", ip=ip, result="too many failed attempts")
        raise HTTPException(429, "Too many failed attempts. Try again later.")
    user = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    ok = verify_password(body.password, user.password_hash if user else _DUMMY)  # constant-ish time either way
    if not user or not ok or not user.is_active:
        limiter.fail(key)
        audit.record(db, action="login_failed", user=body.username[:64], status="DENIED", ip=ip)
        raise HTTPException(401, "Invalid username or password")
    limiter.reset(key)
    token, jti = create_token(s, user.id, user.username, user.role)
    audit.record(db, action="login", user=user.username, status="OK", ip=ip, session_id=jti)
    return {"access_token": token, "token_type": "bearer", "user": user_out(user)}


@router.get("/auth/me")
def me(p: Principal = Depends(get_principal)) -> dict:
    return user_out(p.user)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: Role


class RoleUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None


@router.get("/users")
def list_users(db: Session = Depends(get_db), _: Principal = Depends(require(Permission.MANAGE_USERS))) -> list[dict]:
    return [user_out(u) for u in db.execute(select(User).order_by(User.id)).scalars()]


@router.post("/users", status_code=201)
def create_user(body: UserCreate, request: Request, db: Session = Depends(get_db),
                p: Principal = Depends(require(Permission.MANAGE_USERS))) -> dict:
    if db.execute(select(User).where(User.username == body.username)).scalar_one_or_none():
        raise HTTPException(409, "username already exists")
    u = User(username=body.username, password_hash=hash_password(body.password), role=body.role.value)
    db.add(u)
    db.commit()
    audit.record(db, action="user_created", user=p.username, arguments={"username": u.username, "role": u.role},
                 status="OK", ip=p.ip, session_id=p.session_id)
    return user_out(u)


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: RoleUpdate, db: Session = Depends(get_db),
                p: Principal = Depends(require(Permission.MANAGE_USERS))) -> dict:
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "user not found")
    if u.id == p.user.id and (body.is_active is False or (body.role and body.role != Role.ADMIN)):
        raise HTTPException(400, "you cannot demote or disable yourself")
    if body.role:
        u.role = body.role.value
    if body.is_active is not None:
        u.is_active = body.is_active
    db.commit()
    audit.record(db, action="user_updated", user=p.username, arguments={"user_id": u.id, "role": u.role, "active": u.is_active},
                 status="OK", ip=p.ip, session_id=p.session_id)
    return user_out(u)
