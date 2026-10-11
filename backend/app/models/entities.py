from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import audit_triggers
from app.models.base import Base, utcnow


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Repository(Base):
    __tablename__ = "repositories"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    root_path: Mapped[str] = mapped_column(String(1024))
    default_branch: Mapped[str] = mapped_column(String(128), default="main")
    github_repo: Mapped[str | None] = mapped_column(String(256), nullable=True)  # "owner/name"
    allowed_paths: Mapped[list[str]] = mapped_column(JSON, default=list)
    protected_paths: Mapped[list[str]] = mapped_column(JSON, default=list)
    protected_branches: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentTask(Base):
    __tablename__ = "agent_tasks"
    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), index=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    prompt: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="DRAFT", index=True)
    permission_level: Mapped[str] = mapped_column(String(32), default="PROPOSE_CHANGE")
    ai_provider: Mapped[str] = mapped_column(String(32), default="scripted")
    branch_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    patch_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    patch_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    files_changed: Mapped[list[Any]] = mapped_column(JSON, default=list)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    required_scans: Mapped[list[Any]] = mapped_column(JSON, default=list)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    feedback: Mapped[str | None] = mapped_column(Text, nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pr_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    repository: Mapped[Repository] = relationship()
    creator: Mapped[User] = relationship()


class AgentAction(Base):
    __tablename__ = "agent_actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("agent_tasks.id"), index=True)
    step: Mapped[int] = mapped_column(Integer)
    tool: Mapped[str] = mapped_column(String(64))
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16))
    result_summary: Mapped[str] = mapped_column(Text, default="")
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int | None] = mapped_column(ForeignKey("agent_tasks.id"), nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(16))
    tool: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(8))  # ALLOW | DENY
    rule: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(Text)
    required_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    granted_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("agent_tasks.id"), index=True)
    type: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24), default="PENDING")
    summary: Mapped[str] = mapped_column(Text, default="")
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    patch_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)


class SecurityScan(Base):
    __tablename__ = "security_scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("agent_tasks.id"), index=True)
    tool: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))
    critical: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    low: Mapped[int] = mapped_column(Integer, default=0)
    patch_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    findings: Mapped[list[Any]] = mapped_column(JSON, default=list)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_s: Mapped[float] = mapped_column(Float, default=0.0)
    phase: Mapped[str] = mapped_column(String(16), default="proposal")  # proposal | ci
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CICDRun(Base):
    __tablename__ = "cicd_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("agent_tasks.id"), index=True)
    provider: Mapped[str] = mapped_column(String(16))  # github | local
    status: Mapped[str] = mapped_column(String(16), default="QUEUED")
    external_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(128), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    jobs: Mapped[list[Any]] = mapped_column(JSON, default=list)
    logs: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Deployment(Base):
    __tablename__ = "deployments"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("agent_tasks.id"), index=True)
    approval_id: Mapped[int | None] = mapped_column(ForeignKey("approvals.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="PENDING_APPROVAL")
    target: Mapped[str] = mapped_column(String(32), default="dry-run")
    environment: Mapped[str] = mapped_column(String(32), default="production")
    executed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    """Append-only, hash-chained. See app/audit/logger.py."""

    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    user: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    agent: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    repository: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    task_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    permission_decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    affected_files: Mapped[list[Any]] = mapped_column(JSON, default=list)
    approval_state: Mapped[str | None] = mapped_column(String(24), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True)


audit_triggers.install(AuditLog.__table__)  # type: ignore[arg-type]
