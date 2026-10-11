"""Immutable-style audit log: append-only (DB triggers + ORM guard) and hash-chained."""
from __future__ import annotations

import hashlib
import json
import threading
from typing import Any

from sqlalchemy import event, select, text
from sqlalchemy.orm import Session

from app.audit.redaction import redact_obj, redact_text
from app.models import AuditLog, utcnow

GENESIS = "0" * 64
_lock = threading.Lock()


def _canon_ts(dt: Any) -> str:
    return dt.replace(tzinfo=None).isoformat(timespec="microseconds")


def _payload(e: AuditLog) -> dict[str, Any]:
    return {
        "timestamp": _canon_ts(e.timestamp),
        "user": e.user, "agent": e.agent, "repository": e.repository, "task_id": e.task_id,
        "action": e.action, "tool": e.tool, "arguments": e.arguments,
        "permission_decision": e.permission_decision, "result": e.result, "status": e.status,
        "exit_code": e.exit_code, "duration_ms": e.duration_ms, "affected_files": e.affected_files,
        "approval_state": e.approval_state, "ip": e.ip, "session_id": e.session_id,
    }


def compute_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + blob).encode()).hexdigest()


def record(
    db: Session,
    *,
    action: str,
    user: str | None = None,
    agent: str | None = None,
    repository: str | None = None,
    task_id: int | None = None,
    tool: str | None = None,
    arguments: dict[str, Any] | None = None,
    permission_decision: str | None = None,
    result: str | None = None,
    status: str | None = None,
    exit_code: int | None = None,
    duration_ms: int | None = None,
    affected_files: list[str] | None = None,
    approval_state: str | None = None,
    ip: str | None = None,
    session_id: str | None = None,
) -> AuditLog:
    """Append one entry (secrets redacted first) and commit the caller's session."""
    entry = AuditLog(
        timestamp=utcnow(), user=user, agent=agent, repository=repository, task_id=task_id,
        action=action, tool=tool, arguments=redact_obj(arguments or {}),
        permission_decision=permission_decision,
        result=redact_text(result, aggressive=True)[:4000] if result else result,
        status=status, exit_code=exit_code, duration_ms=duration_ms,
        affected_files=list(affected_files or [])[:200], approval_state=approval_state,
        ip=ip, session_id=session_id, prev_hash=GENESIS, entry_hash="",
    )
    with _lock:
        if db.bind is not None and db.bind.dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(7340172)"))
        last = db.execute(select(AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1)).scalar()
        entry.prev_hash = last or GENESIS
        entry.entry_hash = compute_hash(entry.prev_hash, _payload(entry))
        db.add(entry)
        db.commit()
    return entry


def verify_chain(db: Session) -> dict[str, Any]:
    """Recompute the whole chain. Returns {ok, entries, first_bad_id}."""
    prev = GENESIS
    n = 0
    for e in db.execute(select(AuditLog).order_by(AuditLog.id)).scalars():
        n += 1
        if e.prev_hash != prev or e.entry_hash != compute_hash(prev, _payload(e)):
            return {"ok": False, "entries": n, "first_bad_id": e.id}
        prev = e.entry_hash
    return {"ok": True, "entries": n, "first_bad_id": None}


@event.listens_for(Session, "before_flush")
def _forbid_audit_mutation(session: Session, _ctx: Any, _instances: Any) -> None:
    for obj in list(session.dirty) + list(session.deleted):
        if isinstance(obj, AuditLog) and (obj in session.deleted or session.is_modified(obj)):
            raise PermissionError("audit_logs is append-only")
