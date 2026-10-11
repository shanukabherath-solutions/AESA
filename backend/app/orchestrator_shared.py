"""Small helper shared by the agent loop, applier and CI (avoids circular imports)."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.approvals.state import InvalidTransition, transition
from app.audit import logger as audit
from app.audit.redaction import redact_text
from app.models import AgentTask
from app.models.enums import TaskStatus


def fail_task(db: Session, task: AgentTask, reason: str) -> None:
    task.failure_reason = redact_text(reason, aggressive=True)[:1000]
    db.commit()
    try:
        transition(db, task, TaskStatus.FAILED_SAFELY)
    except InvalidTransition:
        pass
    audit.record(db, action="task_failed_safely", user=task.creator.username, repository=task.repository.name,
                 task_id=task.id, result=task.failure_reason, status="FAILED_SAFELY", approval_state=task.status)
