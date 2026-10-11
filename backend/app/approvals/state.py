"""Task state machine. Illegal transitions raise: the approval workflow cannot be skipped."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import AgentTask
from app.models.enums import TaskStatus as S

TRANSITIONS: dict[S, set[S]] = {
    S.DRAFT: {S.ANALYZING, S.CANCELLED, S.FAILED_SAFELY},
    S.ANALYZING: {S.PROPOSED, S.ANALYSIS_ONLY, S.FAILED_SAFELY, S.CANCELLED},
    S.PROPOSED: {S.AWAITING_APPROVAL, S.FAILED_SAFELY, S.CANCELLED},
    S.AWAITING_APPROVAL: {S.APPROVED, S.REJECTED, S.CHANGES_REQUESTED, S.CANCELLED},
    S.APPROVED: {S.APPLIED, S.FAILED_SAFELY},
    S.APPLIED: {S.CI_RUNNING, S.FAILED_SAFELY},
    S.CI_RUNNING: {S.CI_PASSED, S.CI_FAILED, S.FAILED_SAFELY},
    S.CI_PASSED: {S.READY_FOR_DEPLOYMENT},
    S.READY_FOR_DEPLOYMENT: {S.DEPLOY_APPROVED, S.CANCELLED},
    S.DEPLOY_APPROVED: {S.DEPLOYED, S.FAILED_SAFELY},
}
TERMINAL = {S.REJECTED, S.CHANGES_REQUESTED, S.CI_FAILED, S.DEPLOYED, S.ANALYSIS_ONLY, S.FAILED_SAFELY, S.CANCELLED}


class InvalidTransition(Exception):
    pass


def transition(db: Session, task: AgentTask, new: S) -> None:
    cur = S(task.status)
    if new not in TRANSITIONS.get(cur, set()):
        raise InvalidTransition(f"{cur.value} -> {new.value} is not allowed")
    task.status = new.value
    db.commit()


def is_terminal(task: AgentTask) -> bool:
    return S(task.status) in TERMINAL
