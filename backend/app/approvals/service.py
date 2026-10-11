"""Human decisions on approvals. The security gate and patch-hash check are enforced HERE, server-side."""
from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.state import transition
from app.audit import logger as audit
from app.config import get_settings
from app.models import AgentTask, Approval, Deployment, SecurityScan, User, utcnow
from app.models.enums import ApprovalStatus, ApprovalType, DeploymentStatus, TaskStatus
from app.security.gate import evaluate_gate


class ApprovalError(Exception):
    def __init__(self, status_code: int, detail: object):
        super().__init__(str(detail))
        self.status_code = status_code
        self.detail = detail


def gate_for_task(db: Session, task: AgentTask):  # type: ignore[no-untyped-def]
    scans = list(db.execute(select(SecurityScan).where(SecurityScan.task_id == task.id)).scalars())
    return evaluate_gate(scans, task.patch_sha256, list(task.required_scans or []))


def decide(db: Session, approval: Approval, user: User, decision: str, comment: str | None,
           patch_sha256: str | None, ip: str | None, session_id: str | None) -> AgentTask:
    s = get_settings()
    task = db.get(AgentTask, approval.task_id)
    assert task is not None
    repo_name = task.repository.name

    def log(action: str, result: str, status: str) -> None:
        audit.record(db, action=action, user=user.username, repository=repo_name, task_id=task.id,
                     arguments={"approval_id": approval.id, "type": approval.type, "comment": (comment or "")[:500]},
                     permission_decision="ALLOWED" if status != "DENIED" else "DENIED", result=result, status=status,
                     approval_state=task.status, ip=ip, session_id=session_id)

    if approval.status != ApprovalStatus.PENDING.value:
        raise ApprovalError(409, f"approval is already {approval.status}")

    if approval.type == ApprovalType.PATCH.value:
        if task.status != TaskStatus.AWAITING_APPROVAL.value:
            raise ApprovalError(409, f"task is {task.status}, not AWAITING_APPROVAL")
        if decision == "approve":
            if user.id == task.created_by and not s.allow_self_approval:
                log("approval_denied", "self-approval is not allowed", "DENIED")
                raise ApprovalError(403, "you cannot approve a task you created")
            if patch_sha256 != approval.patch_sha256 or task.patch_sha256 != approval.patch_sha256 or \
                    not task.patch_text or hashlib.sha256(task.patch_text.encode()).hexdigest() != approval.patch_sha256:
                log("approval_denied", "patch hash mismatch (patch changed since it was reviewed)", "DENIED")
                raise ApprovalError(409, "the patch changed since you reviewed it; reload and review again")
            gate = gate_for_task(db, task)
            if not gate.passed:
                log("approval_blocked", "security gate failed: " + "; ".join(gate.reasons), "DENIED")
                raise ApprovalError(422, {"message": "blocked by the security gate", "reasons": gate.reasons})
            approval.status = ApprovalStatus.APPROVED.value
            new_state = TaskStatus.APPROVED
        elif decision == "reject":
            approval.status, new_state = ApprovalStatus.REJECTED.value, TaskStatus.REJECTED
        else:
            approval.status, new_state = ApprovalStatus.CHANGES_REQUESTED.value, TaskStatus.CHANGES_REQUESTED
            task.feedback = (comment or "")[:2000]
    else:  # DEPLOY
        if task.status != TaskStatus.READY_FOR_DEPLOYMENT.value:
            raise ApprovalError(409, f"task is {task.status}, not READY_FOR_DEPLOYMENT")
        if decision == "approve":
            if s.require_distinct_deploy_approver:
                prior = db.execute(select(Approval).where(Approval.task_id == task.id, Approval.type == ApprovalType.PATCH.value,
                                                          Approval.status == ApprovalStatus.APPROVED.value)).scalars().first()
                if prior and prior.decided_by == user.id:
                    log("approval_denied", "deploy approver must differ from the patch approver", "DENIED")
                    raise ApprovalError(403, "deployment must be approved by a different person than the patch")
            approval.status, new_state = ApprovalStatus.APPROVED.value, TaskStatus.DEPLOY_APPROVED
            dep = db.execute(select(Deployment).where(Deployment.task_id == task.id).order_by(Deployment.id.desc())).scalars().first()
            if dep:
                dep.status, dep.approval_id = DeploymentStatus.APPROVED.value, approval.id
        else:
            approval.status, new_state = ApprovalStatus.REJECTED.value, TaskStatus.CANCELLED

    approval.decided_by, approval.decided_at, approval.comment = user.id, utcnow(), (comment or "")[:2000]
    db.commit()
    transition(db, task, new_state)
    log(f"{approval.type.lower()}_{decision}", f"{approval.type} approval {approval.status}", approval.status)
    return task
