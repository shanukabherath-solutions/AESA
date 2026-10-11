"""Deployment execution. Requires a DEPLOY_APPROVED task and passes the policy engine with a deploy context."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.service import ApprovalError
from app.approvals.state import transition
from app.audit import logger as audit
from app.config import get_settings
from app.models import AgentTask, Approval, Deployment, User, utcnow
from app.models.enums import ApprovalStatus, ApprovalType, DeploymentStatus, TaskStatus
from app.policy.engine import PolicyContext, PolicyEngine


def execute_deploy(db: Session, task: AgentTask, user: User, ip: str | None, session_id: str | None) -> Deployment:
    s = get_settings()
    approval = db.execute(select(Approval).where(Approval.task_id == task.id, Approval.type == ApprovalType.DEPLOY.value)
                          .order_by(Approval.id.desc())).scalars().first()
    ok_state = task.status == TaskStatus.DEPLOY_APPROVED.value and approval is not None and approval.status == ApprovalStatus.APPROVED.value
    decision = PolicyEngine().evaluate(
        PolicyContext.for_deploy(task.id, task.branch_name) if ok_state else
        PolicyContext("human", PolicyContext.for_deploy(task.id, None).max_level, task.id, True, False, task.branch_name),
        "deploy", {})
    audit.record(db, action="deploy_requested", user=user.username, repository=task.repository.name, task_id=task.id,
                 tool="deploy", permission_decision=decision.label, result=decision.reason,
                 status="ALLOWED" if decision.allowed else "DENIED", approval_state=task.status, ip=ip, session_id=session_id)
    if not decision.allowed or not ok_state:
        raise ApprovalError(409, "deployment has not been separately approved for this task")
    dep = db.execute(select(Deployment).where(Deployment.task_id == task.id).order_by(Deployment.id.desc())).scalars().first()
    assert dep is not None
    details: dict[str, Any] = {"branch": task.branch_name, "commit": task.commit_sha, "patch_sha256": task.patch_sha256,
                               "pr_url": task.pr_url, "approved_by_id": approval.decided_by if approval else None}
    if s.deploy_target == "github-workflow" and task.repository.github_repo and s.github_token:
        from app.ci.github import GitHubClient

        GitHubClient(s).dispatch_workflow(task.repository.github_repo, s.deploy_workflow, task.repository.default_branch,
                                          {"commit": task.commit_sha or "", "task_id": str(task.id)})
        details["mode"] = "workflow_dispatch"
    else:
        details["mode"] = "dry-run (no infrastructure is touched)"
    dep.status, dep.executed_by, dep.executed_at, dep.details, dep.target = (
        DeploymentStatus.DEPLOYED.value, user.id, utcnow(), details, s.deploy_target)
    db.commit()
    transition(db, task, TaskStatus.DEPLOYED)
    audit.record(db, action="deployed", user=user.username, repository=task.repository.name, task_id=task.id,
                 tool="deploy", arguments=details, permission_decision="ALLOWED", result=details["mode"],
                 status="DEPLOYED", approval_state=task.status, ip=ip, session_id=session_id)
    return dep
