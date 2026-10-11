from __future__ import annotations

import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import runner
from app.api.serializers import approval_out, audit_out, ci_out, deployment_out, scan_out, task_out
from app.approvals import deploy as deploy_svc
from app.approvals.applier import apply_approved_change
from app.approvals.service import ApprovalError, decide, gate_for_task
from app.audit import logger as audit
from app.auth.deps import Principal, get_principal, require
from app.auth.security import Permission, has_permission
from app.ci import service as ci_svc
from app.ci.github import GitHubClient, GitHubError
from app.config import get_settings
from app.db import get_db
from app.models import AgentAction, AgentTask, Approval, AuditLog, CICDRun, Deployment, SecurityScan
from app.models.enums import ApprovalStatus, ApprovalType

router = APIRouter(prefix="/api", tags=["workflow"])


class Decision(BaseModel):
    patch_sha256: str | None = Field(default=None, max_length=64)
    comment: str | None = Field(default=None, max_length=2000)


def _approval(db: Session, approval_id: int) -> Approval:
    a = db.get(Approval, approval_id)
    if not a:
        raise HTTPException(404, "approval not found")
    return a


def _perm_for(a: Approval) -> Permission:
    return Permission.APPROVE_PATCH if a.type == ApprovalType.PATCH.value else Permission.APPROVE_DEPLOY


@router.get("/approvals")
def list_approvals(status: str | None = None, type: str | None = None, db: Session = Depends(get_db),
                   _: Principal = Depends(require(Permission.READ_DASHBOARD))) -> list[dict]:
    q = select(Approval).order_by(Approval.id.desc()).limit(100)
    if status:
        q = q.where(Approval.status == status)
    if type:
        q = q.where(Approval.type == type)
    out = []
    for a in db.execute(q).scalars():
        t = db.get(AgentTask, a.task_id)
        out.append({**approval_out(a), "task": task_out(t) if t else None})
    return out


@router.get("/approvals/{approval_id}")
def get_approval(approval_id: int, db: Session = Depends(get_db), _: Principal = Depends(require(Permission.READ_DASHBOARD))) -> dict:
    a = _approval(db, approval_id)
    t = db.get(AgentTask, a.task_id)
    assert t is not None
    g = gate_for_task(db, t)
    return {**approval_out(a), "task": task_out(t, full=True),
            "gate": {"passed": g.passed, "required": g.required, "missing": g.missing, "reasons": g.reasons}}


def _decide(approval_id: int, kind: str, body: Decision, db: Session, p: Principal, perm_check: bool = True) -> dict:
    a = _approval(db, approval_id)
    if not has_permission(p.user.role, _perm_for(a)):
        raise HTTPException(403, f"Role {p.user.role} lacks permission {_perm_for(a).value}")
    try:
        task = decide(db, a, p.user, kind, body.comment, body.patch_sha256, p.ip, p.session_id)
    except ApprovalError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc
    if a.type == ApprovalType.PATCH.value and kind == "approve":
        runner.submit(apply_approved_change, task.id, p.username, p.ip, p.session_id)
        db.refresh(task)
    return {"approval": approval_out(a), "task": task_out(task)}


@router.post("/approvals/{approval_id}/approve")
def approve(approval_id: int, body: Decision, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> dict:
    return _decide(approval_id, "approve", body, db, p)


@router.post("/approvals/{approval_id}/reject")
def reject(approval_id: int, body: Decision, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> dict:
    return _decide(approval_id, "reject", body, db, p)


@router.post("/approvals/{approval_id}/request-changes")
def request_changes(approval_id: int, body: Decision, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> dict:
    if not body.comment:
        raise HTTPException(400, "a comment is required when requesting changes")
    return _decide(approval_id, "changes", body, db, p)


@router.get("/security/scans/{task_id}")
def task_scans(task_id: int, db: Session = Depends(get_db), _: Principal = Depends(require(Permission.READ_DASHBOARD))) -> dict:
    t = db.get(AgentTask, task_id)
    if not t:
        raise HTTPException(404, "task not found")
    scans = list(db.execute(select(SecurityScan).where(SecurityScan.task_id == task_id).order_by(SecurityScan.id)).scalars())
    g = gate_for_task(db, t)
    return {"task_id": task_id, "scans": [scan_out(s) for s in scans],
            "gate": {"passed": g.passed, "required": g.required, "missing": g.missing, "reasons": g.reasons}}


@router.get("/ci/runs/{task_id}")
def ci_runs(task_id: int, db: Session = Depends(get_db), _: Principal = Depends(require(Permission.READ_DASHBOARD))) -> dict:
    runs = db.execute(select(CICDRun).where(CICDRun.task_id == task_id).order_by(CICDRun.id.desc())).scalars()
    dep = db.execute(select(Deployment).where(Deployment.task_id == task_id).order_by(Deployment.id.desc())).scalars().first()
    t = db.get(AgentTask, task_id)
    return {"runs": [ci_out(r) for r in runs], "deployment": deployment_out(dep) if dep else None,
            "pr_url": t.pr_url if t else None, "task_status": t.status if t else None}


@router.post("/ci/runs/{task_id}/refresh")
def ci_refresh(task_id: int, db: Session = Depends(get_db), _: Principal = Depends(require(Permission.INSPECT_REPO))) -> dict:
    t = db.get(AgentTask, task_id)
    if not t or not t.repository.github_repo or not t.branch_name:
        raise HTTPException(404, "no GitHub-backed run for this task")
    try:
        gh = GitHubClient(get_settings())
        run = gh.latest_workflow_run(t.repository.github_repo, t.branch_name)
        if run:
            ci_svc.apply_github_run(db, t, run, gh.run_jobs(t.repository.github_repo, run["id"]))
    except GitHubError as exc:
        raise HTTPException(502, str(exc)) from exc
    db.refresh(t)
    return {"task": task_out(t)}


@router.post("/ci/webhook", include_in_schema=True)
async def github_webhook(request: Request, db: Session = Depends(get_db)) -> dict:
    s = get_settings()
    body = await request.body()
    if not ci_svc.verify_signature(s.github_webhook_secret, body, request.headers.get("X-Hub-Signature-256")):
        audit.record(db, action="webhook_rejected", status="DENIED", result="bad or missing signature",
                     ip=request.client.host if request.client else None)
        raise HTTPException(401, "invalid signature")
    if request.headers.get("X-GitHub-Event") != "workflow_run":
        return {"ignored": True}
    run = json.loads(body).get("workflow_run") or {}
    m = re.fullmatch(r"agent/proposal-(\d+)", str(run.get("head_branch", "")))
    task = db.get(AgentTask, int(m.group(1))) if m else None
    if not task:
        return {"ignored": True}
    ci_svc.apply_github_run(db, task, run)
    return {"ok": True, "task_status": task.status}


@router.get("/deployments/{task_id}")
def get_deployment(task_id: int, db: Session = Depends(get_db), _: Principal = Depends(require(Permission.READ_DASHBOARD))) -> dict:
    dep = db.execute(select(Deployment).where(Deployment.task_id == task_id).order_by(Deployment.id.desc())).scalars().first()
    if not dep:
        raise HTTPException(404, "no deployment for this task")
    return deployment_out(dep)


@router.post("/deployments/{task_id}/execute")
def execute_deployment(task_id: int, db: Session = Depends(get_db), p: Principal = Depends(require(Permission.APPROVE_DEPLOY))) -> dict:
    t = db.get(AgentTask, task_id)
    if not t:
        raise HTTPException(404, "task not found")
    try:
        dep = deploy_svc.execute_deploy(db, t, p.user, p.ip, p.session_id)
    except ApprovalError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc
    except GitHubError as exc:
        raise HTTPException(502, str(exc)) from exc
    return {"deployment": deployment_out(dep), "task": task_out(t)}


@router.get("/audit-logs")
def audit_logs(action: str | None = None, repository: str | None = None, agent: str | None = None, user: str | None = None,
               status: str | None = None, task_id: int | None = None, date_from: str | None = None, date_to: str | None = None,
               q: str | None = None, limit: int = 100, offset: int = 0, db: Session = Depends(get_db),
               _: Principal = Depends(require(Permission.READ_LOGS))) -> dict:
    from datetime import datetime

    stmt = select(AuditLog)
    for col, val in ((AuditLog.action, action), (AuditLog.repository, repository), (AuditLog.agent, agent),
                     (AuditLog.user, user), (AuditLog.status, status), (AuditLog.task_id, task_id)):
        if val is not None and val != "":
            stmt = stmt.where(col == val)
    try:
        if date_from:
            stmt = stmt.where(AuditLog.timestamp >= datetime.fromisoformat(date_from.replace("Z", "+00:00")).replace(tzinfo=None))
        if date_to:
            stmt = stmt.where(AuditLog.timestamp <= datetime.fromisoformat(date_to.replace("Z", "+00:00")).replace(tzinfo=None))
    except ValueError as exc:
        raise HTTPException(400, "invalid date filter") from exc
    if q:
        like = f"%{q[:100]}%"
        stmt = stmt.where(AuditLog.tool.like(like) | AuditLog.result.like(like) | AuditLog.action.like(like))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(AuditLog.id.desc()).limit(min(limit, 500)).offset(max(offset, 0))).scalars()
    return {"total": total, "items": [audit_out(e) for e in rows]}


@router.get("/audit-logs/verify")
def audit_verify(db: Session = Depends(get_db), _: Principal = Depends(require(Permission.MANAGE_POLICY))) -> dict:
    return audit.verify_chain(db)


@router.get("/dashboard/summary")
def dashboard(db: Session = Depends(get_db), _: Principal = Depends(require(Permission.READ_DASHBOARD))) -> dict:
    s = get_settings()
    counts = dict(db.execute(select(AgentTask.status, func.count()).group_by(AgentTask.status)).all())
    latest = db.execute(select(AgentTask).order_by(AgentTask.id.desc()).limit(8)).scalars().all()
    actions = db.execute(select(AgentAction).order_by(AgentAction.id.desc()).limit(10)).scalars().all()
    pending = db.execute(select(func.count()).select_from(Approval).where(Approval.status == ApprovalStatus.PENDING.value)).scalar_one()
    current = next((t for t in latest if t.status in {"ANALYZING", "AWAITING_APPROVAL", "CI_RUNNING"}), latest[0] if latest else None)
    sec = ci = None
    if current:
        g = gate_for_task(db, current) if current.patch_sha256 else None
        sec = {"task_id": current.id, "passed": g.passed if g else None, "reasons": g.reasons if g else []}
        r = db.execute(select(CICDRun).where(CICDRun.task_id == current.id).order_by(CICDRun.id.desc())).scalars().first()
        ci = ci_out(r) if r else None
    return {"agent_status": "RUNNING" if counts.get("ANALYZING") else "IDLE", "ai_provider": s.ai_provider,
            "sandbox_backend": s.sandbox_backend, "task_counts": counts, "pending_approvals": pending,
            "current_task": task_out(current) if current else None, "security": sec, "ci": ci,
            "latest_tasks": [task_out(t) for t in latest],
            "latest_actions": [{"task_id": a.task_id, "tool": a.tool, "status": a.status, "reason": a.reason,
                                "result_summary": a.result_summary[:160]} for a in actions]}
