"""CI: GitHub Actions when configured (webhook / refresh), otherwise a local CI that re-checks the pushed branch."""
from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.state import InvalidTransition, transition
from app.audit import logger as audit
from app.config import Settings, get_settings
from app.db import new_session
from app.models import AgentTask, Approval, CICDRun, Deployment
from app.models.enums import ApprovalStatus, ApprovalType, CIStatus, DeploymentStatus, ScanStatus, TaskStatus
from app.orchestrator_shared import fail_task
from app.repository.workspace import WorkspaceManager
from app.sandbox.runner import SandboxUnavailable, get_sandbox
from app.security.service import run_scan

log = logging.getLogger(__name__)


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    if not secret or not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


def finish_ci(db: Session, task: AgentTask, run: CICDRun, passed: bool) -> None:
    run.status = (CIStatus.PASSED if passed else CIStatus.FAILED).value
    db.commit()
    audit.record(db, action="ci_result", agent="ci", repository=task.repository.name, task_id=task.id,
                 result=f"{run.provider} CI {run.status}", status=run.status, approval_state=task.status)
    try:
        if task.status == TaskStatus.APPLIED.value:
            transition(db, task, TaskStatus.CI_RUNNING)
        if passed:
            transition(db, task, TaskStatus.CI_PASSED)
            transition(db, task, TaskStatus.READY_FOR_DEPLOYMENT)
            db.add(Approval(task_id=task.id, type=ApprovalType.DEPLOY.value, status=ApprovalStatus.PENDING.value,
                            summary=f"Deploy proposal {task.branch_name} ({(task.commit_sha or '')[:10]})",
                            risk_level=task.risk_level, patch_sha256=task.patch_sha256))
            s = get_settings()
            db.add(Deployment(task_id=task.id, status=DeploymentStatus.PENDING_APPROVAL.value, target=s.deploy_target))
            db.commit()
        else:
            transition(db, task, TaskStatus.CI_FAILED)
    except InvalidTransition:
        log.warning("ignoring CI result for task %s in state %s", task.id, task.status)


def start_ci(task_id: int) -> None:
    s = get_settings()
    db = new_session()
    try:
        task = db.get(AgentTask, task_id)
        assert task is not None
        repo = task.repository
        transition(db, task, TaskStatus.CI_RUNNING)
        if repo.github_repo and s.github_token:
            db.add(CICDRun(task_id=task.id, provider="github", status=CIStatus.QUEUED.value, branch=task.branch_name,
                           commit_sha=task.commit_sha, logs="Waiting for GitHub Actions to report (webhook or refresh)."))
            db.commit()
            return
        _run_local_ci(db, s, task)
    except Exception:  # noqa: BLE001
        log.exception("CI start failed")
        db.rollback()
        t = db.get(AgentTask, task_id)
        if t:
            fail_task(db, t, "CI could not be started")
    finally:
        db.close()


def _run_local_ci(db: Session, s: Settings, task: AgentTask) -> None:
    repo = task.repository
    run = CICDRun(task_id=task.id, provider="local", status=CIStatus.RUNNING.value, branch=task.branch_name,
                  commit_sha=task.commit_sha)
    db.add(run)
    db.commit()
    wm = WorkspaceManager(s.workspace_root)
    ws = None
    try:
        sandbox = get_sandbox(s)
        ws = wm.create(repo.root_path, f"ci-{task.id}", branch=task.branch_name)  # the PUSHED branch, not the agent's workspace
        jobs, logs = [], []
        for tool in task.required_scans:
            row, tail = run_scan(db, task, tool, ws, sandbox, s, phase="ci", patch_sha=task.patch_sha256)
            jobs.append({"name": tool, "status": "completed", "conclusion": row.status.lower(), "summary": row.summary})
            logs.append(f"== {tool}: {row.status} - {row.summary}\n{tail[-600:]}")
        run.jobs, run.logs = jobs, "\n".join(logs)[-20000:]
        finish_ci(db, task, run, all(j["conclusion"] == ScanStatus.PASSED.value.lower() for j in jobs))
    except SandboxUnavailable as exc:
        run.logs = f"sandbox unavailable: {exc}"
        finish_ci(db, task, run, False)
    finally:
        if ws is not None and not s.keep_workspaces:
            wm.destroy(ws)


def apply_github_run(db: Session, task: AgentTask, gh_run: dict[str, Any], jobs: list[dict[str, Any]] | None = None) -> CICDRun | None:
    """Fold a GitHub workflow_run payload into our CICDRun + task state."""
    run = db.execute(select(CICDRun).where(CICDRun.task_id == task.id, CICDRun.provider == "github")
                     .order_by(CICDRun.id.desc())).scalars().first()
    if run is None:
        return None
    run.external_id, run.url = str(gh_run.get("id")), gh_run.get("html_url")
    if jobs is not None:
        run.jobs = jobs
    status, conclusion = gh_run.get("status"), gh_run.get("conclusion")
    if status != "completed":
        run.status = CIStatus.RUNNING.value
        db.commit()
        return run
    # sanity: the run must be for the commit we pushed
    if task.commit_sha and gh_run.get("head_sha") and gh_run["head_sha"] != task.commit_sha:
        run.logs = "ignored workflow run for a different commit"
        db.commit()
        return run
    finish_ci(db, task, run, conclusion == "success")
    return run
