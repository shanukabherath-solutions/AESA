"""Applies an APPROVED patch: commit -> push proposal branch -> (optional) pull request.

Every step is individually checked by the PolicyEngine with an approval-bearing context and audited.
Nothing here can touch the default branch: only agent/proposal-<id> is ever pushed, never forced.
"""
from __future__ import annotations

import hashlib
import logging
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.state import transition
from app.audit import logger as audit
from app.config import Settings, get_settings
from app.db import new_session
from app.models import AgentTask, Approval, Repository
from app.models.enums import ApprovalStatus, ApprovalType, TaskStatus
from app.orchestrator_shared import fail_task
from app.policy.engine import PolicyContext, PolicyEngine
from app.repository.git import GitError, github_auth_env, run_git
from app.repository.paths import PathViolation, check_relative
from app.repository.workspace import WorkspaceManager

log = logging.getLogger(__name__)
APPLIER = "approval-executor"


def _patch_paths(patch: str) -> list[str]:
    return [m.group(2) for m in re.finditer(r"^diff --git a/(.+?) b/(.+)$", patch, re.M)]


def _subject(summary: str | None) -> str:
    clean = re.sub(r"[\x00-\x1f\x7f]", " ", summary or "agent proposal").strip()
    return ("fix: " + clean)[:72]


def open_pull_request(db: Session, s: Settings, task: AgentTask, repo: Repository, title: str, body: str) -> str | None:
    if not (repo.github_repo and s.github_token and task.branch_name):
        return None
    from app.ci.github import GitHubClient

    pr = GitHubClient(s).create_pull_request(repo.github_repo, task.branch_name, repo.default_branch, title[:200], body[:4000])
    task.pr_url = pr.get("html_url")
    db.commit()
    return task.pr_url


def apply_approved_change(task_id: int, approver: str, ip: str | None = None, session_id: str | None = None) -> None:
    s = get_settings()
    db = new_session()
    wm = WorkspaceManager(s.workspace_root)
    ws = None
    try:
        task = db.get(AgentTask, task_id)
        assert task is not None
        repo, engine = task.repository, PolicyEngine()
        branch = task.branch_name or f"agent/proposal-{task.id}"
        ctx = PolicyContext.for_approved_change(task.id, branch, repo.protected_branches or s.protected_branch_list, repo.protected_paths)

        def step(tool: str, args: dict, result: str) -> bool:
            d = engine.evaluate(ctx, tool, args)
            audit.record(db, action=f"apply:{tool}", user=approver, agent=APPLIER, repository=repo.name, task_id=task.id,
                         tool=tool, arguments=args, permission_decision=d.label, result=result if d.allowed else d.reason,
                         status="EXECUTED" if d.allowed else "DENIED", approval_state=task.status, ip=ip, session_id=session_id)
            return d.allowed

        approval = db.execute(select(Approval).where(Approval.task_id == task.id, Approval.type == ApprovalType.PATCH.value)
                              .order_by(Approval.id.desc())).scalars().first()
        if (task.status != TaskStatus.APPROVED.value or approval is None or approval.status != ApprovalStatus.APPROVED.value
                or not task.patch_text or hashlib.sha256(task.patch_text.encode()).hexdigest() != approval.patch_sha256):
            return fail_task(db, task, "approval/patch integrity check failed; nothing was applied")
        paths = _patch_paths(task.patch_text)
        try:
            for p in paths:
                check_relative(p)
        except PathViolation as exc:
            return fail_task(db, task, f"patch touches a forbidden path: {exc.detail}")

        ws = wm.create(repo.root_path, f"apply-{task.id}", branch=repo.default_branch)
        run_git(ws, "checkout", "-q", "-B", branch)
        if not step("apply_patch", {"files": [{"path": p} for p in paths]}, f"applying {len(paths)} file(s)"):
            return fail_task(db, task, "policy denied apply_patch")
        run_git(ws, "apply", "--check", "--whitespace=nowarn", input_text=task.patch_text)
        run_git(ws, "apply", "--index", "--whitespace=nowarn", input_text=task.patch_text)

        if not step("git_commit", {"branch": branch}, "committing to the proposal branch"):
            return fail_task(db, task, "policy denied git_commit")
        run_git(ws, "-c", "user.name=AESA", "-c", "user.email=aesa@users.noreply.local",
                "commit", "-q", "--no-verify", "-m", _subject(task.summary),
                "-m", f"Proposed-by: AESA (task {task.id})\nApproved-by: {approver}\nPatch-SHA256: {task.patch_sha256}")
        task.commit_sha = run_git(ws, "rev-parse", "HEAD").stdout.strip()
        db.commit()

        if not step("git_push", {"branch": branch, "force": False}, "pushing the proposal branch (never forced)"):
            return fail_task(db, task, "policy denied git_push")
        env = None
        remote = "origin"
        if repo.github_repo and s.github_token:
            remote, env = f"https://github.com/{repo.github_repo}.git", github_auth_env(s.github_token)
        run_git(ws, "push", "--quiet", remote, f"refs/heads/{branch}:refs/heads/{branch}", env_extra=env, timeout=120)

        if repo.github_repo and s.github_token:
            if step("create_pull_request", {"head": branch}, "opening pull request"):
                body = f"{task.explanation or ''}\n\n_Approved by {approver}. Proposed by AESA (task {task.id})._"
                open_pull_request(db, s, task, repo, task.summary or "Agent proposal", body)
        transition(db, task, TaskStatus.APPLIED)
        audit.record(db, action="change_applied", user=approver, agent=APPLIER, repository=repo.name, task_id=task.id,
                     result=f"branch {branch} @ {task.commit_sha[:10] if task.commit_sha else ''}", status="APPLIED",
                     affected_files=paths, approval_state=task.status, ip=ip, session_id=session_id)
    except (GitError, Exception) as exc:  # noqa: BLE001
        log.exception("apply failed")
        db.rollback()
        t = db.get(AgentTask, task_id)
        if t:
            fail_task(db, t, f"applying the approved change failed: {type(exc).__name__}")
        return
    finally:
        if ws is not None and not s.keep_workspaces:
            wm.destroy(ws)
        db.close()
    from app.ci.service import start_ci

    start_ci(task_id)
