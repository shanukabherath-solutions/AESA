from __future__ import annotations

from typing import Any

from app.models import (
    AgentAction,
    AgentTask,
    Approval,
    AuditLog,
    CICDRun,
    Deployment,
    PolicyDecision,
    Repository,
    SecurityScan,
    User,
    iso,
)


def user_out(u: User) -> dict[str, Any]:
    return {"id": u.id, "username": u.username, "role": u.role, "is_active": u.is_active, "created_at": iso(u.created_at)}


def repo_out(r: Repository) -> dict[str, Any]:
    return {"id": r.id, "name": r.name, "root_path": r.root_path, "default_branch": r.default_branch,
            "github_repo": r.github_repo, "allowed_paths": r.allowed_paths, "protected_paths": r.protected_paths,
            "protected_branches": r.protected_branches, "created_at": iso(r.created_at)}


def task_out(t: AgentTask, full: bool = False) -> dict[str, Any]:
    d = {"id": t.id, "repository_id": t.repository_id, "repository": t.repository.name, "created_by": t.creator.username,
         "prompt": t.prompt, "status": t.status, "permission_level": t.permission_level, "ai_provider": t.ai_provider,
         "branch_name": t.branch_name, "risk_level": t.risk_level, "summary": t.summary, "files_changed": t.files_changed,
         "patch_sha256": t.patch_sha256, "failure_reason": t.failure_reason, "pr_url": t.pr_url, "commit_sha": t.commit_sha,
         "created_at": iso(t.created_at), "updated_at": iso(t.updated_at)}
    if full:
        d.update({"explanation": t.explanation, "feedback": t.feedback, "required_scans": t.required_scans})
    return d


def action_out(a: AgentAction) -> dict[str, Any]:
    return {"id": a.id, "step": a.step, "tool": a.tool, "arguments": a.arguments, "reason": a.reason, "status": a.status,
            "result_summary": a.result_summary, "exit_code": a.exit_code, "duration_ms": a.duration_ms, "created_at": iso(a.created_at)}


def decision_out(d: PolicyDecision) -> dict[str, Any]:
    return {"id": d.id, "tool": d.tool, "actor": d.actor, "decision": d.decision, "rule": d.rule, "reason": d.reason,
            "required_level": d.required_level, "granted_level": d.granted_level, "created_at": iso(d.created_at)}


def approval_out(a: Approval) -> dict[str, Any]:
    return {"id": a.id, "task_id": a.task_id, "type": a.type, "status": a.status, "summary": a.summary,
            "risk_level": a.risk_level, "patch_sha256": a.patch_sha256, "requested_at": iso(a.requested_at),
            "decided_by": a.decided_by, "decided_at": iso(a.decided_at), "comment": a.comment}


def scan_out(s: SecurityScan) -> dict[str, Any]:
    return {"id": s.id, "tool": s.tool, "status": s.status, "critical": s.critical, "high": s.high, "medium": s.medium,
            "low": s.low, "summary": s.summary, "findings": s.findings, "exit_code": s.exit_code, "duration_s": s.duration_s,
            "patch_sha256": s.patch_sha256, "phase": s.phase, "created_at": iso(s.created_at)}


def ci_out(r: CICDRun) -> dict[str, Any]:
    return {"id": r.id, "task_id": r.task_id, "provider": r.provider, "status": r.status, "url": r.url, "branch": r.branch,
            "commit_sha": r.commit_sha, "jobs": r.jobs, "logs": r.logs, "created_at": iso(r.created_at), "updated_at": iso(r.updated_at)}


def deployment_out(d: Deployment) -> dict[str, Any]:
    return {"id": d.id, "task_id": d.task_id, "status": d.status, "target": d.target, "environment": d.environment,
            "details": d.details, "created_at": iso(d.created_at), "executed_at": iso(d.executed_at)}


def audit_out(e: AuditLog) -> dict[str, Any]:
    return {"id": e.id, "timestamp": iso(e.timestamp), "user": e.user, "agent": e.agent, "repository": e.repository,
            "task_id": e.task_id, "action": e.action, "tool": e.tool, "arguments": e.arguments,
            "permission_decision": e.permission_decision, "result": e.result, "status": e.status, "exit_code": e.exit_code,
            "duration_ms": e.duration_ms, "affected_files": e.affected_files, "approval_state": e.approval_state,
            "ip": e.ip, "session_id": e.session_id, "entry_hash": e.entry_hash}
