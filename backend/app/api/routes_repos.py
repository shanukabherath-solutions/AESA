from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.serializers import repo_out
from app.audit import logger as audit
from app.auth.deps import Principal, require
from app.auth.security import Permission
from app.ci.github import REPO_RE
from app.config import get_settings
from app.db import get_db
from app.models import Repository
from app.repository import git, inspector
from app.repository.paths import DEFAULT_ALLOWED, DEFAULT_PROTECTED, PathGuard, PathViolation

router = APIRouter(prefix="/api", tags=["repositories"])


class RepoCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    root_path: str = Field(min_length=1, max_length=1024)
    default_branch: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_./-]{1,100}$")
    github_repo: str | None = None
    allowed_paths: list[str] | None = None
    protected_paths: list[str] | None = None
    protected_branches: list[str] | None = None


class RepoUpdate(BaseModel):
    github_repo: str | None = None
    allowed_paths: list[str] | None = None
    protected_paths: list[str] | None = None
    protected_branches: list[str] | None = None


def _get(db: Session, repo_id: int) -> Repository:
    r = db.get(Repository, repo_id)
    if not r:
        raise HTTPException(404, "repository not found")
    return r


@router.get("/repositories")
def list_repos(db: Session = Depends(get_db), _: Principal = Depends(require(Permission.READ_DASHBOARD))) -> list[dict]:
    return [repo_out(r) for r in db.execute(select(Repository).order_by(Repository.id)).scalars()]


@router.post("/repositories", status_code=201)
def register_repo(body: RepoCreate, db: Session = Depends(get_db), p: Principal = Depends(require(Permission.MANAGE_REPOS))) -> dict:
    s = get_settings()
    root = Path(os.path.realpath(body.root_path))
    allowed_root = Path(os.path.realpath(s.repos_root))
    if allowed_root not in root.parents and root != allowed_root:
        raise HTTPException(400, f"repositories must live under the configured REPOS_ROOT ({allowed_root})")
    if not root.is_dir() or not git.is_git_repo(root):
        raise HTTPException(400, "path is not a Git repository")
    if body.github_repo and not REPO_RE.match(body.github_repo):
        raise HTTPException(400, "github_repo must look like owner/name")
    if db.execute(select(Repository).where(Repository.name == body.name)).scalar_one_or_none():
        raise HTTPException(409, "repository name already registered")
    r = Repository(name=body.name, root_path=str(root), default_branch=body.default_branch or git.current_branch(root),
                   github_repo=body.github_repo, allowed_paths=body.allowed_paths or list(DEFAULT_ALLOWED),
                   protected_paths=body.protected_paths if body.protected_paths is not None else list(DEFAULT_PROTECTED),
                   protected_branches=body.protected_branches or s.protected_branch_list, created_by=p.user.id)
    db.add(r)
    db.commit()
    audit.record(db, action="repository_registered", user=p.username, repository=r.name, arguments={"root_path": r.root_path},
                 status="OK", ip=p.ip, session_id=p.session_id)
    return repo_out(r)


@router.patch("/repositories/{repo_id}")
def update_repo(repo_id: int, body: RepoUpdate, db: Session = Depends(get_db), p: Principal = Depends(require(Permission.MANAGE_POLICY))) -> dict:
    r = _get(db, repo_id)
    data = body.model_dump(exclude_unset=True)
    if data.get("github_repo") and not REPO_RE.match(data["github_repo"]):
        raise HTTPException(400, "github_repo must look like owner/name")
    for k, v in data.items():
        setattr(r, k, v)
    db.commit()
    audit.record(db, action="repository_policy_updated", user=p.username, repository=r.name, arguments=data, status="OK",
                 ip=p.ip, session_id=p.session_id)
    return repo_out(r)


@router.get("/repositories/{repo_id}/tree")
def repo_tree(repo_id: int, db: Session = Depends(get_db), p: Principal = Depends(require(Permission.INSPECT_REPO))) -> dict:
    r = _get(db, repo_id)
    try:
        guard = PathGuard(r.root_path, r.allowed_paths or None, r.protected_paths)
    except PathViolation as exc:
        raise HTTPException(400, exc.detail) from exc
    files = list(guard.iter_files(".", max_files=2000))
    audit.record(db, action="repository_inspected", user=p.username, repository=r.name, status="OK", ip=p.ip, session_id=p.session_id,
                 permission_decision="ALLOWED", result=f"{len(files)} permitted files listed")
    return {"repository": r.name, "files": files}


@router.get("/repositories/{repo_id}/stats")
def repo_stats(repo_id: int, db: Session = Depends(get_db), _: Principal = Depends(require(Permission.INSPECT_REPO))) -> dict:
    r = _get(db, repo_id)
    info = inspector.inspect(PathGuard(r.root_path, r.allowed_paths or None, r.protected_paths))
    info.pop("files")
    return {"repository": r.name, "default_branch": r.default_branch, "protected_branches": r.protected_branches, **info}


@router.get("/policy")
def policy_overview(_: Principal = Depends(require(Permission.READ_DASHBOARD))) -> dict:
    from app.models.enums import PermissionLevel
    from app.policy.engine import MODEL_TOOLS, TOOL_POLICIES

    s = get_settings()
    return {"levels": [lv.value for lv in PermissionLevel],
            "tools": {t: {"level": TOOL_POLICIES[t].level.value, "agent_allowed": TOOL_POLICIES[t].agent_allowed,
                          "exposed_to_model": t in MODEL_TOOLS} for t in TOOL_POLICIES},
            "protected_branches": s.protected_branch_list, "security_block_severity": s.security_block_severity,
            "allow_self_approval": s.allow_self_approval, "sandbox_backend": s.sandbox_backend, "ai_provider": s.ai_provider}
