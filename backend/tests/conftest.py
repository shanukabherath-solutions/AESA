from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.auth.security import limiter
from app.config import Settings, override_settings
from app.db import get_engine, new_session, reset_engine
from app.models import AgentTask, Base, Repository, User
from app.models.enums import PermissionLevel
from app.policy.engine import PolicyEngine
from app.repository.paths import DEFAULT_ALLOWED, DEFAULT_PROTECTED, PathGuard
from app.repository.workspace import WorkspaceManager
from app.sandbox.commands import CommandRegistry
from app.sandbox.runner import LocalSandbox
from app.seed import make_demo_git_repo, seed_users
from app.tools.context import ToolContext

DEMO_SRC = Path(__file__).resolve().parents[2] / "demo-repository"
PASSWORD = "Correct-Horse-Battery-9"
INSTALLED = {t: shutil.which(t) is not None for t in ("gitleaks", "trivy", "ruff", "mypy", "bandit")}


@pytest.fixture
def settings(tmp_path: Path) -> Iterator[Settings]:
    s = Settings(
        _env_file=None, jwt_secret="x" * 48, database_url=f"sqlite:///{tmp_path}/test.db", sandbox_backend="local",
        workspace_root=str(tmp_path / "ws"), repos_root=str(tmp_path / "repos"), background_mode="inline",
        required_scans="pytest,ruff,mypy,bandit" + (",gitleaks" if INSTALLED["gitleaks"] else ""),
        ai_provider="scripted", cors_origins="http://localhost:5173",
    )
    override_settings(s)
    reset_engine(s.database_url)
    Base.metadata.create_all(get_engine())
    limiter._fails.clear()
    yield s
    override_settings(None)


@pytest.fixture
def db(settings: Settings):  # type: ignore[no-untyped-def]
    session = new_session()
    seed_users(session, PASSWORD)
    yield session
    session.close()


@pytest.fixture
def demo_repo_path(settings: Settings) -> Path:
    dest = Path(settings.repos_root) / "demo-repo"
    dest.parent.mkdir(parents=True, exist_ok=True)
    make_demo_git_repo(DEMO_SRC, dest)
    return dest


@pytest.fixture
def repo(db, demo_repo_path: Path) -> Repository:  # type: ignore[no-untyped-def]
    r = Repository(name="demo-repo", root_path=str(demo_repo_path), default_branch="main",
                   allowed_paths=list(DEFAULT_ALLOWED), protected_paths=list(DEFAULT_PROTECTED), protected_branches=["main", "master"])
    db.add(r)
    db.commit()
    return r


@pytest.fixture
def make_ctx(db, repo, settings):  # type: ignore[no-untyped-def]
    """Build a ToolContext (task + isolated workspace) exactly like the orchestrator does."""
    def _make(level: PermissionLevel = PermissionLevel.PROPOSE_CHANGE) -> ToolContext:
        dev = db.query(User).filter_by(username="developer").one()
        t = AgentTask(repository_id=repo.id, created_by=dev.id, prompt="test task", status="ANALYZING", permission_level=level.value)
        db.add(t)
        db.commit()
        ws = WorkspaceManager(settings.workspace_root).create(repo.root_path, f"task-{t.id}", branch="main")
        return ToolContext(db=db, settings=settings, task=t, repo=repo, workspace=ws,
                           guard=PathGuard(ws, repo.allowed_paths, repo.protected_paths), sandbox=LocalSandbox(settings),
                           registry=CommandRegistry(settings), policy=PolicyEngine(), username="developer")
    return _make


@pytest.fixture
def client(settings: Settings, db) -> TestClient:  # type: ignore[no-untyped-def]
    from app.main import app

    return TestClient(app)


def login(client: TestClient, username: str) -> dict[str, str]:
    r = client.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout
