"""Dev/demo seeding: users (passwords from DEMO_PASSWORD) and a git-initialised copy of the demo repository."""
from __future__ import annotations

import logging
import shutil
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.config import Settings, get_settings
from app.db import new_session
from app.models import Repository, User
from app.models.enums import Role
from app.repository.git import run_git
from app.repository.paths import DEFAULT_ALLOWED, DEFAULT_PROTECTED

log = logging.getLogger(__name__)
DEMO_USERS = {"admin": Role.ADMIN, "developer": Role.DEVELOPER, "approver": Role.APPROVER, "viewer": Role.VIEWER}


def seed_users(db: Session, password: str) -> None:
    for name, role in DEMO_USERS.items():
        if not db.execute(select(User).where(User.username == name)).scalar_one_or_none():
            db.add(User(username=name, password_hash=hash_password(password), role=role.value))
    db.commit()


def make_demo_git_repo(src: Path, dest: Path) -> None:
    if (dest / ".git").exists():
        return

    shutil.copytree(
        src,
        dest,
        ignore=shutil.ignore_patterns(
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
        ),
    )

    # Windows-mounted source files may appear executable inside Linux containers.
    # Normalize Python source permissions before Git records the initial commit.
    for python_file in dest.rglob("*.py"):
        python_file.chmod(0o644)

    run_git(dest, "init", "-q", "-b", "main")
    run_git(dest, "add", "-A")
    run_git(
        dest,
        "-c", "user.name=Demo Author",
        "-c", "user.email=demo@example.invalid",
        "commit",
        "-q",
        "-m", "Initial (intentionally vulnerable) demo service",
    )


def seed_demo(db: Session, s: Settings) -> Repository:
    dest = Path(s.demo_repo_dest).resolve()
    make_demo_git_repo(Path(s.demo_repo_source), dest)
    repo = db.execute(select(Repository).where(Repository.name == "demo-repo")).scalar_one_or_none()
    if not repo:
        repo = Repository(name="demo-repo", root_path=str(dest), default_branch="main", allowed_paths=list(DEFAULT_ALLOWED),
                          protected_paths=list(DEFAULT_PROTECTED), protected_branches=s.protected_branch_list)
        db.add(repo)
        db.commit()
    return repo


def main() -> None:
    s = get_settings()
    if not s.seed_demo:
        return
    if not s.demo_password or len(s.demo_password) < 12:
        raise SystemExit("SEED_DEMO=true requires DEMO_PASSWORD (min 12 chars) so no default credentials exist")
    db = new_session()
    try:
        seed_users(db, s.demo_password)
        seed_demo(db, s)
        log.warning("Seeded demo users (admin/developer/approver/viewer) and demo-repo. Do not use in production.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
