"""Isolated per-task workspaces: local clones containing only committed content."""
from __future__ import annotations

import shutil
from pathlib import Path

from app.repository.git import run_git

IGNORED_DIRS = {"node_modules", "__pycache__", ".venv", "venv"}


class WorkspaceError(Exception):
    pass


class WorkspaceManager:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, name: str) -> Path:
        if not name or "/" in name or ".." in name:
            raise WorkspaceError("invalid workspace name")
        return self.root / name

    def create(self, source_repo: str | Path, name: str, branch: str | None = None) -> Path:
        """Clone committed content only: untracked files such as a local .env never enter the workspace."""
        dest = self.path_for(name)
        if dest.exists():
            self.destroy(dest)
        args = ["clone", "--quiet", "--local", "--no-hardlinks", "--no-tags"]
        if branch:
            args += ["--branch", branch]
        args += ["--", str(source_repo), str(dest)]
        run_git(None, *args, timeout=120)
        return dest

    def destroy(self, path: str | Path) -> None:
        p = Path(path).resolve()
        if self.root not in p.parents:  # refuse to delete anything outside the workspace root
            raise WorkspaceError("refusing to delete a path outside the workspace root")
        shutil.rmtree(p, ignore_errors=True)
