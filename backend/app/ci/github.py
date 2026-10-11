"""Minimal GitHub REST client (httpx). Use a fine-grained token / GitHub App installation token with
only: contents:write (branch push), pull_requests:write, actions:read (+ actions:write for dispatch)."""
from __future__ import annotations

import re
from typing import Any

import httpx

from app.config import Settings

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class GitHubError(Exception):
    pass


class GitHubClient:
    def __init__(self, s: Settings, transport: httpx.BaseTransport | None = None):
        if not s.github_token:
            raise GitHubError("GITHUB_TOKEN is not configured")
        self._c = httpx.Client(
            base_url=s.github_api_url.rstrip("/"), timeout=30, transport=transport,
            headers={"Authorization": f"Bearer {s.github_token}", "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"},
        )

    @staticmethod
    def _check(repo: str) -> str:
        if not REPO_RE.match(repo):
            raise GitHubError("invalid repository name")
        return repo

    def _req(self, method: str, url: str, **kw: Any) -> Any:
        try:
            r = self._c.request(method, url, **kw)
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise GitHubError(f"GitHub API returned HTTP {exc.response.status_code}") from None
        except httpx.HTTPError:
            raise GitHubError("GitHub API request failed") from None
        return r.json() if r.content else {}

    def create_pull_request(self, repo: str, head: str, base: str, title: str, body: str) -> dict[str, Any]:
        return self._req("POST", f"/repos/{self._check(repo)}/pulls",
                         json={"title": title, "head": head, "base": base, "body": body, "maintainer_can_modify": False})

    def latest_workflow_run(self, repo: str, branch: str) -> dict[str, Any] | None:
        data = self._req("GET", f"/repos/{self._check(repo)}/actions/runs", params={"branch": branch, "per_page": 1})
        runs = data.get("workflow_runs") or []
        return runs[0] if runs else None

    def run_jobs(self, repo: str, run_id: int) -> list[dict[str, Any]]:
        data = self._req("GET", f"/repos/{self._check(repo)}/actions/runs/{int(run_id)}/jobs")
        return [{"name": j.get("name"), "status": j.get("status"), "conclusion": j.get("conclusion")} for j in data.get("jobs", [])]

    def dispatch_workflow(self, repo: str, workflow: str, ref: str, inputs: dict[str, str]) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", workflow):
            raise GitHubError("invalid workflow file name")
        self._req("POST", f"/repos/{self._check(repo)}/actions/workflows/{workflow}/dispatches",
                  json={"ref": ref, "inputs": inputs})
