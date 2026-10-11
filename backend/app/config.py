"""Application settings, read from environment variables (never hardcoded secrets)."""
from __future__ import annotations

import logging
import re
import secrets
from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger(__name__)
_EPHEMERAL_SECRET = ""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    app_env: str = "development"
    database_url: str = "sqlite:///./secureai.db"
    cors_origins: str = "http://localhost:5173"

    # --- auth ---
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_ttl_minutes: int = 60
    login_max_failures: int = 5
    login_lockout_seconds: int = 300

    # --- AI provider (abstracted; see app/agent/provider.py) ---
    ai_provider: str = "scripted"  # scripted | openai | gemini
    ai_api_key: str = ""
    ai_base_url: str = ""  # empty -> provider default
    ai_model: str = ""
    ai_timeout_seconds: float = 60.0

    # --- GitHub ---
    github_token: str = ""
    github_api_url: str = "https://api.github.com"
    github_webhook_secret: str = ""
    deploy_target: str = "dry-run"  # dry-run | github-workflow
    deploy_workflow: str = "deploy.yml"

    # --- sandbox ---
    sandbox_backend: str = "docker"  # docker | local (local is NOT a security boundary)
    sandbox_image: str = "aesa-sandbox:latest"
    sandbox_cpus: float = 1.0
    sandbox_memory: str = "1g"
    sandbox_pids_limit: int = 256
    sandbox_egress_network: str = ""  # docker network for commands needing network; empty = none
    # Trivy needs a writable copy of its baked DB in the /tmp tmpfs (see sandbox/scripts/trivy-wrapper.sh). tmpfs pages are
    # charged to the container's memory limit, so only trivy_fs gets a larger tmpfs AND a larger memory ceiling.
    sandbox_tmpfs_size: str = "256m"
    sandbox_trivy_tmpfs: str = "1200m"
    sandbox_trivy_memory: str = "2g"
    workspace_root: str = "./.workspaces"
    workspace_host_root: str = ""  # host path of workspace_root when backend itself runs in Docker
    max_output_bytes: int = 200_000
    default_command_timeout: int = 120
    keep_workspaces: bool = False
    trivy_skip_db_update: bool = True

    # --- policy ---
    agent_max_steps: int = 30
    agent_max_denials: int = 5
    agent_max_invalid: int = 3
    protected_branches: str = "main,master,production,release/*"
    security_block_severity: str = "high"  # critical | high | medium
    required_scans: str = ""  # comma list; empty -> derived from detected languages
    allow_self_approval: bool = False
    require_distinct_deploy_approver: bool = False
    max_read_bytes: int = 200_000
    max_patch_files: int = 20
    max_patch_file_bytes: int = 200_000

    # --- runtime ---
    background_mode: str = "thread"  # thread | inline (tests)
    seed_demo: bool = False
    demo_password: str = ""
    demo_repo_source: str = "/seed/demo-repository"
    demo_repo_dest: str = "./data/repos/demo-repo"
    repos_root: str = "./data/repos"  # repositories may only be registered beneath this directory

    @field_validator("sandbox_memory", "sandbox_tmpfs_size", "sandbox_trivy_tmpfs", "sandbox_trivy_memory")
    @classmethod
    def _docker_size(cls, v: str) -> str:
        if not re.fullmatch(r"[1-9][0-9]{0,5}[mg]", v):  # blocks injecting extra mount/limit options
            raise ValueError("must look like 256m or 2g")
        return v

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def protected_branch_list(self) -> list[str]:
        return [b.strip() for b in self.protected_branches.split(",") if b.strip()]

    @property
    def required_scan_list(self) -> list[str]:
        return [s.strip() for s in self.required_scans.split(",") if s.strip()]

    @property
    def effective_jwt_secret(self) -> str:
        if self.jwt_secret:
            if len(self.jwt_secret) < 32:
                raise RuntimeError("JWT_SECRET must be at least 32 characters")
            return self.jwt_secret
        if self.app_env == "production":
            raise RuntimeError("JWT_SECRET must be set in production")
        global _EPHEMERAL_SECRET
        if not _EPHEMERAL_SECRET:
            _EPHEMERAL_SECRET = secrets.token_urlsafe(48)
            log.warning("JWT_SECRET not set: using an ephemeral secret (tokens die on restart)")
        return _EPHEMERAL_SECRET


_override: Settings | None = None


@lru_cache(maxsize=1)
def _cached() -> Settings:
    return Settings()


def get_settings() -> Settings:
    return _override or _cached()


def override_settings(s: Settings | None) -> None:
    """Test hook."""
    global _override
    _override = s


