"""Guards for the SecureAI-Agent -> AESA rename and for the Compose/Docker security posture.

Config-level checks only (no Docker daemon needed). They stop the sandbox image name from drifting between Compose, the
backend default, the scripts and the tests, stop the security properties of docker-compose.yml from being weakened, and
fail if an old-name reference appears anywhere outside the explicit allowlist below.
"""
import json
import re
from pathlib import Path

import pytest
import yaml

from app.config import Settings
from app.sandbox.commands import CommandRegistry
from app.sandbox.runner import CommandResult, DockerSandbox

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "aesa-sandbox:latest"
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
SVC = COMPOSE["services"]


# ------------------------------------------------------------------ naming / image consistency
def test_compose_project_is_named_aesa():
    assert COMPOSE["name"] == "aesa"


def test_sandbox_image_name_is_identical_everywhere():
    assert SVC["sandbox-image"]["image"] == IMAGE  # what Compose builds
    assert SVC["backend"]["environment"]["SANDBOX_IMAGE"] == IMAGE  # what the backend runs
    assert Settings(_env_file=None).sandbox_image == IMAGE  # the backend's own default
    assert f'IMAGE = "{IMAGE}"' in (ROOT / "backend/tests/test_docker_sandbox_integration.py").read_text()
    assert f":-{IMAGE}" in (ROOT / "sandbox/scripts/verify-trivy.sh").read_text()
    assert f":-{IMAGE}" in (ROOT / "sandbox/scripts/smoke.sh").read_text()


def test_stale_env_file_cannot_override_the_sandbox_image():
    # `environment:` outranks `env_file:` in Compose, so as long as the key is set here an old .env cannot cause a mismatch
    assert "SANDBOX_IMAGE" in SVC["backend"]["environment"]
    assert ".env" in SVC["backend"]["env_file"]


def test_backend_starts_only_after_the_sandbox_image_is_built():
    dep = SVC["backend"]["depends_on"]
    assert dep["sandbox-image"]["condition"] == "service_completed_successfully"
    assert "docker-proxy" in dep


def test_build_contexts_and_bind_sources_are_relative_and_exist():
    for name, svc in SVC.items():
        build = svc.get("build")
        if build:
            ctx = build if isinstance(build, str) else build["context"]
            assert ctx.startswith("./"), f"{name}: build context must be relative to the compose file"
            assert (ROOT / ctx / "Dockerfile").is_file(), f"{name}: missing Dockerfile in {ctx}"
        for v in svc.get("volumes", []):
            src = v.split(":")[0]
            if src.startswith("./"):
                assert (ROOT / src).exists(), f"{name}: bind source {src} does not exist"


def test_container_and_docker_name_hardcodes_are_absent():
    for name, svc in SVC.items():
        assert "container_name" not in svc, f"{name}: a fixed container_name would break per-project naming"


# ------------------------------------------------------------------ persistent data is preserved
def test_data_volume_is_pinned_overridable_and_mounted():
    assert COMPOSE["volumes"]["backend-data"]["name"] == "${BACKEND_DATA_VOLUME:-aesa_backend-data}"
    assert "backend-data:/data" in SVC["backend"]["volumes"]
    assert "BACKEND_DATA_VOLUME" in (ROOT / ".env.example").read_text()
    assert "secureai-agent_backend-data" in (ROOT / ".env.example").read_text()  # the documented way to keep old data


def test_database_file_keeps_its_original_name():
    assert SVC["backend"]["environment"]["DATABASE_URL"].endswith(":-sqlite:////data/secureai.db}")
    assert Settings(_env_file=None).database_url == "sqlite:///./secureai.db"


# ------------------------------------------------------------------ security posture of docker-compose.yml is unchanged
def test_docker_socket_proxy_permissions_are_unchanged():
    env = {k: int(v) for k, v in SVC["docker-proxy"]["environment"].items()}
    assert env == {"CONTAINERS": 1, "IMAGES": 1, "POST": 1, "INFO": 1, "EXEC": 0, "VOLUMES": 0, "NETWORKS": 0, "SERVICES": 0,
                   "SWARM": 0, "SECRETS": 0, "BUILD": 0, "COMMIT": 0, "AUTH": 0}


def test_raw_docker_socket_is_mounted_only_into_the_proxy_and_read_only():
    assert SVC["docker-proxy"]["volumes"] == ["/var/run/docker.sock:/var/run/docker.sock:ro"]
    for name in ("backend", "frontend", "sandbox-image"):
        assert not any("docker.sock" in v for v in SVC[name].get("volumes", [])), name
        assert "docker.sock" not in json.dumps(SVC[name].get("environment", {}))


def test_proxy_stays_on_the_internal_only_network():
    assert SVC["docker-proxy"]["networks"] == ["internal"]
    assert COMPOSE["networks"]["internal"]["internal"] is True
    assert SVC["backend"]["environment"]["DOCKER_HOST"] == "tcp://docker-proxy:2375"
    assert "ports" not in SVC["docker-proxy"], "the proxy must never be published on the host"


def test_backend_uses_the_docker_sandbox_and_requires_an_explicit_workspace_dir():
    env = SVC["backend"]["environment"]
    assert env["SANDBOX_BACKEND"] == "docker"
    assert env["WORKSPACE_HOST_ROOT"].startswith("${WORKSPACE_HOST_DIR:?")  # unset => compose refuses to start (no silent default)
    assert "SANDBOX_BACKEND=local" not in json.dumps(COMPOSE)


# ------------------------------------------------------------------ docker run arguments
@pytest.fixture
def sb(settings, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/bin/docker")
    return DockerSandbox(settings)


def test_docker_run_never_pulls_and_uses_the_configured_image(sb, settings, tmp_path, monkeypatch):
    captured = {}

    def fake_run_capped(argv, *a, **k):
        captured["argv"] = argv
        return CommandResult("x", 0, "", "", 0.0)

    monkeypatch.setattr("app.sandbox.runner.run_capped", fake_run_capped)
    planned = CommandRegistry(settings).plan("pytest", {})
    sb.run(planned, tmp_path)
    argv = captured["argv"]
    assert argv[argv.index("--pull") + 1] == "never", "a missing image must fail closed, not be pulled"
    assert argv[argv.index("--name") + 1].startswith("aesa-")
    assert argv[argv.index("--label") + 1] == "aesa=sandbox"
    img = argv.index(settings.sandbox_image)
    assert argv[img + 1:] == list(planned.argv), "the image must be immediately followed by exactly the validated command"
    assert argv.count(settings.sandbox_image) == 1 and argv.index("--pull") < img
    for kept in ("--read-only", "--cap-drop", "ALL", "no-new-privileges", "10001:10001", "none"):
        assert kept in argv, kept


# ------------------------------------------------------------------ Trivy path/name wiring is intact
def test_trivy_wrapper_paths_and_renamed_overrides():
    wrapper = (ROOT / "sandbox/scripts/trivy-wrapper.sh").read_text()
    for kept in ("/opt/trivy-db", "/opt/trivy/bin/trivy", "exit 78", 'exec "$REAL_TRIVY" "$@"'):
        assert kept in wrapper, kept
    assert "AESA_TRIVY_BAKED_DB" in wrapper and "AESA_TRIVY_BIN" in wrapper and "aesa-trivy:" in wrapper
    df = (ROOT / "sandbox/Dockerfile").read_text()
    assert "COPY scripts/trivy-wrapper.sh /usr/local/bin/trivy" in df and "/opt/trivy/bin/trivy" in df
    assert "aquasec/trivy:0.58.1" in df, "the Trivy version must not change as part of a rename"


def test_package_names_and_line_endings_config():
    assert json.loads((ROOT / "frontend/package.json").read_text())["name"] == "aesa-frontend"
    lock = json.loads((ROOT / "frontend/package-lock.json").read_text())
    assert lock["name"] == "aesa-frontend" and lock["packages"][""]["name"] == "aesa-frontend"
    assert 'name = "aesa-backend"' in (ROOT / "backend/pyproject.toml").read_text()
    assert "*.sh text eol=lf" in (ROOT / ".gitattributes").read_text()


# ------------------------------------------------------------------ no stale old-name references
OLD = re.compile(r"(?i)secure[-_ ]?ai")
SKIP_DIRS = {"node_modules", "dist", "__pycache__", ".pytest_cache", ".git", ".mypy_cache", ".ruff_cache", ".workspaces"}
HISTORICAL_FILES = {"docs/example-audit-log.txt"}  # a recorded export; deliberately not rewritten
# Everywhere: the SQLite file keeps its name so existing data is not orphaned.
ALWAYS = [r"secureai\.db"]
# Only in documentation/config prose that explains the rename or quotes pre-rename recorded output.
LEGACY_DOC_LINES = [r"Agent: SecureAI", r"SecureAI for developer", r"before the (project was )?renam", r"previously named SecureAI",
                    r"secureai-agent_backend-data", r"SecureAI-Agent", r"`SecureAI`", r"`SecureAI Agent`", r"`secureai-agent`",
                    r"`secureai-sandbox:latest`", r"docker image rm secureai-sandbox:latest", r"SecureAI Agent to AESA", r'label "SecureAI"', r"captured before"]
DOC_FILES = {"README.md", "docs/deployment.md", "docs/ui-states.md", ".env.example", "docker-compose.yml"}


def _stale_references():
    me = Path(__file__).resolve()
    for p in ROOT.rglob("*"):
        if not p.is_file() or p.resolve() == me or any(part in SKIP_DIRS for part in p.parts):
            continue
        rel = p.relative_to(ROOT).as_posix()
        if rel in HISTORICAL_FILES:
            continue
        try:
            lines = p.read_text().splitlines()
        except UnicodeDecodeError:
            continue
        allowed = ALWAYS + (LEGACY_DOC_LINES if rel in DOC_FILES else [])
        for n, line in enumerate(lines, 1):
            if OLD.search(line) and not any(re.search(a, line) for a in allowed):
                yield f"{rel}:{n}: {line.strip()[:100]}"


def test_no_stale_old_name_references_outside_the_allowlist():
    stale = list(_stale_references())
    assert not stale, "old project name still present:\n" + "\n".join(stale)


def test_historical_audit_export_is_unmodified_apart_from_the_note():
    text = (ROOT / "docs/example-audit-log.txt").read_text()
    assert text.count("Agent: SecureAI") >= 15 and "captured before the project was renamed" in text
