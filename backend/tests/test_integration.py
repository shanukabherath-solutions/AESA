import hashlib
import hmac as hmaclib
import json
import time

import pytest

from app.agent.scripted import FIXERS
from app.models import AgentAction, AgentTask, CICDRun, SecurityScan
from app.models.enums import ScanStatus
from app.sandbox.commands import PlannedCommand
from app.sandbox.runner import DockerSandbox, LocalSandbox, SandboxUnavailable, get_sandbox, run_capped
from app.tools.executor import ToolExecutor
from tests.conftest import git


def fixed_auth(ctx):
    text = ctx.guard.read_text("app/auth.py", 100_000)
    for f in FIXERS:
        text, _ = f(text)
    return text


def test_workspace_is_isolated_and_excludes_untracked_secrets(make_ctx, demo_repo_path):
    (demo_repo_path / ".env").write_text("API_KEY=sk-should-never-be-visible-123456789\n")  # untracked local secret
    ctx = make_ctx()
    assert not (ctx.workspace / ".env").exists()
    ex = ToolExecutor(ctx)
    out = ex.execute("list_files", {"path": "."})
    data = out.observation["data"]
    assert "app/auth.py" in data["files"] and ".env" not in data["files"]
    assert "Python" in data["languages"] and "tests/test_auth.py" in data["test_files"]


def test_read_and_search_tools(make_ctx):
    ex = ToolExecutor(make_ctx())
    assert "hashlib.md5" in ex.execute("read_file", {"path": "app/auth.py"}).observation["data"]["content"]
    hits = ex.execute("search_code", {"query": "md5|sha1"}).observation["data"]["matches"]
    assert any(h["file"] == "app/auth.py" for h in hits)
    assert ex.execute("read_file", {"path": ".git/config"}).observation["status"] == "denied"


def test_sandbox_runs_tests_and_baseline_fails_on_vulnerability(make_ctx, db):
    ctx = make_ctx()
    out = ToolExecutor(ctx).execute("run_tests", {})
    scan = db.query(SecurityScan).filter_by(tool="pytest").one()
    assert scan.status == ScanStatus.FAILED.value  # injection test fails on the vulnerable code
    assert out.observation["status"] == "failed"


def test_patch_branch_and_isolation_from_source_repo(make_ctx, db, demo_repo_path):
    ctx = make_ctx()
    ex = ToolExecutor(ctx)
    head_before = git(demo_repo_path, "rev-parse", "main").strip()
    assert ex.execute("create_branch", {}).observation["status"] == "ok"
    assert ctx.task.branch_name == f"agent/proposal-{ctx.task.id}"
    new = fixed_auth(ctx)
    out = ex.execute("create_patch", {"files": [{"path": "app/auth.py", "new_content": new}], "summary": "fix auth",
                                      "explanation": "hashing", "risk_level": "MEDIUM"})
    assert out.observation["status"] == "ok", out.observation
    t = db.get(AgentTask, ctx.task.id)
    assert t.status == "PROPOSED" and t.files_changed[0]["path"] == "app/auth.py"
    assert t.patch_sha256 == hashlib.sha256(t.patch_text.encode()).hexdigest()
    assert "pbkdf2" in t.patch_text and "-    return hashlib.md5" in t.patch_text
    # the registered repository is untouched: same HEAD, no new branch, clean tree
    assert git(demo_repo_path, "rev-parse", "main").strip() == head_before
    assert t.branch_name not in git(demo_repo_path, "branch", "--list")
    assert git(demo_repo_path, "status", "--porcelain").strip() == ""
    # patch applies cleanly to a pristine checkout
    from app.repository.git import run_git
    run_git(demo_repo_path, "apply", "--check", input_text=t.patch_text)


def test_patch_rejections(make_ctx):
    ctx = make_ctx()
    ex = ToolExecutor(ctx)
    base = {"summary": "s", "explanation": "e", "risk_level": "LOW"}
    assert ex.execute("create_patch", {**base, "files": [{"path": ".github/workflows/ci.yml", "new_content": "x"}]}).observation["status"] == "denied"
    assert ex.execute("create_patch", {**base, "files": [{"path": "app/x.py", "new_content": "k = '[REDACTED:secret]'"}]}).observation["status"] == "failed"
    assert ex.execute("create_patch", {**base, "files": [{"path": "app/auth.py", "new_content": ctx.guard.read_text("app/auth.py", 10**6)}]}).observation["status"] == "failed"  # no-op
    assert ex.execute("create_patch", {**base, "files": [{"path": "../../x.py", "new_content": "x"}]}).observation["status"] == "denied"
    assert ex.execute("create_patch", {**base, "files": [{"path": ".env", "new_content": "x"}]}).observation["status"] == "denied"


def test_invalid_tool_arguments_are_rejected_not_coerced(make_ctx, db):
    ex = ToolExecutor(make_ctx())
    for tool, args in [("read_file", {}), ("read_file", {"path": 5}), ("read_file", {"path": "a", "extra": 1}),
                       ("run_tests", {"runner": "bash"}), ("create_patch", {"files": []}), ("list_files", "not-a-dict"),
                       ("search_code", {"query": "x"}), ("run_security_scan", {"scanner": "; rm -rf /"})]:
        assert ex.execute(tool, args).observation["status"] == "rejected", (tool, args)
    assert db.query(AgentAction).filter_by(status="REJECTED").count() == 8


def test_request_approval_requires_patch_and_checks(make_ctx, db):
    ctx = make_ctx()
    ex = ToolExecutor(ctx)
    assert ex.execute("request_approval", {"summary": "please"}).observation["status"] == "failed"  # nothing proposed
    ex.execute("create_branch", {})
    ex.execute("create_patch", {"files": [{"path": "app/auth.py", "new_content": fixed_auth(ctx)}], "summary": "s", "explanation": "e", "risk_level": "LOW"})
    out = ex.execute("request_approval", {"summary": "please"})
    assert out.observation["status"] == "failed" and "run these checks" in out.observation["summary"]


def test_scans_are_bound_to_the_exact_patch(make_ctx, db):
    from app.approvals.service import gate_for_task
    ctx = make_ctx()
    ex = ToolExecutor(ctx)
    ex.execute("create_branch", {})
    ex.execute("create_patch", {"files": [{"path": "app/auth.py", "new_content": fixed_auth(ctx)}], "summary": "s", "explanation": "e", "risk_level": "LOW"})
    ex.execute("run_tests", {}); ex.execute("run_linter", {}); ex.execute("run_security_scan", {})
    ctx.task.required_scans = ctx.settings.required_scan_list
    assert gate_for_task(db, ctx.task).passed
    # patch changes afterwards -> old scan results no longer count
    text = fixed_auth(ctx) + "\n# tweak\n"
    ex.execute("create_patch", {"files": [{"path": "app/auth.py", "new_content": text}], "summary": "s", "explanation": "e", "risk_level": "LOW"})
    g = gate_for_task(db, db.get(AgentTask, ctx.task.id))
    assert not g.passed and set(g.missing) == set(ctx.settings.required_scan_list)


def test_timeout_kills_process_group_and_reports(tmp_path):
    start = time.time()
    res = run_capped(["sh", "-c", "sleep 30 & sleep 30"], tmp_path, {"PATH": "/usr/bin:/bin"}, timeout=1, max_bytes=1000)
    assert res.timed_out and time.time() - start < 10


def test_output_is_capped(tmp_path):
    res = run_capped(["yes"], tmp_path, {"PATH": "/usr/bin:/bin"}, timeout=10, max_bytes=5000)
    assert res.truncated and len(res.stdout) <= 5000


def test_local_sandbox_env_is_scrubbed(tmp_path, monkeypatch, settings):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "a" * 36)
    monkeypatch.setenv("AI_API_KEY", "sk-abcdefghijklmnopqrstuvwxyz1234")
    cmd = PlannedCommand("x", ("python", "-c", "import os,json;print(json.dumps(dict(os.environ)))"), 10)
    out = LocalSandbox(settings).run(cmd, tmp_path).stdout
    assert "ghp_" not in out and "sk-abc" not in out and "GITHUB_TOKEN" not in out


def test_docker_sandbox_flags_are_locked_down(tmp_path, settings, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/bin/docker")
    sb = DockerSandbox(settings)
    args = sb.build_args(PlannedCommand("pytest", ("python", "-m", "pytest"), 60), tmp_path, "c1")
    joined = " ".join(args)
    for must in ("--rm", "--cap-drop ALL", "no-new-privileges", "--network none", "--read-only", "--user 10001:10001", "--pids-limit", "--memory", "--cpus"):
        assert must in joined
    for never in ("--privileged", "docker.sock", "--network host", "-v /:/", "--volume"):
        assert never not in joined
    assert joined.count("--mount") == 1 and "dst=/workspace" in joined and "/home" not in joined.split("--mount")[1].split()[0].split("src=")[0]


def test_docker_backend_fails_closed_without_docker(settings, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _n: None)
    with pytest.raises(SandboxUnavailable):
        get_sandbox(settings.model_copy(update={"sandbox_backend": "docker"}))


# ------------------------------------------------------------------ CI result handling
def test_ci_webhook_signature_and_state(client, settings, db, repo):
    from app.ci import service as ci
    from app.models import AgentTask, User
    from app.models.enums import TaskStatus

    s = settings.model_copy(update={"github_webhook_secret": "whsec"})
    from app.config import override_settings
    override_settings(s)
    assert ci.verify_signature("whsec", b"{}", "sha256=" + hmaclib.new(b"whsec", b"{}", hashlib.sha256).hexdigest())
    assert not ci.verify_signature("whsec", b"{}", "sha256=deadbeef") and not ci.verify_signature("", b"{}", None)
    dev = db.query(User).filter_by(username="developer").one()
    t = AgentTask(repository_id=repo.id, created_by=dev.id, prompt="p", status=TaskStatus.CI_RUNNING.value, branch_name="agent/proposal-1",
                  commit_sha="abc", patch_sha256="f" * 64, required_scans=[])
    db.add(t); db.commit()
    db.add(CICDRun(task_id=t.id, provider="github", status="QUEUED")); db.commit()
    body = json.dumps({"workflow_run": {"id": 9, "status": "completed", "conclusion": "success", "head_branch": f"agent/proposal-{t.id}", "head_sha": "abc", "html_url": "https://x"}}).encode()
    sig = "sha256=" + hmaclib.new(b"whsec", body, hashlib.sha256).hexdigest()
    h = {"X-GitHub-Event": "workflow_run", "X-Hub-Signature-256": sig, "Content-Type": "application/json"}
    assert client.post("/api/ci/webhook", content=body, headers={**h, "X-Hub-Signature-256": "sha256=bad"}).status_code == 401
    t.branch_name = f"agent/proposal-{t.id}"; db.commit()
    r = client.post("/api/ci/webhook", content=body, headers=h)
    assert r.status_code == 200 and r.json()["task_status"] == "READY_FOR_DEPLOYMENT"
