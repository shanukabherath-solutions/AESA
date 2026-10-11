import pytest

from app.models.enums import PermissionLevel as L
from app.policy.engine import MODEL_TOOLS, TOOL_POLICIES, PolicyContext, PolicyEngine

E = PolicyEngine()


def agent_ctx(level=L.PROPOSE_CHANGE, branch="agent/proposal-1"):
    return PolicyContext.for_agent(1, level, branch, ["main", "release/*"], [".github/", "sandbox/"])


def test_read_allowed():
    assert E.evaluate(agent_ctx(), "read_file", {"path": "app/auth.py"}).allowed


@pytest.mark.parametrize("tool", ["git_push_main", "shell", "run_command", "rm", "exec", ""])
def test_unknown_tools_default_denied(tool):
    d = E.evaluate(agent_ctx(), tool, {})
    assert not d.allowed and d.rule == "default_deny"


@pytest.mark.parametrize("level", [L.APPROVED_CHANGE, L.DEPLOY])
def test_agent_level_is_clamped(level):
    assert agent_ctx(level).max_level == L.PROPOSE_CHANGE


@pytest.mark.parametrize("tool", ["create_pull_request", "apply_patch", "git_commit", "git_push", "deploy"])
def test_agent_cannot_use_privileged_actions_even_if_requesting_deploy_level(tool):
    assert not E.evaluate(agent_ctx(L.DEPLOY), tool, {"branch": "agent/proposal-1"}).allowed


def test_read_only_cannot_write_or_scan():
    ro = agent_ctx(L.READ_ONLY)
    for tool in ("create_patch", "run_tests", "create_branch", "run_security_scan"):
        d = E.evaluate(ro, tool, {"files": [{"path": "app/x.py"}]})
        assert not d.allowed and d.rule == "insufficient_level"


def test_approved_actions_need_approval_flag():
    ctx = PolicyContext(actor="system", max_level=L.APPROVED_CHANGE, task_id=1, approved_change=False, task_branch="agent/proposal-1")
    d = E.evaluate(ctx, "git_push", {"branch": "agent/proposal-1"})
    assert not d.allowed and d.rule == "approval_required"
    ok = PolicyContext.for_approved_change(1, "agent/proposal-1", ["main"], [])
    assert E.evaluate(ok, "git_push", {"branch": "agent/proposal-1", "force": False}).allowed


def test_push_rules():
    ok = PolicyContext.for_approved_change(1, "agent/proposal-1", ["main", "agent/proposal-*"], [])
    assert E.evaluate(ok, "git_push", {"branch": "main"}).rule == "branch_not_allowed"
    assert E.evaluate(ok, "git_push", {"branch": "agent/proposal-1", "force": True}).rule == "force_forbidden"
    assert E.evaluate(ok, "git_push", {"branch": "agent/proposal-2"}).rule in {"protected_branch", "branch_mismatch"}
    assert E.evaluate(ok, "git_push", {}).rule == "branch_not_allowed"


def test_deploy_needs_separate_approval_and_human_actor():
    approved_patch_only = PolicyContext("human", L.DEPLOY, 1, approved_change=True, deploy_approved=False)
    assert E.evaluate(approved_patch_only, "deploy", {}).rule == "deploy_approval_required"
    assert E.evaluate(PolicyContext.for_deploy(1, "agent/proposal-1"), "deploy", {}).allowed


@pytest.mark.parametrize("path,rule", [("../../etc/passwd", "path_traversal"), (".env", "blocked_path"),
                                       ("/etc/passwd", "absolute_path"), ("secrets/key.txt", "blocked_path"),
                                       ("app/server.pem", "blocked_path"), (".git/config", "blocked_path")])
def test_blocked_paths_denied_by_policy(path, rule):
    d = E.evaluate(agent_ctx(), "read_file", {"path": path})
    assert not d.allowed and d.rule == rule


def test_protected_paths_cannot_be_patched():
    d = E.evaluate(agent_ctx(), "create_patch", {"files": [{"path": ".github/workflows/ci.yml"}]})
    assert not d.allowed and d.rule == "protected_path"


def test_patch_file_limit():
    d = E.evaluate(agent_ctx(), "create_patch", {"files": [{"path": f"app/f{i}.py"} for i in range(50)]})
    assert d.rule == "too_many_files"


def test_every_model_tool_is_known_and_never_above_propose_unless_gated():
    for t in MODEL_TOOLS:
        assert t in TOOL_POLICIES
    gated = {t for t in MODEL_TOOLS if TOOL_POLICIES[t].level in (L.APPROVED_CHANGE, L.DEPLOY)}
    assert gated == {"create_pull_request"}
    for t in gated:
        assert not E.evaluate(agent_ctx(), t, {}).allowed
