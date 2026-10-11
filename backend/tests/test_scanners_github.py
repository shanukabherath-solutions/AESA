import json

import httpx
import pytest

from app.ci.github import GitHubClient, GitHubError
from app.models.enums import ScanStatus, Severity
from app.sandbox.runner import CommandResult
from app.security import scanners as sc


def res(stdout="", code=0, stderr="", **kw):
    return CommandResult("cmd", code, stdout, stderr, 0.1, **kw)


HIGH = Severity.HIGH


def test_trivy_blocking_and_pass():
    data = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "x", "Severity": "CRITICAL", "Title": "bad"},
        {"VulnerabilityID": "CVE-2", "PkgName": "y", "Severity": "LOW"}]}]}
    o = sc.parse_trivy(res(json.dumps(data)), HIGH)
    assert o.status == ScanStatus.FAILED and o.counts["critical"] == 1 and o.counts["low"] == 1
    assert sc.parse_trivy(res(json.dumps({"Results": [{"Target": "t", "Vulnerabilities": [{"Severity": "MEDIUM"}]}]})), HIGH).status == ScanStatus.PASSED
    assert sc.parse_trivy(res("{}"), HIGH).status == ScanStatus.PASSED
    sec = sc.parse_trivy(res(json.dumps({"Results": [{"Target": "a", "Secrets": [{"RuleID": "aws", "Severity": "CRITICAL"}]}]})), HIGH)
    assert sec.status == ScanStatus.FAILED


def test_npm_audit():
    bad = {"metadata": {"vulnerabilities": {"critical": 0, "high": 2, "moderate": 1, "low": 0}}, "vulnerabilities": {"lodash": {"severity": "high"}}}
    o = sc.parse_npm_audit(res(json.dumps(bad), 1), HIGH)
    assert o.status == ScanStatus.FAILED and o.counts["high"] == 2 and o.counts["medium"] == 1
    ok = {"metadata": {"vulnerabilities": {"critical": 0, "high": 0, "moderate": 3, "low": 1}}}
    assert sc.parse_npm_audit(res(json.dumps(ok), 1), HIGH).status == ScanStatus.PASSED
    assert sc.parse_npm_audit(res(json.dumps({"error": {"summary": "ENOTFOUND"}}), 1), HIGH).status == ScanStatus.ERROR


def test_gitleaks_bandit_ruff_mypy_pytest():
    assert sc.parse_gitleaks(res("[]"), HIGH).status == ScanStatus.PASSED
    leak = sc.parse_gitleaks(res(json.dumps([{"RuleID": "aws-key", "File": "a.py", "StartLine": 3, "Description": "AWS"}])), HIGH)
    assert leak.status == ScanStatus.FAILED and leak.counts["critical"] == 1
    b = sc.parse_bandit(res(json.dumps({"results": [{"issue_severity": "HIGH", "issue_text": "md5", "test_id": "B324", "filename": "a.py", "line_number": 1}]}), 1), HIGH)
    assert b.status == ScanStatus.FAILED
    assert sc.parse_bandit(res(json.dumps({"results": [{"issue_severity": "MEDIUM", "issue_text": "x", "test_id": "B608"}]}), 1), HIGH).status == ScanStatus.PASSED
    assert sc.parse_bandit(res(json.dumps({"results": [{"issue_severity": "MEDIUM", "issue_text": "x", "test_id": "B608"}]}), 1), Severity.MEDIUM).status == ScanStatus.FAILED
    assert sc.parse_ruff(res("[]"), HIGH).status == ScanStatus.PASSED
    assert sc.parse_ruff(res(json.dumps([{"code": "F401", "message": "unused", "filename": "a.py", "location": {"row": 1}}]), 1), HIGH).status == ScanStatus.FAILED
    assert sc.parse_mypy(res("a.py:3: error: bad [x]\n", 1), HIGH).status == ScanStatus.FAILED
    assert sc.parse_pytest(res("1 passed in 0.1s\n"), HIGH).status == ScanStatus.PASSED
    assert sc.parse_pytest(res("FAILED t.py::x\n1 failed", 1), HIGH).status == ScanStatus.FAILED
    assert sc.parse_pytest(res("", 5), HIGH).status == ScanStatus.ERROR


@pytest.mark.parametrize("parser", [sc.parse_bandit, sc.parse_gitleaks, sc.parse_trivy, sc.parse_npm_audit, sc.parse_ruff, sc.parse_mypy, sc.parse_pytest])
def test_every_parser_fails_closed(parser):
    assert parser(res("", 127), HIGH).status == ScanStatus.ERROR          # not installed
    assert parser(res("", 0, timed_out=True), HIGH).status == ScanStatus.ERROR  # timed out
    assert parser(res("x" * 10, 0, truncated=True), HIGH).status == ScanStatus.ERROR  # output flood
    if parser not in (sc.parse_mypy, sc.parse_pytest):
        assert parser(res("<<not json>>", 0), HIGH).status == ScanStatus.ERROR
        assert parser(res("", 99), HIGH).status == ScanStatus.ERROR


def test_findings_never_contain_secrets():
    o = sc.parse_bandit(res(json.dumps({"results": [{"issue_severity": "LOW", "issue_text": "password = 'hunter2hunter2'", "test_id": "B105"}]}), 1), HIGH)
    assert "hunter2" not in json.dumps(o.findings)


# ------------------------------------------------------------ GitHub client (mocked transport)
def test_github_pr_and_dispatch(settings):
    seen = []

    def handler(req: httpx.Request):
        seen.append((req.method, req.url.path, json.loads(req.content) if req.content else None, req.headers["authorization"]))
        if req.url.path.endswith("/pulls"):
            return httpx.Response(201, json={"html_url": "https://github.com/o/r/pull/7"})
        return httpx.Response(204)

    c = GitHubClient(settings.model_copy(update={"github_token": "ghp_" + "a" * 36}), httpx.MockTransport(handler))
    assert c.create_pull_request("o/r", "agent/proposal-1", "main", "t", "b")["html_url"].endswith("/7")
    c.dispatch_workflow("o/r", "deploy.yml", "main", {"task_id": "1"})
    assert seen[0][1] == "/repos/o/r/pulls" and seen[0][2]["head"] == "agent/proposal-1" and seen[0][2]["base"] == "main"
    assert seen[1][1] == "/repos/o/r/actions/workflows/deploy.yml/dispatches"


def test_github_client_validation(settings):
    c = GitHubClient(settings.model_copy(update={"github_token": "t"}), httpx.MockTransport(lambda r: httpx.Response(403)))
    for bad in ("../../admin", "a/b/c", "x y/z", ""):
        with pytest.raises(GitHubError):
            c.create_pull_request(bad, "h", "b", "t", "b")
    with pytest.raises(GitHubError):
        c.dispatch_workflow("o/r", "../evil.yml", "main", {})
    with pytest.raises(GitHubError, match="403"):
        c.create_pull_request("o/r", "h", "main", "t", "b")
    with pytest.raises(GitHubError):
        GitHubClient(settings)  # no token configured


def test_git_push_token_goes_via_env_not_argv():
    from app.repository.git import github_auth_env
    env = github_auth_env("ghp_" + "b" * 36)
    assert env["GIT_CONFIG_KEY_0"] == "http.extraHeader" and "Authorization: Basic" in env["GIT_CONFIG_VALUE_0"]
