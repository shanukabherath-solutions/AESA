"""End-to-end: inspect -> propose -> checks -> human approval -> apply -> CI -> deployment approval -> deploy."""
import jwt
import pytest

from app.audit import logger as audit
from app.models import AgentTask, SecurityScan, User
from tests.conftest import PASSWORD, git, login


@pytest.fixture
def api(client, repo):
    return {"admin": login(client, "admin"), "developer": login(client, "developer"),
            "approver": login(client, "approver"), "viewer": login(client, "viewer"), "repo": repo}


PROMPT = "Analyze this repository and identify a security issue in the authentication module. Propose a safe fix and run all available tests."


def create_task(client, api, who="developer"):
    r = client.post("/api/agent/tasks", json={"repository_id": api["repo"].id, "prompt": PROMPT}, headers=api[who])
    assert r.status_code == 201, r.text
    return client.get(f"/api/agent/tasks/{r.json()['id']}", headers=api[who]).json()


def test_full_workflow(client, api, demo_repo_path, db):
    main_before = git(demo_repo_path, "rev-parse", "main").strip()

    # 1-10: agent inspects, finds issues, patches in an isolated workspace, runs checks, requests approval
    t = create_task(client, api)
    assert t["status"] == "AWAITING_APPROVAL", t
    tid = t["id"]
    acts = client.get(f"/api/tasks/{tid}/actions", headers=api["viewer"]).json()
    tools = [a["tool"] for a in acts["actions"]]
    assert tools[:2] == ["list_files", "search_code"] and tools[-1] == "request_approval"
    for needed in ("read_file", "create_branch", "create_patch", "run_tests", "run_linter", "run_security_scan"):
        assert needed in tools
    # nothing was denied or rejected on the happy path (an uninstalled scanner may report FAILED/ERROR: fail closed)
    assert not [a for a in acts["actions"] if a["status"] in ("DENIED", "REJECTED")]
    assert all(d["decision"] == "ALLOW" for d in acts["policy_decisions"])

    diff = client.get(f"/api/tasks/{tid}/diff", headers=api["viewer"]).json()
    assert "pbkdf2" in diff["diff"] and diff["files"][0]["path"] == "app/auth.py" and diff["risk_level"] == "MEDIUM"
    scans = client.get(f"/api/security/scans/{tid}", headers=api["viewer"]).json()
    assert scans["gate"]["passed"], scans["gate"]
    assert {s["tool"] for s in scans["scans"]} >= {"pytest", "ruff", "mypy", "bandit"}
    assert git(demo_repo_path, "rev-parse", "main").strip() == main_before  # nothing applied yet

    # 11: only an APPROVER (who is not the author) may approve; the displayed patch hash is bound to the decision
    approval = client.get("/api/approvals?status=PENDING&type=PATCH", headers=api["viewer"]).json()[0]
    aid = approval["id"]
    assert client.post(f"/api/approvals/{aid}/approve", json={"patch_sha256": diff["patch_sha256"]}, headers=api["developer"]).status_code == 403
    assert client.post(f"/api/approvals/{aid}/approve", json={"patch_sha256": diff["patch_sha256"]}, headers=api["viewer"]).status_code == 403
    assert client.post(f"/api/approvals/{aid}/approve", json={"patch_sha256": "0" * 64}, headers=api["approver"]).status_code == 409
    assert git(demo_repo_path, "rev-parse", "main").strip() == main_before
    r = client.post(f"/api/approvals/{aid}/approve", json={"patch_sha256": diff["patch_sha256"], "comment": "LGTM"}, headers=api["approver"])
    assert r.status_code == 200, r.text

    # 12-16: committed to a feature branch (never main), CI ran against the pushed branch and passed
    t = client.get(f"/api/agent/tasks/{tid}", headers=api["viewer"]).json()
    assert t["status"] == "READY_FOR_DEPLOYMENT", t
    branch = f"agent/proposal-{tid}"
    assert t["branch_name"] == branch and t["commit_sha"]
    assert git(demo_repo_path, "rev-parse", "main").strip() == main_before
    assert git(demo_repo_path, "rev-parse", branch).strip() == t["commit_sha"]
    msg = git(demo_repo_path, "log", "-1", "--format=%B", branch)
    assert "Approved-by: approver" in msg and "AESA" in msg
    ci = client.get(f"/api/ci/runs/{tid}", headers=api["viewer"]).json()
    assert ci["runs"][0]["status"] == "PASSED" and ci["runs"][0]["provider"] == "local"
    assert ci["deployment"]["status"] == "PENDING_APPROVAL"

    # 17: deployment needs a SECOND, separate approval; patch approval alone cannot deploy
    assert client.post(f"/api/deployments/{tid}/execute", headers=api["approver"]).status_code == 409
    dep_approval = client.get("/api/approvals?status=PENDING&type=DEPLOY", headers=api["viewer"]).json()[0]
    assert client.post(f"/api/approvals/{dep_approval['id']}/approve", json={}, headers=api["developer"]).status_code == 403
    assert client.post(f"/api/approvals/{dep_approval['id']}/approve", json={}, headers=api["approver"]).status_code == 200
    assert client.get(f"/api/agent/tasks/{tid}", headers=api["viewer"]).json()["status"] == "DEPLOY_APPROVED"
    assert client.post(f"/api/deployments/{tid}/execute", headers=api["developer"]).status_code == 403
    r = client.post(f"/api/deployments/{tid}/execute", headers=api["approver"])
    assert r.status_code == 200 and r.json()["task"]["status"] == "DEPLOYED"

    # audit: complete, chain intact, secrets absent
    assert client.get("/api/audit-logs/verify", headers=api["admin"]).json()["ok"] is True
    logs = client.get("/api/audit-logs?limit=500", headers=api["viewer"]).json()
    actions = {e["action"] for e in logs["items"]}
    assert {"login", "task_created", "tool_call", "pending_patch" if False else "patch_approve", "change_applied", "ci_result", "deployed"} <= actions
    assert client.get(f"/api/audit-logs?action=tool_call&task_id={tid}", headers=api["viewer"]).json()["total"] == len(tools)
    assert PASSWORD not in str(logs)


def test_failed_security_check_blocks_approval(client, api, db):
    t = create_task(client, api)
    scan = db.query(SecurityScan).filter_by(task_id=t["id"], tool="bandit").one()
    scan.status, scan.high, scan.summary = "FAILED", 1, "1 high finding"
    db.commit()
    aid = client.get("/api/approvals?status=PENDING", headers=api["viewer"]).json()[0]["id"]
    r = client.post(f"/api/approvals/{aid}/approve", json={"patch_sha256": t["patch_sha256"]}, headers=api["approver"])
    assert r.status_code == 422 and "bandit" in str(r.json())
    assert client.get(f"/api/agent/tasks/{t['id']}", headers=api["viewer"]).json()["status"] == "AWAITING_APPROVAL"


def test_missing_scan_error_status_also_blocks(client, api, db):
    t = create_task(client, api)
    scan = db.query(SecurityScan).filter_by(task_id=t["id"], tool="mypy").one()
    scan.status = "ERROR"; db.commit()
    aid = client.get("/api/approvals?status=PENDING", headers=api["viewer"]).json()[0]["id"]
    assert client.post(f"/api/approvals/{aid}/approve", json={"patch_sha256": t["patch_sha256"]}, headers=api["approver"]).status_code == 422


def test_reject_and_request_changes_and_no_double_decision(client, api):
    t = create_task(client, api)
    aid = client.get("/api/approvals?status=PENDING", headers=api["viewer"]).json()[0]["id"]
    assert client.post(f"/api/approvals/{aid}/request-changes", json={}, headers=api["approver"]).status_code == 400
    assert client.post(f"/api/approvals/{aid}/request-changes", json={"comment": "add tests"}, headers=api["approver"]).status_code == 200
    assert client.get(f"/api/agent/tasks/{t['id']}", headers=api["viewer"]).json()["status"] == "CHANGES_REQUESTED"
    assert client.post(f"/api/approvals/{aid}/approve", json={"patch_sha256": t["patch_sha256"]}, headers=api["approver"]).status_code == 409
    t2 = create_task(client, api)
    aid2 = client.get("/api/approvals?status=PENDING", headers=api["viewer"]).json()[0]["id"]
    assert client.post(f"/api/approvals/{aid2}/reject", json={"comment": "no"}, headers=api["approver"]).status_code == 200
    assert client.get(f"/api/agent/tasks/{t2['id']}", headers=api["viewer"]).json()["status"] == "REJECTED"


def test_no_self_approval(client, api, db):
    t = create_task(client, api, who="admin")  # admin authors the task...
    aid = client.get("/api/approvals?status=PENDING", headers=api["viewer"]).json()[0]["id"]
    r = client.post(f"/api/approvals/{aid}/approve", json={"patch_sha256": t["patch_sha256"]}, headers=api["admin"])
    assert r.status_code == 403  # ...and cannot approve it, despite being ADMIN


def test_task_cannot_skip_states(db, repo):
    from app.approvals.state import InvalidTransition, transition
    from app.models.enums import TaskStatus
    dev = db.query(User).filter_by(username="developer").one()
    t = AgentTask(repository_id=repo.id, created_by=dev.id, prompt="p", status="ANALYZING"); db.add(t); db.commit()
    for target in (TaskStatus.APPROVED, TaskStatus.APPLIED, TaskStatus.DEPLOYED, TaskStatus.DEPLOY_APPROVED):
        with pytest.raises(InvalidTransition):
            transition(db, t, target)


# ------------------------------------------------------------------ auth / roles
def test_auth_required_everywhere(client):
    for method, path in [("get", "/api/repositories"), ("get", "/api/audit-logs"), ("post", "/api/agent/tasks"),
                         ("get", "/api/dashboard/summary"), ("post", "/api/approvals/1/approve"), ("post", "/api/deployments/1/execute")]:
        assert getattr(client, method)(path).status_code == 401, path
    assert client.get("/api/health").status_code == 200


def test_login_failures_and_lockout(client, db):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "ghost", "password": "wrong"}).status_code == 401
    for _ in range(6):
        client.post("/api/auth/login", json={"username": "viewer", "password": "bad"})
    assert client.post("/api/auth/login", json={"username": "viewer", "password": PASSWORD}).status_code == 429


def test_passwords_are_argon2_hashed(db):
    u = db.query(User).filter_by(username="admin").one()
    assert u.password_hash.startswith("$argon2") and PASSWORD not in u.password_hash


def test_forged_and_tampered_tokens_rejected(client, settings, api):
    forged = jwt.encode({"sub": "1", "role": "ADMIN", "jti": "x"}, "wrong-secret-wrong-secret-wrong-secret!", algorithm="HS256")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    none_alg = jwt.encode({"sub": "1"}, key="", algorithm="none")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {none_alg}"}).status_code == 401


def test_role_matrix(client, api):
    rid = api["repo"].id
    body = {"repository_id": rid, "prompt": PROMPT}
    assert client.post("/api/agent/tasks", json=body, headers=api["viewer"]).status_code == 403
    assert client.post("/api/agent/tasks", json=body, headers=api["approver"]).status_code == 403
    assert client.get(f"/api/repositories/{rid}/tree", headers=api["viewer"]).status_code == 403
    assert client.get(f"/api/repositories/{rid}/tree", headers=api["developer"]).status_code == 200
    assert client.get("/api/audit-logs", headers=api["viewer"]).status_code == 200
    for who in ("viewer", "developer", "approver"):
        assert client.get("/api/users", headers=api[who]).status_code == 403
        assert client.get("/api/audit-logs/verify", headers=api[who]).status_code == 403
        assert client.post("/api/repositories", json={"name": "x", "root_path": "/tmp"}, headers=api[who]).status_code == 403
    assert client.get("/api/users", headers=api["admin"]).status_code == 200


def test_tree_hides_sensitive_files(client, api, demo_repo_path):
    (demo_repo_path / ".env").write_text("A=1")
    files = client.get(f"/api/repositories/{api['repo'].id}/tree", headers=api["developer"]).json()["files"]
    assert "app/auth.py" in files and ".env" not in files and not any(f.startswith(".git/") for f in files)


def test_repository_registration_is_confined(client, api, tmp_path):
    h = api["admin"]
    assert client.post("/api/repositories", json={"name": "etc", "root_path": "/etc"}, headers=h).status_code == 400
    assert client.post("/api/repositories", json={"name": "t", "root_path": str(tmp_path)}, headers=h).status_code == 400
    assert client.post("/api/repositories", json={"name": "t", "root_path": "../../etc"}, headers=h).status_code == 400
    assert client.post("/api/repositories", json={"name": "demo-repo", "root_path": api["repo"].root_path}, headers=h).status_code == 409


def test_user_management_validates(client, api):
    h = api["admin"]
    assert client.post("/api/users", json={"username": "x", "password": "short", "role": "ADMIN"}, headers=h).status_code == 422
    assert client.post("/api/users", json={"username": "newdev", "password": PASSWORD, "role": "SUPERUSER"}, headers=h).status_code == 422
    assert client.post("/api/users", json={"username": "newdev", "password": PASSWORD, "role": "DEVELOPER"}, headers=h).status_code == 201
    assert client.patch("/api/users/1", json={"role": "VIEWER"}, headers=h).status_code == 400  # cannot demote yourself


def test_dashboard_and_policy_endpoints(client, api):
    create_task(client, api)
    d = client.get("/api/dashboard/summary", headers=api["viewer"]).json()
    assert d["pending_approvals"] == 1 and d["current_task"]["status"] == "AWAITING_APPROVAL" and d["security"]["passed"] is True
    pol = client.get("/api/policy", headers=api["viewer"]).json()
    assert pol["tools"]["deploy"]["exposed_to_model"] is False and pol["tools"]["create_pull_request"]["level"] == "APPROVED_CHANGE"


def test_cancel_task_permissions(client, api):
    t = create_task(client, api)
    assert client.post(f"/api/agent/tasks/{t['id']}/cancel", headers=api["approver"]).status_code == 403
    assert client.post(f"/api/agent/tasks/{t['id']}/cancel", headers=api["developer"]).status_code == 200
    assert client.post(f"/api/agent/tasks/{t['id']}/cancel", headers=api["developer"]).status_code == 409


def test_audit_chain_detects_tampering(db):
    from app.models import AuditLog
    audit.record(db, action="a", status="OK")
    e = audit.record(db, action="b", status="OK")
    db.add(AuditLog(timestamp=e.timestamp, action="forged", prev_hash="0" * 64, entry_hash="f" * 64, arguments={}, affected_files=[]))
    db.commit()
    v = audit.verify_chain(db)
    assert v["ok"] is False and v["first_bad_id"] == 3
