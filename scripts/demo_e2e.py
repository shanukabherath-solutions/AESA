"""Drive the full workflow against a RUNNING stack over HTTP:
inspect -> propose -> checks -> human approval -> branch -> CI -> deployment approval -> deploy.

    BASE_URL=http://localhost:8000 DEMO_PASSWORD=... python scripts/demo_e2e.py
"""
from __future__ import annotations

import os
import sys
import time

import httpx

BASE = os.environ.get("BASE_URL", "http://localhost:8000")
PASSWORD = os.environ.get("DEMO_PASSWORD", "")
PROMPT = ("Analyze this repository and identify a security issue in the authentication module. "
          "Propose a safe fix and run all available tests.")


def step(msg: str) -> None:
    print(f"\n== {msg}")


def login(c: httpx.Client, user: str) -> dict[str, str]:
    r = c.post("/api/auth/login", json={"username": user, "password": PASSWORD})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def wait(c: httpx.Client, h: dict, tid: int, until: set[str], timeout: int = 600) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        t = c.get(f"/api/agent/tasks/{tid}", headers=h).json()
        if t["status"] in until:
            return t
        if t["status"] in {"FAILED_SAFELY", "CANCELLED", "REJECTED", "CI_FAILED", "ANALYSIS_ONLY"}:
            sys.exit(f"task ended in {t['status']}: {t.get('failure_reason')}")
        time.sleep(1.5)
    sys.exit("timed out")


def main() -> None:
    if not PASSWORD:
        sys.exit("set DEMO_PASSWORD")
    with httpx.Client(base_url=BASE, timeout=60) as c:
        dev, appr, admin = login(c, "developer"), login(c, "approver"), login(c, "admin")
        repo = c.get("/api/repositories", headers=dev).json()[0]
        step(f"developer starts a task on {repo['name']}")
        tid = c.post("/api/agent/tasks", json={"repository_id": repo["id"], "prompt": PROMPT}, headers=dev).json()["id"]
        t = wait(c, dev, tid, {"AWAITING_APPROVAL"})
        for a in c.get(f"/api/tasks/{tid}/actions", headers=dev).json()["actions"]:
            print(f"  {a['step']:>2}. {a['tool']:<18} {a['status']:<9} {a['result_summary'][:90]}")
        d = c.get(f"/api/tasks/{tid}/diff", headers=dev).json()
        print(f"\n  risk={d['risk_level']} files={[f['path'] for f in d['files']]} sha256={d['patch_sha256'][:16]}")
        sc = c.get(f"/api/security/scans/{tid}", headers=dev).json()
        print("  gate:", "PASSED" if sc["gate"]["passed"] else f"BLOCKED {sc['gate']['reasons']}")

        step("the workflow cannot be skipped: deploying before any approval is refused")
        print("  POST /deployments/execute ->", c.post(f"/api/deployments/{tid}/execute", headers=appr).status_code, "(expected 409)")

        step("approver reviews the diff and approves (bound to the patch hash)")
        aid = next(a["id"] for a in c.get("/api/approvals?status=PENDING&type=PATCH", headers=appr).json() if a["task_id"] == tid)
        r = c.post(f"/api/approvals/{aid}/approve", json={"patch_sha256": d["patch_sha256"], "comment": "Reviewed: LGTM"}, headers=appr)
        print("  approve ->", r.status_code)
        t = wait(c, dev, tid, {"READY_FOR_DEPLOYMENT"})
        print(f"  branch={t['branch_name']} commit={t['commit_sha'][:10]} status={t['status']}")
        ci = c.get(f"/api/ci/runs/{tid}", headers=dev).json()["runs"][0]
        print(f"  CI ({ci['provider']}): {ci['status']} jobs={[(j['name'], j['conclusion']) for j in ci['jobs']]}")

        step("second, separate approval for deployment")
        did = next(a["id"] for a in c.get("/api/approvals?status=PENDING&type=DEPLOY", headers=appr).json() if a["task_id"] == tid)
        print("  approve deployment ->", c.post(f"/api/approvals/{did}/approve", json={}, headers=appr).status_code)
        r = c.post(f"/api/deployments/{tid}/execute", headers=appr)
        print("  execute ->", r.status_code, r.json()["deployment"]["details"].get("mode"))

        step("audit chain")
        print(" ", c.get("/api/audit-logs/verify", headers=admin).json())
        print(f"\nDONE: task {tid} -> {r.json()['task']['status']}")


if __name__ == "__main__":
    main()
