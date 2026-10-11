"""Print the audit log in a human-readable form.  BASE_URL=... DEMO_PASSWORD=... python scripts/export_audit.py [task_id]"""
import os
import sys

import httpx

BASE = os.environ.get("BASE_URL", "http://localhost:8000")
with httpx.Client(base_url=BASE, timeout=30) as c:
    tok = c.post("/api/auth/login", json={"username": "admin", "password": os.environ["DEMO_PASSWORD"]}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    params = {"limit": 500, **({"task_id": sys.argv[1]} if len(sys.argv) > 1 else {})}
    items = list(reversed(c.get("/api/audit-logs", params=params, headers=h).json()["items"]))
    for e in items:
        who = f"Agent: {e['agent']}" if e["agent"] else f"User: {e['user'] or 'system'}"
        line = [e["timestamp"].replace("T", " ").replace("Z", ""), who, f"Action: {e['tool'] or e['action']}"]
        if e["tool"]:
            line.append(f"({e['action']})")
        if e["permission_decision"]:
            line.append(f"Permission: {e['permission_decision']}")
        if e["status"]:
            line.append(f"Result: {e['status']}")
        if e["duration_ms"] is not None:
            line.append(f"Duration: {e['duration_ms'] / 1000:.1f}s")
        if e["exit_code"] is not None:
            line.append(f"Exit: {e['exit_code']}")
        print("  ".join(line))
        if e["result"]:
            print(f"    -> {e['result'][:150]}")
    print(f"\n{len(items)} entries; chain verify: {c.get('/api/audit-logs/verify', headers=h).json()}")
