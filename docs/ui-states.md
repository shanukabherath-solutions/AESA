# UI states

Real screenshots of the running dashboard are in [`docs/screenshots/`](screenshots/README.md). The text renderings below describe
the same states and use data from a real run of `scripts/demo_e2e.py`.

## Gate tracker (every task page)
The one persistent visual: the task's progress through the state machine with the two human barriers.

```
 (1)Analyzing ─ (2)Proposed ─ (3)Review ─[ 🔒 Human approval ]─ (4)Approved ─ (5)Applied ─ (6)CI ─[ 🔒 Deployment approval ]─ (7)Ready ─ (8)Cleared ─ (9)Deployed
                                  ▲ current (pulsing amber barrier = waiting for a person)
```
Completed steps are green, the current step is blue, barriers turn green and "unlock" once a person has decided.

## Proposed change review (state: AWAITING_APPROVAL)
```
Review patch for task 1                                        [medium risk] [Awaiting approval]
demo-repo · proposed by the agent for developer

What the agent wants to change
  Fix insecure authentication code
  - app/auth.py: Passwords were hashed with unsalted MD5/SHA-1 and compared with ==; replaced with salted PBKDF2…
  - app/auth.py: A signing secret (SECRET_KEY) was hard-coded in source; now read from APP_SECRET_KEY.
  - app/auth.py: 1 SQL statement(s) were built with string interpolation; converted to parameterised queries.
  - app/auth.py: A signature was compared with != (timing side channel); now uses hmac.compare_digest.

Before and after                                    app/auth.py  +29 −7
   9   9   import json
        10 +import os
        11 +import secrets
  14      -SECRET_KEY = "super-secret-signing-key-123"
        …  +def get_secret_key() -> str: …

Test and security results      Security gate passed
  pytest   Passed   5 passed in 1.39s          ruff     Passed   no lint issues
  mypy     Passed   no type errors             bandit   Passed   0 finding(s)
  gitleaks Passed   no secrets detected

Files affected: app/auth.py +29 −7      Branch agent/proposal-1 (never the default branch)
Decision   [Approve] [Reject] [Request changes]      Patch hash b8aed46fcc070a9b…  (your decision is bound to it)
```
Variants: the Approve button is disabled with the failing checks listed when the gate fails; a self-authored task shows
"You started this task, so someone else must approve it"; viewers see the request but no buttons.

## Agent task (state: FAILED_SAFELY / blocked actions)
```
Agent actions   10 actions · 0 denied
  1  list_files        Inspect the repository structure and detect languages     9 file(s) listed         Executed
  …
Blocked by policy
  run_command  default_deny: 'run_command' is not a recognised tool; unknown actions are denied
  read_file    blocked_path: '.env' is a sensitive path
```

## Audit logs
(Sample captured before the rename to AESA, so the agent label reads "SecureAI"; new entries read "AESA".)

Filters: action, repository, agent, status, date range, free text. Row (click to expand JSON and hash):
```
2026-10-05 10:47:41  SecureAI for developer  run_command · tool_call  [DENIED]  [DENIED]  denied by policy (default_deny)…
```
Admins get **Verify chain** → "Chain intact across 36 entries."

## CI/CD
Pipeline status and per-job results (`pytest passed · ruff passed · mypy passed · bandit passed · gitleaks passed`),
build log, scan history (proposal + CI phases), deployment state (Pending approval → Deploy approved → Deployed), PR link.
