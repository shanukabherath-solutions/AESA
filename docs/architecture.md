# Architecture

```
User ─▶ Web dashboard (React) ─▶ FastAPI (auth + RBAC)
                                     │
                          create task│                       human decisions
                                     ▼                       (APPROVER role)
                            Agent orchestrator ◀──────────────────────────┐
                                     │ proposes JSON action               │
                                     ▼                                    │
                              ToolExecutor  (single choke point)          │
                    validate ─▶ PolicyEngine ─▶ execute ─▶ redact ─▶ audit│
                                     │                                    │
                ┌────────────────────┼───────────────────┐                │
                ▼                    ▼                   ▼                │
          PathGuard             Command registry     Hardened git         │
       (canonical paths)     (typed argv templates)  (isolated clone)     │
                                     │                                    │
                                     ▼                                    │
                               Sandbox (Docker)                           │
                                     │                                    │
                                     ▼                                    │
                     Tests + security scans ─▶ Security gate              │
                                     │                                    │
                                     ▼                                    │
                     Patch + proposal branch (in workspace) ──▶ AWAITING_APPROVAL
                                                                          │
              APPROVED ─▶ Applier (commit, push proposal branch, PR) ─────┘
                  │
                  ▼
              CI (GitHub Actions, or local CI that re-checks the pushed branch)
                  │ passed
                  ▼
        READY_FOR_DEPLOYMENT ─▶ second approval ─▶ DEPLOY_APPROVED ─▶ DEPLOYED
```

## Modules (`backend/app/`)

| Module | Responsibility |
|---|---|
| `models/` | SQLAlchemy entities (User, Repository, AgentTask, AgentAction, PolicyDecision, Approval, SecurityScan, CICDRun, Deployment, AuditLog) and enums. Alembic migration in `backend/alembic/`. |
| `auth/` | Argon2 hashing, JWT, role→permission map, FastAPI dependencies, login throttle. |
| `policy/` | `PolicyEngine`, `PolicyContext`, tool→level table. Pure and deterministic. |
| `repository/` | `PathGuard` (canonical path rules), hardened `git` wrapper, per-task `WorkspaceManager`, language/framework inspector. |
| `sandbox/` | Command registry (allowlist) and runners: Docker (real) / local (dev only). Output caps, timeouts, process-group kill. |
| `tools/` | Pydantic argument schemas, handlers, `ToolExecutor`. |
| `security/` | Scanner output parsers (fail closed), approval gate, scan service. |
| `agent/` | System prompt, `AIProvider` abstraction (OpenAI-compatible, Gemini, offline scripted), orchestrator loop. |
| `approvals/` | State machine, approval decisions, applier (commit/push/PR), deployment. |
| `ci/` | GitHub REST client, CI service (webhook signature, GitHub run folding, local CI). |
| `audit/` | Redaction and the hash-chained append-only log. |
| `api/` | Routers and serialisers. |

## Request flow for one tool call

1. Orchestrator asks the provider for the next action (JSON). Malformed output is counted and eventually stops the task.
2. `ToolExecutor.execute` looks the tool up. **Unknown tools skip straight to the policy engine, which denies them.**
3. Arguments are validated with the tool's Pydantic model (`extra="forbid"`). Failures are `REJECTED`.
4. `PolicyEngine.evaluate(ctx, tool, args)` where `ctx` is built from the task row (level, branch) and protected-path config; the model contributes nothing to it. The decision is stored in `policy_decisions`.
5. Handler runs. File access goes through `PathGuard`; commands go through the registry then the sandbox.
6. Output is truncated and credential-redacted, wrapped in untrusted-data markers, and returned to the model.
7. An `agent_actions` row and a hash-chained `audit_logs` entry are written (also for denials).

## Permission levels

| Level | Who can hold it | Actions |
|---|---|---|
| `READ_ONLY` | agent | list/read/search, git status/diff |
| `PROPOSE_CHANGE` | agent (maximum) | sandboxed tests/lint/scans, create_patch (workspace only), create_branch, request_approval |
| `APPROVED_CHANGE` | backend, only after a human approval record | apply patch, commit, push `agent/proposal-<id>`, open PR |
| `DEPLOY` | backend, only after a *separate* deployment approval | deploy |

## State machine

```
DRAFT → ANALYZING → PROPOSED → AWAITING_APPROVAL → APPROVED → APPLIED → CI_RUNNING → CI_PASSED
        → READY_FOR_DEPLOYMENT → DEPLOY_APPROVED → DEPLOYED

side exits: REJECTED, CHANGES_REQUESTED (from AWAITING_APPROVAL); CI_FAILED; ANALYSIS_ONLY (no fix found);
            FAILED_SAFELY (any failure: AI error, sandbox unavailable, denied/malformed storm, step budget);
            CANCELLED
```
`approvals/state.py` encodes the legal transitions; illegal ones raise (tested: you cannot reach APPLIED or DEPLOYED without the intermediate states).

## Why the security gate is bound to the patch hash

Scan rows store the SHA-256 of the patch they ran against. The gate only counts rows whose hash equals the current patch and phase. Re-patching therefore invalidates all earlier results; approving requires the reviewer's displayed hash to equal the stored hash; the applier re-verifies the hash before applying. A different patch can't ride in on an old approval or old scan results.

## AI provider abstraction

`AIProvider.next_action(messages, tools) -> ModelAction` returns either a tool call or a final message. Providers speak a *JSON-action protocol* over plain chat completion rather than vendor function-calling APIs. That keeps one code path for OpenAI-compatible servers (OpenAI, vLLM, Ollama, gateways) and Gemini, and makes the structured-output rule ("one JSON object, concise reason, no chain of thought") identical for all. Configure via `AI_PROVIDER`, `AI_API_KEY`, `AI_BASE_URL`, `AI_MODEL`.

## Data stores

SQLite by default; the schema and code are PostgreSQL-compatible (JSON columns, no SQLite-specific SQL; the audit triggers have a PostgreSQL variant and an advisory lock serialises the hash chain). The PostgreSQL path has **not** been run in this build.
