# Deployment and GitHub configuration

## Local (Docker Compose)

```bash
cp .env.example .env
#  set JWT_SECRET, DEMO_PASSWORD, and WORKSPACE_HOST_DIR (absolute path, e.g. $PWD/.workspaces)
mkdir -p .workspaces
docker compose up --build
```

Windows (PowerShell, Docker Desktop), from the project folder:

```powershell
cd E:\AESA
Copy-Item .env.example .env          # then edit .env: JWT_SECRET, DEMO_PASSWORD, WORKSPACE_HOST_DIR=E:/AESA/.workspaces
New-Item -ItemType Directory -Force .workspaces | Out-Null
docker compose config                # validates the file; the first line shows: name: aesa
docker compose up --build
```
Use forward slashes in `WORKSPACE_HOST_DIR` on Windows. Keep shell scripts as LF (`.gitattributes` enforces this for Git checkouts).

| Service | URL |
|---|---|
| Frontend | http://localhost:5173 |
| Backend | http://localhost:8000 |
| API docs | http://localhost:8000/docs |

Compose (project name `aesa`) builds the sandbox image (`aesa-sandbox:latest`) *before* the backend starts
(`depends_on: service_completed_successfully`), starts a restricted Docker socket proxy, runs
`alembic upgrade head`, seeds demo users/repo (`SEED_DEMO=true`), and serves the API. Sign in as `developer`
(creates tasks), `approver` (decides), `admin`, or `viewer` with `DEMO_PASSWORD`.

How the sandbox is launched: the backend container has the Docker **CLI** only and talks to
`tcp://docker-proxy:2375`; the raw `/var/run/docker.sock` is mounted only into the proxy, read-only, with
only container/image endpoints enabled. Workspaces live in `WORKSPACE_HOST_DIR`, which is bind-mounted into the
backend *and* is the source for each sandbox container's single `/workspace` mount, so `WORKSPACE_HOST_DIR` must
be an absolute host path.

The sandbox image tag is defined once in `docker-compose.yml` (a YAML anchor) and used both as the image Compose builds and
as the backend's `SANDBOX_IMAGE`, so they cannot differ. The backend runs sandbox containers with `docker run --pull never`:
if the image is ever missing, the run fails closed (the scan becomes an `ERROR` and blocks approval) instead of the daemon
trying to download an image of that name from a registry.

Verify the image's isolation after building: `sandbox/scripts/smoke.sh`.

## Upgrading from SecureAI-Agent (the rename to AESA)

What changed, and what deliberately did not:

| Item | Before | Now |
|---|---|---|
| Compose project | folder name, e.g. `secureai-agent` | `aesa` (`name:` in `docker-compose.yml`) |
| Sandbox image | `secureai-sandbox:latest` | `aesa-sandbox:latest` (rebuild required) |
| Data volume | `secureai-agent_backend-data` | `aesa_backend-data`, **or keep the old one** via `BACKEND_DATA_VOLUME` |
| SQLite file inside the volume | `secureai.db` | **unchanged** (renaming it would orphan the data) |
| Audit-log `agent` value for new entries | `SecureAI` | `AESA`. Existing rows are append-only and keep `SecureAI` |
| Git author/trailers on new commits | `SecureAI Agent` | `AESA`. Existing commits are immutable history |

**Keep your existing data (recommended if you have tasks, approvals, or audit history you care about).** Compose names a
project's volumes after the project, so after the rename a plain `docker compose up` would create a new, empty
`aesa_backend-data` and your old data would stay behind, intact but unused. Find the old volume and point Compose at it:

```powershell
docker volume ls --filter name=backend-data      # expect: secureai-agent_backend-data
# add to .env:   BACKEND_DATA_VOLUME=secureai-agent_backend-data
docker compose up --build
```
Compose may print a warning that the volume "was not created by Docker Compose" for this project. That is expected when
reusing a volume across a project rename.

**Or move the data into the new volume** (copy, never move; the old volume is left untouched). Run this *before* the first
`docker compose up` with the new name, and only if `aesa_backend-data` does not exist or is empty. It reuses the backend
image's non-root user and drops all capabilities; it has not been run in the environment this was written in:

```powershell
docker compose build backend
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --user 10002 `
  -v secureai-agent_backend-data:/from:ro -v aesa_backend-data:/data --entrypoint sh aesa-backend `
  -c "cp -a /from/. /data/"
```

Old artifacts are not removed automatically. After you have confirmed everything works you may delete them yourself:
`docker image rm secureai-sandbox:latest` and the old containers/networks under the previous project name.


## Trivy inside the read-only sandbox

The sandbox runs with `--read-only`, `--network none`, `--cap-drop ALL`, `no-new-privileges`, UID 10001 and a `/tmp` tmpfs.
Trivy 0.58.x opens its BoltDB vulnerability database **read-write**, so a DB that lives in the image cannot be used
in place (`failed to open db: ... read-only file system`). The image therefore:

1. bakes the DB at build time into `/opt/trivy-db` (root-owned, no write bit for anyone; a failed download fails the build);
2. keeps the real binary at `/opt/trivy/bin/trivy` (not on `PATH`) and puts `sandbox/scripts/trivy-wrapper.sh` on `PATH` as `trivy`;
3. at run time the wrapper copies the DB into `/tmp/trivy-cache` (private, mode 0600, per container, gone with the container),
   sets `TRIVY_CACHE_DIR`, and `exec`s the real binary with the registry's arguments untouched. No network is used:
   the scan runs with `--skip-db-update --offline-scan`, and `trivy_fs` is `--network none` even if an egress network is configured
   (unless you explicitly set `TRIVY_SKIP_DB_UPDATE=false`).

**Sizing matters.** The DB copy lives in tmpfs, and tmpfs pages are charged to the container's memory limit. The default
256 MB tmpfs is too small for the Trivy DB, so *only* `trivy_fs` gets a larger profile: `SANDBOX_TRIVY_TMPFS` (default `1200m`)
and `SANDBOX_TRIVY_MEMORY` (default `2g`). Every other command keeps `SANDBOX_TMPFS_SIZE=256m` / `SANDBOX_MEMORY=1g`.
The image build prints the DB size and **fails** if `DB + 128 MB > TRIVY_TMPFS_MB`, so a too-small budget is a build error, not a
runtime surprise; the wrapper also refuses to run (exit 78, scan `ERROR`, approval blocked) if the copy cannot fit.
If you raise the runtime values, raise the build arg to match (`TRIVY_TMPFS_MB`, wired through `docker-compose.yml`).

Verify on a machine with Docker: `sandbox/scripts/verify-trivy.sh` (builds the image, prints the exact `docker run` command the
backend will use, and runs the integration tests in `backend/tests/test_docker_sandbox_integration.py` through the production
code path).

Alternative: newer Trivy releases (0.70 and 0.75 were checked) open the DB read-only, which would remove the copy and the extra
memory entirely. Bumping the pinned `aquasec/trivy` tag is a scanner-version decision, so it is left to you; the wrapper works
with either.

## Troubleshooting the security gate

**mypy: `error: INTERNAL ERROR ... please use --show-traceback`.** Mypy writes a cache to `./.mypy_cache` in the working
directory. The backend clones each workspace as its own user, but sandbox commands run as UID 10001, so the directory is not
writable for the sandbox user and mypy crashes with `PermissionError: [Errno 13] Permission denied: '.mypy_cache'` before it
reads any code. The registry now runs mypy with `--cache-dir=/dev/null` (nothing is written anywhere, nothing persists between
runs) and `--show-traceback` (a real crash reports its cause). The scan stays an `ERROR` that blocks approval if mypy fails for
any reason. The fix is in the **backend** (it builds the command line), so apply it with `docker compose up --build backend`;
the sandbox image does not need rebuilding.

**Finding the exact lint/type/security findings the gate recorded.** Every scan stores its normalised findings (rule, file,
line, message; up to 100 per tool). In the dashboard open *Proposed changes*, then the request, then click a scan row. Or:

```bash
curl -s localhost:8000/api/security/scans/<task_id> -H "authorization: Bearer $TOKEN" \
  | jq -r '.scans[] | select(.tool=="ruff") | .findings[] | "\(.file):\(.line) \(.rule) \(.message)"'
```

**Ruff results depend on where Ruff is launched.** The gate runs Ruff with the *scanned repository* as its root. Import-order
(`I001`) results depend on whether a package like `app` is first-party, which Ruff infers from the launch directory unless the
project pins it (`[tool.ruff] src = ["."]`, as the demo repository now does). Shebang lines on files without the executable bit
(`EXE001`) depend on file modes, which do not survive zips or Git on Windows, so the project's scripts have no shebangs.

**Known limitation (not changed):** the workspace is not writable by the sandbox user, so a target repository whose tests write
files into the working directory will fail with `PermissionError`. Granting write access would change workspace isolation, so it
is left as a deliberate decision for you.

## Without Docker (development only)
```bash
cd backend && python -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
export JWT_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))")
export SANDBOX_BACKEND=local SEED_DEMO=true DEMO_PASSWORD='change-me-please-123' \
       DEMO_REPO_SOURCE=../demo-repository DEMO_REPO_DEST=./data/repos/demo-repo REPOS_ROOT=./data/repos
alembic upgrade head && python -m app.seed && uvicorn app.main:app --reload
# second shell
cd frontend && npm ci && npm run dev
```
`SANDBOX_BACKEND=local` runs scanners as ordinary subprocesses with a scrubbed environment, timeouts and rlimits.
It provides **no** filesystem or network isolation. Never use it with untrusted repositories. Install `gitleaks`,
`trivy`, `ruff`, `mypy`, `bandit` on PATH, or set `REQUIRED_SCANS` to the tools you have (a missing required tool
blocks approval by design).

## Tests
```bash
cd backend && PATH=$PATH:/path/to/gitleaks pytest -q      # 231 tests (+5 Docker-only, skipped without Docker; ~100 s)
cd frontend && npm test && npm run build
alembic upgrade head && alembic check                    # migrations match the models
```

## GitHub setup

1. **Credentials.** Prefer a GitHub App; otherwise a fine-grained PAT restricted to the target repo with only:
   *Contents: read & write* (push proposal branches), *Pull requests: read & write*, *Actions: read*
   (+ *Actions: write* only if `DEPLOY_TARGET=github-workflow`). **Never** grant Administration. Put it in `GITHUB_TOKEN`.
2. **Register the repository** (admin) with `github_repo: "owner/name"` so approved branches are pushed there and a PR is opened.
   Without `github_repo`/`GITHUB_TOKEN` the system pushes the proposal branch to the local repository and runs local CI.
3. **Branch protection on `main`** (this is what stops even a leaked token):
   require a pull request, require ≥1 approving review and Code Owner review (`.github/CODEOWNERS`),
   require status checks from `ci.yml` (`backend-lint`, `backend-types`, `backend-tests`, `frontend`, `security`),
   require branches to be up to date, **disallow force pushes and deletions**, include administrators.
4. **Environment `production`:** Settings → Environments → add **required reviewers**. The `deploy` job in `ci.yml`
   then waits for a person, which is the pipeline's "Deployment approval" stage.
5. **Webhook** (for agent-branch CI results): payload URL `https://<host>/api/ci/webhook`, content type `application/json`,
   secret = `GITHUB_WEBHOOK_SECRET`, event *Workflow runs*. Alternatively use the dashboard's "Refresh from GitHub".
6. Replace the placeholder deploy step in `ci.yml` and the `@your-org/security-reviewers` team in `CODEOWNERS`.

## Production hardening checklist
- Terminate TLS in front of the API; set `APP_ENV=production` (requires `JWT_SECRET`); restrict `CORS_ORIGINS`.
- Use PostgreSQL; revoke UPDATE/DELETE on `audit_logs` from the app role; ship the audit stream and the latest hash externally.
- Run the sandbox on a dedicated host with rootless Docker, gVisor, or Kata; keep `--network none`; if npm/Trivy need network, create a dedicated egress network with an allowlisting proxy and set `SANDBOX_EGRESS_NETWORK`.
- Pin base images by digest; enable Dependabot; keep Trivy DB fresh in the sandbox image build.
- Add API rate limiting and per-user task quotas at the proxy; move the login limiter to a shared store.
- Store secrets in a secrets manager rather than `.env`.
