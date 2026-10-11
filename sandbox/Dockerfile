# Image in which every agent-triggered command runs. Tools are baked in so that no network is needed at run time.
FROM aquasec/trivy:0.58.1 AS trivy
FROM zricethezav/gitleaks:v8.21.2 AS gitleaks

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends git nodejs npm ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN pip install pytest==9.1.1 ruff==0.16.10 mypy==2.4.0 bandit==1.9.4
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks

# --- Trivy -------------------------------------------------------------------------------------------------------
# The real binary lives OFF the PATH. `trivy` on the PATH is a small wrapper (sandbox/scripts/trivy-wrapper.sh) that
# seeds a private writable copy of the baked DB into the /tmp tmpfs and then execs the real binary. Reason: the sandbox
# runs with `--read-only` and Trivy 0.58.x opens its BoltDB database read-write.
COPY --from=trivy /usr/local/bin/trivy /opt/trivy/bin/trivy

# Bake the vulnerability DB at build time (fails the build if it cannot be fetched: never ship a scanner with no DB).
# It goes to an immutable, root-owned path that the unprivileged sandbox user can read but never write.
RUN TRIVY_CACHE_DIR=/opt/trivy-db /opt/trivy/bin/trivy image --download-db-only --quiet \
    && chown -R root:root /opt/trivy-db /opt/trivy \
    && chmod -R a=rX /opt/trivy-db /opt/trivy

# The runtime copy lives in the /tmp tmpfs (SANDBOX_TRIVY_TMPFS). Fail the BUILD, not a scan, if the DB cannot fit.
ARG TRIVY_TMPFS_MB=1200
RUN set -eu; \
    test -s /opt/trivy-db/db/trivy.db && test -s /opt/trivy-db/db/metadata.json; \
    db_mb=$(du -sm --apparent-size /opt/trivy-db/db | cut -f1); \
    echo "baked Trivy DB: ${db_mb} MB (runtime tmpfs budget: ${TRIVY_TMPFS_MB} MB)"; \
    if [ "$((db_mb + 128))" -gt "${TRIVY_TMPFS_MB}" ]; then \
        echo "ERROR: Trivy DB (${db_mb} MB) plus headroom does not fit ${TRIVY_TMPFS_MB} MB. Raise this ARG and SANDBOX_TRIVY_TMPFS (and SANDBOX_TRIVY_MEMORY)." >&2; \
        exit 1; \
    fi

COPY scripts/trivy-wrapper.sh /usr/local/bin/trivy
RUN chown root:root /usr/local/bin/trivy && chmod 0755 /usr/local/bin/trivy

# Unprivileged user, matches `docker run --user 10001:10001`.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin sandbox
USER 10001:10001
WORKDIR /workspace
