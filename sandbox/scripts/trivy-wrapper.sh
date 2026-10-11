#!/bin/sh
# Installed in the sandbox image as /usr/local/bin/trivy. The real binary lives at /opt/trivy/bin/trivy.
#
# Why this exists: the sandbox root filesystem is read-only (`docker run --read-only`) and Trivy 0.58.x opens its
# BoltDB vulnerability database read-WRITE, so it cannot use a DB stored in the image ("failed to open db: ...
# read-only file system"). This wrapper keeps the baked DB immutable in /opt/trivy-db and gives Trivy a private,
# per-container, writable COPY inside the /tmp tmpfs, then executes the real binary. It adds no capabilities,
# touches no network, and passes the arguments through untouched (the backend's command registry already
# decided them; the model never supplies a command line).
#
# Fails CLOSED: if the baked DB is missing or the copy cannot fit, it exits non-zero WITHOUT running Trivy, which the
# backend records as a scan ERROR (and an ERROR blocks approval).
set -eu

BAKED_DB="${AESA_TRIVY_BAKED_DB:-/opt/trivy-db}"
REAL_TRIVY="${AESA_TRIVY_BIN:-/opt/trivy/bin/trivy}"
CACHE_ROOT="${AESA_TRIVY_CACHE_ROOT:-/tmp}"
CACHE_DIR="$CACHE_ROOT/trivy-cache"
HEADROOM_KB=65536   # Trivy also writes small scan-cache files next to the DB

die() { echo "aesa-trivy: $*" >&2; exit 78; }

[ -x "$REAL_TRIVY" ] || die "real trivy binary not found at $REAL_TRIVY"
[ -s "$BAKED_DB/db/trivy.db" ] || die "baked vulnerability DB missing ($BAKED_DB/db/trivy.db); refusing to scan"
[ -s "$BAKED_DB/db/metadata.json" ] || die "baked DB metadata missing ($BAKED_DB/db/metadata.json); refusing to scan"

if [ ! -f "$CACHE_DIR/.seeded" ]; then
    need_kb=$(du -sk --apparent-size "$BAKED_DB/db" | cut -f1)
    free_kb=$(df -Pk "$CACHE_ROOT" | awk 'NR==2 {print $4}')
    if [ "$free_kb" -lt "$((need_kb + HEADROOM_KB))" ]; then
        die "not enough space in $CACHE_ROOT for the vulnerability DB (need ~$((need_kb / 1024)) MB + headroom, have $((free_kb / 1024)) MB); raise SANDBOX_TRIVY_TMPFS"
    fi
    umask 077
    mkdir -p "$CACHE_DIR/db"
    # copy then rename so a killed container can never leave a half-written DB that looks valid
    cp "$BAKED_DB/db/trivy.db" "$CACHE_DIR/db/trivy.db.partial" && mv "$CACHE_DIR/db/trivy.db.partial" "$CACHE_DIR/db/trivy.db"
    cp "$BAKED_DB/db/metadata.json" "$CACHE_DIR/db/metadata.json"
    # The baked files are read-only (0444) and cp carries those bits over; Trivy 0.58 needs to open its copy read-write.
    chmod 0600 "$CACHE_DIR/db/trivy.db" "$CACHE_DIR/db/metadata.json"
    : > "$CACHE_DIR/.seeded"
fi

export TRIVY_CACHE_DIR="$CACHE_DIR"
exec "$REAL_TRIVY" "$@"
