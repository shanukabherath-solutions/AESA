#!/bin/sh
# Verify the sandbox image really is locked down. Usage: sandbox/scripts/smoke.sh [image]
set -eu
IMG="${1:-aesa-sandbox:latest}"
RUN="docker run --rm --user 10001:10001 --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,size=1200m $IMG"
echo "uid:      $($RUN id -u)"                                       # expect 10001
echo "network:  $($RUN python -c 'import socket;socket.create_connection((\"1.1.1.1\",53),2)' 2>&1 | tail -1)"   # expect failure
echo "rootfs:   $($RUN sh -c 'touch /etc/x' 2>&1 | tail -1)"        # expect read-only
echo "docker:   $($RUN sh -c 'ls /var/run/docker.sock' 2>&1 | tail -1)"  # expect not found
echo "tools:    $($RUN sh -c 'ruff --version; bandit --version | head -1; gitleaks version; trivy --version | head -1')"
