"""sandbox/scripts/trivy-wrapper.sh: seeds a private writable copy of the baked DB into the /tmp tmpfs, then execs Trivy.

Runs the REAL script with a fake `trivy`. It needs `sh`, GNU `du --apparent-size`, `df`, `awk` (all present in the sandbox image)."""
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "sandbox" / "scripts" / "trivy-wrapper.sh"
DOCKERFILE = ROOT / "sandbox" / "Dockerfile"

pytestmark = pytest.mark.skipif(
    subprocess.run(["du", "--apparent-size", "-sk", "."], capture_output=True).returncode != 0,
    reason="needs GNU coreutils (du --apparent-size)",
)

FAKE_ECHO = """#!/bin/sh
printf '%s\\n' "$@" > "$MARKER_DIR/args.txt"
echo "$TRIVY_CACHE_DIR" > "$MARKER_DIR/cache_dir.txt"
exit "${FAKE_EXIT:-0}"
"""
FAKE_RW_OPEN = f"""#!{sys.executable}
import os, sys   # stands in for Trivy 0.58.x, which opens its BoltDB read-write
p = os.path.join(os.environ["TRIVY_CACHE_DIR"], "db", "trivy.db")
open(p, "r+b").close()
open(os.path.join(os.environ["MARKER_DIR"], "rw_open_ok"), "w").close()
"""


@pytest.fixture
def env(tmp_path):
    baked = tmp_path / "baked"
    (baked / "db").mkdir(parents=True)
    (baked / "db" / "trivy.db").write_bytes(b"BOLT" * 4096)
    (baked / "db" / "metadata.json").write_text('{"Version":2}')
    for f in (baked / "db").iterdir():
        f.chmod(0o444)  # like the image: root-owned, read-only
    (baked / "db").chmod(0o555)
    fake = tmp_path / "fake-trivy"
    fake.write_text(FAKE_ECHO)
    fake.chmod(0o755)
    cache_root, markers = tmp_path / "tmp", tmp_path / "markers"
    cache_root.mkdir()
    markers.mkdir()
    yield {"tmp": tmp_path, "baked": baked, "fake": fake, "cache_root": cache_root, "markers": markers}
    (baked / "db").chmod(0o755)  # let pytest clean up


def run(e, *args, extra_env=None, bin_path=None):
    environ = {
        "PATH": os.environ["PATH"], "AESA_TRIVY_BAKED_DB": str(e["baked"]), "AESA_TRIVY_BIN": str(bin_path or e["fake"]),
        "AESA_TRIVY_CACHE_ROOT": str(e["cache_root"]), "MARKER_DIR": str(e["markers"]),
    }
    environ.update(extra_env or {})
    return subprocess.run(["sh", str(WRAPPER), *args], env=environ, capture_output=True, text=True, timeout=60)


def test_script_is_valid_posix_sh():
    assert subprocess.run(["sh", "-n", str(WRAPPER)]).returncode == 0
    assert WRAPPER.stat().st_mode & stat.S_IXUSR


def test_seeds_private_copy_and_runs_real_binary_with_untouched_args(env):
    weird = ["fs", "--quiet", "--format", "json", "path with spaces", "a;b", "$(id)", "`id`", "--", "-x"]
    r = run(env, *weird)
    assert r.returncode == 0, r.stderr
    cache = env["cache_root"] / "trivy-cache"
    assert (env["markers"] / "cache_dir.txt").read_text().strip() == str(cache)  # TRIVY_CACHE_DIR points at the tmpfs copy
    assert (cache / "db" / "trivy.db").read_bytes() == (env["baked"] / "db" / "trivy.db").read_bytes()
    assert (cache / "db" / "metadata.json").read_text() == '{"Version":2}'
    assert (env["markers"] / "args.txt").read_text().splitlines() == weird  # byte-for-byte, nothing interpreted


def test_copy_is_writable_even_though_baked_db_is_read_only(env):
    """Regression: cp carries the baked 0444 bits over; Trivy 0.58 opens the DB read-write and would still fail."""
    run(env, "fs")
    for name in ("trivy.db", "metadata.json"):
        mode = stat.S_IMODE((env["cache_root"] / "trivy-cache" / "db" / name).stat().st_mode)
        assert mode & 0o200, f"{name} copy is not owner-writable (mode {oct(mode)})"
        assert not mode & 0o077, "the cache copy must be private"


def test_read_write_opening_trivy_works_and_baked_db_stays_byte_identical(env):
    rw = env["tmp"] / "rw-trivy"
    rw.write_text(FAKE_RW_OPEN)
    rw.chmod(0o755)
    before = (env["baked"] / "db" / "trivy.db").read_bytes()
    r = run(env, "fs", bin_path=rw)
    assert r.returncode == 0, r.stderr
    assert (env["markers"] / "rw_open_ok").exists()
    assert (env["baked"] / "db" / "trivy.db").read_bytes() == before
    assert stat.S_IMODE((env["baked"] / "db" / "trivy.db").stat().st_mode) == 0o444


def test_exit_code_is_propagated(env):
    assert run(env, "fs", extra_env={"FAKE_EXIT": "3"}).returncode == 3  # exec, not a subshell that swallows it


def test_second_invocation_does_not_recopy(env):
    run(env, "fs")
    marker = env["cache_root"] / "trivy-cache" / "db" / "trivy.db"
    marker.write_bytes(b"scan-modified")
    run(env, "fs")
    assert marker.read_bytes() == b"scan-modified"


@pytest.mark.parametrize("victim", ["db/trivy.db", "db/metadata.json"])
def test_fails_closed_when_baked_db_is_missing_or_empty(env, victim):
    (env["baked"] / "db").chmod(0o755)
    (env["baked"] / victim).write_bytes(b"")  # empty file == missing
    r = run(env, "fs")
    assert r.returncode == 78 and "refusing to scan" in r.stderr
    assert not (env["markers"] / "args.txt").exists(), "Trivy must NOT run without its DB"


def test_fails_closed_when_real_binary_is_missing(env):
    r = run(env, "fs", bin_path=env["tmp"] / "nope")
    assert r.returncode == 78 and "not found" in r.stderr


def test_fails_closed_with_clear_message_when_db_does_not_fit_the_tmpfs(env):
    (env["baked"] / "db").chmod(0o755)
    big = env["baked"] / "db" / "trivy.db"
    try:
        big.unlink()
        with open(big, "wb") as f:
            f.truncate(1 << 40)  # 1 TiB apparent size (sparse): far more than any free space
    except OSError:
        pytest.skip("filesystem refuses a 1 TiB sparse file")
    r = run(env, "fs")
    assert r.returncode == 78 and "not enough space" in r.stderr and "SANDBOX_TRIVY_TMPFS" in r.stderr
    assert not (env["markers"] / "args.txt").exists()
    assert not (env["cache_root"] / "trivy-cache" / "db" / "trivy.db").exists(), "no partial copy may be left behind"


# ------------------------------------------------------------------ static guards on the image definition
DF = DOCKERFILE.read_text()


def test_dockerfile_keeps_real_binary_off_path_and_wrapper_on_it():
    assert "/opt/trivy/bin/trivy" in DF
    assert re.search(r"COPY scripts/trivy-wrapper\.sh /usr/local/bin/trivy", DF)
    assert not re.search(r"COPY --from=trivy \S+ /usr/local/bin/trivy", DF), "the real binary must not shadow the wrapper"


def test_dockerfile_bakes_db_immutably_and_fails_closed():
    assert re.search(r"TRIVY_CACHE_DIR=/opt/trivy-db .*download-db-only", DF)
    dl = next(ln for ln in DF.splitlines() if "download-db-only" in ln)
    assert "||" not in dl and "|| true" not in DF and "|| echo" not in DF, "a failed DB download must fail the build"
    assert "/opt/trivy-cache" not in DF, "the old read-only cache location must be gone"
    assert "chmod -R a=rX /opt/trivy-db" in DF and "chown -R root:root /opt/trivy-db" in DF  # no write bit for anyone


def test_dockerfile_asserts_db_fits_runtime_tmpfs_at_build_time():
    assert "ARG TRIVY_TMPFS_MB" in DF and "exit 1" in DF and "du -sm" in DF


def test_dockerfile_still_runs_as_unprivileged_user_and_sets_no_secrets():
    last_user = [ln for ln in DF.splitlines() if ln.startswith("USER ")][-1]
    assert last_user == "USER 10001:10001"
    assert not re.search(r"(?i)(token|secret|password|api_key)\s*=", DF)


def test_wrapper_never_touches_network_or_privileges():
    body = re.sub(r"(?m)^\s*#.*$", "", WRAPPER.read_text())
    for banned in ("curl", "wget", "nc ", "sudo", "chmod 777", "docker", "--db-repository", "eval ", "$(cat"):
        assert banned not in body, banned
    assert json.dumps(body).count("exec ") == 1 and 'exec "$REAL_TRIVY" "$@"' in body
