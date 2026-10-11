"""Trivy resource profile / network policy in the command registry and the `docker run` argument builder."""
import pytest
from pydantic import ValidationError

from app.config import Settings
from app.sandbox.commands import CommandRegistry
from app.sandbox.runner import DockerSandbox


def sb(settings, monkeypatch, **upd):
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/bin/docker")
    return DockerSandbox(settings.model_copy(update=upd))


def flag(args, name):
    return args[args.index(name) + 1]


def test_trivy_plan_is_offline_against_baked_db(settings):
    p = CommandRegistry(settings).plan("trivy_fs", {})
    assert p.argv[:3] == ("trivy", "fs", "--quiet") and "json" in p.argv
    assert "--skip-db-update" in p.argv and "--offline-scan" in p.argv
    assert p.network is False and not p.host
    assert (p.tmpfs_size, p.memory) == ("1200m", "2g")


def test_trivy_gets_network_only_if_db_updates_are_explicitly_enabled(settings):
    p = CommandRegistry(settings.model_copy(update={"trivy_skip_db_update": False})).plan("trivy_fs", {})
    assert p.network is True and "--skip-db-update" not in p.argv


def test_other_commands_keep_default_limits(settings):
    reg = CommandRegistry(settings)
    for key in ("pytest", "ruff_check", "mypy", "bandit", "gitleaks", "npm_audit"):
        p = reg.plan(key, {})
        assert (p.tmpfs_size, p.memory) == (None, None), key


def test_default_command_args_are_unchanged(settings, monkeypatch, tmp_path):
    args = sb(settings, monkeypatch).build_args(CommandRegistry(settings).plan("pytest", {}), tmp_path, "c")
    assert flag(args, "--tmpfs") == "/tmp:rw,nosuid,size=256m"
    assert flag(args, "--memory") == flag(args, "--memory-swap") == "1g"


def test_trivy_args_keep_every_restriction_and_only_resize_tmpfs_and_memory(settings, monkeypatch, tmp_path):
    s = sb(settings, monkeypatch, sandbox_egress_network="egress-net")  # even with an egress network configured...
    args = s.build_args(CommandRegistry(settings).plan("trivy_fs", {}), tmp_path, "c")
    j = " ".join(args)
    assert flag(args, "--network") == "none"  # ...the offline Trivy scan stays isolated
    assert flag(args, "--tmpfs") == "/tmp:rw,nosuid,size=1200m"
    assert flag(args, "--memory") == flag(args, "--memory-swap") == "2g"
    for must in ("--read-only", "--cap-drop ALL", "no-new-privileges", "--user 10001:10001", "--pids-limit", "--cpus", "nofile=1024", "--rm"):
        assert must in j, must
    for never in ("--privileged", "docker.sock", "--network host", "--cap-add", "--user root", "--user 0"):
        assert never not in j, never
    # the tmpfs option set is exactly rw + nosuid + size: never exec or suid
    assert set(flag(args, "--tmpfs").split(":", 1)[1].split(",")) == {"rw", "nosuid", "size=1200m"}
    assert j.count("--mount") == 1 and "dst=/workspace" in j  # still the only bind mount


def test_trivy_with_updates_enabled_may_use_the_configured_egress_network(settings, monkeypatch, tmp_path):
    s = settings.model_copy(update={"trivy_skip_db_update": False, "sandbox_egress_network": "egress-net"})
    args = sb(s, monkeypatch, trivy_skip_db_update=False, sandbox_egress_network="egress-net").build_args(
        CommandRegistry(s).plan("trivy_fs", {}), tmp_path, "c")
    assert flag(args, "--network") == "egress-net"


@pytest.mark.parametrize("field", ["sandbox_memory", "sandbox_tmpfs_size", "sandbox_trivy_tmpfs", "sandbox_trivy_memory"])
@pytest.mark.parametrize("bad", ["1g,exec", "256m --privileged", "0m", "-1g", "1.5g", "1t", "", "abc", "2g;ls"])
def test_resource_settings_cannot_inject_docker_options(field, bad):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: bad})


def test_resource_settings_accept_sane_values():
    s = Settings(_env_file=None, sandbox_trivy_tmpfs="1500m", sandbox_trivy_memory="3g")
    assert (s.sandbox_trivy_tmpfs, s.sandbox_trivy_memory) == ("1500m", "3g")
