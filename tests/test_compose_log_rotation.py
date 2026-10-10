"""Container output is rotated on every service of the shipped compose files.

Docker keeps each container's output (`docker logs`) without limit unless its logging is configured, which
fills the host's disk. Every service of deploy/docker-compose.yml and deploy/docker-compose.secure.yml keeps
it in json-file files, at most DOCKER_LOG_MAX_FILE of DOCKER_LOG_MAX_SIZE each (10m x 5 by default). The
rotation is in the compose files, not the image, so the setup matrix checks it rendered and applied, with this
release's image and with the previous one. dockvault.py writes the two values only when they differ from the
defaults, keeps them across a fresh volume set, refuses to recreate the stack with a value Docker would refuse,
and says where container output goes when the host's Docker sends it to another driver.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = ("deploy/docker-compose.yml", "deploy/docker-compose.secure.yml")
BLOCK = {"driver": "json-file",
         "options": {"max-size": "${DOCKER_LOG_MAX_SIZE:-10m}", "max-file": "${DOCKER_LOG_MAX_FILE:-5}"}}

_spec = importlib.util.spec_from_file_location("dockvault_logs_mod", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)


class _Proc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _services(rel):
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))["services"]


@pytest.mark.parametrize("rel", COMPOSE_FILES)
def test_every_service_of_a_shipped_compose_file_rotates_its_output(rel):
    services = _services(rel)
    assert len(services) >= 4, f"{rel} lost services"
    for name, service in services.items():
        assert service.get("logging") == BLOCK, f"{rel}: service {name} does not rotate its output"


def test_the_root_shims_only_include_the_deploy_files():
    # A root file that defined a service of its own would need the block too.
    for shim, target in (("docker-compose.yml", "deploy/docker-compose.yml"),
                         ("docker-compose.secure.yml", "deploy/docker-compose.secure.yml")):
        doc = yaml.safe_load((ROOT / shim).read_text(encoding="utf-8"))
        assert "services" not in doc, f"{shim} defines services of its own"
        assert doc["include"] == [target]


def _render(tmp_path, compose, **env):
    """docker compose config of a copy of the shipped files with an empty .env beside them, so nothing of the
    developer's own .env leaks in; every profile on."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    probe = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True, timeout=60)
    if probe.returncode != 0:
        pytest.skip("the docker compose plugin is not installed")
    (tmp_path / "deploy").mkdir()
    for rel in ("docker-compose.yml", "docker-compose.secure.yml") + COMPOSE_FILES:
        shutil.copy(ROOT / rel, tmp_path / rel)
    (tmp_path / ".env").write_text("", encoding="utf-8")
    run_env = {k: v for k, v in os.environ.items() if not k.startswith(("DOCKER_LOG_", "COMPOSE_"))}
    run_env.update(VAULT_DB_PASSWORD="renderonly", **env)
    r = subprocess.run(["docker", "compose", "-f", compose, "--profile", "combined", "--profile", "split",
                        "config", "--format", "json"], cwd=str(tmp_path), env=run_env, capture_output=True,
                       text=True, timeout=90)
    assert r.returncode == 0, r.stderr[:800]
    return json.loads(r.stdout)["services"]


@pytest.mark.docker
@pytest.mark.parametrize("compose, count", [("docker-compose.yml", 4), ("docker-compose.secure.yml", 5)])
@pytest.mark.parametrize("env, size, files", [({}, "10m", "5"),
                                              ({"DOCKER_LOG_MAX_SIZE": "50m", "DOCKER_LOG_MAX_FILE": "3"}, "50m", "3"),
                                              ({"DOCKER_LOG_MAX_SIZE": "", "DOCKER_LOG_MAX_FILE": ""}, "10m", "5")])
def test_compose_renders_the_rotation_on_every_service(tmp_path, compose, count, env, size, files):
    services = _render(tmp_path, compose, **env)
    assert len(services) == count
    for name, service in services.items():
        assert service.get("logging") == {"driver": "json-file", "options": {"max-size": size, "max-file": files}}, name


def _step(text, name, next_name):
    return text.split(f"- name: {name}", 1)[1].split(f"- name: {next_name}", 1)[0]


def test_the_setup_matrix_checks_the_rotation_rendered_and_applied():
    text = (ROOT / ".github" / "workflows" / "setup-matrix.yml").read_text(encoding="utf-8")
    a4 = _step(text, "Scenario A4 — container output is rotated", "Plant data to prove continuity against")
    assert "--profile combined --profile split config --format json" in a4
    assert '"max-size": "10m", "max-file": "5"' in a4 and "len(services) < 5" in a4
    assert "dc ps -q" in a4 and '*" json-file 10m 5")' in a4 and "exit 1" in a4
    # With the previous release's image: the rotation is in the compose files, so it applies to it too.
    i = _step(text, "Scenario I — install from the published release image",
              "Scenario I2 — an unpublished version falls back to a source build")
    assert "HostConfig.LogConfig.Type" in i and '*" json-file 10m 5") ;;' in i


def test_env_example_documents_both_values_at_the_compose_defaults():
    env = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"^# DOCKER_LOG_MAX_SIZE=10m$", env, re.M)
    assert re.search(r"^# DOCKER_LOG_MAX_FILE=5$", env, re.M)
    assert dict((k, d) for _c, k, d in dv.CONTAINER_LOG_ENV_KEYS) == {"DOCKER_LOG_MAX_SIZE": "10m",
                                                                       "DOCKER_LOG_MAX_FILE": "5"}


def test_the_documents_say_the_output_is_rotated_and_where_it_is_not():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Container logs", 1)[1].split("\n## ", 1)[0]
    for words in ("DOCKER_LOG_MAX_SIZE", "DOCKER_LOG_MAX_FILE", "updates only by pulling",
                  "logging: *logging", "daemon.json", "journald"):
        assert words in section, words
    inventory = (ROOT / "docs" / "data-inventory.md").read_text(encoding="utf-8")
    assert "set no limit" not in inventory
    assert "DOCKER_LOG_MAX_FILE" in inventory.split("## Logs", 1)[1].split("\n## ", 1)[0]


@pytest.mark.parametrize("size, ok", [("10m", True), ("50MB", True), ("1g", True), ("1.5g", True), ("512k", True),
                                      ("2 MiB", True), ("0.5k", True), ("100", True), ("", True), ("0", False), ("0m", False),
                                      ("0.5", False), ("-1", False), ("10x", False), ("ten", False), ("1.2.3m", False),
                                      ("10 m b", False)])
def test_a_log_size_docker_refuses_is_named(size, ok):
    problems = dv.container_log_problems({"DOCKER_LOG_MAX_SIZE": size})
    assert (problems == []) is ok, problems
    if not ok:
        assert problems == [f"DOCKER_LOG_MAX_SIZE={size} is not a size Docker reads (for example 10m, 50m, 1g)"]


@pytest.mark.parametrize("count, ok", [("5", True), ("1", True), ("+3", True), ("", True), ("0", False),
                                       ("-1", False), ("2.5", False), ("five", False)])
def test_a_log_file_count_docker_refuses_is_named(count, ok):
    problems = dv.container_log_problems({"DOCKER_LOG_MAX_FILE": count})
    assert (problems == []) is ok, problems


@pytest.mark.parametrize("values, named", [
    ({"DOCKER_LOG_MAX_SIZE": " 10m"}, 'DOCKER_LOG_MAX_SIZE=" 10m" is not a size'),
    ({"DOCKER_LOG_MAX_SIZE": "10m "}, 'DOCKER_LOG_MAX_SIZE="10m " is not a size'),
    ({"DOCKER_LOG_MAX_SIZE": "10m\n"}, 'DOCKER_LOG_MAX_SIZE="10m\\n" is not a size'),
    ({"DOCKER_LOG_MAX_FILE": " 5"}, 'DOCKER_LOG_MAX_FILE=" 5" is not a whole number'),
    ({"DOCKER_LOG_MAX_FILE": "5\n"}, 'DOCKER_LOG_MAX_FILE="5\\n" is not a whole number'),
    ({"DOCKER_LOG_MAX_SIZE": None}, "DOCKER_LOG_MAX_SIZE has a quote that is never closed"),
    ({"DOCKER_LOG_MAX_FILE": None}, "DOCKER_LOG_MAX_FILE has a quote that is never closed"),
])
def test_a_space_around_a_value_or_a_quote_never_closed_is_named(values, named):
    """Docker starts no container whose log size or file count has a space before or after it, and compose keeps
    the spaces of a quoted value: such a value is named, and so is a quote never closed (compose refuses .env)."""
    (problem,) = dv.container_log_problems(values)
    assert problem.startswith(named), problem


# .env lines, the process environment, and what docker compose gives the compose files (checked against docker
# compose 2.40 by test_compose_reads_env_as_compose_env_values_says): (size, file count), None for a quote never
# closed, absent when .env does not set it.
ABSENT = "absent"
COMPOSE_READS = [
    ("DOCKER_LOG_MAX_SIZE=10m # comment", {}, ("10m", ABSENT)),
    ("DOCKER_LOG_MAX_SIZE=10m#x", {}, ("10m#x", ABSENT)),
    ("DOCKER_LOG_MAX_SIZE=10m\t# tab comment", {}, ("10m\t# tab comment", ABSENT)),
    ('DOCKER_LOG_MAX_SIZE="10m" # comment', {}, ("10m", ABSENT)),
    ("DOCKER_LOG_MAX_SIZE='10m' # comment", {}, ("10m", ABSENT)),
    ('DOCKER_LOG_MAX_SIZE=" 10m"', {}, (" 10m", ABSENT)),
    ('DOCKER_LOG_MAX_SIZE="10m "', {}, ("10m ", ABSENT)),
    ("DOCKER_LOG_MAX_SIZE=' 10m'", {}, (" 10m", ABSENT)),
    ("DOCKER_LOG_MAX_SIZE= 10m", {}, ("10m", ABSENT)),
    ("DOCKER_LOG_MAX_SIZE=10m   ", {}, ("10m", ABSENT)),
    ("DOCKER_LOG_MAX_SIZE=\t10m\t", {}, ("10m", ABSENT)),
    ("  DOCKER_LOG_MAX_SIZE = 10m", {}, ("10m", ABSENT)),
    ("export DOCKER_LOG_MAX_SIZE=7m", {}, ("7m", ABSENT)),
    ("DOCKER_LOG_MAX_SIZE=10m\nDOCKER_LOG_MAX_SIZE=20m", {}, ("20m", ABSENT)),
    ('DOCKER_LOG_MAX_SIZE="1\\"0m"', {}, ('1"0m', ABSENT)),
    ('DOCKER_LOG_MAX_SIZE="10\\nm"', {}, ("10\nm", ABSENT)),
    ("DOCKER_LOG_MAX_SIZE='10\\nm'", {}, ("10\\nm", ABSENT)),
    ('DOCKER_LOG_MAX_SIZE="a\\qb"', {}, ("a\\qb", ABSENT)),
    ('DOCKER_LOG_MAX_SIZE=10m "x"', {}, ('10m "x"', ABSENT)),
    ('DOCKER_LOG_MAX_SIZE="10m', {}, (None, ABSENT)),
    ("DOCKER_LOG_MAX_SIZE=${OTHER:-30m}", {}, ("30m", ABSENT)),
    ("OTHER=\nDOCKER_LOG_MAX_SIZE=${OTHER-8m}", {}, ("", ABSENT)),
    ("OTHER=\nDOCKER_LOG_MAX_SIZE=${OTHER:-8m}", {}, ("8m", ABSENT)),
    ("OTHER=40m\nDOCKER_LOG_MAX_SIZE=${OTHER}", {}, ("40m", ABSENT)),
    ("DOCKER_LOG_MAX_SIZE=$OTHER", {}, ("", ABSENT)),
    ("DOCKER_LOG_MAX_SIZE=${DOCKER_LOG_MAX_FILE}m\nDOCKER_LOG_MAX_FILE=3", {}, ("m", "3")),
    ("DOCKER_LOG_MAX_FILE=3\nDOCKER_LOG_MAX_SIZE=${DOCKER_LOG_MAX_FILE}m", {}, ("3m", "3")),
    ("DOCKER_LOG_MAX_SIZE='$OTHER'", {}, ("$OTHER", ABSENT)),
    ('DOCKER_LOG_MAX_SIZE="\\$x"', {}, ("$x", ABSENT)),
    ("DOCKER_LOG_MAX_SIZE=44m", {"DOCKER_LOG_MAX_SIZE": "33m"}, ("33m", ABSENT)),
    ("DOCKER_LOG_MAX_SIZE=${LOGSIZE}", {"LOGSIZE": "55m"}, ("55m", ABSENT)),
    ('DOCKER_LOG_MAX_FILE=" 5"', {}, (ABSENT, " 5")),
    ("DOCKER_LOG_MAX_FILE=5 # five", {}, (ABSENT, "5")),
    ("# DOCKER_LOG_MAX_SIZE=50m", {}, (ABSENT, ABSENT)),
]
_NAMES = ("DOCKER_LOG_MAX_SIZE", "DOCKER_LOG_MAX_FILE")


@pytest.mark.parametrize("text, environ, expected", COMPOSE_READS)
def test_the_values_are_read_as_docker_compose_reads_them(text, environ, expected):
    values = dv.compose_env_values(text + "\n", _NAMES, environ)
    assert tuple(values.get(name, ABSENT) for name in _NAMES) == expected


@pytest.mark.docker
@pytest.mark.parametrize("text, environ, expected", COMPOSE_READS)
def test_compose_reads_env_as_compose_env_values_says(tmp_path, text, environ, expected):
    """The table above, against the docker compose installed here: what it renders into a compose file's logging
    options (an empty or missing value takes the default, as the shipped files' ${...:-default} does)."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    (tmp_path / "docker-compose.yml").write_text(
        'services:\n  a:\n    image: busybox\n    logging:\n      driver: json-file\n      options:\n'
        '        max-size: "${DOCKER_LOG_MAX_SIZE:-10m}"\n        max-file: "${DOCKER_LOG_MAX_FILE:-5}"\n',
        encoding="utf-8")
    (tmp_path / ".env").write_text(text + "\n", encoding="utf-8")
    run_env = {k: v for k, v in os.environ.items() if not k.startswith(("DOCKER_LOG_", "COMPOSE_"))}
    for name in ("OTHER", "LOGSIZE"):
        run_env.pop(name, None)
    run_env.update(environ)
    r = subprocess.run(["docker", "compose", "--env-file", str(tmp_path / ".env"), "-f",
                        str(tmp_path / "docker-compose.yml"), "config", "--format", "json"],
                       cwd=str(tmp_path), env=run_env, capture_output=True, text=True, timeout=90)
    if None in expected:
        assert r.returncode != 0 and "unterminated" in r.stderr, r.stderr
        return
    assert r.returncode == 0, r.stderr[:800]
    options = json.loads(r.stdout)["services"]["a"]["logging"]["options"]
    rendered = (options["max-size"].replace("$$", "$"), options["max-file"].replace("$$", "$"))
    values = dv.compose_env_values(text + "\n", _NAMES, environ)
    assert rendered == (values.get("DOCKER_LOG_MAX_SIZE") or "10m", values.get("DOCKER_LOG_MAX_FILE") or "5")


def test_the_check_before_a_recreate_reads_env_as_compose_does(tmp_path, monkeypatch, capsys):
    """A quoted space compose keeps is refused before anything is recreated; a value with a comment compose drops
    is not; and the process environment, which compose prefers, is the one checked."""
    for name in _NAMES:
        monkeypatch.delenv(name, raising=False)
    calls = []
    for text, ok in (('DOCKER_LOG_MAX_SIZE=" 10m"\n', False), ('DOCKER_LOG_MAX_FILE=" 5"\n', False),
                     ("DOCKER_LOG_MAX_SIZE=10m # rotate at ten megabytes\n", True),
                     ("DOCKER_LOG_MAX_FILE=5 # five files\n", True), ('DOCKER_LOG_MAX_SIZE="10m\n', False)):
        tool = _tool(tmp_path, "COMPOSE_PROFILES=combined\n" + text)
        monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: calls.append(a) or _Proc(0, ""))
        assert tool._recreate_stack(build=True) is ok, text
    assert "is not a size Docker reads" in capsys.readouterr().out
    tool = _tool(tmp_path, "COMPOSE_PROFILES=combined\nDOCKER_LOG_MAX_SIZE=20m\n")
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: calls.append(a) or _Proc(0, ""))
    monkeypatch.setenv("DOCKER_LOG_MAX_SIZE", "0m")
    assert tool._recreate_stack(build=True) is False
    assert "DOCKER_LOG_MAX_SIZE=0m is not a size" in capsys.readouterr().out


def _cfg(**extra):
    cfg = {"server_name": "localhost", "encryption_key": "k", "jwt_secret_key": "j", "vault_db_password": "p",
           "redis_password": "r", "admin_username": "admin", "admin_email": "a@example.com",
           "admin_password": "pw", "compose_profiles": "combined"}
    cfg.update(extra)
    return cfg


def test_dockvault_writes_the_values_only_when_they_differ_from_the_defaults():
    lines = dv.build_env_lines(_cfg(docker_log_max_size="10m", docker_log_max_file="5"))
    assert not [line for line in lines if line.startswith("DOCKER_LOG_")]
    lines = dv.build_env_lines(_cfg(docker_log_max_size="50m", docker_log_max_file="3"))
    assert "DOCKER_LOG_MAX_SIZE=50m" in lines and "DOCKER_LOG_MAX_FILE=3" in lines


def test_a_fresh_volume_set_keeps_the_values():
    cfg = dv.new_set_config({"DOCKER_LOG_MAX_SIZE": "50m", "DOCKER_LOG_MAX_FILE": "3",
                             "ENCRYPTION_KEY": "old"}, "dockvault-vault-x1", "x1")
    assert cfg["docker_log_max_size"] == "50m" and cfg["docker_log_max_file"] == "3"
    lines = dv.build_env_lines(cfg)
    assert "DOCKER_LOG_MAX_SIZE=50m" in lines and "DOCKER_LOG_MAX_FILE=3" in lines


def _tool(tmp_path, env_text):
    (tmp_path / ".env").write_text(env_text, encoding="utf-8")
    return dv.DockVault(dv.Palette(False), root=str(tmp_path))


def test_the_stack_is_not_recreated_with_a_value_docker_would_refuse(tmp_path, monkeypatch, capsys):
    tool = _tool(tmp_path, "COMPOSE_PROFILES=combined\nDOCKER_LOG_MAX_SIZE=0m\n")
    calls = []
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: calls.append(a) or _Proc(0, ""))
    assert tool._recreate_stack(build=True) is False
    assert tool._start_secure_stack() is False
    assert calls == []
    assert "DOCKER_LOG_MAX_SIZE=0m is not a size Docker reads" in capsys.readouterr().out
    (tmp_path / ".env").write_text("COMPOSE_PROFILES=combined\nDOCKER_LOG_MAX_SIZE=20m\n", encoding="utf-8")
    assert tool._recreate_stack(build=True) is True
    assert calls[-1] == ("up", "--build", "-d", "--force-recreate", "--remove-orphans")


def test_a_release_image_is_not_pulled_with_a_value_docker_would_refuse(tmp_path, monkeypatch):
    tool = _tool(tmp_path, "COMPOSE_PROFILES=combined\nDOCKVAULT_IMAGE=ghcr.io/dockvault/vault:v0.34.0\n"
                           "DOCKER_LOG_MAX_FILE=0\n")
    calls = []
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: calls.append(a) or _Proc(0, ""))
    assert tool._start_secure_stack() is False
    assert calls == []


def test_restart_takes_nothing_down_with_a_value_docker_would_refuse(tmp_path, monkeypatch):
    tool = _tool(tmp_path, "COMPOSE_PROFILES=combined\nDOCKER_LOG_MAX_FILE=0\n")
    taken = []
    monkeypatch.setattr(tool, "_tear_down_containers", lambda: taken.append(1))
    monkeypatch.setattr(tool, "start", lambda args=None: taken.append(2))
    with pytest.raises(SystemExit):
        tool.restart()
    assert taken == []


def test_update_stops_before_anything_with_a_value_docker_would_refuse(tmp_path, monkeypatch):
    tool = _tool(tmp_path, "COMPOSE_PROFILES=combined\nDOCKER_LOG_MAX_FILE=none\n")
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, "ok"))
    monkeypatch.setattr(tool, "_running_version", lambda profiles: pytest.fail("update went on"))
    with pytest.raises(SystemExit):
        tool.update()


def _with_compose(tmp_path, block=True):
    (tmp_path / "deploy").mkdir(exist_ok=True)
    text = (ROOT / "deploy" / "docker-compose.secure.yml").read_text(encoding="utf-8")
    if not block:
        text = "\n".join(line for line in text.splitlines() if line.strip() != "logging: *logging")
    (tmp_path / "deploy" / "docker-compose.secure.yml").write_text(text, encoding="utf-8")
    return str(tmp_path)


def _docker_info(driver, code=0):
    seen = []

    def run(cmd, **kwargs):
        seen.append(cmd)
        assert cmd == ["docker", "info", "--format", "{{.LoggingDriver}}"]
        return _Proc(code, driver + "\n")
    return run, seen


def test_the_host_driver_note(tmp_path):
    root = _with_compose(tmp_path)
    assert dv.compose_sets_logging(root) is True
    run, _ = _docker_info("journald")
    note = dv.container_log_note(root, run)
    assert note and "'journald'" in note and "README" in note and "does not get it" in note
    for quiet in (_docker_info("json-file")[0], _docker_info("", 1)[0], _docker_info("journald", 1)[0]):
        assert dv.container_log_note(root, quiet) is None


def test_the_note_for_a_checkout_without_the_rotation(tmp_path):
    root = _with_compose(tmp_path, block=False)
    assert dv.compose_sets_logging(root) is False
    note = dv.container_log_note(root, _docker_info("json-file")[0])
    assert note and "do not rotate container output" in note
    assert "do not rotate" in dv.container_log_note(root, _docker_info("", 1)[0])
    # Removed to keep the host's own driver: nothing to say.
    assert dv.container_log_note(root, _docker_info("journald")[0]) is None


def test_no_note_without_a_compose_file(tmp_path):
    run, seen = _docker_info("journald")
    assert dv.compose_sets_logging(str(tmp_path)) is None
    assert dv.container_log_note(str(tmp_path), run) is None
    assert seen == []


def test_setup_and_update_say_the_note(tmp_path, monkeypatch, capsys):
    root = _with_compose(tmp_path)
    tool = dv.DockVault(dv.Palette(False), root=root)
    monkeypatch.setattr(dv, "host_log_driver", lambda run=None: "syslog")
    tool._note_host_log_driver()
    assert "Note: This host's Docker sends container output to 'syslog'" in capsys.readouterr().out
    source = (ROOT / "dockvault.py").read_text(encoding="utf-8")
    setup = source.split("    def setup(self, args=None):", 1)[1].split("\n    def ", 1)[0]
    update = source.split("    def update(self, args=None):", 1)[1].split("\n    def ", 1)[0]
    assert setup.count("self._note_host_log_driver()") == 1
    assert update.count("self._note_host_log_driver()") == 1
    assert update.index("self._container_logs_readable()") < update.index("self._running_version(")
