"""A restore keeps the .env it is about to replace (dockvault.py: _do_restore, _keep_env_before_restore).

The .env of the set a host is on holds that set's secrets: its database password and its ENCRYPTION_KEY. Without
it the set's volumes cannot be read. A restore of another set's backup leaves those volumes as they were and
installs the backup's .env, so it used to leave the host with volumes nothing could open again, while it said the
set's data was kept. The restore now keeps the current .env first, as .env.<prefix of the set the host is on>,
never over a file already there, says where it is and how to go back to that set, and refuses to go on when the
copy cannot be made or when .env is sealed by `lock`.

Every path through it: another set's backup; the same set's, with its own .env and with one changed since the
backup; no .env at all; a kept file (and a folder) already there; a copy that cannot be made; a restore that stops
before it installs the backup's .env, and one that fails while installing it; a sealed .env. With real Docker, the
volumes of the set the host was on open again from the kept file, through the command the restore prints.
"""
import argparse
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("dockvault_restore_mod", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)

HERE, THERE = "dvhere", "dvthere"


@pytest.fixture(autouse=True)
def _no_acl_changes(monkeypatch):
    """The host's ACLs of the temporary secret files are left alone (as in tests/test_dockvault_tool.py)."""
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)


def _env_bytes(prefix, **extra):
    cfg = {
        "server_name": "localhost", "encryption_key": dv.gen_fernet_key(), "jwt_secret_key": dv.gen_hex(32),
        "vault_db_password": dv.gen_hex(16), "redis_password": dv.gen_hex(24), "admin_username": "admin",
        "admin_email": "a@example.com", "admin_password": "Strong-Pass-1234", "compose_profiles": "combined",
        "volume_prefix": prefix, "deployment_id": prefix,
    }
    lines = dv.build_env_lines(cfg) + ["%s=%s" % kv for kv in extra.items()]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _bundle(tmp_path, env, name="bundle", roles=("keys", "pg", "storage")):
    """A backup of the set `env` names, with an archive (a stand-in) for each role. Written as bytes, so the
    comparisons below see exactly what a restore installs."""
    bundle = tmp_path / name
    bundle.mkdir()
    (bundle / "env").write_bytes(env)
    parsed = dv.parse_env(env.decode("utf-8"))
    entries = [{"role": r, "name": "x", "archive": "%s.tar.gz" % dv.VOLUME_BASENAMES[r]} for r in roles]
    man = dv.build_backup_manifest(dv.volume_prefix(parsed), parsed.get("DEPLOYMENT_ID", "default"), entries,
                                   dv.gen_salt(), parsed)
    (bundle / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
    for e in entries:
        (bundle / e["archive"]).write_bytes(b"x")
    return bundle


def _tool(tmp_path, monkeypatch, steps, clear=True):
    """The tool, with Docker answered by stand-ins that record what the restore did, in order. Each step records
    whether a kept copy of the current .env existed at that moment."""
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))

    def kept_now():
        return any(p.name.startswith(".env.") and p.name != ".env.enc" for p in tmp_path.iterdir())

    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: False)
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)
    monkeypatch.setattr(dv, "docker_available", lambda **k: (True, "ok"))
    monkeypatch.setattr(dv, "read_volume_json", lambda *a, **k: None)
    monkeypatch.setattr(dv, "clear_volume", lambda vol, **k: steps.append(("clear", kept_now())) or clear)
    monkeypatch.setattr(dv, "untar_volume", lambda vol, *a, **k: steps.append(("untar", kept_now())) or True)
    monkeypatch.setattr(tool, "_stop_stack", lambda: steps.append(("stop", kept_now())))
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: steps.append(("start", kept_now())) or True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    return tool


def _restore(tool, bundle):
    tool._do_restore(argparse.Namespace(non_interactive=True, bundle_dir=str(bundle), force=True))


def _said(capsys):
    return " ".join(capsys.readouterr().out.split())


def _kept_files(tmp_path):
    return sorted(p.name for p in tmp_path.iterdir() if p.name.startswith(".env."))


def _go_back_command(kept):
    arg = '"%s"' % kept if any(c.isspace() for c in str(kept)) else str(kept)
    return ("python dockvault.py volumes --non-interactive --action repoint --target-prefix %s --env-source %s"
            % (HERE, arg))


def test_a_restore_of_another_sets_backup_keeps_the_current_env_first_and_says_how_to_go_back(
        tmp_path, monkeypatch, capsys):
    current, theirs = _env_bytes(HERE), _env_bytes(THERE)
    (tmp_path / ".env").write_bytes(current)
    bundle = _bundle(tmp_path, theirs)
    steps = []
    _restore(_tool(tmp_path, monkeypatch, steps), bundle)

    kept = tmp_path / (".env." + HERE)
    assert kept.read_bytes() == current                       # the set the host was on, byte for byte
    assert (tmp_path / ".env").read_bytes() == theirs         # the backup's .env is installed
    assert _kept_files(tmp_path) == [".env." + HERE]
    if os.name != "nt":
        assert (os.stat(kept).st_mode & 0o077) == 0, "the kept .env holds secrets: owner-only"
    # Kept before anything was stopped or replaced.
    assert steps[0] == ("stop", True) and all(seen for _step, seen in steps), steps
    said = _said(capsys)
    assert "Kept the current .env (set '%s') as %s" % (HERE, kept) in said
    assert "its volumes are untouched, and its .env is kept in %s" % kept in said
    command = _go_back_command(kept)
    assert command in said
    # The printed command is one the tool takes, and it names the kept file.
    args = dv.build_parser().parse_args(shlex.split(command, posix=os.name != "nt")[2:])
    assert (args.volume_action, args.target_prefix, args.non_interactive) == ("repoint", HERE, True)
    assert Path(args.env_source.strip('"')) == kept


@pytest.mark.parametrize("changed", [False, True], ids=["its-own-env", "a-changed-env"])
def test_a_restore_over_the_same_set_keeps_the_env_only_when_something_would_be_lost(
        tmp_path, monkeypatch, capsys, changed):
    backup = _env_bytes(HERE)
    current = backup + b"SMTP_HOST=mail.example.com\n" if changed else backup
    (tmp_path / ".env").write_bytes(current)
    bundle = _bundle(tmp_path, backup)
    steps = []
    _restore(_tool(tmp_path, monkeypatch, steps), bundle)

    assert (tmp_path / ".env").read_bytes() == backup
    said = _said(capsys)
    assert "repoint" not in said
    if changed:
        kept = tmp_path / (".env." + HERE)
        assert _kept_files(tmp_path) == [".env." + HERE] and kept.read_bytes() == current
        assert "The .env this set had before the restore is kept in %s. It does not open the restored data" \
            % kept in said
    else:
        assert _kept_files(tmp_path) == [], "nothing would be lost: its own .env, byte for byte"
        assert "Kept the current .env" not in said


def test_a_restore_onto_a_host_with_no_env_keeps_nothing(tmp_path, monkeypatch, capsys):
    theirs = _env_bytes(THERE)
    bundle = _bundle(tmp_path, theirs)
    steps = []
    _restore(_tool(tmp_path, monkeypatch, steps), bundle)

    assert (tmp_path / ".env").read_bytes() == theirs
    assert _kept_files(tmp_path) == []
    assert [s for s, _seen in steps][:1] == ["stop"] and "Kept the current" not in _said(capsys)


def test_a_kept_file_already_there_is_never_written_over(tmp_path, monkeypatch, capsys):
    current = _env_bytes(HERE)
    (tmp_path / ".env").write_bytes(current)
    (tmp_path / (".env." + HERE)).write_bytes(b"an older one\n")
    (tmp_path / (".env." + HERE + ".1")).mkdir()               # a folder holds the next name
    (tmp_path / (".env." + HERE + ".1") / "inside").write_bytes(b"left alone\n")
    bundle = _bundle(tmp_path, _env_bytes(THERE))
    _restore(_tool(tmp_path, monkeypatch, []), bundle)

    kept = tmp_path / (".env." + HERE + ".2")
    assert kept.read_bytes() == current
    assert (tmp_path / (".env." + HERE)).read_bytes() == b"an older one\n"
    assert (tmp_path / (".env." + HERE + ".1") / "inside").read_bytes() == b"left alone\n"
    said = _said(capsys)
    assert "Kept the current .env (set '%s') as %s" % (HERE, kept) in said
    assert _go_back_command(kept) in said


def _no_sync(_directory):
    raise OSError(28, "No space left on device")


def _no_copy(_label, _data):
    raise PermissionError(13, "Permission denied")


@pytest.mark.parametrize("failure", ["written-then-not-synced", "not-created"])
def test_a_copy_that_cannot_be_made_refuses_the_restore_with_nothing_changed(tmp_path, monkeypatch, capsys, failure):
    current = _env_bytes(HERE)
    (tmp_path / ".env").write_bytes(current)
    bundle = _bundle(tmp_path, _env_bytes(THERE))
    steps = []
    tool = _tool(tmp_path, monkeypatch, steps)
    if failure == "written-then-not-synced":
        monkeypatch.setattr(dv, "sync_directory", _no_sync)   # the copy is written, then cannot be put on the disk
    else:
        monkeypatch.setattr(tool, "_keep_env_copy", _no_copy)
    with pytest.raises(SystemExit):
        _restore(tool, bundle)

    assert steps == [], "nothing was stopped, cleared or extracted"
    assert (tmp_path / ".env").read_bytes() == current
    assert _kept_files(tmp_path) == [], "a copy that could not be finished is removed"
    said = _said(capsys)
    assert "could not keep the current .env as %s" % (tmp_path / (".env." + HERE)) in said
    assert "Nothing changed." in said


def test_a_restore_that_stops_before_the_install_removes_the_copy_again(tmp_path, monkeypatch):
    """The current .env is then still in place, so the copy would only be a second plain-text copy of it."""
    current = _env_bytes(HERE)
    (tmp_path / ".env").write_bytes(current)
    bundle = _bundle(tmp_path, _env_bytes(THERE))
    steps = []
    with pytest.raises(SystemExit):
        _restore(_tool(tmp_path, monkeypatch, steps, clear=False), bundle)

    assert ("clear", True) in steps, "the copy existed while the restore ran"
    assert (tmp_path / ".env").read_bytes() == current
    assert _kept_files(tmp_path) == []


def test_a_restore_that_fails_while_installing_the_backups_env_keeps_the_copy(tmp_path, monkeypatch):
    """.env no longer reads as it did: the copy is then the only whole copy of it, and stays."""
    current = _env_bytes(HERE)
    (tmp_path / ".env").write_bytes(current)
    bundle = _bundle(tmp_path, _env_bytes(THERE))
    tool = _tool(tmp_path, monkeypatch, [])

    def half_written(_src, dst):
        Path(dst).write_bytes(b"ENCRYPTION_KEY=")
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(dv, "_copy_secret", half_written)
    with pytest.raises(OSError):
        _restore(tool, bundle)
    assert (tmp_path / (".env." + HERE)).read_bytes() == current


def test_a_restore_while_env_is_sealed_is_refused_before_anything(tmp_path, monkeypatch, capsys):
    (tmp_path / ".env.enc").write_text("sealed", encoding="utf-8")
    bundle = _bundle(tmp_path, _env_bytes(THERE))
    steps = []
    tool = _tool(tmp_path, monkeypatch, steps)
    monkeypatch.setattr(tool, "_unseal_bundle_env", lambda *a, **k: pytest.fail("the backup was opened"))
    with pytest.raises(SystemExit):
        _restore(tool, bundle)

    assert steps == []
    assert sorted(p.name for p in tmp_path.iterdir()) == [".env.enc", "bundle"]
    assert (tmp_path / ".env.enc").read_text(encoding="utf-8") == "sealed"
    said = _said(capsys)
    assert ".env is locked (sealed in .env.enc): unlock it first (python dockvault.py unlock)" in said
    assert "Nothing changed." in said


# --------------------------------------------------------------------------- with real Docker

_PG_IMAGE = ("postgres:15-alpine@sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f")


def _run(*args, timeout=180):
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)


def _start_pg(name, volume, password=None):
    """A postgres of this test's own name on `volume`: a first start creates the database with `password`; a
    later one opens the database already there (it never looks at a password then)."""
    cmd = ["docker", "run", "-d", "--name", name, "-v", "%s:/var/lib/postgresql/data" % volume,
           "-e", "POSTGRES_USER=%s" % dv.PG_USER, "-e", "POSTGRES_DB=%s" % dv.PG_DB]
    if password is not None:
        cmd += ["-e", "POSTGRES_PASSWORD"]
    r = subprocess.run(cmd + [_PG_IMAGE], capture_output=True, text=True, timeout=300,
                       env=dict(os.environ, POSTGRES_PASSWORD=password or ""))
    assert r.returncode == 0, r.stderr[-400:]
    # pg_isready answers on the socket during the first start's temporary server too, so wait for the server
    # that listens on the network, as the probe connects.
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        ip = _run("docker", "exec", name, "hostname", "-i").stdout.split()
        if ip and _run("docker", "exec", name, "pg_isready", "-h", ip[0], "-U", dv.PG_USER,
                       "-d", dv.PG_DB).returncode == 0:
            return
        time.sleep(1)
    raise AssertionError("the database on %s did not come up: %s" % (volume, _run("docker", "logs", name).stderr[-400:]))


def _stop_pg(name):
    _run("docker", "rm", "-f", name, timeout=60)


@pytest.mark.docker
def test_the_volumes_of_the_set_the_host_was_on_open_again_from_the_kept_env(tmp_path, monkeypatch, capsys):
    """Set A is the host's (a database made with A's password); a backup of set B is restored. Afterwards .env is
    B's and A's password does not open A's database, but the kept file's does, and the command the restore prints
    puts A back: the tool's own check opens A's database with it."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    tag = uuid.uuid4().hex[:8]
    pa, pb = "dvkeepa" + tag, "dvkeepb" + tag
    names_a, names_b = dv.set_volume_names(pa), dv.set_volume_names(pb)
    pg = "dvkeep-%s-pg" % tag
    env_a, env_b = _env_bytes(pa), _env_bytes(pb)
    pw_a = dv.parse_env(env_a.decode())["VAULT_DB_PASSWORD"]
    pw_b = dv.parse_env(env_b.decode())["VAULT_DB_PASSWORD"]
    mine = [names_a[r] for r in ("pg", "storage", "keys")] + [names_b[r] for r in ("pg", "storage", "keys")]
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)   # no vault-db is this test's
    monkeypatch.setattr(tool, "_stop_stack", lambda: None)
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    try:
        try:
            seed = _run("docker", "run", "--rm", "busybox", "true")
        except (subprocess.SubprocessError, OSError) as exc:
            pytest.skip("docker unavailable: %s" % exc)
        if seed.returncode != 0:
            pytest.skip("docker run unavailable: %s" % seed.stderr[:120])
        # Set A, the host's: its database made with A's password, and its .env.
        _start_pg(pg, names_a["pg"], password=pw_a)
        assert dv.probe_pg_password(pg, dv.PG_USER, dv.PG_DB, pw_a) == "ok"     # the instrument, before
        _stop_pg(pg)
        # A backup of set B, made on this host from B's own volumes and .env.
        for v in (names_b["pg"], names_b["storage"], names_b["keys"]):
            assert _run("docker", "volume", "create", v).returncode == 0
        assert _run("docker", "run", "--rm", "-v", names_b["keys"] + ":/d", "busybox", "sh", "-c",
                    "echo SET-B > /d/marker.txt").returncode == 0
        (tmp_path / ".env").write_bytes(env_b)
        tool._do_backup(dv.parse_env(env_b.decode()), argparse.Namespace(
            non_interactive=True, backup_dir=str(tmp_path / "backups")))
        bundle = next((tmp_path / "backups").iterdir())
        for v in (names_b["pg"], names_b["storage"], names_b["keys"]):
            assert _run("docker", "volume", "rm", v).returncode == 0
        (tmp_path / ".env").write_bytes(env_a)                  # the host is on set A again

        tool._do_restore(argparse.Namespace(non_interactive=True, bundle_dir=str(bundle), force=False))
        said = _said(capsys)
        kept = tmp_path / (".env." + pa)
        assert kept.read_bytes() == env_a and (tmp_path / ".env").read_bytes() == env_b
        got = _run("docker", "run", "--rm", "-v", names_b["keys"] + ":/d:ro", "busybox", "cat", "/d/marker.txt")
        assert "SET-B" in got.stdout, "set B was restored"

        # A's database, as the restore left it: .env's password (B's) does not open it; the kept file's does.
        _start_pg(pg, names_a["pg"])
        try:
            assert dv.probe_pg_password(pg, dv.PG_USER, dv.PG_DB, pw_b) == "mismatch"
            kept_pw = dv.parse_env(kept.read_text(encoding="utf-8"))["VAULT_DB_PASSWORD"]
            assert dv.probe_pg_password(pg, dv.PG_USER, dv.PG_DB, kept_pw) == "ok"
        finally:
            _stop_pg(pg)

        # The command the restore printed, run as printed: the tool checks the kept .env against A's database
        # (on this test's own postgres, never a vault-db) and puts it back as .env.
        prefix_line = "To go back to it: "
        command = said[said.index(prefix_line) + len(prefix_line):].split(" That file")[0]
        args = dv.build_parser().parse_args(shlex.split(command, posix=os.name != "nt")[2:])
        args.env_source = args.env_source.strip('"')
        checked = []
        monkeypatch.setattr(tool, "_start_db_only", lambda: (_start_pg(pg, names_a["pg"]), True)[1])
        monkeypatch.setattr(tool, "_wait_db_ready", lambda *a, **k: True)
        monkeypatch.setattr(tool, "_stop_db_only", lambda: _stop_pg(pg))
        real_probe = dv.probe_pg_password

        def probe(_container, user, db, password, **k):
            checked.append(password)
            return real_probe(pg, user, db, password)

        monkeypatch.setattr(dv, "probe_pg_password", probe)
        tool.volumes(args)
        assert checked == [pw_a], "the tool's own check opened A's database with the kept .env's password"
        assert (tmp_path / ".env").read_bytes() == env_a
        assert (tmp_path / (".env." + pb)).read_bytes() == env_b   # B's .env, set aside by the repoint in turn
    finally:
        _stop_pg(pg)
        for v in mine:
            _run("docker", "volume", "rm", "-f", v, timeout=60)
