"""The audit chain's keys and head record on the host (dockvault.py, the shipped compose files), offline:

- a backup archives the keys volume (the head record) before the database, and pauses the database while its
  volume is copied, resuming it whatever happens;
- a restore puts the keys volume back first, whatever order the bundle lists, and writes the restore mark
  right after it, before any other volume, holding the head record it replaced and the one it restored;
- an update to a release with the chain offers AUDIT_CHAIN_KEY (yes by default; --no-chain-key declines);
- the key change writes the new key, recreates the stack and moves the chain with the old key on standard
  input, keeping the old key aside (mode 600) until the move is done; while that kept file is there, a new key
  change is refused and the kept file is never written over;
- a key change, an update and every line written into .env are refused while .env is sealed (no .env is ever
  made beside a .env.enc); the new key is on the disk in .env (file and name) before the stack is recreated under
  it, and when it cannot be, .env is put back as it was, or the operator is told what to do;
- a backup taken during an unfinished key change carries the kept old key (sealed with its env under --lock), and
  a restore puts it back beside .env before .env, never over another, and says to move the chain before
  accepting the restore;
- the split layout's SFTP container never gets the chain's key and mounts the keys volume read-only; the web
  server writes the SSH host key it needs.

Docker is stubbed throughout."""
import argparse
import json
from pathlib import Path

import pytest

import dockvault as dv
from test_dockvault_tool import _reusable_env_cfg, _write_bundle

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parent.parent


def _env_file(tmp_path, **cfg):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(dict(_reusable_env_cfg(), **cfg))) + "\n",
                                   encoding="utf-8")
    return dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))


def _kept(tmp_path, prefix=dv.DEFAULT_PROJECT):
    """The file a key change keeps the old key of the volume set `prefix` in."""
    return Path(dv.kept_chain_key_path(str(tmp_path), prefix))


class _Result:
    def __init__(self, code=0, stdout=""):
        self.returncode = code
        self.stdout = stdout
        self.stderr = ""


def test_a_backup_archives_the_keys_volume_first_and_pauses_the_database_around_its_copy(tmp_path, monkeypatch):
    env = _env_file(tmp_path, volume_prefix="dockvault-vault-k1", deployment_id="k1")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    order = []
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: not name.endswith("_vault_brand"))
    monkeypatch.setattr(dv, "container_running", lambda name, **k: True)
    monkeypatch.setattr(dv, "tar_volume", lambda vol, *a, **k: order.append(vol.rsplit("_vault_", 1)[1]) or True)
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: order.append(" ".join(a[:2])) or _Result())
    tool._do_backup(env, argparse.Namespace(non_interactive=True, backup_dir=str(tmp_path / "backups")))
    assert order == ["keys", "pause vault-db", "pg_data", "unpause vault-db", "storage"]
    man = json.loads(next((tmp_path / "backups").glob("dockvault-*/manifest.json")).read_text(encoding="utf-8"))
    assert [e["role"] for e in man["volumes"]] == ["keys", "pg", "storage"]


def test_the_database_is_resumed_when_its_copy_fails(tmp_path, monkeypatch):
    env = _env_file(tmp_path, volume_prefix="dockvault-vault-k2", deployment_id="k2")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    calls = []
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: True)
    monkeypatch.setattr(dv, "container_running", lambda name, **k: True)
    monkeypatch.setattr(dv, "tar_volume", lambda vol, *a, **k: not vol.endswith("_vault_pg_data"))
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: calls.append(a[0]) or _Result())
    with pytest.raises(SystemExit):
        tool._do_backup(env, argparse.Namespace(non_interactive=True, backup_dir=str(tmp_path / "backups")))
    assert calls == ["pause", "unpause"]


def test_a_stopped_database_is_copied_without_a_pause(tmp_path, monkeypatch):
    env = _env_file(tmp_path, volume_prefix="dockvault-vault-k3", deployment_id="k3")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    calls = []
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: True)
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)
    monkeypatch.setattr(dv, "tar_volume", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: calls.append(a[0]) or _Result())
    tool._do_backup(env, argparse.Namespace(non_interactive=True, backup_dir=str(tmp_path / "backups")))
    assert calls == []


def _restore(tmp_path, monkeypatch, entries, head_file=None):
    cfg = dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-rk", deployment_id="rk")
    bundle = _write_bundle(tmp_path, cfg, entries, name="bundle-rk")
    if head_file is not None:
        env_path = bundle / "env"
        env_path.write_text(env_path.read_text(encoding="utf-8") + "AUDIT_CHAIN_HEAD_FILE=%s\n" % head_file,
                            encoding="utf-8")
        man = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        man_env = dv.parse_env(env_path.read_text(encoding="utf-8"))
        man = dv.build_backup_manifest("dockvault-vault-rk", "rk", entries, dv.gen_salt(), man_env)
        (bundle / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
    for e in entries:
        (bundle / e["archive"]).write_bytes(b"x")
    (tmp_path / ".env").write_text("x=1\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    order = []
    records = {"before": {"seq": 40, "link": "aa"}, "after": {"seq": 12, "link": "bb"}}
    state = {"untarred": False}
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: name.endswith("_vault_keys"))
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)
    monkeypatch.setattr(dv, "docker_available", lambda **k: (True, "ok"))

    def read(vol, rel, **k):
        order.append("read:" + rel)
        return records["after"] if state["untarred"] else records["before"]

    def untar(vol, *a, **k):
        order.append("untar:" + vol.rsplit("_vault_", 1)[1])
        if vol.endswith("_vault_keys"):
            state["untarred"] = True
        return True

    monkeypatch.setattr(dv, "read_volume_json", read)
    monkeypatch.setattr(dv, "clear_volume", lambda vol, **k: order.append("clear:" + vol.rsplit("_vault_", 1)[1]) or True)
    monkeypatch.setattr(dv, "untar_volume", untar)
    monkeypatch.setattr(dv, "write_volume_file", lambda vol, rel, text, **k: order.append(("mark", rel,
                                                                                            json.loads(text))) or True)
    monkeypatch.setattr(dv, "_copy_secret", lambda *a, **k: order.append("env"))
    monkeypatch.setattr(dv, "tighten_secret_file", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_stop_stack", lambda: order.append("stop"))
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    tool._do_restore(argparse.Namespace(non_interactive=True, bundle_dir=str(bundle), force=True))
    return order


def test_a_restore_puts_the_keys_volume_back_first_and_marks_the_restore_before_anything_else(tmp_path,
                                                                                            monkeypatch):
    entries = [{"role": r, "name": "x", "archive": "vault_%s.tar.gz" % b}
               for r, b in (("pg", "pg_data"), ("storage", "storage"), ("keys", "keys"))]   # an older bundle's order
    order = _restore(tmp_path, monkeypatch, entries)
    steps = [s if isinstance(s, str) else "mark" for s in order]
    assert steps.index("read:audit-chain-head.json") < steps.index("clear:keys") < steps.index("untar:keys")
    assert steps.index("untar:keys") < steps.index("mark") < steps.index("clear:pg_data")
    assert steps.index("mark") < steps.index("env")
    (_m, rel, mark), = [s for s in order if not isinstance(s, str)]
    assert rel == "audit-chain-head.json.restore-pending"
    assert mark["record"] == {"seq": 40, "link": "aa"} and mark["restored_record"] == {"seq": 12, "link": "bb"}
    assert mark["bundle"] == "bundle-rk" and mark["at"].endswith("Z")


def test_a_head_record_kept_outside_the_keys_volume_gets_no_mark(tmp_path, monkeypatch):
    entries = [{"role": "keys", "name": "x", "archive": "vault_keys.tar.gz"}]
    order = _restore(tmp_path, monkeypatch, entries, head_file="/srv/elsewhere/head.json")
    assert not [s for s in order if not isinstance(s, str)]


@pytest.mark.parametrize("value,rel", [
    (None, "audit-chain-head.json"), ("/app/keys/audit-chain-head.json", "audit-chain-head.json"),
    ("/app/keys/chain/head.json", "chain/head.json"), ("/srv/x.json", None), ("/app/keys/../etc/x", None),
])
def test_the_head_records_place_in_the_keys_volume(value, rel):
    env = {} if value is None else {"AUDIT_CHAIN_HEAD_FILE": value}
    assert dv.chain_head_relpath(env) == rel


def _updating(tmp_path, monkeypatch, answer=True, **env_cfg):
    _env_file(tmp_path, **env_cfg)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "confirm", lambda *a, **k: answer)
    return tool


def _chain_key(tmp_path):
    return dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8")).get("AUDIT_CHAIN_KEY")


def test_an_update_to_a_release_with_the_chain_offers_a_chain_key(tmp_path, monkeypatch):
    tool = _updating(tmp_path, monkeypatch)
    lines = [ln for ln in (tmp_path / ".env").read_text(encoding="utf-8").splitlines()
             if not ln.startswith("AUDIT_CHAIN_KEY")]
    (tmp_path / ".env").write_text("\n".join(lines) + "\n", encoding="utf-8")
    tool._offer_chain_key(argparse.Namespace(no_chain_key=False), True, "0.34.0")
    assert len(_chain_key(tmp_path)) == 64
    kept = _chain_key(tmp_path)
    tool._offer_chain_key(argparse.Namespace(no_chain_key=False), True, "0.34.1")
    assert _chain_key(tmp_path) == kept                      # never replaced once set


@pytest.mark.parametrize("target,no_key,answer", [("0.33.3", False, True), ("0.34.0", True, True),
                                                   ("0.34.0", False, False)])
def test_no_chain_key_is_written_when_declined_or_for_an_older_release(tmp_path, monkeypatch, target, no_key, answer):
    tool = _updating(tmp_path, monkeypatch, answer=answer)
    lines = [ln for ln in (tmp_path / ".env").read_text(encoding="utf-8").splitlines()
             if not ln.startswith("AUDIT_CHAIN_KEY")]
    (tmp_path / ".env").write_text("\n".join(lines) + "\n", encoding="utf-8")
    tool._offer_chain_key(argparse.Namespace(no_chain_key=no_key), True, target)
    assert not _chain_key(tmp_path)


def test_the_key_change_moves_the_chain_with_the_old_key_on_standard_input(tmp_path, monkeypatch):
    env = _env_file(tmp_path, audit_chain_key=dv.gen_hex(32))
    old = env["AUDIT_CHAIN_KEY"]
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    seen = []

    def tool_call(*args, input_text=None):
        seen.append((list(args), input_text, _kept(tmp_path).read_text(encoding="utf-8")))
        return {"ok": True, "sealed": 30}
    monkeypatch.setattr(tool, "_audit_tool", tool_call)
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    (args, given, kept), = seen
    assert args == ["rekey", "--old-key-stdin", "--now"] and given == old + "\n" and kept == old + "\n"
    assert _chain_key(tmp_path) != old and len(_chain_key(tmp_path)) == 64
    assert not _kept(tmp_path).exists()


@pytest.mark.skipif(not hasattr(__import__("os"), "O_DIRECTORY"), reason="a directory cannot be synced here")
def test_the_old_key_is_on_the_disk_with_its_name_before_env_changes(tmp_path, monkeypatch):
    """The old key kept beside .env is synced, then its directory, before .env is rewritten: a power cut then keeps
    the old key beside the new one, and the chain can still be moved with a proof."""
    import os
    import stat
    _env_file(tmp_path, audit_chain_key=dv.gen_hex(32))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    events = []
    real_fsync = os.fsync

    def fsync(fd):
        st = os.fstat(fd)
        events.append(("dir" if stat.S_ISDIR(st.st_mode) else "file", st.st_ino))
        return real_fsync(fd)
    monkeypatch.setattr(os, "fsync", fsync)
    real_set = tool._set_env_key
    monkeypatch.setattr(tool, "_set_env_key", lambda *a, **k: (events.append(("env",)), real_set(*a, **k))[1])
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, **k: {"ok": False, "error": "key-unverified"})
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    with pytest.raises(SystemExit):
        tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    kept = _kept(tmp_path)
    assert events[:3] == [("file", kept.stat().st_ino), ("dir", tmp_path.stat().st_ino), ("env",)], events


def test_a_key_change_whose_old_key_cannot_be_synced_changes_nothing(tmp_path, monkeypatch):
    import errno
    import os
    env = _env_file(tmp_path, audit_chain_key=dv.gen_hex(32))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))

    def broken(fd):
        raise OSError(errno.EIO, "Input/output error")
    monkeypatch.setattr(os, "fsync", broken)
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: pytest.fail("the stack was recreated"))
    with pytest.raises(SystemExit):
        tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    assert _chain_key(tmp_path) == env["AUDIT_CHAIN_KEY"]


def test_a_key_change_that_cannot_move_the_chain_keeps_the_old_key_aside(tmp_path, monkeypatch):
    env = _env_file(tmp_path, audit_chain_key=dv.gen_hex(32))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, **k: {"ok": False, "error": "key-unverified"})
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    with pytest.raises(SystemExit):
        tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    assert _kept(tmp_path).read_text(encoding="utf-8") == env["AUDIT_CHAIN_KEY"] + "\n"


def _key_change_with_a_failed_move(tmp_path, monkeypatch):
    """A key change whose move failed: .env holds the new key, the kept file the key the chain is under."""
    env = _env_file(tmp_path, audit_chain_key=dv.gen_hex(32))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, **k: {"ok": False, "error": "busy"})
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    with pytest.raises(SystemExit):
        tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    kept = _kept(tmp_path)
    assert kept.read_text(encoding="utf-8") == env["AUDIT_CHAIN_KEY"] + "\n"
    assert _chain_key(tmp_path) != env["AUDIT_CHAIN_KEY"]
    return env["AUDIT_CHAIN_KEY"], _chain_key(tmp_path), kept


def test_a_second_key_change_after_a_failed_move_is_refused_and_keeps_the_key_the_chain_is_under(
        tmp_path, monkeypatch, capsys):
    """The kept file holds the only copy of the key the chain is under: a second change would have kept the first
    change's new key over it (never in force), and the chain could then be moved only without a proof. It is
    refused before anything is asked, naming the command that finishes the first change."""
    under, written, kept = _key_change_with_a_failed_move(tmp_path, monkeypatch)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, **k: pytest.fail("the chain was asked to move"))
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: pytest.fail("the stack was recreated"))
    monkeypatch.setattr(dv, "confirm", lambda *a, **k: pytest.fail("asked before refusing"))
    capsys.readouterr()
    with pytest.raises(SystemExit):
        tool.audit(dv.build_parser().parse_args(["audit", "change-key"]))
    out = capsys.readouterr().out
    assert kept.read_text(encoding="utf-8") == under + "\n"
    assert _chain_key(tmp_path) == written
    assert "not finished" in out and f"audit rekey --old-key-file {kept}" in out and "Nothing changed" in out


def test_a_key_change_never_writes_over_a_kept_file_it_did_not_see(tmp_path, monkeypatch, capsys):
    """A kept file that appears between the check and the write (another run of the tool) is never truncated:
    the file is created by this run or not at all."""
    import os
    under, written, kept = _key_change_with_a_failed_move(tmp_path, monkeypatch)
    real = os.path.lexists
    monkeypatch.setattr(os.path, "lexists", lambda p: False if str(p) == str(kept) else real(p))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: pytest.fail("the stack was recreated"))
    capsys.readouterr()
    with pytest.raises(SystemExit):
        tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    assert kept.read_text(encoding="utf-8") == under + "\n"
    assert _chain_key(tmp_path) == written
    assert "not finished" in capsys.readouterr().out


def test_a_kept_file_this_run_could_not_finish_writing_is_removed_with_nothing_changed(tmp_path, monkeypatch):
    """When the old key cannot be kept aside, .env still holds it: the copy begun is removed, so the next change is
    not refused for a change that never happened."""
    import errno
    import os
    env = _env_file(tmp_path, audit_chain_key=dv.gen_hex(32))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))

    def broken(fd):
        raise OSError(errno.EIO, "Input/output error")
    monkeypatch.setattr(os, "fsync", broken)
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: pytest.fail("the stack was recreated"))
    with pytest.raises(SystemExit):
        tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    assert _chain_key(tmp_path) == env["AUDIT_CHAIN_KEY"]
    assert not _kept(tmp_path).exists()


@pytest.mark.parametrize("compose", ["deploy/docker-compose.yml", "deploy/docker-compose.secure.yml"])
def test_the_split_sftp_container_holds_no_chain_key_and_cannot_write_the_head_record(compose):
    import yaml
    doc = yaml.safe_load((ROOT / compose).read_text(encoding="utf-8"))
    sftp = doc["services"]["vault-sftp"]
    assert sftp["environment"]["AUDIT_CHAIN_KEY"] == ""
    keys = [v for v in sftp["volumes"] if v.startswith("vault_keys:")]
    assert keys == ["vault_keys:/app/keys:ro"]
    api = doc["services"]["vault-api"]
    assert "vault_keys:/app/keys" in api["volumes"] and "AUDIT_CHAIN_KEY" not in (api.get("environment") or {})


def test_the_web_server_writes_the_sftp_host_key_when_there_is_none(tmp_path):
    from app.sftp.host_key import ensure_host_key, load_host_key
    path = tmp_path / "keys" / "ssh_host_rsa_key"
    assert ensure_host_key(path) is True and load_host_key(path) is not None
    before = path.read_bytes()
    assert ensure_host_key(path) is False and path.read_bytes() == before
    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert "ensure_host_key(settings.sftp_host_key_path)" in source


# --------------------------------------------------------------------------- a sealed .env, and .env on the disk

def _lock_args(**kw):
    base = dict(passphrase_file=None, passphrase_stdin=False, hint=None, recovery_out=None, recovery_key=False,
                recovery_key_file=None, show_recovery_key=False, force=False, lock=False, new_passphrase_file=None,
                new_passphrase_stdin=False)
    base.update(kw)
    return argparse.Namespace(**base)


def test_a_key_change_on_a_locked_env_is_refused_with_nothing_written(tmp_path, monkeypatch, capsys):
    """A deployment whose .env is sealed into .env.enc has no plaintext .env: a key change would write a .env holding
    only the new key, and a lock after it would seal that over the real one. It is refused before anything."""
    (tmp_path / ".env.enc").write_text("sealed", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, **k: pytest.fail("the chain was asked to move"))
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: pytest.fail("the stack was recreated"))
    monkeypatch.setattr(dv, "confirm", lambda *a, **k: pytest.fail("asked before refusing"))
    with pytest.raises(SystemExit):
        tool.audit(dv.build_parser().parse_args(["audit", "change-key"]))
    assert sorted(p.name for p in tmp_path.iterdir()) == [".env.enc"]
    assert (tmp_path / ".env.enc").read_text(encoding="utf-8") == "sealed"
    out = capsys.readouterr().out
    assert "locked" in out and "dockvault.py unlock" in out and "Nothing changed" in out


def test_a_key_change_with_no_env_is_refused_with_nothing_written(tmp_path, monkeypatch, capsys):
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: pytest.fail("the stack was recreated"))
    with pytest.raises(SystemExit):
        tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    assert list(tmp_path.iterdir()) == []
    out = capsys.readouterr().out
    assert "there is no .env" in out and "Nothing changed" in out


def test_a_sealed_env_keeps_every_secret_through_a_key_change_and_a_lock(tmp_path, monkeypatch):
    """lock, change-key (refused), lock again, unlock: .env comes back whole, the chain's key with it."""
    pytest.importorskip("cryptography")
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _p: True)
    env = _env_file(tmp_path, audit_chain_key=dv.gen_hex(32))
    text = (tmp_path / ".env").read_text(encoding="utf-8")
    passfile = tmp_path / "pass.txt"
    passfile.write_text("correct horse battery staple\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    tool.lock(_lock_args(passphrase_file=str(passfile)))
    assert tool._is_locked()
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: pytest.fail("the stack was recreated"))
    with pytest.raises(SystemExit):
        tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    assert not (tmp_path / ".env").exists() and tool._is_locked()
    tool.lock(_lock_args(passphrase_file=str(passfile)))
    tool.unlock(_lock_args(passphrase_file=str(passfile)))
    assert (tmp_path / ".env").read_text(encoding="utf-8") == text
    assert dv.parse_env(text)["ENCRYPTION_KEY"] == env["ENCRYPTION_KEY"]


def test_no_line_is_ever_written_into_a_new_env_beside_a_sealed_one(tmp_path, monkeypatch, capsys):
    """Every command that writes a line into .env goes through _set_env_key: beside a .env.enc and no .env it
    refuses, rather than make a .env holding that line alone."""
    (tmp_path / ".env.enc").write_text("sealed", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    with pytest.raises(SystemExit):
        tool._set_env_key(tool._env_path(), "DOCKVAULT_IMAGE", "ghcr.io/dockvault/vault:v1.0.0")
    assert not (tmp_path / ".env").exists()
    assert "locked" in capsys.readouterr().out


def test_an_update_on_a_locked_env_is_refused_and_the_chain_key_is_never_written_beside_it(tmp_path, monkeypatch):
    (tmp_path / ".env.enc").write_text("sealed", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: pytest.fail("update went on"))
    with pytest.raises(SystemExit):
        tool.update(argparse.Namespace(tag="v0.34.0", non_interactive=True, yes=True))
    monkeypatch.setattr(dv, "confirm", lambda *a, **k: pytest.fail("asked before refusing"))
    with pytest.raises(SystemExit):
        tool._offer_chain_key(argparse.Namespace(no_chain_key=False), True, "0.34.0")
    assert sorted(p.name for p in tmp_path.iterdir()) == [".env.enc"]


def _fsyncs(monkeypatch, events):
    """Record each fsync: ("dir"|"file", the inode)."""
    import os
    import stat
    real_fsync = os.fsync

    def fsync(fd):
        st = os.fstat(fd)
        events.append(("dir" if stat.S_ISDIR(st.st_mode) else "file", st.st_ino))
        return real_fsync(fd)
    monkeypatch.setattr(os, "fsync", fsync)


@pytest.mark.skipif(not hasattr(__import__("os"), "O_DIRECTORY"), reason="a directory cannot be synced here")
def test_the_new_key_is_on_the_disk_in_env_before_the_stack_is_recreated_under_it(tmp_path, monkeypatch):
    """Once the stack runs under the new key the chain moves to it (a durable commit), and the kept old key is
    removed: by then .env's new bytes and its name must be on the disk, or a power cut leaves the chain under a key
    that is in no file."""
    env = _env_file(tmp_path, audit_chain_key=dv.gen_hex(32))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    events = []
    _fsyncs(monkeypatch, events)

    def recreate(build):
        events.append(("recreate", _chain_key(tmp_path)))
        return True
    monkeypatch.setattr(tool, "_recreate_stack", recreate)
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, input_text=None: events.append(("move",)) or
                        {"ok": True, "sealed": 30})
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    new = _chain_key(tmp_path)
    assert new != env["AUDIT_CHAIN_KEY"]
    env_file = ("file", (tmp_path / ".env").stat().st_ino)
    directory = ("dir", tmp_path.stat().st_ino)
    recreated = events.index(("recreate", new))
    synced = events.index(env_file)
    assert synced < recreated and directory in events[synced + 1:recreated], events
    assert events[-1] == ("move",)


@pytest.mark.skipif(not hasattr(__import__("os"), "O_DIRECTORY"), reason="a directory cannot be synced here")
def test_the_chain_key_an_update_offers_is_on_the_disk_before_the_update_goes_on(tmp_path, monkeypatch):
    tool = _updating(tmp_path, monkeypatch)
    lines = [ln for ln in (tmp_path / ".env").read_text(encoding="utf-8").splitlines()
             if not ln.startswith("AUDIT_CHAIN_KEY")]
    (tmp_path / ".env").write_text("\n".join(lines) + "\n", encoding="utf-8")
    events = []
    _fsyncs(monkeypatch, events)
    tool._offer_chain_key(argparse.Namespace(no_chain_key=False), True, "0.34.0")
    assert len(_chain_key(tmp_path)) == 64
    synced = events.index(("file", (tmp_path / ".env").stat().st_ino))
    assert ("dir", tmp_path.stat().st_ino) in events[synced + 1:], events


@pytest.mark.skipif(__import__("os").name == "nt", reason="a symbolic link and an owner are POSIX's")
def test_a_line_written_into_env_follows_a_link_and_keeps_the_files_owner(tmp_path, monkeypatch):
    import os
    real = tmp_path / "kept-elsewhere"
    real.mkdir()
    (real / ".env").write_text("A=1\nB=2\n", encoding="utf-8")
    root = tmp_path / "deploy"
    root.mkdir()
    os.symlink(real / ".env", root / ".env")
    owners = []
    real_fchown = os.fchown
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: owners.append((uid, gid)) or real_fchown(fd, uid, gid))
    tool = dv.DockVault(dv.Palette(False), root=str(root))
    st = (real / ".env").stat()
    tool._set_env_key(str(root / ".env"), "B", "3")
    assert os.path.islink(root / ".env") and (real / ".env").read_text(encoding="utf-8") == "A=1\nB=3\n"
    assert owners == [(st.st_uid, st.st_gid)]
    assert (real / ".env").stat().st_mode & 0o777 == 0o600
    assert [p.name for p in real.iterdir()] == [".env"]                     # no temporary file left


def test_a_line_that_cannot_be_written_leaves_env_as_it_was_and_no_temporary_file(tmp_path, monkeypatch):
    import errno
    import os
    (tmp_path / ".env").write_bytes(b"A=1\r\nB=2\n")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))

    def full(fd):
        raise OSError(errno.ENOSPC, "No space left on device")
    monkeypatch.setattr(os, "fsync", full)
    with pytest.raises(OSError):
        tool._set_env_key(tool._env_path(), "B", "3")
    assert (tmp_path / ".env").read_bytes() == b"A=1\r\nB=2\n"
    assert [p.name for p in tmp_path.iterdir()] == [".env"]


def _a_key_change_whose_env_write_fails(tmp_path, monkeypatch, failing_calls):
    """A key change whose write of the new key into .env fails at the directory syncs numbered in
    `failing_calls` (1 is the kept old key's own)."""
    import errno
    env = _env_file(tmp_path, audit_chain_key=dv.gen_hex(32))
    before = (tmp_path / ".env").read_bytes()
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    real_sync = dv.sync_directory
    calls = []

    def sync(directory):
        calls.append(directory)
        if len(calls) in failing_calls:
            raise OSError(errno.EIO, "Input/output error")
        return real_sync(directory)
    monkeypatch.setattr(dv, "sync_directory", sync)
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: pytest.fail("the stack was recreated"))
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, **k: pytest.fail("the chain was asked to move"))
    with pytest.raises(SystemExit):
        tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    return env["AUDIT_CHAIN_KEY"], before


def test_a_key_change_whose_new_env_cannot_be_synced_puts_env_back_and_changes_nothing(tmp_path, monkeypatch,
                                                                                         capsys):
    """The rename of the new .env was done, its directory's sync failed: .env is put back as it was, byte for byte,
    and the kept copy of the old key goes, as nothing changed."""
    old, before = _a_key_change_whose_env_write_fails(tmp_path, monkeypatch, {2})
    assert (tmp_path / ".env").read_bytes() == before
    assert not _kept(tmp_path).exists()
    out = capsys.readouterr().out
    assert ".env is as it was" in out and "Nothing changed" in out


def test_a_key_change_whose_env_can_be_neither_written_nor_put_back_keeps_the_old_key_and_says_what_to_do(
        tmp_path, monkeypatch, capsys):
    old, _before = _a_key_change_whose_env_write_fails(tmp_path, monkeypatch, {2, 3})
    kept = _kept(tmp_path)
    assert kept.read_text(encoding="utf-8") == old + "\n"
    out = capsys.readouterr().out
    assert "nor put .env back" in out and str(kept) in out and "make AUDIT_CHAIN_KEY in .env that key again" in out


# --------------------------------------------------------------------------- a backup during an unfinished change

def _unfinished_change(tmp_path, **cfg):
    """.env holding the new key, and the old key kept beside it, as a key change whose move failed leaves them."""
    env = _env_file(tmp_path, audit_chain_key=dv.gen_hex(32), **cfg)
    old = dv.gen_hex(32)
    _kept(tmp_path, cfg.get("volume_prefix", dv.DEFAULT_PROJECT)).write_text(old + "\n", encoding="utf-8")
    return env, old


def _backing_up(tmp_path, monkeypatch, env, **args):
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: True)
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)
    monkeypatch.setattr(dv, "tar_volume", lambda vol, bundle, archive, **k: (Path(bundle) / archive).write_bytes(b"x")
                        or True)
    tool._do_backup(env, argparse.Namespace(non_interactive=True, backup_dir=str(tmp_path / "backups"), **args))
    return next((tmp_path / "backups").iterdir())


def test_a_backup_during_an_unfinished_key_change_carries_the_old_key(tmp_path, monkeypatch, capsys):
    import os
    env, old = _unfinished_change(tmp_path, volume_prefix="dockvault-vault-carry", deployment_id="carry")
    bundle = _backing_up(tmp_path, monkeypatch, env)
    assert (bundle / "audit-chain-key.previous").read_text(encoding="utf-8") == old + "\n"
    if os.name != "nt":
        assert (bundle / "audit-chain-key.previous").stat().st_mode & 0o077 == 0
    assert "dockvault.py audit rekey --old-key-file" in capsys.readouterr().out


def test_a_backup_with_no_unfinished_key_change_carries_no_old_key(tmp_path, monkeypatch):
    env = _env_file(tmp_path, volume_prefix="dockvault-vault-plain", deployment_id="plain")
    bundle = _backing_up(tmp_path, monkeypatch, env)
    assert not [p for p in bundle.iterdir() if p.name.startswith("audit-chain-key")]


def test_a_sealed_backup_seals_the_old_key_with_its_env(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    env, old = _unfinished_change(tmp_path, volume_prefix="dockvault-vault-sealed", deployment_id="sealed")
    passfile = tmp_path / "pass.txt"
    passfile.write_text("seal-passphrase-1\n", encoding="utf-8")
    rout = tmp_path / "recovery.txt"
    bundle = _backing_up(tmp_path, monkeypatch, env, lock=True, passphrase_file=str(passfile),
                         passphrase_stdin=False, hint=None, recovery_out=str(rout))
    names = sorted(p.name for p in bundle.iterdir())
    assert "env" not in names and "audit-chain-key.previous" not in names
    assert {"env.enc", "audit-chain-key.previous.enc"} <= set(names)
    sealed = (bundle / "audit-chain-key.previous.enc").read_text(encoding="utf-8")
    fernet = dv.load_fernet()
    assert dv.env_lock_open(fernet, sealed, passphrase="seal-passphrase-1")[0] == (old + "\n").encode()
    assert dv.env_lock_open(fernet, sealed, recovery_key=rout.read_text().strip())[0] == (old + "\n").encode()


def test_a_backup_whose_kept_file_holds_no_key_is_refused_and_removed(tmp_path, monkeypatch, capsys):
    env = _env_file(tmp_path, volume_prefix="dockvault-vault-empty", deployment_id="empty")
    _kept(tmp_path, "dockvault-vault-empty").write_text("\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        _backing_up(tmp_path, monkeypatch, env)
    assert list((tmp_path / "backups").iterdir()) == []
    assert "holds none" in capsys.readouterr().out


def _restoring(tmp_path, monkeypatch, *, carried=None, sealed=False, here=None, interactive=False):
    """A restore of a bundle carrying the old key `carried` (or none), its env sealed or not, onto a host whose own
    kept file holds `here` (or none). Returns (the steps, in order, and whether the kept file was there when .env
    was installed)."""
    cfg = dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-rc", deployment_id="rc")
    entries = [{"role": "keys", "name": "x", "archive": "vault_keys.tar.gz"},
               {"role": "pg", "name": "x", "archive": "vault_pg_data.tar.gz"}]
    bundle = _write_bundle(tmp_path, cfg, entries, name="bundle-rc")
    for e in entries:
        (bundle / e["archive"]).write_bytes(b"x")
    if carried is not None:
        (bundle / "audit-chain-key.previous").write_text(carried + "\n", encoding="utf-8")
    passfile = tmp_path / "pass.txt"
    passfile.write_text("seal-passphrase-1\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    if sealed:
        tool._seal_bundle_env(str(bundle), argparse.Namespace(
            passphrase_file=str(passfile), passphrase_stdin=False, hint=None, recovery_out=None, non_interactive=True))
    (tmp_path / ".env").write_text("x=1\n", encoding="utf-8")
    if here is not None:
        _kept(tmp_path, "dockvault-vault-rc").write_text(here + "\n", encoding="utf-8")
    kept = _kept(tmp_path, "dockvault-vault-rc")
    steps = []
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: True)
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)
    monkeypatch.setattr(dv, "docker_available", lambda **k: (True, "ok"))
    monkeypatch.setattr(dv, "read_volume_json", lambda vol, rel, **k: {"seq": 4, "link": "aa"})
    monkeypatch.setattr(dv, "clear_volume", lambda vol, **k: True)
    monkeypatch.setattr(dv, "untar_volume", lambda vol, *a, **k: steps.append("untar") or True)
    monkeypatch.setattr(dv, "write_volume_file", lambda *a, **k: steps.append("mark") or True)
    monkeypatch.setattr(dv, "_copy_secret", lambda *a, **k: steps.append(("env", kept.exists())))
    monkeypatch.setattr(tool, "_atomic_write_secret", lambda *a, **k: steps.append(("env", kept.exists())))
    monkeypatch.setattr(dv, "tighten_secret_file", lambda *a, **k: True)
    monkeypatch.setattr(dv, "ask", lambda *a, **k: "dockvault-vault-rc")
    monkeypatch.setattr(tool, "_stop_stack", lambda: steps.append("stop"))
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: steps.append("start") or True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_audit_host_command", lambda args, action: steps.append(action))
    args = argparse.Namespace(bundle_dir=str(bundle), force=True, passphrase_file=str(passfile),
                              passphrase_stdin=False, recovery_key_file=None, use_recovery_key=False)
    if not interactive:
        args.non_interactive = True
    tool._do_restore(args)
    return steps


@pytest.mark.parametrize("sealed", [False, True], ids=["plain", "sealed"])
def test_a_restore_puts_the_carried_old_key_back_beside_env_before_env(tmp_path, monkeypatch, capsys, sealed):
    if sealed:
        pytest.importorskip("cryptography")
    old = dv.gen_hex(32)
    steps = _restoring(tmp_path, monkeypatch, carried=old, sealed=sealed)
    assert ("env", True) in steps and ("env", False) not in steps
    assert _kept(tmp_path, "dockvault-vault-rc").read_text(encoding="utf-8") == old + "\n"
    out = " ".join(capsys.readouterr().out.split())
    kept = _kept(tmp_path, "dockvault-vault-rc")
    rekey = "python dockvault.py audit rekey --old-key-file %s" % kept
    assert rekey in out and out.index(rekey) < out.index("python dockvault.py audit accept-restore")


def test_an_interactive_restore_of_a_carried_key_moves_nothing_on_its_own(tmp_path, monkeypatch, capsys):
    """accept-restore seals under the current key: with the chain maybe still under the carried key, the restore
    leaves both steps to the operator, in their order, and runs neither."""
    steps = _restoring(tmp_path, monkeypatch, carried=dv.gen_hex(32), interactive=True)
    assert "accept-restore" not in steps and "start" in steps
    out = " ".join(capsys.readouterr().out.split())
    assert out.index("audit rekey --old-key-file") < out.index("audit accept-restore")


def test_an_interactive_restore_with_no_carried_key_still_accepts_the_restore(tmp_path, monkeypatch):
    steps = _restoring(tmp_path, monkeypatch, interactive=True)
    assert steps[-1] == "accept-restore"
    assert not _kept(tmp_path, "dockvault-vault-rc").exists()


def test_a_restore_onto_a_host_with_another_unfinished_key_change_is_refused_before_anything(tmp_path, monkeypatch,
                                                                                            capsys):
    mine = dv.gen_hex(32)
    with pytest.raises(SystemExit):
        _restoring(tmp_path, monkeypatch, carried=dv.gen_hex(32), here=mine)
    assert _kept(tmp_path, "dockvault-vault-rc").read_text(encoding="utf-8") == mine + "\n"
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "x=1\n"
    assert "Nothing was changed" in capsys.readouterr().out


def test_a_restore_onto_a_host_holding_the_same_kept_key_goes_on(tmp_path, monkeypatch):
    old = dv.gen_hex(32)
    steps = _restoring(tmp_path, monkeypatch, carried=old, here=old)
    assert "stop" in steps and ("env", True) in steps


@pytest.mark.parametrize("text", ["", "   \n", "one\ntwo\n", "tab\there"])
def test_a_restore_refuses_a_carried_old_key_that_is_not_a_key_before_anything(tmp_path, monkeypatch, text):
    cfg = dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-rd", deployment_id="rd")
    bundle = _write_bundle(tmp_path, cfg, [], name="bundle-rd")
    (bundle / "audit-chain-key.previous").write_text(text, encoding="utf-8")
    (tmp_path / ".env").write_text("x=1\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_stop_stack", lambda: pytest.fail("the deployment was stopped"))
    with pytest.raises(SystemExit):
        tool._do_restore(argparse.Namespace(non_interactive=True, bundle_dir=str(bundle), force=True))
    assert not _kept(tmp_path, "dockvault-vault-rd").exists()


def test_a_restore_refuses_a_sealed_old_key_beside_a_plain_env(tmp_path, monkeypatch):
    cfg = dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-re", deployment_id="re")
    bundle = _write_bundle(tmp_path, cfg, [], name="bundle-re")
    (bundle / "audit-chain-key.previous.enc").write_text("sealed", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_stop_stack", lambda: pytest.fail("the deployment was stopped"))
    with pytest.raises(SystemExit):
        tool._do_restore(argparse.Namespace(non_interactive=True, bundle_dir=str(bundle), force=True))


# --------------------------------------------------------------------------- each volume set's own kept key

def _on_set(tool, monkeypatch, sealed=7):
    """`tool`'s key change with the stack and the server stubbed: the chain moves as asked."""
    moved = []
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, **k: moved.append(list(a)) or {"ok": True, "sealed": sealed})
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    return moved


def test_each_volume_set_keeps_its_old_key_in_a_file_of_its_own_through_a_change_of_set(tmp_path, monkeypatch, capsys):
    """A key change of set A whose move failed keeps A's chain key in A's own file. Volumes' new set archives A's .env
    (which holds the new key only) and installs set B's: B's key change is not refused for A's, keeps and removes only
    B's own file, and a backup of B carries none of A's. Repointed back to A, A's key change is refused, naming A's
    file, which still holds the key A's chain is under."""
    under, written, kept_a = _key_change_with_a_failed_move(tmp_path, monkeypatch)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    env_a = tool._load_env()
    prefix_a = dv.volume_prefix(env_a)
    assert kept_a == _kept(tmp_path, prefix_a)
    monkeypatch.setattr(tool, "_emit_secret", lambda *a, **k: None)
    tool._volume_new(env_a, argparse.Namespace(non_interactive=True))
    env_b = tool._load_env()
    prefix_b = dv.volume_prefix(env_b)
    assert prefix_b != prefix_a and env_b["AUDIT_CHAIN_KEY"] not in (under, written)

    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    seen = []
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, input_text=None: seen.append(
        (list(a), input_text, _kept(tmp_path, prefix_b).read_text(encoding="utf-8"))) or {"ok": True, "sealed": 7})
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    (args, given, kept_b_then), = seen
    assert given == env_b["AUDIT_CHAIN_KEY"] + "\n" and kept_b_then == env_b["AUDIT_CHAIN_KEY"] + "\n"
    assert not _kept(tmp_path, prefix_b).exists()
    assert kept_a.read_text(encoding="utf-8") == under + "\n"

    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: True)
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)
    monkeypatch.setattr(dv, "tar_volume", lambda vol, bundle, archive, **k: (Path(bundle) / archive).write_bytes(b"x")
                        or True)
    tool._do_backup(tool._load_env(), argparse.Namespace(non_interactive=True, backup_dir=str(tmp_path / "backups")))
    bundle = next((tmp_path / "backups").iterdir())
    assert not [p for p in bundle.iterdir() if p.name.startswith("audit-chain-key")]

    monkeypatch.setattr(tool, "_guard_db_secret", lambda env, **k: True)
    monkeypatch.setattr(tool, "_stop_stack", lambda: None)
    monkeypatch.setattr(tool, "_stop_db_only", lambda: None)
    monkeypatch.setattr(dv, "list_managed_volumes", lambda *a, **k: [
        {"name": "%s_vault_pg_data" % prefix_a, "role": "pg", "bundle": "a"},
        {"name": "%s_vault_pg_data" % prefix_b, "role": "pg", "bundle": "b"}])
    tool._volume_repoint(tool._load_env(), argparse.Namespace(non_interactive=True, target_prefix=prefix_a,
                                                                env_source=None))
    assert dv.volume_prefix(tool._load_env()) == prefix_a
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, **k: pytest.fail("the chain was asked to move"))
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: pytest.fail("the stack was recreated"))
    capsys.readouterr()
    with pytest.raises(SystemExit):
        tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    out = " ".join(capsys.readouterr().out.split())
    assert "('%s') is not finished" % prefix_a in out and "audit rekey --old-key-file %s" % kept_a in out
    assert "only once that rekey says the key it holds is no longer needed" in out
    assert kept_a.read_text(encoding="utf-8") == under + "\n"


def test_a_restore_of_another_sets_backup_puts_its_key_in_that_sets_file_and_leaves_this_sets_alone(
        tmp_path, monkeypatch):
    """The host's own set has an unfinished key change; a backup of another set carries the key of its own: the
    restore is not refused for a key that is not its set's, writes the carried key into its set's file, and leaves the
    host set's file as it was."""
    mine = dv.gen_hex(32)
    _kept(tmp_path).write_text(mine + "\n", encoding="utf-8")
    carried = dv.gen_hex(32)
    steps = _restoring(tmp_path, monkeypatch, carried=carried)
    assert ("env", True) in steps
    assert _kept(tmp_path, "dockvault-vault-rc").read_text(encoding="utf-8") == carried + "\n"
    assert _kept(tmp_path).read_text(encoding="utf-8") == mine + "\n"


def test_reset_moves_the_destroyed_sets_kept_key_aside_and_a_new_set_of_that_prefix_changes_its_key(
        tmp_path, monkeypatch, capsys):
    """Reset destroys the set and its chain: the old key its unfinished change kept is moved aside with its .env,
    never over another file, so a new set with the same prefix is not refused for a change of a chain that is gone."""
    under, _written, kept = _key_change_with_a_failed_move(tmp_path, monkeypatch)
    (tmp_path / (dv.KEPT_CHAIN_KEY_REMOVED + dv.DEFAULT_PROJECT)).write_text("an earlier one\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: _Result())
    capsys.readouterr()
    tool.reset(argparse.Namespace(non_interactive=True, confirm=True))
    moved = tmp_path / (dv.KEPT_CHAIN_KEY_REMOVED + dv.DEFAULT_PROJECT + ".1")
    assert not kept.exists() and moved.read_text(encoding="utf-8") == under + "\n"
    assert (tmp_path / (dv.KEPT_CHAIN_KEY_REMOVED + dv.DEFAULT_PROJECT)).read_text(encoding="utf-8") == \
        "an earlier one\n"
    assert str(moved) in capsys.readouterr().out
    _env_file(tmp_path, audit_chain_key=dv.gen_hex(32))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    moves = _on_set(tool, monkeypatch)
    tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    assert moves == [["rekey", "--old-key-stdin", "--now"]] and not kept.exists()


def test_a_reset_with_no_kept_key_moves_nothing(tmp_path, monkeypatch):
    _env_file(tmp_path)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: _Result())
    tool.reset(argparse.Namespace(non_interactive=True, confirm=True))
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".audit-chain-key")]


@pytest.mark.parametrize("prefix", ["", "../outside", "a/b", "-dash", "has space", "trailing\n", "line\nend"])
def test_a_prefix_that_is_not_a_volume_sets_name_names_no_kept_file(tmp_path, prefix):
    with pytest.raises(ValueError):
        dv.kept_chain_key_path(str(tmp_path), prefix)


def test_lock_says_the_kept_old_keys_are_not_sealed(tmp_path, monkeypatch, capsys):
    """lock seals .env only: the old key an unfinished change keeps (the key the chain is still under) stays in plain
    text, and lock says so, naming each file, as it does of the .env archives."""
    pytest.importorskip("cryptography")
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _p: True)
    monkeypatch.setattr(dv, "container_exists", lambda *a, **k: False)
    _unfinished_change(tmp_path)
    (tmp_path / (dv.KEPT_CHAIN_KEY_REMOVED + "dockvault-vault-old")).write_text(dv.gen_hex(32) + "\n",
                                                                                encoding="utf-8")
    passfile = tmp_path / "pass.txt"
    passfile.write_text("correct horse battery staple\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    capsys.readouterr()
    tool.lock(_lock_args(passphrase_file=str(passfile)))
    out = " ".join(capsys.readouterr().out.split())
    assert "2 old AUDIT_CHAIN_KEY file(s) are NOT sealed by lock" in out
    assert _kept(tmp_path).name in out and dv.KEPT_CHAIN_KEY_REMOVED + "dockvault-vault-old" in out
    assert dv.CHAIN_KEY_LOCK not in out


def test_lock_with_no_kept_old_key_says_nothing_of_one(tmp_path, monkeypatch, capsys):
    pytest.importorskip("cryptography")
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _p: True)
    monkeypatch.setattr(dv, "container_exists", lambda *a, **k: False)
    _env_file(tmp_path, audit_chain_key=dv.gen_hex(32))
    (tmp_path / dv.CHAIN_KEY_LOCK).write_text("", encoding="utf-8")
    passfile = tmp_path / "pass.txt"
    passfile.write_text("correct horse battery staple\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    capsys.readouterr()
    tool.lock(_lock_args(passphrase_file=str(passfile)))
    assert "AUDIT_CHAIN_KEY file" not in capsys.readouterr().out


# --------------------------------------------------------------------------- two key changes at once

def test_a_key_change_started_while_another_waits_for_its_answer_is_refused_and_the_chains_key_stays_in_a_file(
        tmp_path, monkeypatch, capsys):
    """Two runs on one host. The one waiting at its confirmation holds the lock from before it read the key in .env:
    the other, started meanwhile, is refused at once with nothing written, and the first then moves the chain with
    the key it read. A stand-in for the server moves the chain only with the proof of the key it is under, as rekey
    does: the chain's key is in .env or the kept file at every step."""
    env = _env_file(tmp_path, audit_chain_key=dv.gen_hex(32))
    chain = {"in_force": env["AUDIT_CHAIN_KEY"]}

    def server(tool):
        def audit_tool(*args, input_text=None):
            old = (input_text or "").strip()
            current = _chain_key(tmp_path)
            if chain["in_force"] == current:
                return {"ok": False, "error": "already under the current key: nothing to do"}
            if old != chain["in_force"]:
                return {"ok": False, "error": "the key in force is not held"}
            chain["in_force"] = current
            return {"ok": True, "sealed": 9}
        monkeypatch.setattr(tool, "_audit_tool", audit_tool)
        monkeypatch.setattr(tool, "_recreate_stack", lambda build: True)
        monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)

    waiting = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    other = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    server(waiting)
    server(other)
    seen = {}

    def confirm(prompt, pal, default=True):
        before = (tmp_path / ".env").read_bytes()
        capsys.readouterr()
        with pytest.raises(SystemExit):
            other.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
        seen["refusal"] = " ".join(capsys.readouterr().out.split())
        seen["unchanged"] = (tmp_path / ".env").read_bytes() == before and not _kept(tmp_path).exists()
        return True
    monkeypatch.setattr(dv, "confirm", confirm)
    waiting.audit(dv.build_parser().parse_args(["audit", "change-key"]))
    assert "another change of AUDIT_CHAIN_KEY" in seen["refusal"] and "Nothing changed" in seen["refusal"]
    assert seen["unchanged"]
    assert chain["in_force"] == _chain_key(tmp_path) != env["AUDIT_CHAIN_KEY"]
    assert not _kept(tmp_path).exists()
    # The lock is let go at the end: a later change goes on.
    monkeypatch.setattr(dv, "confirm", lambda *a, **k: True)
    other.audit(dv.build_parser().parse_args(["audit", "change-key"]))
    assert chain["in_force"] == _chain_key(tmp_path)


def test_an_update_offering_a_key_while_a_key_change_waits_is_refused_and_writes_nothing(tmp_path, monkeypatch,
                                                                                          capsys):
    """With no AUDIT_CHAIN_KEY yet there is no kept file: the lock alone keeps the update's offered key from being
    written over the key a change is about to write (or the other way round)."""
    _env_file(tmp_path)
    lines = [ln for ln in (tmp_path / ".env").read_text(encoding="utf-8").splitlines()
             if not ln.startswith("AUDIT_CHAIN_KEY")]
    (tmp_path / ".env").write_text("\n".join(lines) + "\n", encoding="utf-8")
    changing = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    updating = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    _on_set(changing, monkeypatch)
    seen = {}

    def confirm(prompt, pal, default=True):
        capsys.readouterr()
        with pytest.raises(SystemExit):
            updating._offer_chain_key(argparse.Namespace(no_chain_key=False), True, "0.34.0")
        seen["refusal"] = " ".join(capsys.readouterr().out.split())
        seen["key"] = _chain_key(tmp_path)
        return True
    monkeypatch.setattr(dv, "confirm", confirm)
    changing.audit(dv.build_parser().parse_args(["audit", "change-key"]))
    assert "another change of AUDIT_CHAIN_KEY" in seen["refusal"] and "run the update again" in seen["refusal"]
    assert not seen["key"] and len(_chain_key(tmp_path)) == 64


def test_a_key_written_into_env_while_the_change_waited_for_its_answer_refuses_it(tmp_path, monkeypatch, capsys):
    """The key read before the confirmation must still be the one in .env after it: a key put there meanwhile (by
    hand) would be the one the chain moves off, and the key kept aside a stale one. Refused, nothing written."""
    _env_file(tmp_path, audit_chain_key=dv.gen_hex(32))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: pytest.fail("the stack was recreated"))
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, **k: pytest.fail("the chain was asked to move"))
    meanwhile = dv.gen_hex(32)

    def confirm(prompt, pal, default=True):
        tool._set_env_key(tool._env_path(), "AUDIT_CHAIN_KEY", "'%s'" % meanwhile)
        return True
    monkeypatch.setattr(dv, "confirm", confirm)
    capsys.readouterr()
    with pytest.raises(SystemExit):
        tool.audit(dv.build_parser().parse_args(["audit", "change-key"]))
    assert _chain_key(tmp_path) == meanwhile and not _kept(tmp_path).exists()
    out = " ".join(capsys.readouterr().out.split())
    assert "changed while this waited for its confirmation" in out and "Nothing changed" in out


def test_the_key_an_update_offers_is_never_written_over_one_set_while_it_waited_for_its_answer(tmp_path, monkeypatch):
    tool = _updating(tmp_path, monkeypatch)
    lines = [ln for ln in (tmp_path / ".env").read_text(encoding="utf-8").splitlines()
             if not ln.startswith("AUDIT_CHAIN_KEY")]
    (tmp_path / ".env").write_text("\n".join(lines) + "\n", encoding="utf-8")
    meanwhile = dv.gen_hex(32)

    def confirm(prompt, pal, default=True):
        tool._set_env_key(tool._env_path(), "AUDIT_CHAIN_KEY", "'%s'" % meanwhile)
        return True
    monkeypatch.setattr(dv, "confirm", confirm)
    tool._offer_chain_key(argparse.Namespace(no_chain_key=False), True, "0.34.0")
    assert _chain_key(tmp_path) == meanwhile


# --------------------------------------------------------------------------- on the disk, in order

@pytest.mark.skipif(__import__("os").name == "nt", reason="an owner is POSIX's")
def test_env_is_given_its_owner_before_its_new_bytes_are_synced(tmp_path, monkeypatch):
    """The file synced is the final one, owner and all: given its owner after the sync, a power cut could leave a
    .env on the disk the deployment's user cannot read."""
    import os
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    events = []
    real_fchown, real_fsync = os.fchown, os.fsync

    def fchown(fd, uid, gid):
        events.append(("chown", os.fstat(fd).st_ino))
        return real_fchown(fd, uid, gid)

    def fsync(fd):
        events.append(("sync", os.fstat(fd).st_ino))
        return real_fsync(fd)
    monkeypatch.setattr(os, "fchown", fchown)
    monkeypatch.setattr(os, "fsync", fsync)
    dv.replace_file_durably(str(tmp_path / ".env"), "A=2\n")
    new = (tmp_path / ".env").stat().st_ino
    assert ("chown", new) in events and events.index(("chown", new)) < events.index(("sync", new)), events
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "A=2\n"


@pytest.mark.skipif(not hasattr(__import__("os"), "O_DIRECTORY"), reason="a directory cannot be synced here")
def test_a_kept_key_is_on_the_disk_with_its_name_when_it_is_written(tmp_path, monkeypatch):
    """The key a backup carries, and the one a restore puts back before the .env that does not hold it: the file is
    synced, then its directory, before write_kept_key returns."""
    events = []
    _fsyncs(monkeypatch, events)
    path = tmp_path / "audit-chain-key.previous"
    dv.write_kept_key(str(path), "k" * 64)
    file_sync = ("file", path.stat().st_ino)
    assert file_sync in events and ("dir", tmp_path.stat().st_ino) in events[events.index(file_sync) + 1:], events
    assert path.read_text(encoding="utf-8") == "k" * 64 + "\n"


def test_the_restore_mark_is_synced_once_it_has_its_name(tmp_path):
    """The restore mark keeps the pruner from deleting until the restore is accepted: written whole under a temporary
    name, owned and narrowed, renamed into place, then synced, before the restore goes on to the next volume."""
    seen = {}

    def run(cmd, **k):
        seen["cmd"], seen["input"] = cmd, k.get("input")
        return _Result()
    assert dv.write_volume_file("set_vault_keys", "audit-chain-head.json.restore-pending", "{}", run=run)
    script = seen["cmd"][seen["cmd"].index("-c") + 1]
    steps = [step.strip().split()[0] for step in script.split("&&")]
    assert steps == ["cat", "chown", "chmod", "mv", "sync"], script
    assert seen["cmd"][-1] == "audit-chain-head.json.restore-pending" and seen["input"] == "{}"


@pytest.mark.skipif(not hasattr(__import__("os"), "O_DIRECTORY"), reason="a directory cannot be synced here")
def test_reset_moves_the_kept_key_aside_and_syncs_the_move_before_it_returns(tmp_path, monkeypatch):
    """Reset moves the destroyed set's kept old key aside under a name no set reads; the move is on the disk (the
    directory synced after the rename) before it returns, or a power cut could put the file back under the set's
    name, and a new set of that prefix would be refused its key change until it is moved by hand."""
    import os
    kept = _kept(tmp_path)
    kept.write_text(dv.gen_hex(32) + "\n", encoding="utf-8")
    events = []
    real_rename = os.rename
    monkeypatch.setattr(os, "rename", lambda a, b: (events.append(("rename", str(a), str(b))), real_rename(a, b))[1])
    _fsyncs(monkeypatch, events)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    moved = tool._archive_kept_key(dv.DEFAULT_PROJECT)
    assert moved is not None and not kept.exists() and Path(moved).is_file()
    renames = [i for i, e in enumerate(events) if e[0] == "rename"]
    assert [events[i][1:] for i in renames] == [(str(kept), moved)], events
    assert ("dir", tmp_path.stat().st_ino) in events[renames[0] + 1:], events
