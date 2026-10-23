"""The audit chain's keys and head record on the host (dockvault.py, the shipped compose files), offline:

- a backup archives the keys volume (the head record) before the database, and pauses the database while its
  volume is copied, resuming it whatever happens;
- a restore puts the keys volume back first, whatever order the bundle lists, and writes the restore mark
  right after it, before any other volume, holding the head record it replaced and the one it restored;
- an update to a release with the chain offers AUDIT_CHAIN_KEY (yes by default; --no-chain-key declines);
- the key change writes the new key, recreates the stack and moves the chain with the old key on standard
  input, keeping the old key aside (mode 600) until the move is done;
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
        seen.append((list(args), input_text, (tmp_path / ".audit-chain-key.previous").read_text(encoding="utf-8")))
        return {"ok": True, "sealed": 30}
    monkeypatch.setattr(tool, "_audit_tool", tool_call)
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))
    (args, given, kept), = seen
    assert args == ["rekey", "--old-key-stdin", "--now"] and given == old + "\n" and kept == old + "\n"
    assert _chain_key(tmp_path) != old and len(_chain_key(tmp_path)) == 64
    assert not (tmp_path / ".audit-chain-key.previous").exists()


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
    kept = tmp_path / ".audit-chain-key.previous"
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
    assert (tmp_path / ".audit-chain-key.previous").read_text(encoding="utf-8") == env["AUDIT_CHAIN_KEY"] + "\n"


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
