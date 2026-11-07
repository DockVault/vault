"""A backup's archives, from the backup to the restore (dockvault.py: _do_backup, _do_restore).

A backup counts an archive only once it is on this host, not empty, and read through whole as a tar.gz, and it
records the archive's SHA-256 and size in its manifest. A sealed backup's manifest is authenticated as well, by a MAC
under the key its env.enc is sealed with. A restore takes the bundle's path as an absolute one, and before it stops or
clears anything it reads every archive through, checks it against what the backup recorded and checks that Docker
sees the same file through the mount the extraction uses. A changed archive, a changed sealed manifest, a manifest
recording some checksums only, and an archive Docker does not see are refused with nothing changed. A backup made
before backups recorded checksums is restored with a notice. Each extraction copies its archive into its own
container, hashes the copy, and extracts it only when it is the archive checked: an archive changed since (the bundle
can change in between) is not extracted at all, and the restore stops there. With real Docker: a backup and a
restore through a relative folder, an archive changed after the backup, which leaves the keys volume as it was, and
an archive changed after the check, which its extraction catches before anything of it is extracted.
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tarfile
import uuid
from pathlib import Path

import pytest

from test_dockvault_tool import _host_digest, _reusable_env_cfg, _tgz

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("dockvault_archives_mod", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)
# The real look through Docker, kept before the fixture below stands in for it.
_DIGEST_IN_DOCKER = getattr(dv, "archive_digest_in_docker", None)


@pytest.fixture(autouse=True)
def _hermetic(request, monkeypatch):
    """No host ACL changes; without real Docker, Docker sees this host's folder (a test marked docker keeps it)."""
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    if request.node.get_closest_marker("docker") is None:
        monkeypatch.setattr(dv, "archive_digest_in_docker", _host_digest, raising=False)


def _env(tmp_path, prefix):
    text = "\n".join(dv.build_env_lines(dict(_reusable_env_cfg(), volume_prefix=prefix, deployment_id=prefix))) + "\n"
    (tmp_path / ".env").write_text(text, encoding="utf-8")
    return dv.parse_env(text)


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _backed_up(tmp_path, monkeypatch, prefix, lock=False, write=None):
    """A backup of set `prefix` with Docker stubbed: each volume's archive written by `write` (a real tar.gz by
    default). Returns the bundle."""
    env = _env(tmp_path, prefix)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: not name.endswith("_vault_brand"))
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)
    monkeypatch.setattr(dv, "tar_volume", write or (lambda vol, bundle, archive, **k: _tgz(
        Path(bundle) / archive, {"from.txt": vol.encode()}) and True))
    args = argparse.Namespace(non_interactive=True, backup_dir=str(tmp_path / "backups"))
    if lock:
        pf = tmp_path / "pass.txt"
        pf.write_text("seal-passphrase-1\n", encoding="utf-8")
        args = argparse.Namespace(non_interactive=True, backup_dir=str(tmp_path / "backups"), lock=True,
                                  passphrase_file=str(pf), passphrase_stdin=False, hint=None, recovery_out=None)
    tool._do_backup(env, args)
    return next((tmp_path / "backups").iterdir())


def _restoring_tool(tmp_path, monkeypatch, steps):
    """The tool with Docker's volume and stack steps recorded in `steps` (nothing real is touched)."""
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: True)
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)
    monkeypatch.setattr(dv, "docker_available", lambda **k: (True, "ok"))
    monkeypatch.setattr(dv, "read_volume_json", lambda *a, **k: None)
    monkeypatch.setattr(dv, "clear_volume", lambda vol, **k: steps.append(("clear", vol)) or True)
    monkeypatch.setattr(dv, "untar_volume", lambda vol, src, archive, **k: steps.append(("untar", vol, src)) or True)
    monkeypatch.setattr(tool, "_stop_stack", lambda: steps.append(("stop",)))
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: steps.append(("start",)) or True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    return tool


def _restore_args(bundle, **kw):
    base = dict(non_interactive=True, bundle_dir=str(bundle), force=True, passphrase_file=None,
                passphrase_stdin=False, use_recovery_key=False, recovery_key_file=None)
    base.update(kw)
    return argparse.Namespace(**base)


def _said(capsys):
    return " ".join(capsys.readouterr().out.split())


# --------------------------------------------------------------------------- the archive file itself

def test_check_archive_file_reads_a_whole_tar_gz_and_gives_its_checksum_and_size(tmp_path):
    path = _tgz(tmp_path / "a.tar.gz", {"one.txt": b"1" * 3000, "two/three.txt": b"3"})
    assert dv.check_archive_file(str(path)) == (_sha(path), path.stat().st_size)


def _gzip_with_a_bad_checksum(tmp_path):
    good = _tgz(tmp_path / "good.tar.gz").read_bytes()
    bad = bytearray(good)
    bad[-8] ^= 0xFF                                  # the stream's own CRC-32, in its trailer
    return bytes(bad)


@pytest.mark.parametrize("damage", ["missing", "empty", "truncated", "bad-checksum", "not-gzip", "not-tar"])
def test_check_archive_file_refuses_an_archive_that_does_not_read_whole(tmp_path, damage):
    path = tmp_path / "a.tar.gz"
    if damage == "empty":
        path.write_bytes(b"")
    elif damage == "truncated":
        whole = _tgz(tmp_path / "w.tar.gz", {"big.bin": os.urandom(40000)}).read_bytes()
        path.write_bytes(whole[: len(whole) // 2])
    elif damage == "bad-checksum":
        path.write_bytes(_gzip_with_a_bad_checksum(tmp_path))
    elif damage == "not-gzip":
        path.write_bytes(b"this is not an archive")
    elif damage == "not-tar":
        path.write_bytes(gzip.compress(b"plain text, gzip'd, but no tar inside"))
    with pytest.raises(ValueError):
        dv.check_archive_file(str(path))


@pytest.mark.skipif(os.name == "nt", reason="a symbolic link needs a privilege on Windows")
def test_check_archive_file_refuses_a_link(tmp_path):
    real = _tgz(tmp_path / "real.tar.gz")
    (tmp_path / "a.tar.gz").symlink_to(real)
    with pytest.raises(ValueError):
        dv.check_archive_file(str(tmp_path / "a.tar.gz"))


# --------------------------------------------------------------------------- the backup

def test_a_backup_records_each_archives_checksum_and_size(tmp_path, monkeypatch):
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchsum")
    man = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert [e["role"] for e in man["volumes"]] == ["keys", "pg", "storage"]
    for e in man["volumes"]:
        archive = bundle / e["archive"]
        assert e["sha256"] == _sha(archive) and e["size"] == archive.stat().st_size


@pytest.mark.parametrize("written", ["nothing", "empty", "truncated", "not-an-archive"])
def test_a_backup_whose_archive_did_not_reach_the_host_folder_whole_fails(tmp_path, monkeypatch, capsys, written):
    """The container's tar exited 0, but what reached the bundle (nothing, when Docker writes to a folder of its own;
    or a damaged file) is not the archive: the backup fails and leaves no bundle behind."""
    def write(vol, bundle, archive, **k):
        if vol.endswith("_vault_pg_data"):
            path = Path(bundle) / archive
            if written == "empty":
                path.write_bytes(b"")
            elif written == "truncated":
                whole = _tgz(Path(bundle) / "w.tmp", {"big.bin": os.urandom(40000)}).read_bytes()
                path.write_bytes(whole[: len(whole) // 2])
            elif written == "not-an-archive":
                path.write_bytes(b"not an archive")
            return True
        return _tgz(Path(bundle) / archive) and True

    with pytest.raises(SystemExit):
        _backed_up(tmp_path, monkeypatch, "dvarchfail", write=write)
    assert not list((tmp_path / "backups").iterdir()), "a failed backup leaves no bundle behind"
    said = _said(capsys)
    assert "the archive of volume dvarchfail_vault_pg_data did not reach the backup folder whole" in said


def test_a_backup_to_a_relative_folder_writes_its_archives_under_an_absolute_path(tmp_path, monkeypatch):
    """Docker takes a relative source for a volume's name, so the bundle path it is given is absolute."""
    seen = []

    def write(vol, bundle, archive, **k):
        seen.append(bundle)
        return _tgz(Path(bundle) / archive) and True

    monkeypatch.chdir(tmp_path)
    env = _env(tmp_path, "dvarchrel")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: not name.endswith("_vault_brand"))
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)
    monkeypatch.setattr(dv, "tar_volume", write)
    tool._do_backup(env, argparse.Namespace(non_interactive=True, backup_dir="relative-backups"))
    assert seen and all(os.path.isabs(b) for b in seen), seen


# --------------------------------------------------------------------------- the restore

def test_a_restore_checks_every_archive_before_it_stops_anything(tmp_path, monkeypatch):
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchok")
    checked, steps = [], []
    monkeypatch.setattr(dv, "archive_digest_in_docker",
                        lambda src, name, **k: checked.append((name, len(steps))) or _host_digest(src, name))
    _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(_restore_args(bundle))
    assert sorted(n for n, _ in checked) == ["vault_keys.tar.gz", "vault_pg_data.tar.gz", "vault_storage.tar.gz"]
    assert all(at == 0 for _, at in checked), "every archive was checked before the stack was stopped"
    assert steps[0] == ("stop",) and ("start",) in steps


@pytest.mark.parametrize("change", ["another-archive", "one-byte-more", "manifest-checksum"])
def test_a_restore_refuses_an_archive_whose_checksum_differs_with_nothing_changed(tmp_path, monkeypatch, capsys,
                                                                                    change):
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchbad")
    pg = bundle / "vault_pg_data.tar.gz"
    if change == "another-archive":
        _tgz(pg, {"swapped.txt": b"not what the backup made"})
    elif change == "one-byte-more":
        pg.write_bytes(pg.read_bytes() + b"\x00")
    else:
        man = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        man["volumes"][1]["sha256"] = "0" * 64
        (bundle / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
    env_before = (tmp_path / ".env").read_bytes()
    steps = []
    with pytest.raises(SystemExit):
        _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(_restore_args(bundle))
    assert steps == [], "nothing was stopped, cleared or extracted"
    assert (tmp_path / ".env").read_bytes() == env_before
    said = _said(capsys)
    assert "%s is not the archive this backup made" % pg in said and "nothing changed" in said


@pytest.mark.parametrize("change", ["checksum-and-archive", "mac-removed", "mac-of-another-manifest"])
def test_a_restore_refuses_a_sealed_backup_whose_manifest_was_changed(tmp_path, monkeypatch, capsys, change):
    """A plain checksum stops damage only: whoever can write the bundle can write the manifest's checksum too. A
    sealed backup's manifest carries a MAC under the key its env.enc is sealed with, which nobody without the
    passphrase or the recovery key can make: a manifest changed to match another archive is refused."""
    pytest.importorskip("cryptography")
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchmac", lock=True)
    assert (bundle / dv.BUNDLE_MANIFEST_MAC).exists() and not (bundle / "env").exists()
    if change == "checksum-and-archive":
        pg = _tgz(bundle / "vault_pg_data.tar.gz", {"swapped.txt": b"another database"})
        man = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        man["volumes"][1].update(sha256=_sha(pg), size=pg.stat().st_size)
        (bundle / "manifest.json").write_text(json.dumps(man, indent=2), encoding="utf-8")
    elif change == "mac-removed":
        (bundle / dv.BUNDLE_MANIFEST_MAC).unlink()
    else:
        (bundle / dv.BUNDLE_MANIFEST_MAC).write_text(json.dumps({"dockvault_manifest_mac": 1,
                                                                 "hmac_sha256": "ab" * 32}), encoding="utf-8")
    steps = []
    with pytest.raises(SystemExit):
        _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(
            _restore_args(bundle, passphrase_file=str(tmp_path / "pass.txt")))
    assert steps == []
    said = _said(capsys)
    assert "Nothing changed" in said or "nothing changed" in said
    if change == "mac-removed":
        assert "%s, which proves the manifest is the one sealed with it, is missing" % dv.BUNDLE_MANIFEST_MAC in said
    else:
        assert "the manifest of this sealed backup is not the one it was sealed with" in said


def test_a_sealed_backup_with_its_manifest_as_sealed_restores(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchmacok", lock=True)
    steps = []
    host_env = (tmp_path / ".env").read_bytes()
    (tmp_path / ".env").unlink()
    _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(
        _restore_args(bundle, passphrase_file=str(tmp_path / "pass.txt")))
    assert steps[0] == ("stop",) and ("start",) in steps
    assert (tmp_path / ".env").read_bytes() == host_env, "the .env installed is the one backed up, byte for byte"


def _sealed_payload(bundle, passphrase="seal-passphrase-1"):
    """(the payload a bundle's env.enc seals, the data key it is sealed under)."""
    text = (bundle / "env.enc").read_text(encoding="utf-8")
    return dv.env_lock_open(dv.load_fernet(), text, passphrase=passphrase)


def test_a_sealed_backup_says_in_its_sealed_env_that_its_manifest_is_authenticated(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchsays", lock=True)
    payload, dek = _sealed_payload(bundle)
    env, line = payload.rsplit(b"\n# dockvault sealed backup ", 1)
    assert env == (tmp_path / ".env").read_bytes(), "the env, then the line"
    assert line == b"%s: its manifest is authenticated (manifest.json.mac)\n" % dv.sealed_line_id(dek).encode()
    assert dv.split_sealed_bundle_payload(payload, dek) == (env, True)
    assert (bundle / dv.BUNDLE_MANIFEST_MAC).exists()
    assert json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))["dockvault_backup"] == 2


@pytest.mark.parametrize("strip", ["mac-and-checksums", "mac-checksums-and-format"])
def test_a_sealed_backup_stripped_to_look_old_is_refused(tmp_path, monkeypatch, capsys, strip):
    """Whoever can write a sealed bundle, with neither its passphrase nor its recovery key, deleted its MAC and every
    checksum (and set its manifest's format back to 1): the restore took it for a backup made before both, said so,
    and restored archives nobody had checked (a database of their choosing, say). Its sealed env says it was made
    with its manifest authenticated, and that cannot be taken out without the key: refused, with nothing changed."""
    pytest.importorskip("cryptography")
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchstrip", lock=True)
    (bundle / dv.BUNDLE_MANIFEST_MAC).unlink()
    man = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    for e in man["volumes"]:
        del e["sha256"], e["size"]
    if strip == "mac-checksums-and-format":
        man["dockvault_backup"] = 1
    (bundle / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
    _tgz(bundle / "vault_pg_data.tar.gz", {"planted.txt": b"a database of their choosing"})
    host_env = (tmp_path / ".env").read_bytes()
    steps = []
    capsys.readouterr()
    with pytest.raises(SystemExit):
        _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(
            _restore_args(bundle, passphrase_file=str(tmp_path / "pass.txt")))
    assert steps == [] and (tmp_path / ".env").read_bytes() == host_env
    said = _said(capsys)
    assert "made before backups" not in said
    if strip == "mac-checksums-and-format":
        assert ("this sealed backup was made with its manifest authenticated (its sealed env says so), but %s, which "
                "proves the manifest is the one sealed with it, is missing" % dv.BUNDLE_MANIFEST_MAC) in said
    else:
        assert "is of the format that records the checksum of every archive, and it records none for keys" in said


@pytest.mark.parametrize("fmt", [3, 0, "2", True, None], ids=["newer", "zero", "a-text", "a-bool", "null"])
def test_a_manifest_of_a_format_this_tool_does_not_know_is_refused(tmp_path, monkeypatch, capsys, fmt):
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchfmt")
    man = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    man["dockvault_backup"] = fmt
    (bundle / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
    steps = []
    capsys.readouterr()
    with pytest.raises(SystemExit):
        _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(_restore_args(bundle))
    assert steps == []
    assert "this backup's manifest is of format %r, which this version of the tool does not know" % (fmt,) in _said(
        capsys)


def test_split_sealed_bundle_payload_takes_only_the_line_of_its_own_seal():
    """The line names the data key the payload is sealed under: under that key it is this bundle's line, taken off
    the env; under another key (another seal's line, which an earlier version installed with a .env) it is part of
    the env, and the bundle an old one."""
    env, key, other = b"A=1\nB=2\n", b"the-seal's-own-data-key", b"another-seal's-data-key"
    payload = dv.sealed_bundle_payload(env, key)
    line_id = dv.sealed_line_id(key)
    assert len(line_id) == 32 and line_id != dv.sealed_line_id(other)
    assert payload == env + b"\n# dockvault sealed backup %s: its manifest is authenticated (manifest.json.mac)\n" % (
        line_id.encode())
    assert dv.split_sealed_bundle_payload(payload, key) == (env, True)
    assert dv.split_sealed_bundle_payload(payload, key.decode()) == (env, True), "the recovery key as text"
    for wrong in (other, None):
        assert dv.split_sealed_bundle_payload(payload, wrong) == (payload, False), "another seal's line"
    assert dv.split_sealed_bundle_payload(payload + b"C=3\n", key) == (payload + b"C=3\n", False)
    assert dv.split_sealed_bundle_payload(env, key) == (env, False)
    assert dv.split_sealed_bundle_payload(dv.sealed_bundle_payload(b"", key), key) == (b"", True)
    no_end = b"X=1"
    assert dv.split_sealed_bundle_payload(dv.sealed_bundle_payload(no_end, key), key) == (no_end, True)


def _old_backup(tmp_path, prefix, sealed=False, env_tail=b""):
    """A backup as a dockvault.py before checksums wrote it: entries without sha256/size, and no MAC; its env is the
    host's .env with `env_tail` after it."""
    env = _env(tmp_path, prefix)
    bundle = tmp_path / "old-bundle"
    bundle.mkdir()
    (bundle / "env").write_bytes((tmp_path / ".env").read_bytes() + env_tail)
    entries = [{"role": r, "name": dv.set_volume_names(prefix)[r], "archive": "%s.tar.gz" % dv.VOLUME_BASENAMES[r]}
               for r in ("keys", "pg", "storage")]
    for e in entries:
        _tgz(bundle / e["archive"])
    (bundle / "manifest.json").write_text(json.dumps(dv.build_backup_manifest(prefix, prefix, entries, dv.gen_salt(),
                                                                              env)), encoding="utf-8")
    if sealed:
        pf = tmp_path / "pass.txt"
        pf.write_text("seal-passphrase-1\n", encoding="utf-8")
        fernet = dv.load_fernet()
        enc, _dek = dv.env_lock_seal(fernet, (bundle / "env").read_bytes(), "seal-passphrase-1")
        (bundle / "env.enc").write_text(enc, encoding="utf-8")
        (bundle / "env").unlink()
    return bundle


@pytest.mark.parametrize("sealed", [False, True], ids=["plain", "sealed"])
def test_a_backup_made_before_checksums_restores_with_a_notice(tmp_path, monkeypatch, capsys, sealed):
    if sealed:
        pytest.importorskip("cryptography")
    bundle = _old_backup(tmp_path, "dvarchold", sealed=sealed)
    steps = []
    _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(
        _restore_args(bundle, passphrase_file=str(tmp_path / "pass.txt") if sealed else None))
    assert ("start",) in steps
    said = _said(capsys)
    assert "this backup was made before backups recorded the checksums of their archives" in said
    assert ("this sealed backup was made before backups authenticated their manifest" in said) is sealed


def test_an_old_sealed_backup_whose_env_carries_another_seals_line_restores_as_an_old_one(tmp_path, monkeypatch,
                                                                                          capsys):
    """An earlier version of the tool installs a sealed payload as it is, so the line that says a manifest is
    authenticated can reach a .env, and the backup an earlier version then seals of that .env (no MAC, no checksums)
    carries it at the end of its env. That line names the data key of another seal: the backup is an old one, restored
    with its notice, and its env (line and all) installed as it is."""
    pytest.importorskip("cryptography")
    tail = dv.sealed_bundle_payload(b"", dv.load_fernet().generate_key())    # the line of an earlier seal
    bundle = _old_backup(tmp_path, "dvarchtail", sealed=True, env_tail=tail)
    host_env = (tmp_path / ".env").read_bytes()
    steps = []
    _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(
        _restore_args(bundle, passphrase_file=str(tmp_path / "pass.txt")))
    assert ("start",) in steps
    assert "this sealed backup was made before backups authenticated their manifest" in _said(capsys)
    assert (tmp_path / ".env").read_bytes() == host_env + tail


def test_an_old_backup_whose_archive_does_not_read_whole_is_still_refused(tmp_path, monkeypatch, capsys):
    bundle = _old_backup(tmp_path, "dvarcholdbad")
    (bundle / "vault_storage.tar.gz").write_bytes(b"x")
    steps = []
    with pytest.raises(SystemExit):
        _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(_restore_args(bundle))
    assert steps == []
    assert "the archive for volume dvarcholdbad_vault_storage cannot be restored" in _said(capsys)


@pytest.mark.parametrize("manifest", ["some-only", "none-left", "some-only-format-1", "not-a-checksum", "not-a-size",
                                      "a-size-as-a-float"])
def test_a_manifest_whose_checksums_no_backup_writes_is_refused(tmp_path, monkeypatch, capsys, manifest):
    """Each by the check of what a backup writes, before any archive is compared with it: a size of the right value
    as a float compares equal to the archive's own, and True to 1. A manifest of the format that records every
    archive's checksum, with one or all of them taken out, is refused too."""
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchodd")
    man = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert man["volumes"][0]["role"] == "keys" and man["dockvault_backup"] == 2
    if manifest.startswith("some-only"):
        del man["volumes"][2]["sha256"], man["volumes"][2]["size"]
        if manifest == "some-only-format-1":
            man["dockvault_backup"] = 1
    elif manifest == "none-left":
        for e in man["volumes"]:
            del e["sha256"], e["size"]
    elif manifest == "not-a-checksum":
        man["volumes"][0]["sha256"] = "not-hex"
    elif manifest == "not-a-size":
        man["volumes"][0]["size"] = True
    else:
        man["volumes"][0]["size"] = float(man["volumes"][0]["size"])
    (bundle / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
    steps = []
    capsys.readouterr()
    with pytest.raises(SystemExit):
        _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(_restore_args(bundle))
    assert steps == []
    said = _said(capsys)
    if manifest == "some-only":
        assert ("this backup's manifest is of the format that records the checksum of every archive, and it records "
                "none for storage: it was changed since the backup was made") in said
    elif manifest == "none-left":
        assert ("this backup's manifest is of the format that records the checksum of every archive, and it records "
                "none for keys, pg, storage: it was changed since the backup was made") in said
    elif manifest == "some-only-format-1":
        assert "records the checksum of some of its archives only" in said
    else:
        assert "records a checksum or size for volume role 'keys' that is not one" in said
    assert "is not the archive this backup made" not in said


@pytest.mark.parametrize("docker", ["sees-nothing", "sees-another-file"])
def test_a_restore_whose_docker_does_not_see_the_archive_stops_before_anything(tmp_path, monkeypatch, capsys, docker):
    """The extraction goes through Docker: a Docker that does not see this host's folder (another host's daemon, a
    confined one) would have emptied the keys volume and then failed to extract."""
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchdocker")
    answer = (None, "no such archive, or an empty one") if docker == "sees-nothing" else ("1" * 64, "")
    monkeypatch.setattr(dv, "archive_digest_in_docker", lambda src, name, **k: answer)
    steps = []
    with pytest.raises(SystemExit):
        _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(_restore_args(bundle))
    assert steps == []
    assert "Docker does not see" in _said(capsys)


def test_a_restore_from_a_relative_bundle_dir_extracts_from_its_absolute_path(tmp_path, monkeypatch):
    """`--bundle-dir backups/dockvault-...` from the checkout: Docker would take that for a volume's name."""
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchrelr")
    monkeypatch.chdir(tmp_path)
    looked = []
    monkeypatch.setattr(dv, "archive_digest_in_docker",
                        lambda src, name, **k: looked.append(src) or _host_digest(src, name))
    steps = []
    _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(
        _restore_args(os.path.relpath(str(bundle), str(tmp_path))))
    sources = looked + [s[2] for s in steps if s[0] == "untar"]
    assert sources and all(os.path.isabs(s) and os.path.samefile(s, str(bundle)) for s in sources), sources


def test_the_restores_docker_check_lists_and_hashes_through_the_extractions_mount():
    """archive_digest_in_docker asks Docker the way the extraction reads: the bundle mounted read-only at /src, the
    archive copied into the container and hashed, then `tar tzf` through the whole copy."""
    calls = []

    class _R:
        returncode, stdout, stderr = 0, "dv-sha256 %s\n" % ("a" * 64), ""

    got = _DIGEST_IN_DOCKER("/b/dockvault-x", "vault_keys.tar.gz", run=lambda cmd, **k: calls.append(cmd) or _R())
    assert got == ("a" * 64, "")
    cmd = calls[0]
    assert "/b/dockvault-x:/src:ro" in cmd and "tar tzf /tmp/dv-archive" in cmd[-1] and "sha256sum" in cmd[-1]

    class _Fail:
        returncode, stdout, stderr = 4, "", "tar: short read"

    assert _DIGEST_IN_DOCKER("/b", "vault_keys.tar.gz", run=lambda cmd, **k: _Fail())[0] is None


# --------------------------------------------------------------------------- with real Docker

def _docker(*a, timeout=120):
    return subprocess.run(list(a), capture_output=True, text=True, timeout=timeout)


@pytest.mark.docker
def test_a_backup_and_a_restore_through_relative_folders_live(tmp_path, monkeypatch):
    """Real volumes: a backup to a relative --backup-dir records each archive's real checksum, and a restore from a
    relative --bundle-dir brings the data back."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    prefix = "dvarchlive" + uuid.uuid4().hex[:6]
    names = dv.set_volume_names(prefix)
    vols = [names["pg"], names["storage"], names["keys"]]
    env = _env(tmp_path, prefix)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)
    monkeypatch.setattr(tool, "_stop_stack", lambda: None)
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    try:
        try:
            for v in vols:
                _docker("docker", "volume", "create", v)
            seed = _docker("docker", "run", "--rm", "-v", names["keys"] + ":/d", "busybox", "sh", "-c",
                           "echo LIVE-KEYS > /d/marker.txt")
        except (subprocess.SubprocessError, OSError) as exc:
            pytest.skip("docker unavailable: %s" % exc)
        if seed.returncode != 0:
            pytest.skip("docker run unavailable: %s" % seed.stderr[:120])
        monkeypatch.chdir(tmp_path)
        tool._do_backup(env, argparse.Namespace(non_interactive=True, backup_dir="relative-backups"))
        bundle = next((tmp_path / "relative-backups").iterdir())
        man = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        for e in man["volumes"]:
            assert e["sha256"] == _sha(bundle / e["archive"])
        _docker("docker", "run", "--rm", "-v", names["keys"] + ":/d", "busybox", "sh", "-c",
                "rm -f /d/marker.txt && echo AFTER > /d/after.txt")
        tool._do_restore(_restore_args(os.path.relpath(str(bundle), str(tmp_path))))
        got = _docker("docker", "run", "--rm", "-v", names["keys"] + ":/d:ro", "busybox", "sh", "-c",
                      "cat /d/marker.txt; ls /d")
        assert "LIVE-KEYS" in got.stdout and "after.txt" not in got.stdout
    finally:
        for v in vols:
            _docker("docker", "volume", "rm", "-f", v)


@pytest.mark.docker
def test_an_archive_changed_after_the_backup_leaves_every_volume_as_it_was_live(tmp_path, monkeypatch, capsys):
    """Real volumes: the keys archive changed after the backup is refused before the keys volume is emptied."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    prefix = "dvarchlivebad" + uuid.uuid4().hex[:6]
    names = dv.set_volume_names(prefix)
    vols = [names["pg"], names["storage"], names["keys"]]
    env = _env(tmp_path, prefix)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    stopped = []
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)
    monkeypatch.setattr(tool, "_stop_stack", lambda: stopped.append(1))
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    try:
        try:
            for v in vols:
                _docker("docker", "volume", "create", v)
            seed = _docker("docker", "run", "--rm", "-v", names["keys"] + ":/d", "busybox", "sh", "-c",
                           "echo KEPT-KEYS > /d/marker.txt")
        except (subprocess.SubprocessError, OSError) as exc:
            pytest.skip("docker unavailable: %s" % exc)
        if seed.returncode != 0:
            pytest.skip("docker run unavailable: %s" % seed.stderr[:120])
        tool._do_backup(env, argparse.Namespace(non_interactive=True, backup_dir=str(tmp_path / "backups")))
        bundle = next((tmp_path / "backups").iterdir())
        keys = bundle / "vault_keys.tar.gz"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"PLANTED"
            info = tarfile.TarInfo("marker.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        keys.unlink()                         # written by the container's root: replaced, not rewritten
        keys.write_bytes(buf.getvalue())
        with pytest.raises(SystemExit):
            tool._do_restore(_restore_args(bundle))
        assert stopped == []
        got = _docker("docker", "run", "--rm", "-v", names["keys"] + ":/d:ro", "busybox", "cat", "/d/marker.txt")
        assert "KEPT-KEYS" in got.stdout, "the keys volume was not emptied"
        assert "is not the archive this backup made" in _said(capsys)
    finally:
        for v in vols:
            _docker("docker", "volume", "rm", "-f", v)


# --------------------------------------------------------------------------- a restore that stops part way

def _stopping(tmp_path, monkeypatch, capsys, fail, host="same-set"):
    """A restore of a backup of set dvarchstop that stops at `fail` (the second volume cannot be cleared, or does not
    extract; or the restore mark cannot be written after the keys volume). The host is on the same set, or on
    another set's .env. Returns (the steps, the names of the set's volumes, the host's .env bytes, what was said)."""
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchstop")
    if host == "another-set":
        _env(tmp_path, "dvarchhost")
    host_env = (tmp_path / ".env").read_bytes()
    names = dv.set_volume_names("dvarchstop")
    steps = []
    tool = _restoring_tool(tmp_path, monkeypatch, steps)
    monkeypatch.setattr(dv, "read_volume_json", lambda *a, **k: {"seq": 3, "link": "aa"})
    monkeypatch.setattr(dv, "write_volume_file", lambda vol, rel, text, **k: steps.append(("mark", vol))
                        or fail != "mark")
    if fail == "clear":
        monkeypatch.setattr(dv, "clear_volume", lambda vol, **k: steps.append(("clear", vol))
                            or vol != names["pg"])
    elif fail == "untar":
        monkeypatch.setattr(dv, "untar_volume", lambda vol, src, archive, **k: steps.append(("untar", vol, src))
                            or vol != names["pg"])
    elif fail == "changed":
        def untar(vol, src, archive, **k):
            steps.append(("untar", vol, src))
            if vol == names["pg"]:
                raise dv.ArchiveChanged("c" * 64)
            return True

        monkeypatch.setattr(dv, "untar_volume", untar)
    capsys.readouterr()
    with pytest.raises(SystemExit):
        tool._do_restore(_restore_args(bundle))
    return steps, names, host_env, _said(capsys)


def _again(tmp_path):
    bundle = next((tmp_path / "backups").iterdir())
    arg = '"%s"' % bundle if any(c.isspace() for c in str(bundle)) else str(bundle)
    return "python dockvault.py backup --action restore --bundle-dir %s --force" % arg


@pytest.mark.parametrize("host", ["same-set", "another-set"])
def test_a_restore_whose_volume_cannot_be_cleared_stops_there_with_the_way_back(tmp_path, monkeypatch, capsys, host):
    steps, names, host_env, said = _stopping(tmp_path, monkeypatch, capsys, "clear", host)
    assert steps[-1] == ("clear", names["pg"]), "nothing is extracted into a volume that was not cleared"
    assert not [s for s in steps if s[0] == "untar" and s[1] == names["pg"]]
    assert ("clear", names["storage"]) not in steps and ("start",) not in steps
    assert (tmp_path / ".env").read_bytes() == host_env, ".env is as it was"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".env.")], "no second copy of .env is left"
    assert "could not clear volume %s before restoring it" % names["pg"] in said
    assert "the deployment is stopped, .env is as it was" in said
    assert "replaced from the backup, or emptied in part, so far are: %s, %s" % (names["keys"], names["pg"]) in said
    assert _again(tmp_path) in said
    if host == "another-set":
        assert "The set the host was on, 'dvarchhost', is untouched: python dockvault.py start brings it back" in said
    else:
        assert "Do not start the deployment now" in said


def test_a_restore_whose_archive_does_not_extract_stops_there_with_the_way_back(tmp_path, monkeypatch, capsys):
    steps, names, host_env, said = _stopping(tmp_path, monkeypatch, capsys, "untar")
    assert steps[-1][:2] == ("untar", names["pg"])
    assert ("clear", names["storage"]) not in steps and ("start",) not in steps
    assert (tmp_path / ".env").read_bytes() == host_env
    assert "could not extract vault_pg_data.tar.gz into volume %s" % names["pg"] in said
    assert "the deployment is stopped" in said and "Do not start the deployment now" in said
    assert _again(tmp_path) in said


def test_a_restore_whose_mark_cannot_be_written_stops_before_any_other_volume(tmp_path, monkeypatch, capsys):
    """The mark keeps the audit log's pruner from deleting until the restore is accepted: without it, nothing else
    of the backup is restored."""
    steps, names, host_env, said = _stopping(tmp_path, monkeypatch, capsys, "mark")
    assert steps[-1] == ("mark", names["keys"])
    assert ("clear", names["pg"]) not in steps and ("start",) not in steps
    assert (tmp_path / ".env").read_bytes() == host_env
    assert "could not write the restore mark into volume %s" % names["keys"] in said
    assert "the volumes it replaced from the backup, or emptied in part, so far are: %s." % names["keys"] in said
    assert "the deployment is stopped" in said and _again(tmp_path) in said


# --------------------------------------------------------------------------- a restore that did not finish

def _marker(tmp_path, prefix="dvarchstop"):
    return tmp_path / (".restore-incomplete." + prefix)


def _starting(tool, monkeypatch, started):
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: started.append(1) or True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_print_status", lambda *a, **k: None)
    monkeypatch.setattr(dv, "docker_available", lambda **k: (True, "ok"))


@pytest.mark.parametrize("fail", ["clear", "untar", "changed", "mark"])
def test_a_restore_that_stopped_part_way_leaves_a_marker_and_start_refuses_that_set(tmp_path, monkeypatch, capsys,
                                                                                    fail):
    """The restore said not to start the set (its volumes hold part of a backup), but nothing kept anyone from it:
    start, restart, setup and update started it on those volumes. The marker the restore leaves stops them, and says
    the way back."""
    steps, names, host_env, said = _stopping(tmp_path, monkeypatch, capsys, fail)
    marker = _marker(tmp_path)
    doc = json.loads(marker.read_text(encoding="utf-8"))
    bundle = next((tmp_path / "backups").iterdir())
    assert doc["volume_prefix"] == "dvarchstop" and doc["bundle"] == str(bundle)
    assert doc["volumes"] == ([names["keys"]] if fail == "mark" else [names["keys"], names["pg"]])
    assert doc["backup_changed"] is (fail == "changed")
    assert ("Until set 'dvarchstop' is restored, start, restart, setup, update, storage, logs and audit change-key "
            "refuse to start it") in said
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    started = []
    _starting(tool, monkeypatch, started)
    with pytest.raises(SystemExit):
        tool.start()
    assert started == []
    said = _said(capsys)
    assert "start would start set 'dvarchstop', but a restore of set 'dvarchstop' from %s" % bundle in said
    assert "Nothing was started." in said and str(marker) in said
    if fail == "changed":
        assert "restore it from a copy of a backup of set 'dvarchstop' you trust" in said and _again(tmp_path) not in said
    else:
        assert "run the restore again (it starts over from the backup): %s" % _again(tmp_path) in said


def test_a_restore_of_another_set_that_stopped_part_way_does_not_keep_the_host_set_from_starting(tmp_path,
                                                                                                monkeypatch, capsys):
    """The host's own set is untouched: start brings it back, and says what the other set's restore left."""
    _stopping(tmp_path, monkeypatch, capsys, "untar", "another-set")
    assert _marker(tmp_path).exists() and not _marker(tmp_path, "dvarchhost").exists()
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    started = []
    _starting(tool, monkeypatch, started)
    tool.start()
    assert started == [1]
    assert "Note: a restore of set 'dvarchstop' from" in _said(capsys)


def test_a_restore_marks_the_set_before_it_changes_a_volume_and_removes_the_mark_once_it_is_whole(tmp_path,
                                                                                                 monkeypatch):
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchmark")
    marker = _marker(tmp_path, "dvarchmark")
    seen = []
    tool = _restoring_tool(tmp_path, monkeypatch, [])
    monkeypatch.setattr(dv, "clear_volume", lambda vol, **k: seen.append(("clear", marker.exists())) or True)
    real_install = tool._atomic_write_secret

    def install(path, data):
        seen.append(("write", os.path.basename(path), marker.exists()))
        return real_install(path, data)

    monkeypatch.setattr(tool, "_atomic_write_secret", install)
    monkeypatch.setattr(dv, "_copy_secret", lambda src, dst: seen.append(("env", marker.exists())) or shutil.copyfile(
        src, dst))
    tool._do_restore(_restore_args(bundle))
    clears = [s for s in seen if s[0] == "clear"]
    assert clears and all(present for _c, present in clears), "the mark is there before each volume is cleared"
    assert ("env", True) in seen, "and while the backup's .env is installed"
    assert not marker.exists(), "a restore that finished leaves no mark"


def test_a_restore_that_finishes_removes_the_mark_an_earlier_one_left(tmp_path, monkeypatch, capsys):
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchagain")
    marker = _marker(tmp_path, "dvarchagain")
    marker.write_text(json.dumps({"volume_prefix": "dvarchagain", "bundle": str(bundle)}), encoding="utf-8")
    steps = []
    _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(_restore_args(bundle))
    assert ("start",) in steps and not marker.exists()
    assert "an earlier restore of set 'dvarchagain' did not finish" in _said(capsys)


def test_a_restore_ended_by_ctrl_c_part_way_leaves_its_mark(tmp_path, monkeypatch):
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchctrlc")
    tool = _restoring_tool(tmp_path, monkeypatch, [])

    def untar(vol, src, archive, **k):
        if vol.endswith("_vault_pg_data"):
            raise KeyboardInterrupt
        return True

    monkeypatch.setattr(dv, "untar_volume", untar)
    with pytest.raises(KeyboardInterrupt):
        tool._do_restore(_restore_args(bundle))
    assert _marker(tmp_path, "dvarchctrlc").exists()


def test_a_restore_whose_mark_cannot_be_written_changes_no_volume(tmp_path, monkeypatch, capsys):
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchnomark")
    steps = []
    tool = _restoring_tool(tmp_path, monkeypatch, steps)

    def cannot(prefix, bundle, changed=(), backup_changed=False):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(tool, "_mark_restore_incomplete", cannot)
    with pytest.raises(SystemExit):
        tool._do_restore(_restore_args(bundle))
    assert steps == [("stop",)], "stopped, and no volume cleared or extracted"
    said = _said(capsys)
    assert "could not write %s" % _marker(tmp_path, "dvarchnomark") in said and "no volume was changed" in said
    assert not _marker(tmp_path, "dvarchnomark").exists()


def test_a_restore_that_stops_before_any_volume_keeps_the_mark_an_earlier_one_left(tmp_path, monkeypatch, capsys):
    """The volumes an earlier restore did not finish still hold part of a backup: a restore that stops before it
    changes any of them leaves that restore's mark as it is."""
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchkeep")
    marker = _marker(tmp_path, "dvarchkeep")
    earlier = json.dumps({"volume_prefix": "dvarchkeep", "bundle": "/b/earlier", "volumes": ["dvarchkeep_vault_keys"]})
    marker.write_text(earlier, encoding="utf-8")
    steps = []
    tool = _restoring_tool(tmp_path, monkeypatch, steps)

    def cannot(prefix, bundle, changed=(), backup_changed=False):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(tool, "_mark_restore_incomplete", cannot)
    with pytest.raises(SystemExit):
        tool._do_restore(_restore_args(bundle))
    assert steps == [("stop",)]
    assert marker.read_text(encoding="utf-8") == earlier
    said = _said(capsys)
    assert ("Until set 'dvarchkeep' is restored, start, restart, setup, update, storage, logs and audit change-key "
            "refuse to start it") in said
    assert "This restore changed nothing, but an earlier restore of the set did not finish" in said
    assert "start brings it back as it was" not in said


@pytest.mark.parametrize("command", ["restart", "setup", "update"])
def test_restart_setup_and_update_refuse_to_start_a_set_whose_restore_did_not_finish(tmp_path, monkeypatch, capsys,
                                                                                    command):
    _env(tmp_path, "dvarchcmd")
    _marker(tmp_path, "dvarchcmd").write_text(json.dumps({"volume_prefix": "dvarchcmd", "bundle": "/b/x"}),
                                              encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda **k: pytest.fail("%s went on" % command))
    monkeypatch.setattr(tool, "_tear_down_containers", lambda: pytest.fail("the deployment was taken down"))
    monkeypatch.setattr(tool, "_container_logs_readable", lambda: True)
    args = argparse.Namespace(non_interactive=True, no_start=False)
    with pytest.raises(SystemExit):
        getattr(tool, command)(args)
    said = _said(capsys)
    assert "%s would start set 'dvarchcmd', but a restore of set 'dvarchcmd' from /b/x" % command in said
    assert "Nothing was started." in said


class _Ran:
    returncode = 0
    stdout = stderr = ""


def _marked_tool(tmp_path, monkeypatch, prefix="dvarchcmd"):
    """The host on set `prefix`, whose restore did not finish (its marker there), with every compose command recorded
    instead of run (nothing real is touched). Returns (the tool, the compose commands, .env's bytes)."""
    _env(tmp_path, prefix)
    _marker(tmp_path, prefix).write_text(json.dumps({"volume_prefix": prefix, "bundle": "/b/x"}), encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    composed = []
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: composed.append(list(a)) or _Ran())
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, "ok"))
    monkeypatch.setattr(tool, "_container_logs_readable", lambda: True)
    monkeypatch.setattr(tool, "_stored_bytes", lambda: None)
    monkeypatch.setattr(tool, "_volume_capacity", lambda: None)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, **k: pytest.fail("the audit tool was asked"))
    return tool, composed, (tmp_path / ".env").read_bytes()


@pytest.mark.parametrize("command", ["storage", "logs", "audit change-key"])
def test_storage_logs_and_audit_change_key_refuse_a_set_whose_restore_did_not_finish(tmp_path, monkeypatch, capsys,
                                                                                    command):
    """Each writes .env and then recreates the stack (docker compose up): they started the set whose volumes a restore
    had half replaced. Each now refuses before it writes anything, and no compose up runs."""
    tool, composed, env_before = _marked_tool(tmp_path, monkeypatch)
    run = {"storage": lambda: tool.storage(argparse.Namespace(non_interactive=True, set_gb=64.0, set_transfers=None,
                                                              no_restart=False)),
           "logs": lambda: tool.logs(argparse.Namespace(non_interactive=True, enable=True)),
           "audit change-key": lambda: tool.audit(dv.build_parser().parse_args(["audit", "change-key", "--yes"]))}
    capsys.readouterr()
    with pytest.raises(SystemExit):
        run[command]()
    assert not [c for c in composed if "up" in c], "no compose up ran"
    assert (tmp_path / ".env").read_bytes() == env_before
    assert sorted(p.name for p in tmp_path.iterdir()) == [".env", ".restore-incomplete.dvarchcmd"]
    said = _said(capsys)
    assert "%s would start set 'dvarchcmd', but a restore of set 'dvarchcmd' from /b/x" % command in said
    assert "Nothing was changed" in said and str(_marker(tmp_path, "dvarchcmd")) in said


def test_storage_with_no_restart_still_writes_the_limit_of_a_set_whose_restore_did_not_finish(tmp_path, monkeypatch):
    """--no-restart starts nothing: the limit goes into .env as before."""
    tool, composed, _ = _marked_tool(tmp_path, monkeypatch)
    tool.storage(argparse.Namespace(non_interactive=True, set_gb=64.0, set_transfers=None, no_restart=True))
    assert dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))["MAX_STORAGE_GB"] == "64"
    assert not [c for c in composed if "up" in c]


@pytest.mark.parametrize("how", ["recreate", "recreate-with-build", "secure-start"])
def test_the_stack_of_a_set_whose_restore_did_not_finish_is_never_started_whatever_asks(tmp_path, monkeypatch, capsys,
                                                                                       how):
    """Every compose up of the stack goes through _recreate_stack: whatever asks for it (a command that has its own
    refusal, or one that has none yet), it refuses the set before anything is touched."""
    tool, composed, _ = _marked_tool(tmp_path, monkeypatch)
    monkeypatch.setattr(dv, "image_present", lambda *a, **k: True)
    start = {"recreate": lambda: tool._recreate_stack(build=False),
             "recreate-with-build": lambda: tool._recreate_stack(build=True),
             "secure-start": tool._start_secure_stack}[how]
    with pytest.raises(SystemExit):
        start()
    assert composed == [], "nothing was asked of compose, not even the removal of another profile's containers"
    said = _said(capsys)
    assert "set 'dvarchcmd' is not started: a restore of set 'dvarchcmd' from /b/x began" in said
    assert "Nothing was started." in said


def test_the_database_of_a_set_whose_restore_did_not_finish_is_not_started_to_check_env(tmp_path, monkeypatch, capsys):
    """The check of .env against an existing volume starts the set's database (compose up -d vault-db): on a volume a
    restore emptied, postgres would make a new database there. Not started; the check has no answer and says why."""
    tool, composed, _ = _marked_tool(tmp_path, monkeypatch)
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert tool._start_db_only() is False
    assert composed == []
    said = _said(capsys)
    assert "The database of set 'dvarchcmd' was not started to check .env: a restore of set 'dvarchcmd'" in said
    assert tool._guard_db_secret(env, interactive=False, exists_fn=lambda v: True,
                                 marker_fn=lambda v: None, stamp_fn=lambda v, e: None) is False
    assert not [c for c in composed if "up" in c], "the guard's own check started nothing either"


def test_setup_pointed_by_its_menu_at_a_set_whose_restore_did_not_finish_does_not_start_it(tmp_path, monkeypatch,
                                                                                         capsys):
    """Setup's refusal looked only at the set .env named when setup began. Its existing-volume menu (option 2) can
    install the .env of a set whose restore did not finish, and setup then started that set. It is refused once the
    menu is done, before anything is started."""
    _env(tmp_path, "dvarchhost")
    marked_text = (tmp_path / ".env").read_text(encoding="utf-8").replace("dvarchhost", "dvarchmenu")
    _marker(tmp_path, "dvarchmenu").write_text(json.dumps({"volume_prefix": "dvarchmenu", "bundle": "/b/x"}),
                                               encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv, "_cert_pair_present", lambda *a, **k: True)
    monkeypatch.setattr(dv, "apply_cert_owner", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv, "cert_readable_by_app_uid", lambda *a, **k: True)
    monkeypatch.setattr(dv, "port_free", lambda *a, **k: True)

    def option_2_installs_the_marked_sets_env(_env_now, **kwargs):
        (tmp_path / ".env").write_text(marked_text, encoding="utf-8")
        return True

    monkeypatch.setattr(tool, "_guard_db_secret", option_2_installs_the_marked_sets_env)
    started = []
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: started.append(1) or True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_print_setup_summary", lambda *a, **k: None)
    monkeypatch.setattr(dv, "ask", lambda *a, **k: "")
    with pytest.raises(SystemExit):
        tool.setup(argparse.Namespace(no_start=False, non_interactive=False))
    assert started == []
    said = _said(capsys)
    assert "setup would start set 'dvarchmenu', but a restore of set 'dvarchmenu' from /b/x" in said
    assert "Nothing was started." in said and _marker(tmp_path, "dvarchmenu").exists()


def test_setup_destroying_the_data_of_a_set_whose_restore_did_not_finish_removes_its_mark(tmp_path, monkeypatch):
    """Option 4 deletes the set's volumes (down -v), as Reset does: what the restore left is gone, and so is its mark,
    so that setup can start the set afresh."""
    tool, composed, _ = _marked_tool(tmp_path, monkeypatch)
    monkeypatch.setattr(dv, "flush_stdin", lambda: None)
    monkeypatch.setattr(dv, "confirm", lambda *a, **k: True)
    assert tool._destroy_data("dvarchcmd_vault_pg_data") is True
    assert ["down", "-v", "--remove-orphans"] in composed and not _marker(tmp_path, "dvarchcmd").exists()


def test_setup_whose_destroy_failed_does_not_go_on_as_if_the_data_were_gone(tmp_path, monkeypatch, capsys):
    """down -v that failed (a volume still in use) was taken as done: setup went on to start on the data it said it
    had destroyed. It now says so and goes back to the menu, the mark (if any) left as it was."""
    tool, composed, _ = _marked_tool(tmp_path, monkeypatch)
    monkeypatch.setattr(dv, "flush_stdin", lambda: None)
    monkeypatch.setattr(dv, "confirm", lambda *a, **k: True)

    class _Failed:
        returncode = 1

    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: composed.append(list(a)) or _Failed())
    assert tool._destroy_data("dvarchcmd_vault_pg_data") is False
    assert _marker(tmp_path, "dvarchcmd").exists()
    said = _said(capsys)
    assert "'docker compose down -v' failed (exit 1): the data was NOT destroyed" in said
    assert "Destroyed the old data" not in said


def test_a_restore_that_cannot_remove_its_mark_does_not_start_the_set(tmp_path, monkeypatch, capsys):
    """The restore finished, but its mark could not be removed: every start of the set refuses while it is there, so
    the restore says so and does not try."""
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchstuck")
    steps = []
    tool = _restoring_tool(tmp_path, monkeypatch, steps)
    monkeypatch.setattr(tool, "_drop_restore_incomplete", lambda prefix: False)
    with pytest.raises(SystemExit):
        tool._do_restore(_restore_args(bundle))
    assert ("start",) not in steps and [s for s in steps if s[0] == "untar"], "restored, and not started"
    said = _said(capsys)
    marker = _marker(tmp_path, "dvarchstuck")
    assert "WARNING: could not remove %s, though the restore finished" % marker in said
    assert "restored, but not started: delete %s, then start it (python dockvault.py start)." % marker in said


def test_reset_of_a_set_removes_the_mark_its_restore_left(tmp_path, monkeypatch):
    _env(tmp_path, "dvarchreset")
    marker = _marker(tmp_path, "dvarchreset")
    marker.write_text("{}", encoding="utf-8")
    other = _marker(tmp_path, "dvarchother")
    other.write_text("{}", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda **k: (True, "ok"))

    class _Ran:
        returncode = 0

    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: _Ran())
    tool.reset(argparse.Namespace(non_interactive=True, confirm=True))
    assert not marker.exists() and other.exists(), "another set's mark is that set's"


def _deployment_in(tmp_path, folder, prefix="dvarchglob", marked=True):
    """A deployment folder named `folder` under tmp_path, with set `prefix`'s .env and (when `marked`) the marker of a
    restore of that set that did not finish."""
    root = tmp_path / folder
    root.mkdir()
    _env(root, prefix)
    if marked:
        _marker(root, prefix).write_text(json.dumps({"volume_prefix": prefix, "bundle": "/b/x"}), encoding="utf-8")
    return root


@pytest.mark.parametrize("folder", ["vault[1]", "dv-[ab]-set"])
def test_a_restore_marker_is_found_in_a_folder_whose_name_holds_brackets(tmp_path, monkeypatch, capsys, folder):
    """The markers were looked for with the folder's own path read as a pattern: in vault[1] (brackets are ordinary in
    folder names) no marker was ever found, start started the set, and the next restore did not know an earlier one
    had not finished."""
    root = _deployment_in(tmp_path, folder)
    tool = dv.DockVault(dv.Palette(False), root=str(root))
    assert set(tool._incomplete_restores()) == {"dvarchglob"}
    started = []
    _starting(tool, monkeypatch, started)
    with pytest.raises(SystemExit):
        tool.start()
    assert started == []
    assert "start would start set 'dvarchglob', but a restore of set 'dvarchglob' from /b/x" in _said(capsys)


@pytest.mark.skipif(os.name == "nt", reason="* and ? cannot be in a folder's name on Windows")
@pytest.mark.parametrize("folder,beside", [("vault?", "vaultX"), ("vault*", "vault-old")])
def test_a_marker_of_another_folder_that_the_folders_name_would_match_is_not_this_ones(tmp_path, monkeypatch, folder,
                                                                                      beside):
    """Read as a pattern, vault? or vault* matched the folders beside it too: a marker of another deployment there,
    for a set of the same name, refused this one's start."""
    root = _deployment_in(tmp_path, folder, marked=False)
    _deployment_in(tmp_path, beside)
    tool = dv.DockVault(dv.Palette(False), root=str(root))
    assert tool._incomplete_restores() == {}
    started = []
    _starting(tool, monkeypatch, started)
    tool.start()
    assert started == [1]


def test_the_listings_of_a_folder_whose_name_holds_brackets_find_what_is_there(tmp_path):
    """The kept chain keys lock warns about, the plain-text .env copies status and lock name, and the backups a
    restore offers were looked for with the folder read as a pattern too: in a folder named with brackets none was
    found."""
    root = tmp_path / "vault[1]"
    root.mkdir()
    kept = root / (dv.KEPT_CHAIN_KEY + ".dvarchglob")
    kept.write_text("ab" * 32 + "\n", encoding="utf-8")
    (root / ".env.dvarchglob").write_text("X=1\n", encoding="utf-8")
    backups = tmp_path / "backups[1]"
    bundle = backups / "dockvault-dvarchglob-20261107-010203"
    bundle.mkdir(parents=True)
    tool = dv.DockVault(dv.Palette(False), root=str(root))
    assert dv.kept_chain_key_files(str(root)) == [str(kept)]
    assert tool._env_archives() == [str(root / ".env.dvarchglob")]
    assert tool._list_bundles(argparse.Namespace(backup_dir=str(backups))) == [str(bundle)]


# --------------------------------------------------------------------------- the extraction reads what was checked

def test_an_extraction_extracts_only_a_copy_whose_checksum_is_the_one_checked(tmp_path):
    """The archives are checked before anything is stopped, and each extraction reads its archive again: it copies
    the archive into its own container, hashes the copy, and extracts that copy only when it is the archive checked.
    Other bytes never reach tar (ArchiveChanged, nothing extracted), and a copy that could not be made extracts
    nothing."""
    calls = []
    good, other = "a" * 64, "b" * 64

    class _R:
        returncode, stdout, stderr = 0, "dv-sha256 %s\n" % good, ""

    def run(cmd, **k):
        calls.append(cmd)
        return _R()

    assert dv.untar_volume("v_keys", "/b", "vault_keys.tar.gz", run=run, sha256=good) is True
    script = calls[0][-1]
    assert "/b:/src:ro" in calls[0] and "v_keys:/dest" in calls[0]
    copy, check, extract = (script.index(s) for s in ('cp "$f" /tmp/dv-archive', '[ "$1" = %s ]' % good,
                                                       "tar xzf /tmp/dv-archive"))
    assert copy < script.index("sha256sum < /tmp/dv-archive") < check < extract, "the copy is checked, then extracted"
    assert "/src/vault_keys.tar.gz" in script and script.count("tar ") == 1, "tar reads the checked copy only"
    _R.returncode, _R.stdout = 6, "dv-sha256 %s\n" % other
    with pytest.raises(dv.ArchiveChanged) as changed:
        dv.untar_volume("v_keys", "/b", "vault_keys.tar.gz", run=run, sha256=good)
    assert changed.value.seen == other
    _R.returncode, _R.stdout = 4, ""
    assert dv.untar_volume("v_keys", "/b", "vault_keys.tar.gz", run=run, sha256=good) is False
    _R.returncode, _R.stdout = 1, "dv-sha256 %s\n" % good          # tar itself failed
    assert dv.untar_volume("v_keys", "/b", "vault_keys.tar.gz", run=run, sha256=good) is False
    calls.clear()
    assert dv.untar_volume("v_keys", "/b", "vault_keys.tar.gz", run=run, sha256="not; a checksum") is False
    assert calls == [], "nothing that is not a checksum reaches the script"
    # The look before anything is stopped copies the archive the same way, so it proves the extraction can (Docker
    # sees the file, and has room for the copy).
    _R.returncode, _R.stdout = 0, "dv-sha256 %s\n" % good
    assert _DIGEST_IN_DOCKER("/b", "vault_keys.tar.gz", run=run) == (good, "")
    look = calls[0][-1]
    assert look[:look.index("tar tzf")] == script[len("cd /dest || exit 5; "):script.index('[ "$1" =')]
    assert "tar tzf /tmp/dv-archive" in look


@pytest.mark.parametrize("made", ["with-checksums", "before-checksums"])
def test_each_extraction_is_handed_the_checksum_of_its_archive_as_checked(tmp_path, monkeypatch, made):
    bundle = (_backed_up(tmp_path, monkeypatch, "dvarchhand") if made == "with-checksums"
              else _old_backup(tmp_path, "dvarchhand"))
    handed = {}
    tool = _restoring_tool(tmp_path, monkeypatch, [])
    monkeypatch.setattr(dv, "untar_volume",
                        lambda vol, src, archive, **k: handed.update({archive: k.get("sha256")}) or True)
    tool._do_restore(_restore_args(bundle))
    assert handed == {a: _sha(bundle / a) for a in ("vault_keys.tar.gz", "vault_pg_data.tar.gz",
                                                     "vault_storage.tar.gz")}


@pytest.mark.parametrize("host", ["same-set", "another-set"])
def test_a_restore_whose_archive_changed_after_the_check_stops_there_and_not_back_to_that_backup(
        tmp_path, monkeypatch, capsys, host):
    """A bundle restored from a share or a removable disk, or one someone else can write while the restore waits
    for its confirmation, can change between the check and the extraction."""
    steps, names, host_env, said = _stopping(tmp_path, monkeypatch, capsys, "changed", host)
    assert steps[-1][:2] == ("untar", names["pg"])
    assert ("clear", names["storage"]) not in steps and ("start",) not in steps
    assert (tmp_path / ".env").read_bytes() == host_env
    bundle = next((tmp_path / "backups").iterdir())
    assert ("%s changed after the restore checked it (its copy taken for the extraction has the checksum %s): "
            "nothing of it was extracted, and volume %s, emptied for it, is empty"
            % (bundle / "vault_pg_data.tar.gz", "c" * 64, names["pg"])) in said
    assert _again(tmp_path) not in said, "never sent back to the backup that changed"
    assert "copy a backup of set 'dvarchstop' you trust into a folder only you can write, then restore from" in said
    if host == "another-set":
        assert "The set the host was on, 'dvarchhost', is untouched: python dockvault.py start brings it back" in said
    else:
        assert ("Do not start the deployment now: volume %s is empty and the volumes before it hold the backup's "
                "data" % names["pg"]) in said


@pytest.mark.docker
def test_an_extraction_of_real_bytes_is_checked_before_anything_is_extracted_live(tmp_path):
    """Real busybox: the copy in the container, its checksum (of the whole file as Docker read it), and nothing of an
    archive whose copy is not the one checked reaches the volume."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    vol = "dvarchread" + uuid.uuid4().hex[:6] + "_vault_storage"
    archive = _tgz(tmp_path / "vault_storage.tar.gz", {"a.txt": b"A" * 70000, "d/b.txt": b"B"})
    try:
        try:
            made = _docker("docker", "volume", "create", vol)
        except (subprocess.SubprocessError, OSError) as exc:
            pytest.skip("docker unavailable: %s" % exc)
        if made.returncode != 0:
            pytest.skip("docker volume create unavailable: %s" % made.stderr[:120])
        with pytest.raises(dv.ArchiveChanged) as changed:
            dv.untar_volume(vol, str(tmp_path), archive.name, sha256="0" * 64)
        assert changed.value.seen == _sha(archive)
        empty = _docker("docker", "run", "--rm", "-v", vol + ":/d:ro", "busybox", "sh", "-c", "ls -A /d | wc -l")
        assert empty.stdout.strip() == "0", "nothing of an archive that is not the one checked was extracted"
        assert dv.untar_volume(vol, str(tmp_path), archive.name, sha256=_sha(archive)) is True
        got = _docker("docker", "run", "--rm", "-v", vol + ":/d:ro", "busybox", "sh", "-c",
                      "cat /d/d/b.txt; wc -c /d/a.txt; ls -A /d")
        assert got.stdout.startswith("B") and "70000" in got.stdout
        assert "dv-archive" not in got.stdout, "the copy stays in the container, never in the volume"
    finally:
        _docker("docker", "volume", "rm", "-f", vol)


@pytest.mark.docker
def test_an_archive_swapped_after_the_restore_checked_it_is_caught_before_its_extraction_live(tmp_path, monkeypatch,
                                                                                               capsys):
    """Real volumes: the storage archive is replaced after the check (as on a share, during the confirmation): the
    extraction's copy is other bytes than the ones checked, nothing of it is extracted, and the restore stops there
    with the storage volume empty."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    prefix = "dvarchswap" + uuid.uuid4().hex[:6]
    names = dv.set_volume_names(prefix)
    vols = [names["pg"], names["storage"], names["keys"]]
    env = _env(tmp_path, prefix)
    host_env = (tmp_path / ".env").read_bytes()
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    started = []
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)
    monkeypatch.setattr(tool, "_stop_stack", lambda: None)
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: started.append(1) or True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    try:
        try:
            for v in vols:
                _docker("docker", "volume", "create", v)
            seed = _docker("docker", "run", "--rm", "-v", names["storage"] + ":/d", "busybox", "sh", "-c",
                           "echo STORED > /d/marker.txt")
        except (subprocess.SubprocessError, OSError) as exc:
            pytest.skip("docker unavailable: %s" % exc)
        if seed.returncode != 0:
            pytest.skip("docker run unavailable: %s" % seed.stderr[:120])
        tool._do_backup(env, argparse.Namespace(non_interactive=True, backup_dir=str(tmp_path / "backups")))
        bundle = next((tmp_path / "backups").iterdir())
        checked = tool._check_bundle_archives

        def check_then_swap(bundle_dir, plan, recorded):
            digests = checked(bundle_dir, plan, recorded)
            storage = Path(bundle_dir) / "vault_storage.tar.gz"
            storage.unlink()                      # written by the container's root: replaced, not rewritten
            _tgz(storage, {"marker.txt": b"PLANTED"})
            return digests

        monkeypatch.setattr(tool, "_check_bundle_archives", check_then_swap)
        capsys.readouterr()
        with pytest.raises(SystemExit):
            tool._do_restore(_restore_args(bundle))
        said = _said(capsys)
        assert "%s changed after the restore checked it" % (bundle / "vault_storage.tar.gz") in said
        assert "nothing of it was extracted, and volume %s, emptied for it, is empty" % names["storage"] in said
        assert "Do not start the deployment now: volume %s is empty" % names["storage"] in said
        assert started == [] and (tmp_path / ".env").read_bytes() == host_env
        left = _docker("docker", "run", "--rm", "-v", names["storage"] + ":/d:ro", "busybox", "sh", "-c",
                       "ls -A /d | wc -l")
        assert left.stdout.strip() == "0", "the planted archive never reached the volume"
    finally:
        for v in vols:
            _docker("docker", "volume", "rm", "-f", v)
