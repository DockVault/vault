"""A backup's archives, from the backup to the restore (dockvault.py: _do_backup, _do_restore).

A backup counts an archive only once it is on this host, not empty, and read through whole as a tar.gz, and it
records the archive's SHA-256 and size in its manifest. A sealed backup's manifest is authenticated as well, by a MAC
under the key its env.enc is sealed with. A restore takes the bundle's path as an absolute one, and before it stops or
clears anything it reads every archive through, checks it against what the backup recorded and checks that Docker
sees the same file through the mount the extraction uses. A changed archive, a changed sealed manifest, a manifest
recording some checksums only, and an archive Docker does not see are refused with nothing changed. A backup made
before backups recorded checksums is restored with a notice. Each extraction hashes the bytes it extracts and stops
the restore there when they are not the ones checked (the bundle can change in between). With real Docker: a backup
and a restore through a relative folder, an archive changed after the backup, which leaves the keys volume as it
was, and an archive changed after the check, which its extraction catches.
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
    _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(
        _restore_args(bundle, passphrase_file=str(tmp_path / "pass.txt")))
    assert steps[0] == ("stop",) and ("start",) in steps


def _old_backup(tmp_path, prefix, sealed=False):
    """A backup as a dockvault.py before checksums wrote it: entries without sha256/size, and no MAC."""
    env = _env(tmp_path, prefix)
    bundle = tmp_path / "old-bundle"
    bundle.mkdir()
    (bundle / "env").write_bytes((tmp_path / ".env").read_bytes())
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


def test_an_old_backup_whose_archive_does_not_read_whole_is_still_refused(tmp_path, monkeypatch, capsys):
    bundle = _old_backup(tmp_path, "dvarcholdbad")
    (bundle / "vault_storage.tar.gz").write_bytes(b"x")
    steps = []
    with pytest.raises(SystemExit):
        _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(_restore_args(bundle))
    assert steps == []
    assert "the archive for volume dvarcholdbad_vault_storage cannot be restored" in _said(capsys)


@pytest.mark.parametrize("manifest", ["some-only", "not-a-checksum", "not-a-size"])
def test_a_manifest_whose_checksums_no_backup_writes_is_refused(tmp_path, monkeypatch, capsys, manifest):
    bundle = _backed_up(tmp_path, monkeypatch, "dvarchodd")
    man = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    if manifest == "some-only":
        del man["volumes"][2]["sha256"], man["volumes"][2]["size"]
    elif manifest == "not-a-checksum":
        man["volumes"][0]["sha256"] = "not-hex"
    else:
        man["volumes"][0]["size"] = True
    (bundle / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
    steps = []
    with pytest.raises(SystemExit):
        _restoring_tool(tmp_path, monkeypatch, steps)._do_restore(_restore_args(bundle))
    assert steps == []


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
    """archive_digest_in_docker asks Docker the way the extraction reads: the bundle mounted read-only at /src,
    `tar tzf` through the whole archive, then its SHA-256."""
    calls = []

    class _R:
        returncode, stdout, stderr = 0, "%s  /src/vault_keys.tar.gz\n" % ("a" * 64), ""

    got = _DIGEST_IN_DOCKER("/b/dockvault-x", "vault_keys.tar.gz", run=lambda cmd, **k: calls.append(cmd) or _R())
    assert got == ("a" * 64, "")
    cmd = calls[0]
    assert "/b/dockvault-x:/src:ro" in cmd and "tar tzf" in cmd[-1] and "sha256sum" in cmd[-1]

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


# --------------------------------------------------------------------------- the extraction reads what was checked

def test_an_extraction_given_the_checked_checksum_hashes_the_bytes_it_extracts(tmp_path):
    """The archives are checked before anything is stopped, and each extraction reads its archive again: the
    extraction hashes what it reads, in the same read, and raises when that is not what was checked."""
    calls = []
    good, other = "a" * 64, "b" * 64

    class _R:
        returncode, stdout, stderr = 0, "%s  -\n" % good, ""

    def run(cmd, **k):
        calls.append(cmd)
        return _R()

    assert dv.untar_volume("v_keys", "/b", "vault_keys.tar.gz", run=run, sha256=good) is True
    script = calls[0][-1]
    assert "/b:/src:ro" in calls[0] and "v_keys:/dest" in calls[0]
    assert "tee /tmp/dv-sum" in script and "sha256sum < /tmp/dv-sum" in script and "tar xzf -" in script
    assert "tar xzf /src" not in script, "tar reads only the stream the checksum is taken of"
    _R.stdout = "%s  -\n" % other
    with pytest.raises(dv.ArchiveChanged) as changed:
        dv.untar_volume("v_keys", "/b", "vault_keys.tar.gz", run=run, sha256=good)
    assert changed.value.seen == other
    _R.stdout = ""
    with pytest.raises(dv.ArchiveChanged) as changed:
        dv.untar_volume("v_keys", "/b", "vault_keys.tar.gz", run=run, sha256=good)
    assert changed.value.seen is None
    _R.returncode = 1
    assert dv.untar_volume("v_keys", "/b", "vault_keys.tar.gz", run=run, sha256=good) is False
    # The look before anything is stopped reads the archive the same way, so it proves the extraction can.
    calls.clear()
    _R.returncode, _R.stdout = 0, "%s  -\n" % good
    assert _DIGEST_IN_DOCKER("/b", "vault_keys.tar.gz", run=run) == (good, "")
    assert calls[0][-1].replace("tar tzf - > /dev/null", "tar xzf -") == script.split("; ", 1)[1]


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
    assert ("%s changed after the restore checked it: what was extracted into volume %s is not the archive checked "
            "(its checksum as extracted is %s)" % (bundle / "vault_pg_data.tar.gz", names["pg"], "c" * 64)) in said
    assert _again(tmp_path) not in said, "never sent back to the backup that changed"
    assert "copy a backup of set 'dvarchstop' you trust into a folder only you can write, then restore from" in said
    if host == "another-set":
        assert "The set the host was on, 'dvarchhost', is untouched: python dockvault.py start brings it back" in said
    else:
        assert "Do not start the deployment now: volume %s holds data nobody checked" % names["pg"] in said


@pytest.mark.docker
def test_an_extraction_of_real_bytes_is_checked_in_the_same_read_live(tmp_path):
    """Real busybox: the FIFO, the tee and the drain give the checksum of the whole file as Docker read it."""
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
        assert dv.untar_volume(vol, str(tmp_path), archive.name, sha256=_sha(archive)) is True
        got = _docker("docker", "run", "--rm", "-v", vol + ":/d:ro", "busybox", "sh", "-c",
                      "cat /d/d/b.txt; wc -c /d/a.txt")
        assert got.stdout.startswith("B") and "70000" in got.stdout
        with pytest.raises(dv.ArchiveChanged) as changed:
            dv.untar_volume(vol, str(tmp_path), archive.name, sha256="0" * 64)
        assert changed.value.seen == _sha(archive)
    finally:
        _docker("docker", "volume", "rm", "-f", vol)


@pytest.mark.docker
def test_an_archive_swapped_after_the_restore_checked_it_is_caught_by_its_extraction_live(tmp_path, monkeypatch,
                                                                                            capsys):
    """Real volumes: the storage archive is replaced after the check (as on a share, during the confirmation): the
    extraction reads other bytes than the ones checked, and the restore stops there."""
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
        assert "Do not start the deployment now: volume %s holds data nobody checked" % names["storage"] in said
        assert started == [] and (tmp_path / ".env").read_bytes() == host_env
    finally:
        for v in vols:
            _docker("docker", "volume", "rm", "-f", v)
