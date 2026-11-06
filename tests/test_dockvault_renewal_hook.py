"""The Let's Encrypt renewal hook dockvault.py installs (render_renewal_hook, install_renewal_hook).

certbot runs the hook as root, unattended, at each renewal. It used to run `docker compose` with the checkout's own
.env and compose file (which the account owning the checkout can change) and to re-own a file in the
certificate folder through a name that could be a link by then. Run here by bash against a real certificate pair and
a stand-in `docker`: it renews and restarts the container by name with nothing read from the checkout; a
certificate folder replaced by a link, writable by others, or owned by someone else stops it with nothing changed;
a pair that does not match stops it too. The hook file itself is written over its name, never through a link.
"""
import importlib.util
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("dockvault_hook_mod", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)


def _gnu_tools():
    if os.name == "nt" or not shutil.which("bash") or not shutil.which("openssl"):
        return False
    probe = subprocess.run(["stat", "-c", "%u", "."], capture_output=True, text=True)
    return probe.returncode == 0 and probe.stdout.strip().isdigit()


pytestmark = [pytest.mark.unit,
              pytest.mark.skipif(not _gnu_tools(), reason="the hook is Linux's: bash, GNU stat, openssl")]


def _pair(folder, name="test"):
    folder.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=%s" % name, "-keyout", str(folder / "privkey.pem"),
                        "-out", str(folder / "fullchain.pem")], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-300:]
    return folder


class _Host:
    """A checkout, a certificate folder holding the current pair, a renewed pair where certbot leaves it, and a
    `docker` that records what it was asked."""

    def __init__(self, tmp_path, owners=None):
        self.live = _pair(tmp_path / "live")
        self.certs = tmp_path / "certs"
        old = _pair(tmp_path / "old", "old")
        self.certs.mkdir(mode=0o700)
        os.chmod(self.certs, 0o700)
        shutil.copy(old / "fullchain.pem", self.certs / "cert.pem")
        shutil.copy(old / "privkey.pem", self.certs / "key.pem")
        os.chmod(self.certs / "key.pem", 0o600)
        self.checkout = tmp_path / "checkout"
        self.checkout.mkdir()
        (self.checkout / ".env").write_text("COMPOSE_PROFILES=combined\n", encoding="utf-8")
        (self.checkout / "docker-compose.secure.yml").write_text("services: {}\n", encoding="utf-8")
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.log = tmp_path / "docker.log"
        fake = self.bin / "docker"
        fake.write_text('#!/bin/sh\necho "$@" >> "$DOCKER_LOG"\n', encoding="utf-8")
        os.chmod(fake, 0o755)
        self.hook = tmp_path / "hook.sh"
        self.hook.write_text(dv.render_renewal_hook(
            str(self.checkout), str(self.certs), "vault.example.test", "vault", live_dir=str(self.live),
            owners=owners if owners is not None else (0, os.getuid())), encoding="utf-8")

    def run(self):
        env = dict(os.environ, PATH="%s%s%s" % (self.bin, os.pathsep, os.environ.get("PATH", "")),
                   DOCKER_LOG=str(self.log))
        return subprocess.run(["bash", str(self.hook)], capture_output=True, text=True, env=env, timeout=120,
                              cwd=str(self.checkout))

    def docker_calls(self):
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def held(self):
        return {p.name: p.read_bytes() for p in self.certs.iterdir()} if self.certs.is_dir() else {}


def test_the_hook_renews_the_pair_and_restarts_the_container_by_name_reading_nothing_of_the_checkout(tmp_path):
    host = _Host(tmp_path)
    r = host.run()
    assert r.returncode == 0, r.stderr
    assert (host.certs / "key.pem").read_bytes() == (host.live / "privkey.pem").read_bytes()
    assert (host.certs / "cert.pem").read_bytes() == (host.live / "fullchain.pem").read_bytes()
    assert stat.S_IMODE((host.certs / "key.pem").stat().st_mode) == 0o600, "the live key's mode is kept"
    assert sorted(p.name for p in host.certs.iterdir()) == ["cert.pem", "key.pem"], "no staging left behind"
    assert host.docker_calls() == ["restart vault"], "docker is given no file of the checkout"


@pytest.mark.parametrize("change", ["a-link-in-its-place", "writable-by-others", "owned-by-someone-else"])
def test_a_certificate_folder_that_is_not_the_one_setup_made_stops_the_hook_with_nothing_changed(tmp_path, change):
    """The account owning the checkout can replace certs/ (it owns the folder above it). Root then must not write
    the key wherever that leads, nor into a folder others can put names in."""
    host = _Host(tmp_path, owners=(os.getuid() + 1,) if change == "owned-by-someone-else" else None)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    if change == "a-link-in-its-place":
        os.rename(host.certs, tmp_path / "certs-moved")
        os.symlink(str(elsewhere), str(host.certs))
    elif change == "writable-by-others":
        os.chmod(host.certs, 0o770)
    before = host.held()
    r = host.run()
    assert r.returncode != 0
    assert "nothing was renewed" in r.stderr
    assert host.docker_calls() == []
    assert list(elsewhere.iterdir()) == [], "nothing was written where the link led"
    if change != "a-link-in-its-place":
        assert host.held() == before


def test_a_renewed_pair_that_does_not_match_is_not_installed(tmp_path):
    host = _Host(tmp_path)
    other = _pair(tmp_path / "other", "other")
    shutil.copy(other / "privkey.pem", host.live / "privkey.pem")
    before = host.held()
    r = host.run()
    assert r.returncode != 0
    assert host.held() == before and host.docker_calls() == []
    assert sorted(p.name for p in host.certs.iterdir()) == ["cert.pem", "key.pem"]


def test_the_hook_file_is_written_over_its_name_never_through_a_link(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("leave me\n", encoding="utf-8")
    hook = tmp_path / "deploy" / "dockvault-vault.sh"
    hook.parent.mkdir()
    os.symlink(str(victim), str(hook))
    assert dv.install_renewal_hook(str(tmp_path), str(tmp_path / "certs"), "vault.example.test", "vault",
                                   hook=str(hook)) is True
    assert victim.read_text(encoding="utf-8") == "leave me\n"
    assert not hook.is_symlink() and stat.S_IMODE(hook.stat().st_mode) == 0o755
    assert "docker restart vault" in hook.read_text(encoding="utf-8")
    assert [p.name for p in hook.parent.iterdir()] == ["dockvault-vault.sh"]
