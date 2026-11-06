"""The Let's Encrypt renewal hook dockvault.py installs (render_renewal_hook, install_renewal_hook,
refresh_renewal_hook).

certbot runs the hook as root, unattended, at each renewal. It used to run `docker compose` with the checkout's own
.env and compose file (which the account owning the checkout can change) and to re-own a file in the
certificate folder through a name that could be a link by then. Run here by bash against a real certificate pair and
a stand-in `docker`: it renews and restarts the container by name with nothing read from the checkout; a
certificate folder replaced by a link, writable by others, or owned by someone else stops it with nothing changed;
a pair that does not match stops it too. The hook file itself is written over its name, never through a link.

A setup re-run keeps the certificate it finds, so it never wrote the hook: an upgraded deployment kept the one an
earlier version wrote. A re-run as root now rewrites this deployment's hook (the one naming its certificate folder),
keeping the live folder it renews from; another deployment's hook, or one naming no folders, is left alone; run as
another user, it is left and the operator is told how to replace it.
"""
import argparse
import importlib.util
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from test_dockvault_tool import _reusable_env_cfg

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


def test_an_openssl_that_prints_nothing_stops_the_hook_with_nothing_changed(tmp_path):
    """Under set -e, a failing test in an && list stops nothing unless it is the list's last command: an openssl that
    printed nothing and answered 0 left "$_c" empty, the list failed at its first test, and the hook went on to swap
    in a pair nobody had checked and restart the container. The list's outcome stops it now."""
    host = _Host(tmp_path)
    silent = host.bin / "openssl"
    silent.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(silent, 0o755)
    before = host.held()
    r = host.run()
    assert r.returncode != 0
    assert host.held() == before and host.docker_calls() == []
    assert sorted(p.name for p in host.certs.iterdir()) == ["cert.pem", "key.pem"], "no staging left behind"
    assert ("dockvault renewal: the renewed certificate and key are not a pair, or openssl could not read them; "
            "nothing was renewed") in r.stderr


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


# --------------------------------------------------------------------------- a hook an earlier version wrote

def _hook_as_first_written(checkout, certs, server_name, service="vault"):
    """The renewal hook as dockvault.py wrote it before the hook stopped trusting the checkout: it runs docker
    compose, as root, with the checkout's .env and compose file."""
    return "\n".join([
        "#!/bin/bash",
        "# Written by dockvault.py - deploys a renewed Let's Encrypt cert into the vault stack and",
        "# restarts the API so uvicorn picks it up.",
        "set -e",
        'CD="%s"' % certs,
        'install -m 644 "/etc/letsencrypt/live/%s/fullchain.pem" "$CD/.new-cert.pem"' % server_name,
        'install -m 600 "/etc/letsencrypt/live/%s/privkey.pem"   "$CD/.new-key.pem"' % server_name,
        'mv "$CD/.new-key.pem"  "$CD/key.pem"',
        'mv "$CD/.new-cert.pem" "$CD/cert.pem"',
        'cd "%s" && docker compose --env-file "%s/.env" -f "%s/docker-compose.secure.yml" restart %s'
        % (checkout, checkout, checkout, service),
        "",
    ])


def _owners():
    return (0, os.getuid())


def test_a_setup_rerun_as_root_rewrites_an_earlier_versions_hook_for_its_certificate_folder(tmp_path):
    """A setup re-run keeps the certificate it finds and so never wrote the hook: an upgraded deployment kept the
    one that runs docker compose from the checkout as root."""
    certs = tmp_path / "certs"
    certs.mkdir()
    hook = tmp_path / "deploy" / "dockvault-vault.sh"
    hook.parent.mkdir()
    hook.write_text(_hook_as_first_written(tmp_path, certs, "vault.example.test"), encoding="utf-8")
    outcome, said = dv.refresh_renewal_hook(str(tmp_path), str(certs), "vault", owners=_owners(), hook=str(hook),
                                            is_root=True)
    assert outcome == "rewritten", said
    text = hook.read_text(encoding="utf-8")
    assert text == dv.render_renewal_hook(str(tmp_path), str(certs), "vault.example.test", "vault",
                                          live_dir="/etc/letsencrypt/live/vault.example.test", owners=_owners())
    assert "docker compose" not in text and "docker restart vault" in text
    assert stat.S_IMODE(hook.stat().st_mode) == 0o755
    assert "rewrote the Let's Encrypt renewal hook %s" % hook in said
    assert dv.refresh_renewal_hook(str(tmp_path), str(certs), "vault", owners=_owners(), hook=str(hook),
                                   is_root=True) == ("current", None)


def test_a_rewritten_hook_renews_from_the_live_folder_the_old_one_named(tmp_path):
    """A hook for other settings (here: owners the folder no longer has) is rewritten, and the new one renews."""
    host = _Host(tmp_path, owners=(os.getuid() + 1,))
    outcome, said = dv.refresh_renewal_hook(str(host.checkout), str(host.certs), "vault", owners=_owners(),
                                            hook=str(host.hook), is_root=True)
    assert outcome == "rewritten", said
    r = host.run()
    assert r.returncode == 0, r.stderr
    assert (host.certs / "key.pem").read_bytes() == (host.live / "privkey.pem").read_bytes()
    assert host.docker_calls() == ["restart vault"]


def test_a_hook_that_names_another_certificate_folder_is_left_alone(tmp_path):
    """One hook name serves the host: the hook of another checkout's deployment is that deployment's."""
    hook = tmp_path / "dockvault-vault.sh"
    before = _hook_as_first_written(tmp_path / "other", tmp_path / "other" / "certs", "other.example.test")
    hook.write_text(before, encoding="utf-8")
    (tmp_path / "certs").mkdir()
    assert dv.refresh_renewal_hook(str(tmp_path), str(tmp_path / "certs"), "vault", owners=_owners(),
                                   hook=str(hook), is_root=True) == ("none", None)
    assert hook.read_text(encoding="utf-8") == before


def test_without_root_an_outdated_hook_is_left_and_the_operator_is_told_how_to_replace_it(tmp_path):
    certs = tmp_path / "certs"
    certs.mkdir()
    hook = tmp_path / "dockvault-vault.sh"
    before = _hook_as_first_written(tmp_path, certs, "vault.example.test")
    hook.write_text(before, encoding="utf-8")
    outcome, said = dv.refresh_renewal_hook(str(tmp_path), str(certs), "vault", owners=_owners(), hook=str(hook),
                                            is_root=False)
    assert outcome == "not-root"
    assert hook.read_text(encoding="utf-8") == before
    assert "runs, as root, what this checkout's compose file and .env say" in said
    assert "Run setup again as root (sudo python3 dockvault.py setup) to replace it" in said


@pytest.mark.parametrize("hook_text", [None, "#!/bin/sh\necho something else\n"])
def test_no_hook_or_one_that_names_no_folders_is_not_written(tmp_path, hook_text):
    hook = tmp_path / "dockvault-vault.sh"
    if hook_text is not None:
        hook.write_text(hook_text, encoding="utf-8")
    outcome, said = dv.refresh_renewal_hook(str(tmp_path), str(tmp_path / "certs"), "vault", owners=_owners(),
                                            hook=str(hook), is_root=True)
    if hook_text is None:
        assert (outcome, said) == ("none", None) and not hook.exists()
    else:
        assert outcome == "unreadable" and "left as it is" in said
        assert hook.read_text(encoding="utf-8") == hook_text


@pytest.mark.parametrize("this_folder_first", [True, False])
def test_a_hook_that_names_two_certificate_folders_is_left_as_it_is(tmp_path, this_folder_first):
    """Which deployment such a hook serves cannot be told (each of its `CD=` lines names one), so neither line is taken
    for its folder: it is not rewritten, nor passed over as another deployment's."""
    certs = tmp_path / "certs"
    certs.mkdir()
    lines = _hook_as_first_written(tmp_path, certs, "vault.example.test").split("\n")
    at = next(i for i, line in enumerate(lines) if line.startswith("CD="))
    other = 'CD="%s"' % (tmp_path / "other" / "certs")
    lines.insert(at + 1 if this_folder_first else at, other)
    before = "\n".join(lines)
    assert [line for line in lines if line.startswith("CD=")][1 if this_folder_first else 0] == other
    hook = tmp_path / "dockvault-vault.sh"
    hook.write_text(before, encoding="utf-8")
    assert dv.renewal_hook_targets(before) is None
    outcome, said = dv.refresh_renewal_hook(str(tmp_path), str(certs), "vault", owners=_owners(), hook=str(hook),
                                            is_root=True)
    assert outcome == "unreadable" and "left as it is" in said
    assert hook.read_text(encoding="utf-8") == before


def test_a_hook_that_names_two_live_folders_names_none():
    text = ('CD="/srv/certs"\nLIVE="/etc/letsencrypt/live/a.example.test"\n'
            'LIVE="/etc/letsencrypt/live/b.example.test"\n')
    assert dv.renewal_hook_targets(text) is None
    assert dv.renewal_hook_targets(text.rsplit("LIVE=", 1)[0]) == ("/srv/certs", "/etc/letsencrypt/live/a.example.test")


@pytest.mark.parametrize("profile, service", [("combined", "vault"), ("split", "vault-api")])
def test_a_setup_rerun_that_keeps_the_certificate_brings_its_renewal_hook_up_to_date(tmp_path, monkeypatch, capsys,
                                                                                      profile, service):
    cfg = dict(_reusable_env_cfg(), compose_profiles=profile)
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(cfg)) + "\n", encoding="utf-8")
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "cert.pem").write_text("cert\n", encoding="utf-8")
    (certs / "key.pem").write_text("key\n", encoding="utf-8")
    seen = []
    monkeypatch.setattr(dv, "refresh_renewal_hook", lambda app_dir, cert_dir, svc, **k: seen.append(
        (app_dir, cert_dir, svc)) or ("rewritten", "rewrote the Let's Encrypt renewal hook HOOK"))
    monkeypatch.setattr(dv, "apply_cert_owner", lambda cert_dir, **k: (True, ""))
    monkeypatch.setattr(dv, "tighten_secret_file", lambda path: True)
    dv.DockVault(dv.Palette(False), root=str(tmp_path)).setup(argparse.Namespace(no_start=True,
                                                                                 non_interactive=True))
    assert seen == [(str(tmp_path), str(certs), service)]
    assert "rewrote the Let's Encrypt renewal hook HOOK." in capsys.readouterr().out
