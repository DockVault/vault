"""The host tool's setup (dockvault.py): the lines a fresh .env carries over from the one before it, the flags setup
takes, the files it copies into certs/ and checks the vault container can read, and what its summary says. Offline:
Docker is never asked."""
import argparse
import importlib.util
import os
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("dockvault_setup_mod", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)

# The passkey settings that take a deployment value from .env under their own names (app/core/webauthn_settings.py).
PASSKEY_ENV = ("WEBAUTHN_MODE", "WEBAUTHN_REQUIRED_ROLES", "WEBAUTHN_ENROLLMENT_GRACE_DAYS", "WEBAUTHN_SIGN_IN",
               "WEBAUTHN_REQUIRE_UV", "WEBAUTHN_ALLOWED_ALGS", "WEBAUTHN_DEVICE_BOUND_ROLES")


@pytest.fixture(autouse=True)
def _keep_secret_acl_changes_hermetic(monkeypatch):
    """No test here changes the host ACL of its temporary secret files."""
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)


def _example():
    """.env.example, read as words: the backticks around a command are left out."""
    return (ROOT / ".env.example").read_text(encoding="utf-8").replace("`", "")


def _comment_block(text, line_start):
    """The comment that runs on from the line starting with ``line_start`` (its continuation lines too), as one
    line of words."""
    at = text.index(line_start)
    lines = []
    for raw in text[at:].splitlines():
        if lines and (not raw.lstrip().startswith("#") or re.match(r"# [A-Z_]+=", raw)):
            break
        lines.append(raw.strip().lstrip("#").strip())
    return " ".join(" ".join(lines).split())


def _lines(cfg):
    return dv.build_env_lines({**cfg, "server_name": "vault.example.com"})


# --------------------------------------------------------------------------- the passkey settings' .env values

def test_the_example_file_lists_each_passkey_setting_and_the_lock_names_their_group():
    text = _example()
    for name in PASSKEY_ENV:
        assert re.search(r"^# %s=" % name, text, re.M), name
    said = _comment_block(text, "# SETTINGS_LOCKED_KEYS=")
    assert ("The group webauthn (or each passkey setting by name, webauthn_mode and the others) locks the passkey "
            "settings of Settings, Sign-in methods at their WEBAUTHN_* values above") in said
    assert ("Attestation and the allowed authenticator makes have no .env value: locked, they stay at none and any "
            "make. * locks them, and the group sso, too.") in said


def test_the_example_file_says_whose_value_wins_and_what_a_requirement_set_there_skips():
    said = " ".join(line.lstrip("#").strip() for line in _example().split("# WEBAUTHN_MODE=")[0][-1600:].splitlines())
    said = " ".join(said.split())
    assert ("These are the deployment's values: an administrator's change in Settings, Sign-in methods replaces them "
            "unless SETTINGS_LOCKED_KEYS names the key or the group webauthn.") in said
    assert ("A requirement set here skips the panel's checks (that the vault's address can make a passkey, and that "
            "an administrator can still sign in): the grace period and python dockvault.py accounts --action "
            "clear-passkey-requirement are the safety net.") in said


def test_the_attestation_roots_line_says_how_a_change_to_it_takes_effect():
    text = _example()
    entry = text[text.index("# Passkeys: the file of root certificates"):text.index("# WEBAUTHN_ATTESTATION_ROOTS=")]
    said = " ".join(" ".join(line.lstrip("#").strip() for line in entry.splitlines()).split())
    assert ("A change to this line takes effect when the vault is restarted with python dockvault.py restart (a plain "
            "docker restart keeps the old environment).") in said


def test_a_fresh_volume_set_keeps_the_passkey_settings_the_old_env_gave():
    old = {"WEBAUTHN_MODE": "off", "WEBAUTHN_REQUIRED_ROLES": "admin, user", "WEBAUTHN_SIGN_IN": "",
           "WEBAUTHN_ENROLLMENT_GRACE_DAYS": "30", "WEBAUTHN_REQUIRE_UV": "false",
           "WEBAUTHN_ALLOWED_ALGS": "ES256", "WEBAUTHN_DEVICE_BOUND_ROLES": "admin"}
    lines = _lines(dv.new_set_config(old, "prefix-1", "dep-1"))
    written = dv.parse_env("\n".join(lines))
    for name, value in old.items():
        assert written.get(name) == value, (name, lines)
    # An empty line says something (no role signs in with a passkey alone): it is kept, not dropped.
    assert "WEBAUTHN_SIGN_IN=" in lines
    # Only what the old .env set is written: the others keep taking the default.
    one = dv.parse_env("\n".join(_lines(dv.new_set_config({"WEBAUTHN_MODE": "off"}, "prefix-1", "dep-1"))))
    assert one["WEBAUTHN_MODE"] == "off" and not [k for k in one if k.startswith("WEBAUTHN_") and k != "WEBAUTHN_MODE"]
    plain = _lines(dv.new_set_config({}, "prefix-1", "dep-1"))
    assert not [line for line in plain if line.startswith("WEBAUTHN_")], plain


def test_each_passkey_line_of_the_example_file_uncommented_keeps_its_value_in_a_fresh_volume_set():
    """An operator uncomments a line of the example file. The vault reads it as docker compose does, and a fresh
    volume set made from that .env must carry the same value, or the new set's vault refuses to start."""
    lines = [line for line in _example().splitlines()
             if re.match(r"# WEBAUTHN_[A-Z_]+=", line) and not line.startswith("# WEBAUTHN_ATTESTATION_ROOTS=")]
    assert sorted(line[2:].split("=", 1)[0] for line in lines) == sorted(PASSKEY_ENV)
    # Each note stands on its own line, above its setting, never after a value.
    assert not [line for line in lines if "#" in line[1:]], lines
    text = "\n".join(line[2:] for line in lines) + "\n"
    env = dv.parse_env(text)
    assert env == dv.compose_env_values(text, PASSKEY_ENV, environ={})
    assert env == {"WEBAUTHN_MODE": "optional", "WEBAUTHN_REQUIRED_ROLES": "", "WEBAUTHN_ENROLLMENT_GRACE_DAYS": "14",
                   "WEBAUTHN_SIGN_IN": "user,external", "WEBAUTHN_REQUIRE_UV": "true",
                   "WEBAUTHN_ALLOWED_ALGS": "ES256,RS256,EdDSA", "WEBAUTHN_DEVICE_BOUND_ROLES": ""}
    written = "\n".join(_lines(dv.new_set_config(env, "prefix-1", "dep-1"))) + "\n"
    assert dv.compose_env_values(written, PASSKEY_ENV, environ={}) == env


def test_a_note_after_a_value_is_dropped_as_docker_compose_drops_it():
    """An .env written from the earlier example file can carry a note after a value. parse_env reads it as docker
    compose does: an unquoted value ends before " #"."""
    text = ("A=optional                    # off, optional or required_for_roles\n"
            "B=                  # with required_for_roles\n"
            "C='x # y'\n"
            "D=x#y\n"
            "E=\"two words\"\n")
    parsed = dv.parse_env(text)
    assert parsed == dv.compose_env_values(text, list("ABCDE"), environ={})
    assert parsed["A"] == "optional" and parsed["C"] == "x # y" and parsed["D"] == "x#y"
    # A fresh volume set made from such a .env carries the value alone.
    old = dv.parse_env("WEBAUTHN_SIGN_IN=user,external            # roles a passkey signs in alone\n")
    assert "WEBAUTHN_SIGN_IN=user,external" in _lines(dv.new_set_config(old, "prefix-1", "dep-1"))


# --------------------------------------------------------------------------- the certificate authorities of a provider

def test_the_example_file_says_where_a_providers_private_authority_goes_and_that_a_proxy_is_honoured():
    text = _example()
    assert re.search(r"^# SSO_CA_BUNDLE=/app/certs/", text, re.M)
    block = text[text.index("# Single sign-on: the certificate authorities"):text.index("# SSO_CA_BUNDLE=")]
    said = " ".join(" ".join(line.lstrip("#").strip() for line in block.splitlines()).split())
    assert "added to the image's trust store for the calls to providers only" in said
    assert "Put the file in certs/ (the HTTPS compose mounts that folder, read-only, at /app/certs)" in said
    assert "While the file named here cannot be read, no provider can be reached, and the container log says why." in said
    assert "HTTPS_PROXY and NO_PROXY in .env are honoured for the calls to providers." in said


def test_a_fresh_volume_set_keeps_the_providers_authorities_and_status_says_when_the_file_is_not_in_certs(
        tmp_path, monkeypatch):
    lines = _lines(dv.new_set_config({"SSO_CA_BUNDLE": "/app/certs/sso-ca.pem"}, "prefix-1", "dep-1"))
    assert "SSO_CA_BUNDLE=/app/certs/sso-ca.pem" in lines
    assert not [line for line in _lines(dv.new_set_config({}, "prefix-1", "dep-1")) if line.startswith("SSO_CA")]
    # A backup does not carry certs/: status and a restore say when the file .env names is not there.
    assert "SSO_CA_BUNDLE" in [key for key, _label, _follows in dv.CERTS_FILE_SETTINGS]
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_passkey_addresses", lambda: None)
    monkeypatch.setattr(dv, "cert_self_issued", lambda path: None)
    printed = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: printed.append(" ".join(str(x) for x in a)))
    tool._print_sign_in_lines({"ALLOWED_HOSTS": "vault.example.com", "SSO_CA_BUNDLE": "/app/certs/sso-ca.pem"})
    assert ("  Single sign-on: SSO_CA_BUNDLE names /app/certs/sso-ca.pem, and certs/sso-ca.pem does not exist (a "
            "backup does not carry certs/): copy the file there.") in printed, printed


# --------------------------------------------------------------------------- the attestation roots file

PEM = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


def _reusable_env(tmp_path, **extra):
    cfg = {"server_name": "vault.example.com", "encryption_key": dv.gen_fernet_key(), "jwt_secret_key": dv.gen_hex(32),
           "vault_db_password": dv.gen_hex(16), "redis_password": dv.gen_hex(24), "admin_username": "admin",
           "admin_email": "a@example.com", "admin_password": "Strong-Pass-1234", "compose_profiles": "combined",
           **extra}
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(cfg)) + "\n", encoding="utf-8")


def _quiet_certificate_step(monkeypatch, owned=None):
    """The certificate step without openssl, chown or Docker: a pair is made by writing two files, and the files
    handed to the container's user are noted in ``owned``."""
    def made(cert_dir, *a, **k):
        os.makedirs(cert_dir, exist_ok=True)
        for name in ("cert.pem", "key.pem"):
            with open(os.path.join(cert_dir, name), "w", encoding="utf-8") as fh:
                fh.write("x\n")
        return True, "made the pair"

    def owner(cert_dir, **k):
        if owned is not None:
            owned.append(tuple(k.get("extra") or ()))
        return True, ""
    monkeypatch.setattr(dv, "generate_self_signed_cert", made)
    monkeypatch.setattr(dv, "apply_cert_owner", owner)
    monkeypatch.setattr(dv, "refresh_renewal_hook", lambda *a, **k: (None, ""))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (False, "not in a unit test"))


def _setup_args(**kw):
    base = dict(no_start=True, non_interactive=True, cert_mode="selfsigned")
    base.update(kw)
    return argparse.Namespace(**base)


def test_setup_copies_the_attestation_roots_into_certs_and_names_them_in_env(tmp_path, monkeypatch):
    roots = tmp_path / "vendor-roots.pem"
    roots.write_bytes(PEM)
    owned = []
    _quiet_certificate_step(monkeypatch, owned)
    root = tmp_path / "deployment"
    root.mkdir()
    tool = dv.DockVault(dv.Palette(False), root=str(root))
    # A fresh install: the line is in the .env setup writes.
    tool.setup(_setup_args(server_name="vault.example.com", webauthn_attestation_roots=str(roots)))
    assert (root / "certs" / "vendor-roots.pem").read_bytes() == PEM
    assert dv.parse_env((root / ".env").read_text(encoding="utf-8"))["WEBAUTHN_ATTESTATION_ROOTS"] == \
        "/app/certs/vendor-roots.pem"
    # The container's user is given the file with the TLS pair.
    assert owned and "vendor-roots.pem" in owned[-1], owned
    # A re-run over that .env: another file replaces the line, and the setting is the only one changed.
    other = tmp_path / "other-roots.pem"
    other.write_bytes(PEM + PEM)
    before = dv.parse_env((root / ".env").read_text(encoding="utf-8"))
    tool.setup(_setup_args(webauthn_attestation_roots=str(other)))
    after = dv.parse_env((root / ".env").read_text(encoding="utf-8"))
    assert after["WEBAUTHN_ATTESTATION_ROOTS"] == "/app/certs/other-roots.pem"
    assert {k: v for k, v in after.items() if k != "WEBAUTHN_ATTESTATION_ROOTS"} == \
        {k: v for k, v in before.items() if k != "WEBAUTHN_ATTESTATION_ROOTS"}
    assert (root / "certs" / "other-roots.pem").read_bytes() == PEM + PEM
    assert "other-roots.pem" in owned[-1], owned
    # The example file says so beside the line.
    said = " ".join(_example().split())
    assert ("# python dockvault.py setup --webauthn-attestation-roots <file> copies a file into certs/ and writes "
            "# this line; each time setup starts the vault, it says when the vault container cannot read the "
            "file.") in said


@pytest.mark.parametrize("locked, said, held", [
    (None, "Copied {src} to certs/roots.pem. The file alone turns nothing on: an administrator chooses Direct for "
           "Attestation (an advanced setting) in Settings -> Sign-in methods.", False),
    ("webauthn", "Copied {src} to certs/roots.pem. SETTINGS_LOCKED_KEYS in .env holds Attestation at None, so "
                 "direct attestation cannot be turned on until the lock names neither *, the group webauthn nor "
                 "webauthn_attestation.", True),
    ("audit_levels;*", "SETTINGS_LOCKED_KEYS in .env holds Attestation at None", True),
    ("WEBAUTHN_ATTESTATION", "SETTINGS_LOCKED_KEYS in .env holds Attestation at None", True),
    ("webauthn_mode,audit_levels", "The file alone turns nothing on: an administrator chooses Direct", False),
], ids=["unlocked", "group", "all", "key", "other-keys"])
def test_setup_says_the_attestation_roots_turn_nothing_on_and_when_a_lock_holds_attestation_at_none(
        tmp_path, monkeypatch, capsys, locked, said, held):
    source = tmp_path / "roots.pem"
    source.write_bytes(PEM)
    _quiet_certificate_step(monkeypatch)
    root = tmp_path / "deployment"
    root.mkdir()
    _reusable_env(root, **({"settings_locked_keys": locked} if locked else {}))
    tool = dv.DockVault(dv.Palette(False), root=str(root))
    tool.setup(_setup_args(webauthn_attestation_roots=str(source)))
    out = " ".join(capsys.readouterr().out.split())
    assert said.format(src=source) in out, out
    # The file alone turns nothing on: setup never says that direct attestation is on.
    assert "Direct attestation is turned on" not in out
    assert ("holds Attestation at None" in out) is held
    assert ("an administrator chooses Direct" in out) is not held


@pytest.mark.parametrize("name, body, said", [
    ("missing.pem", None, "is not a file"),
    ("roots.pem", b"not a certificate\n", "holds no PEM certificate"),
    ("key.pem", PEM, "the name of the TLS pair's"),
    ("my roots.pem", PEM, "letters, digits"),
])
def test_setup_refuses_an_attestation_roots_file_it_cannot_use_and_changes_nothing(tmp_path, monkeypatch, capsys,
                                                                                   name, body, said):
    source = tmp_path / "given" / name
    source.parent.mkdir()
    if body is not None:
        source.write_bytes(body)
    _quiet_certificate_step(monkeypatch)
    root = tmp_path / "deployment"
    root.mkdir()
    _reusable_env(root)
    env_before = (root / ".env").read_text(encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(root))
    with pytest.raises(SystemExit):
        tool.setup(_setup_args(webauthn_attestation_roots=str(source)))
    assert said in capsys.readouterr().out
    assert (root / ".env").read_text(encoding="utf-8") == env_before
    assert not (root / "certs" / name).exists()


def test_setup_copies_a_providers_certificate_authorities_into_certs_and_names_them_in_env(tmp_path, monkeypatch,
                                                                                           capsys):
    bundle = tmp_path / "corp-ca.pem"
    bundle.write_bytes(PEM)
    owned = []
    _quiet_certificate_step(monkeypatch, owned)
    root = tmp_path / "deployment"
    root.mkdir()
    tool = dv.DockVault(dv.Palette(False), root=str(root))
    # A fresh install: the line is in the .env setup writes, and the container's user is given the file.
    tool.setup(_setup_args(server_name="vault.example.com", sso_ca_bundle=str(bundle)))
    assert (root / "certs" / "corp-ca.pem").read_bytes() == PEM
    assert dv.parse_env((root / ".env").read_text(encoding="utf-8"))["SSO_CA_BUNDLE"] == "/app/certs/corp-ca.pem"
    assert owned and "corp-ca.pem" in owned[-1], owned
    assert "Copied %s to certs/corp-ca.pem." % bundle in capsys.readouterr().out
    # A re-run with both flags: each setting is written, and nothing else changes.
    roots = tmp_path / "roots.pem"
    roots.write_bytes(PEM + PEM)
    before = dv.parse_env((root / ".env").read_text(encoding="utf-8"))
    tool.setup(_setup_args(sso_ca_bundle=str(bundle), webauthn_attestation_roots=str(roots)))
    after = dv.parse_env((root / ".env").read_text(encoding="utf-8"))
    assert after["SSO_CA_BUNDLE"] == "/app/certs/corp-ca.pem"
    assert after["WEBAUTHN_ATTESTATION_ROOTS"] == "/app/certs/roots.pem"
    assert {k: v for k, v in after.items() if k != "WEBAUTHN_ATTESTATION_ROOTS"} == before
    # The flag is offered, and the example file names it beside the line.
    assert dv.build_parser().parse_args(["setup", "--sso-ca-bundle", "x.pem"]).sso_ca_bundle == "x.pem"
    assert ("# python dockvault.py setup --sso-ca-bundle <file> copies a file into certs/ and writes this line."
            in _example())


def test_setup_refuses_a_file_whose_name_another_file_in_certs_has_and_changes_nothing(tmp_path, monkeypatch, capsys):
    _quiet_certificate_step(monkeypatch)
    root = tmp_path / "deployment"
    root.mkdir()
    _reusable_env(root, sso_ca_bundle="/app/certs/ca.pem")
    (root / "certs").mkdir()
    (root / "certs" / "ca.pem").write_bytes(PEM)
    other = tmp_path / "given" / "ca.pem"
    other.parent.mkdir()
    other.write_bytes(PEM + PEM)
    env_before = (root / ".env").read_text(encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(root))
    # The file SSO_CA_BUNDLE names is not overwritten by attestation roots of the same name.
    with pytest.raises(SystemExit):
        tool.setup(_setup_args(webauthn_attestation_roots=str(other)))
    assert "certs/ca.pem already exists with other contents" in capsys.readouterr().out
    assert (root / "certs" / "ca.pem").read_bytes() == PEM
    assert (root / ".env").read_text(encoding="utf-8") == env_before
    # Two flags that name one file name: refused before either is copied.
    first, second = tmp_path / "a" / "same.pem", tmp_path / "b" / "same.pem"
    for path, body in ((first, PEM), (second, PEM + PEM)):
        path.parent.mkdir()
        path.write_bytes(body)
    with pytest.raises(SystemExit):
        tool.setup(_setup_args(webauthn_attestation_roots=str(first), sso_ca_bundle=str(second)))
    assert "has the name of the file --webauthn-attestation-roots copies" in capsys.readouterr().out
    assert not (root / "certs" / "same.pem").exists()
    # A new copy of the file .env already names for the same setting replaces it.
    tool.setup(_setup_args(sso_ca_bundle=str(other)))
    assert (root / "certs" / "ca.pem").read_bytes() == PEM + PEM


def test_the_readability_probe_names_each_file_it_is_given(monkeypatch):
    seen = {}

    class Proc:
        returncode = 0

    monkeypatch.setattr(dv.shutil, "which", lambda *_a: "docker")
    assert dv.cert_readable_by_app_uid("/c", run=lambda cmd, **k: seen.update(cmd=cmd) or Proc(),
                                       extra=("roots.pem",)) is True
    script = seen["cmd"][-1]
    assert "head -c 1 /certs/cert.pem >/dev/null 2>&1" in script and "head -c 1 /certs/key.pem >/dev/null 2>&1" in script
    assert "head -c 1 /certs/roots.pem >/dev/null 2>&1" in script
    # Without one, the probe reads the pair alone, as it always did.
    dv.cert_readable_by_app_uid("/c", run=lambda cmd, **k: seen.update(cmd=cmd) or Proc())
    assert "roots.pem" not in seen["cmd"][-1]


def _start_ready(tool, monkeypatch):
    """Setup's start, up to and past the start itself, with nothing run."""
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv, "_cert_pair_present", lambda *a, **k: True)
    monkeypatch.setattr(dv, "refresh_renewal_hook", lambda *a, **k: (None, ""))
    monkeypatch.setattr(dv, "apply_cert_owner", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv, "port_free", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_guard_db_secret", lambda env, **k: True)
    monkeypatch.setattr(tool, "_note_host_log_driver", lambda: None)
    monkeypatch.setattr(tool, "_resolve_rerun_image_source", lambda *a, **k: None)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_strip_spent_admin_password", lambda *a, **k: None)
    monkeypatch.setattr(tool, "_passkey_addresses", lambda: None)
    started = []
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: started.append(1) or True)
    return started


def test_setup_warns_and_starts_when_the_container_cannot_read_only_the_attestation_roots(tmp_path, monkeypatch,
                                                                                          capsys):
    _reusable_env(tmp_path, webauthn_attestation_roots="/app/certs/roots.pem")
    (tmp_path / "certs").mkdir()
    (tmp_path / "certs" / "roots.pem").write_bytes(PEM)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    started = _start_ready(tool, monkeypatch)
    probed = []

    def probe(cert_dir, run=None, extra=()):
        probed.append(tuple(extra))
        return not extra
    monkeypatch.setattr(dv, "cert_readable_by_app_uid", probe)
    tool.setup(argparse.Namespace(no_start=False, non_interactive=True))
    out = " ".join(capsys.readouterr().out.split())
    assert ("Passkeys: the vault container (uid 10001) cannot read certs/roots.pem (WEBAUTHN_ATTESTATION_ROOTS). Until "
            "the server can read it, every new passkey is refused while attestation is direct. Make it readable "
            "(chmod 644) and restart the vault with python dockvault.py restart.") in out, out
    assert ("roots.pem",) in probed and started == [1]
    # Readable: nothing is said.
    monkeypatch.setattr(dv, "cert_readable_by_app_uid", lambda cert_dir, run=None, extra=(): True)
    tool.setup(argparse.Namespace(no_start=False, non_interactive=True))
    assert "cannot read certs/roots.pem" not in capsys.readouterr().out
    # A file not in certs/ is said as status says it, and the container is not asked about it.
    (tmp_path / "certs" / "roots.pem").unlink()
    probed.clear()
    monkeypatch.setattr(dv, "cert_readable_by_app_uid", probe)
    tool.setup(argparse.Namespace(no_start=False, non_interactive=True))
    out = " ".join(capsys.readouterr().out.split())
    assert "Passkeys: WEBAUTHN_ATTESTATION_ROOTS names /app/certs/roots.pem, and certs/roots.pem does not exist" in out
    assert probed == [()], probed


# --------------------------------------------------------------------------- the summary setup ends with

def _summary_lines(monkeypatch, summary):
    tool = dv.DockVault(dv.Palette(False), root=".")
    printed = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: printed.append(" ".join(str(x) for x in a)))
    tool._print_setup_summary(summary, True)
    return printed


def test_the_summary_gives_the_address_people_open_first_and_the_published_port_as_the_direct_one(monkeypatch):
    printed = _summary_lines(monkeypatch, {"server_name": "vault.internal", "web_host_port": 8443,
                                           "open_at": "https://vault.example.com"})
    first = next(i for i, line in enumerate(printed) if "https://vault.example.com/" in line)
    direct = next(i for i, line in enumerate(printed) if "https://vault.internal:8443/" in line)
    assert first < direct, printed
    assert printed[first].startswith(" Web UI / API : https://vault.example.com/   (the first ALLOWED_HOSTS entry: "
                                     "emailed links, passkeys and single sign-on use this address)"), printed[first]
    assert printed[direct] == " Direct       : https://vault.internal:8443/   (host port 8443)", printed[direct]
    # The same address, or none known: one line, as before.
    for open_at in ("https://vault.internal:8443", "https://Vault.Internal:8443/", "", None):
        printed = _summary_lines(monkeypatch, {"server_name": "vault.internal", "web_host_port": 8443,
                                               "open_at": open_at})
        lines = [line for line in printed if "vault.internal" in line.lower()]
        assert lines == [" Web UI / API : https://vault.internal:8443/          (host port 8443)"], (open_at, printed)
        assert not [line for line in printed if line.startswith(" Direct")], printed


def test_setup_hands_the_summary_the_first_allowed_hosts_entry(tmp_path, monkeypatch):
    _reusable_env(tmp_path, web_public_address="https://vault.example.com", web_host_port=8443)
    assert dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))["ALLOWED_HOSTS"].startswith(
        "https://vault.example.com")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    _start_ready(tool, monkeypatch)
    monkeypatch.setattr(dv, "cert_readable_by_app_uid", lambda *a, **k: True)
    summaries = []
    monkeypatch.setattr(tool, "_print_setup_summary",
                        lambda summary, healthy, logs_shown=False: summaries.append(dict(summary)))
    tool.setup(argparse.Namespace(no_start=False, non_interactive=True))
    assert summaries and summaries[-1]["open_at"] == "https://vault.example.com", summaries


# --------------------------------------------------------------------------- how SFTP agrees a connection's keys

def _first_setup_config(monkeypatch, argv):
    """The configuration a first setup collects from ``argv`` (setup's command line), unattended."""
    args = dv.build_parser().parse_args(["setup", "--non-interactive", "--server-name", "vault.example.com"] + argv)
    tool = dv.DockVault(dv.Palette(False), root=".")
    monkeypatch.setattr(tool, "_resolve_setup_image", lambda *a, **k: "")
    return tool._collect_setup_config(args)


def test_setup_takes_the_sftp_key_exchange_policy_and_writes_it_only_when_it_is_not_the_default(monkeypatch):
    required = _lines(_first_setup_config(monkeypatch, ["--enable-sftp", "--sftp-kex-policy", "pq-required"]))
    assert "SFTP_KEX_POLICY=pq-required" in required, required
    # The default is written nowhere: an absent value is the default.
    for argv in (["--enable-sftp"], ["--enable-sftp", "--sftp-kex-policy", "default"]):
        lines = _lines(_first_setup_config(monkeypatch, argv))
        assert not [line for line in lines if line.startswith("SFTP_KEX_POLICY")], (argv, lines)


def test_setup_says_when_it_drops_the_key_exchange_policy_because_sftp_is_off(monkeypatch, capsys):
    lines = _lines(_first_setup_config(monkeypatch, ["--sftp-kex-policy", "pq-required"]))
    assert not [line for line in lines if line.startswith("SFTP_KEX_POLICY")], lines
    assert ("Note: --sftp-kex-policy pq-required is not written: SFTP is off. Add --enable-sftp or --split to run "
            "it.") in capsys.readouterr().out
    # With SFTP on, or the default, nothing is said.
    for argv in (["--enable-sftp", "--sftp-kex-policy", "pq-required"], ["--split", "--sftp-kex-policy", "pq-required"],
                 ["--sftp-kex-policy", "default"]):
        _first_setup_config(monkeypatch, argv)
        assert "is not written: SFTP is off" not in capsys.readouterr().out, argv


def test_the_example_file_says_how_setup_sets_the_key_exchange_policy():
    before = _example().split("\nSFTP_KEX_POLICY=")[0]
    said = " ".join(" ".join(line.lstrip("#").strip() for line in before.splitlines()[-12:]).split())
    assert ("A first python dockvault.py setup that turns SFTP on asks whether to refuse clients without the hybrid "
            "exchange, or takes --sftp-kex-policy, and writes this line only for pq-required.") in said


@pytest.mark.parametrize("value", ["pq-requried", "pq-preferred", "Default"])
def test_the_command_line_takes_only_the_two_key_exchange_policies(capsys, value):
    """The vault takes default and pq-required, and refuses anything else at its start."""
    with pytest.raises(SystemExit) as refused:
        dv.build_parser().parse_args(["setup", "--sftp-kex-policy", value])
    assert refused.value.code == 2
    offered = capsys.readouterr().err.split("choose from")[-1]
    assert "default" in offered and "pq-required" in offered and "pq-preferred" not in offered, offered


def test_the_command_line_offers_the_two_policies_and_says_what_each_does():
    assert dv.SFTP_KEX_POLICIES == ("default", "pq-required")
    for value in dv.SFTP_KEX_POLICIES:
        args = dv.build_parser().parse_args(["setup", "--sftp-kex-policy", value])
        assert args.sftp_kex_policy == value
    source = (ROOT / "dockvault.py").read_text(encoding="utf-8")
    assert 'choices=SFTP_KEX_POLICIES,' in source
    assert "pq-preferred" not in source and "PREFERRED" not in source


def test_an_interactive_setup_asks_whether_to_refuse_clients_without_the_post_quantum_exchange(monkeypatch):
    tool = dv.DockVault(dv.Palette(False), root=".")
    monkeypatch.setattr(tool, "_resolve_setup_image", lambda *a, **k: "")
    monkeypatch.setattr(dv, "port_free", lambda *a, **k: True)
    monkeypatch.setattr(dv, "ask", lambda prompt, pal, default=None: {
        "Public DNS name or IP clients will use (e.g. vault.example.com)": "vault.example.com",
        "Recording preset (full / standard / minimal)": "full"}.get(prompt, default or ""))
    monkeypatch.setattr(dv, "ask_secret", lambda prompt, pal: "")
    question = ("Refuse SFTP clients that cannot use the post-quantum key exchange (OpenSSH before 9.9 and many older "
                "SFTP programs)?")
    for sftp, answer, written in ((True, True, "pq-required"), (True, False, None), (False, True, None)):
        asked = []

        def confirm(prompt, pal, default=True, sftp=sftp, answer=answer):
            asked.append(prompt)
            if prompt.startswith("Enable SFTP"):
                return sftp
            return answer if prompt == question else False
        monkeypatch.setattr(dv, "confirm", confirm)
        cfg = tool._collect_setup_config(argparse.Namespace(non_interactive=False))
        assert (question in asked) is sftp, (sftp, asked)
        assert cfg.get("sftp_kex_policy") == written, (sftp, answer, cfg.get("sftp_kex_policy"))
