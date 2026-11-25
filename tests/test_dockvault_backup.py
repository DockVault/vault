"""A backup holds the volumes and the paired .env, not certs/. A setting in .env that names a file the server reads
from certs/ (the passkey attestation roots) is checked where that matters: status says when the file is not there,
or is no PEM certificate, or is named at a path the HTTPS compose does not mount; a restore says so for the .env it
installs. And no message tells the operator to delete certs/ as a whole, which would take that file with the TLS
pair. Offline."""
import argparse
import importlib.util
import io
import json
import types
from pathlib import Path

import pytest

from test_dockvault_tool import _host_digest, _tgz

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("dockvault_backup_certs", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)

KEY = "WEBAUTHN_ATTESTATION_ROOTS"
PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


def _certs(tmp_path, files=None):
    certs = tmp_path / "certs"
    certs.mkdir(exist_ok=True)
    for name, text in (files or {}).items():
        (certs / name).parent.mkdir(parents=True, exist_ok=True)
        (certs / name).write_text(text, encoding="utf-8")
    return str(certs)


def test_a_file_named_in_certs_that_is_not_there_is_said(tmp_path):
    certs = _certs(tmp_path)
    assert dv.certs_file_problem(KEY, "/app/certs/roots.pem", certs) == (
        "WEBAUTHN_ATTESTATION_ROOTS names /app/certs/roots.pem, and certs/roots.pem does not exist (a backup does not "
        "carry certs/): copy the file there.")
    # A folder of that name is no file either, and a path below certs/ is said as the host has it.
    _certs(tmp_path, {"dir/inner.pem": PEM})
    assert "and certs/dir does not exist" in dv.certs_file_problem(KEY, "/app/certs/dir", certs)
    assert "and certs/sub/roots.pem does not exist" in dv.certs_file_problem(KEY, "/app/certs/sub/roots.pem", certs)


def test_a_file_that_holds_no_pem_certificate_is_said(tmp_path):
    certs = _certs(tmp_path, {"roots.pem": "not a certificate\n", "public.pem": "-----BEGIN PUBLIC KEY-----\n"})
    assert dv.certs_file_problem(KEY, "/app/certs/roots.pem", certs) == (
        "WEBAUTHN_ATTESTATION_ROOTS names /app/certs/roots.pem, and certs/roots.pem holds no PEM certificate.")
    assert dv.certs_file_problem(KEY, "/app/certs/public.pem", certs).endswith("holds no PEM certificate.")


@pytest.mark.parametrize("value", ["/etc/ssl/certs/roots.pem", "/app/roots.pem", "/app/certs", "/app/certs/",
                                   "/app/certs/../roots.pem", "/app/certsx/roots.pem", "roots.pem"])
def test_a_file_named_outside_the_mounted_folder_is_said(tmp_path, value):
    certs = _certs(tmp_path, {"roots.pem": PEM})
    assert dv.certs_file_problem(KEY, value, certs) == (
        "WEBAUTHN_ATTESTATION_ROOTS names %s, outside /app/certs: the HTTPS compose mounts only the certs/ folder "
        "beside .env, at /app/certs, so no file of yours reaches that path." % value)


@pytest.mark.parametrize("value", ["/app/certs/roots.pem", "'/app/certs/roots.pem'", " /app/certs/roots.pem ",
                                   # The server's working directory is /app: a relative path is read from there.
                                   "certs/roots.pem", "/app/certs/./roots.pem"])
def test_a_pem_file_in_certs_gets_no_word(tmp_path, value):
    certs = _certs(tmp_path, {"roots.pem": "a comment first\n" + PEM})
    assert dv.certs_file_problem(KEY, value, certs) is None


@pytest.mark.parametrize("value", ["", None, "  ", "''"])
def test_no_file_named_gets_no_word(tmp_path, value):
    assert dv.certs_file_problem(KEY, value, _certs(tmp_path)) is None


def _status_tool(monkeypatch, tmp_path, env):
    printed = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: printed.append(" ".join(str(x) for x in a)))
    tool = dv.DockVault.__new__(dv.DockVault)
    tool.pal = types.SimpleNamespace(paint=lambda text, colour=None: text)
    tool.root = str(tmp_path)
    (tmp_path / ".env").write_text("ALLOWED_HOSTS=vault.example.com\n", encoding="utf-8")
    monkeypatch.setattr(tool, "_load_env", lambda: env)
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: None)
    monkeypatch.setattr(tool, "_passkey_addresses", lambda: None)
    monkeypatch.setattr(dv, "cert_self_issued", lambda path: False)
    monkeypatch.setattr(dv, "docker_available", lambda: (True, ""))
    return tool, printed


def test_status_says_when_the_attestation_roots_file_is_not_in_certs(monkeypatch, tmp_path):
    _certs(tmp_path)
    tool, printed = _status_tool(monkeypatch, tmp_path, {"ALLOWED_HOSTS": "vault.example.com",
                                                         KEY: "/app/certs/roots.pem"})
    tool._print_status("combined")
    assert printed.count("  Passkeys: " + dv.certs_file_problem(KEY, "/app/certs/roots.pem",
                                                                str(tmp_path / "certs"))) == 1, printed
    # The file in place, or no file named: nothing.
    for env, files in (({"ALLOWED_HOSTS": "vault.example.com", KEY: "/app/certs/roots.pem"}, {"roots.pem": PEM}),
                       ({"ALLOWED_HOSTS": "vault.example.com"}, {})):
        _certs(tmp_path, files)
        printed.clear()
        monkeypatch.setattr(tool, "_load_env", lambda env=env: env)
        tool._print_status("combined")
        assert not [line for line in printed if KEY in line], printed


# --- a restore ------------------------------------------------------------------------------------

@pytest.fixture
def _restorable(monkeypatch):
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    monkeypatch.setattr(dv, "archive_digest_in_docker", _host_digest, raising=False)


def _env_bytes(**extra):
    cfg = {"server_name": "localhost", "encryption_key": dv.gen_fernet_key(), "jwt_secret_key": dv.gen_hex(32),
           "vault_db_password": dv.gen_hex(16), "redis_password": dv.gen_hex(24), "admin_username": "admin",
           "admin_email": "a@example.com", "admin_password": "Strong-Pass-1234", "compose_profiles": "combined",
           "volume_prefix": "dvcerts", "deployment_id": "dvcerts"}
    lines = dv.build_env_lines(cfg) + ["%s=%s" % kv for kv in extra.items()]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _bundle(tmp_path, env):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "env").write_bytes(env)
    parsed = dv.parse_env(env.decode("utf-8"))
    entries = [{"role": r, "name": "x", "archive": "%s.tar.gz" % dv.VOLUME_BASENAMES[r]} for r in ("keys", "pg", "storage")]
    man = dv.build_backup_manifest(dv.volume_prefix(parsed), parsed.get("DEPLOYMENT_ID", "default"), entries,
                                   dv.gen_salt(), parsed)
    (bundle / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
    for e in entries:
        _tgz(bundle / e["archive"])
    return bundle


def _restore(tmp_path, monkeypatch, env, certs=None):
    tmp_path.mkdir(exist_ok=True)
    root = tmp_path / "root"
    root.mkdir()
    _certs(root, certs)
    bundle = _bundle(tmp_path, env)
    tool = dv.DockVault(dv.Palette(False), root=str(root))
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: False)
    monkeypatch.setattr(dv, "container_running", lambda name, **k: False)
    monkeypatch.setattr(dv, "docker_available", lambda **k: (True, "ok"))
    monkeypatch.setattr(dv, "read_volume_json", lambda *a, **k: None)
    monkeypatch.setattr(dv, "clear_volume", lambda vol, **k: True)
    monkeypatch.setattr(dv, "untar_volume", lambda vol, *a, **k: True)
    monkeypatch.setattr(tool, "_stop_stack", lambda: None)
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    tool._do_restore(argparse.Namespace(non_interactive=True, bundle_dir=str(bundle), force=True))
    return root


def test_a_restore_says_when_the_attestation_roots_file_its_env_names_is_not_in_certs(tmp_path, monkeypatch, capsys,
                                                                                       _restorable):
    root = _restore(tmp_path, monkeypatch, _env_bytes(**{KEY: "/app/certs/roots.pem"}))
    said = " ".join(capsys.readouterr().out.split())
    problem = dv.certs_file_problem(KEY, "/app/certs/roots.pem", str(root / "certs"))
    assert problem and said.count("Passkeys: %s Until the server can read it, every new passkey is refused while "
                                  "attestation is direct." % problem) == 1, said
    assert said.index("Restored set 'dvcerts'") < said.index(problem)


def test_a_restore_whose_env_names_no_file_or_one_in_place_says_nothing_of_it(tmp_path, monkeypatch, capsys,
                                                                              _restorable):
    _restore(tmp_path, monkeypatch, _env_bytes())
    assert KEY not in capsys.readouterr().out
    _restore(tmp_path / "again", monkeypatch, _env_bytes(**{KEY: "/app/certs/roots.pem"}), {"roots.pem": PEM})
    out = capsys.readouterr().out
    assert "Restored set" in out and KEY not in out


# --- what the tool and the documents tell the operator ---------------------------------------------

def test_no_message_says_to_delete_the_certs_folder():
    source = " ".join(io.open(ROOT / "dockvault.py", encoding="utf-8").read().split()).lower()
    assert "delete the certs/ directory" not in source
    assert "delete certs/cert.pem and certs/key.pem and re-run setup" in " ".join(dv._CERT_DENIED.split())
    assert "Delete certs/cert.pem and certs/key.pem and re-run setup" in " ".join(
        io.open(ROOT / "dockvault.py", encoding="utf-8").read().split()).replace('" "', "")


SAID = ("certs/ is not in a backup: keep your own copy of the TLS pair and of the attestation roots file, and put "
        "them back in certs/ after a restore on another machine.")


def test_the_readme_backup_section_says_certs_is_not_in_a_backup():
    readme = io.open(ROOT / "README.md", encoding="utf-8").read()
    section = readme[readme.index("### Backup & restore"):]
    section = section[:section.index("\n## ")] if "\n## " in section else section
    assert SAID in " ".join(section.replace("`", "").split())


def test_the_example_file_says_certs_is_not_in_a_backup_beside_the_attestation_roots():
    text = io.open(ROOT / ".env.example", encoding="utf-8").read()
    before, _, _after = text.partition("# WEBAUTHN_ATTESTATION_ROOTS=")
    note = before[before.rindex("# Passkeys: the file of root certificates"):]
    assert SAID in " ".join(line.lstrip("#").strip() for line in note.splitlines())
