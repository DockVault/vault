"""Where SFTP clients are told to connect.

The server binds SFTP inside its container on one port and the host publishes it on another -- 2322
mapped to 2222 on a standard install. The desktop sync client dials exactly the host and port a device
mint returns, and the web page prints an `sftp` command for a temporary credential, so both must name
the port that answers. Each route reads one helper, each compose file hands the API the port it
publishes, and the setup tool writes the override only when clients arrive some other way.

The live proof -- signing in where the mint says SFTP is -- is test_sftp_advertised_endpoint_live.py.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from pydantic import ValidationError

from app.core import config as cfg

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("dockvault_endpoint", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)


def _settings(**over):
    return SimpleNamespace(**{"sftp_public_host": "", "sftp_public_port": 0, "sftp_host_port": 0,
                              "sftp_port": 2222, **over})


# --- the helper both routes read -----------------------------------------------------------------------

@pytest.mark.parametrize("in_container", [True, False])
def test_a_set_public_port_is_always_what_is_advertised(in_container):
    s = _settings(sftp_public_port=40022, sftp_host_port=2200)
    assert cfg.advertised_sftp_endpoint(s, in_container=in_container) == (None, 40022)


def test_in_a_container_the_published_port_is_advertised_not_the_bind_port():
    # What a deployment still on a compose file without SFTP_PUBLIC_PORT gets (updating by pulling the
    # image leaves the checkout alone): the port its host publishes, derived as the compose files do.
    assert cfg.advertised_sftp_endpoint(_settings(), in_container=True) == (None, 2322)
    assert cfg.advertised_sftp_endpoint(_settings(sftp_host_port=2200), in_container=True) == (None, 2200)


def test_outside_a_container_the_bind_port_is_the_reachable_one():
    assert cfg.advertised_sftp_endpoint(_settings(sftp_host_port=2200), in_container=False) == (None, 2222)


def test_the_container_is_detected_the_way_the_rest_of_the_app_detects_it(monkeypatch):
    # Every shipped compose file sets DOCKER_CONTAINER; the default (in_container=None) must read it.
    monkeypatch.setenv("DOCKER_CONTAINER", "true")
    assert cfg.advertised_sftp_endpoint(_settings()) == (None, 2322)
    monkeypatch.setenv("DOCKER_CONTAINER", "false")
    monkeypatch.setattr(cfg.Path, "exists", lambda self: False)      # no /.dockerenv either
    assert cfg.advertised_sftp_endpoint(_settings()) == (None, 2222)


@pytest.mark.parametrize("raw, host", [("  sftp.example.com  ", "sftp.example.com"), ("", None), ("   ", None)])
def test_a_blank_public_host_advertises_none_and_a_set_one_is_trimmed(raw, host):
    assert cfg.advertised_sftp_endpoint(_settings(sftp_public_host=raw))[0] == host


@pytest.mark.parametrize("field", ["sftp_public_port", "sftp_host_port"])
@pytest.mark.parametrize("port, valid", [(0, True), (1, True), (2322, True), (65535, True),
                                         (-1, False), (65536, False)])
def test_the_port_settings_are_ports(field, port, valid):
    try:
        cfg.Settings(_env_file=None, **{field: port})
        rejected = False
    except ValidationError as exc:
        rejected = any(err["loc"][0] == field for err in exc.errors())
    assert rejected is (not valid)


# --- both routes read it -------------------------------------------------------------------------------

def _code(text):
    """Source without comment lines, so a pin cannot be satisfied by a comment."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


_API = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")


def _route(anchor):
    start = _API.index(anchor)
    end = _API.index("\n@app.", start + len(anchor))
    return _code(_API[start:end])


def test_the_device_mint_advertises_through_the_helper_only():
    body = _route('@app.post("/device/sync-credential")')
    assert body.count("advertised_sftp_endpoint()") == 1
    assert 'cred["host"], cred["port"] = advertised_sftp_endpoint()' in body
    # The bind port must not be what a client is sent to.
    assert "settings.sftp_port" not in body and "sftp_public_host" not in body


def test_a_temporary_credential_carries_where_sftp_is():
    body = _route('@app.post("/auth/temp-credentials", response_model=TempCredentialResponse)')
    assert body.count("advertised_sftp_endpoint()") == 1
    assert 'temp_creds["sftp_host"], temp_creds["sftp_port"] = advertised_sftp_endpoint()' in body
    model = _code(_API[_API.index("class TempCredentialResponse(BaseModel):"):_API.index("class VaultCreate(")])
    assert "sftp_host: Optional[str] = None" in model and "sftp_port: Optional[int] = None" in model


# --- the page prints what the server says ---------------------------------------------------------------

def test_the_temporary_credential_dialog_prints_the_advertised_endpoint():
    js = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    start = js.index("function showTempCredsModal(")
    body = js[start:js.index("\nfunction ", start + 1)]
    body = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("//"))
    assert "2222" not in body and "localhost" not in body
    assert "creds.sftp_port" in body and "creds.sftp_host" in body
    assert "window.location.hostname" in body          # the fallback when no host is advertised


# --- every compose file advertises the port it publishes -------------------------------------------------

def _mapping_host_side(service):
    for port in service.get("ports") or []:
        spec = str(port)
        if spec.rsplit(":", 1)[-1] == "2222":
            return spec.rsplit(":", 1)[0]
    return None


@pytest.mark.parametrize("rel", ["deploy/docker-compose.secure.yml", "deploy/docker-compose.yml"])
def test_each_api_service_advertises_the_sftp_port_its_file_publishes(rel):
    services = yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))["services"]
    api = {n: s for n, s in services.items() if "API_PORT" in (s.get("environment") or {})}
    assert api, rel
    for name, service in api.items():
        profiles = set(service.get("profiles") or [])
        # The service that publishes SFTP alongside this API: the same one (combined) or its sibling.
        publishers = [s for s in services.values()
                      if _mapping_host_side(s) is not None
                      and (not profiles or not s.get("profiles") or profiles & set(s["profiles"]))]
        assert len(publishers) == 1, (rel, name, len(publishers))
        published = _mapping_host_side(publishers[0])
        advertised = (service.get("environment") or {}).get("SFTP_PUBLIC_PORT")
        # The default IS the published expression, so the two cannot drift; SFTP_PUBLIC_PORT in .env
        # overrides it for NAT / port forwarding.
        assert advertised == "${SFTP_PUBLIC_PORT:-%s}" % published, (rel, name, advertised, published)


# --- the setup tool --------------------------------------------------------------------------------------

def _cfg(**over):
    base = {
        "server_name": "vault.example.com",
        "encryption_key": dv.gen_fernet_key(), "jwt_secret_key": dv.gen_hex(32),
        "vault_db_password": dv.gen_hex(16), "redis_password": dv.gen_hex(24),
        "admin_username": "admin", "admin_email": "admin@example.com",
        "admin_password": "Strong-Pass-1234", "compose_profiles": "combined",
        "run_sftp": True, "sftp_host_port": 2322,
    }
    return {**base, **over}


def _env(cfg_):
    return dv.parse_env("\n".join(dv.build_env_lines(cfg_)))


def test_setup_writes_where_clients_connect_only_when_it_differs():
    env = _env(_cfg(sftp_public_host="sftp.example.com", sftp_public_port=40022))
    assert env["SFTP_PUBLIC_HOST"] == "sftp.example.com" and env["SFTP_PUBLIC_PORT"] == "40022"
    # The published port is what the compose file advertises anyway: nothing to write.
    same = _env(_cfg(sftp_public_port=2322))
    assert "SFTP_PUBLIC_PORT" not in same and "SFTP_PUBLIC_HOST" not in same
    # No SFTP, nothing about where to reach it.
    off = _env(_cfg(run_sftp=False, sftp_public_host="sftp.example.com", sftp_public_port=40022))
    assert "SFTP_PUBLIC_PORT" not in off and "SFTP_PUBLIC_HOST" not in off


def test_a_fresh_volume_set_keeps_where_clients_connect():
    current = {"RUN_SFTP": "1", "SFTP_HOST_PORT": "2200", "SERVER_NAME": "vault.example.com",
               "SFTP_PUBLIC_HOST": "sftp.example.com", "SFTP_PUBLIC_PORT": "40022"}
    env = _env(dv.new_set_config(current, "dockvault-vault-t9", "t9"))
    assert env["SFTP_PUBLIC_HOST"] == "sftp.example.com" and env["SFTP_PUBLIC_PORT"] == "40022"


def _collect(tmp_path, monkeypatch, **flags):
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_resolve_setup_image", lambda *a, **k: "dockvault-vault:latest")
    args = argparse.Namespace(non_interactive=True, server_name="vault.example.com",
                              admin_password="Strong-Pass-1234", enable_sftp=True, **flags)
    return tool._collect_setup_config(args)


def test_the_setup_flags_reach_the_config(tmp_path, monkeypatch):
    got = _collect(tmp_path, monkeypatch, sftp_public_host="sftp.example.com", sftp_public_port=40022)
    assert (got["sftp_public_host"], got["sftp_public_port"]) == ("sftp.example.com", 40022)
    unset = _collect(tmp_path, monkeypatch)
    assert (unset["sftp_public_host"], unset["sftp_public_port"]) == (None, None)


@pytest.mark.parametrize("flags", [
    {"sftp_public_host": "sftp.example.com\nADMIN_PASSWORD=x"},   # would inject a line into .env
    {"sftp_public_host": "sftp example.com"},
    {"sftp_public_port": 0},
    {"sftp_public_port": 70000},
])
def test_setup_refuses_an_address_or_port_that_is_not_one(tmp_path, monkeypatch, flags):
    with pytest.raises(SystemExit):
        _collect(tmp_path, monkeypatch, **flags)


def test_env_example_documents_both_settings():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"^# SFTP_PUBLIC_HOST=$", text, re.M) and re.search(r"^# SFTP_PUBLIC_PORT=$", text, re.M)
