"""Where the root certificates for direct passkey attestation can live (WEBAUTHN_ATTESTATION_ROOTS), said as the
compose files have it.

The setting names a file as the server sees it, under /app/certs. Only the HTTPS compose
(deploy/docker-compose.secure.yml, which `dockvault.py setup` starts) mounts the repository's certs/ directory
there, read-only, on the services that serve the web app; the quickstart compose keeps /app/certs in memory, so a
file put in certs/ never reaches its server. .env.example, the management tool and the server's refusal of direct
attestation without the file say which compose supports it, and the compose files are read to hold them to it.
"""
from pathlib import Path

import pytest
import yaml

from _bare_api_env import set_bare_api_env

set_bare_api_env()

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
WEB = ("python", "run_combined.py"), ("python", "-m", "app.api.api_server")


def _web_services(rel):
    services = yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))["services"]
    found = {name: s for name, s in services.items() if tuple(s.get("command") or ()) in WEB}
    assert found, rel
    return found


def test_only_the_https_compose_mounts_the_certs_folder_where_the_web_server_reads_it():
    for name, service in _web_services("deploy/docker-compose.secure.yml").items():
        assert "../certs:/app/certs:ro" in service.get("volumes", []), name
        assert not any(str(t).startswith("/app/certs") for t in service.get("tmpfs", [])), name
    for name, service in _web_services("deploy/docker-compose.yml").items():
        assert not any("/app/certs" in str(v) for v in service.get("volumes", [])), name
        assert any(str(t).startswith("/app/certs") for t in service.get("tmpfs", [])), name


def _env_example_block():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    end = text.index("# WEBAUTHN_ATTESTATION_ROOTS=/app/certs/")
    start = text.rindex("\n\n", 0, end)
    return " ".join(line.lstrip("# ").strip() for line in text[start:end].splitlines())


def test_env_example_says_which_compose_mounts_the_folder_and_that_the_quickstart_does_not():
    block = _env_example_block()
    assert "Only the HTTPS compose (deploy/docker-compose.secure.yml" in block
    assert "mounts this folder's certs/ directory, read-only, at /app/certs on the web service" in block
    assert "The quickstart compose (docker-compose.yml) keeps /app/certs in memory" in block
    assert "never reaches the server" in block


def test_the_management_tool_says_the_same():
    tool = (ROOT / "dockvault.py").read_text(encoding="utf-8")
    at = tool.index('roots = str(cfg.get("webauthn_attestation_roots") or "").strip()')
    note = " ".join(line.strip().lstrip("# ") for line in tool[tool.rindex("\n\n", 0, at):at].splitlines())
    assert "which the HTTPS compose this tool starts mounts read-only at /app/certs" in note
    assert "the quickstart compose keeps /app/certs in memory and never sees it" in note


def test_the_server_says_where_the_file_goes_when_it_refuses_direct_attestation_without_it(monkeypatch):
    from _memory_db import MemoryDB
    import app.core.public_url as public_url
    from app.core import settings_registry as registry
    from app.core import webauthn_settings as wss
    from app.core.models import User, WebAuthnCredential
    registry.all_specs()
    monkeypatch.setattr(public_url, "readiness", lambda: {"usable": True})
    monkeypatch.setattr(wss, "trust_anchors", lambda: ())
    said = wss.save_refusal(MemoryDB({User: [], WebAuthnCredential: []}), wss.ATTESTATION, "direct")
    assert said.startswith("Direct attestation needs trust anchors, and "), said
    assert ("Put a PEM bundle of root certificates in the deployment's certs folder (the HTTPS compose, "
            "deploy/docker-compose.secure.yml, mounts it at /app/certs; the quickstart compose does not)") in said
