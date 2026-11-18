"""ALLOWED_HOSTS means the same to the Host check and to the base of every emailed link (app/core/allowed_hosts.py).

They used to read it two ways. A wildcard first made every emailed link start https://*.example.com; an entry with a
port or a scheme made the Host check refuse the site, which compares host names only; and setup wrote the bare name
on a web port other than 443, so emailed links pointed at 443. Each case here is checked both ways: the link base,
and starlette's own TrustedHostMiddleware, run offline, accepting the Host a browser sends and refusing a forged one.
"""
import importlib.util
from pathlib import Path

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import allowed_hosts as ah  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]

# (ALLOWED_HOSTS, link base, a Host a browser sends for it)
CASES = [
    ("vault.example.com", "https://vault.example.com", "vault.example.com"),
    ("*.example.com,vault.example.com", "https://vault.example.com", "vault.example.com"),
    ("vault.example.com:8443", "https://vault.example.com:8443", "vault.example.com:8443"),
    ("https://vault.example.com:8443", "https://vault.example.com:8443", "vault.example.com:8443"),
    ("http://localhost:8200,vault-api", "http://localhost:8200", "localhost:8200"),
]


def _status(allowed, host):
    """What starlette's TrustedHostMiddleware answers a request with ``host``, given ``allowed``."""
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    sent = []

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            sent.append(message["status"])

    scope = {"type": "http", "method": "GET", "path": "/health", "raw_path": b"/health", "query_string": b"",
             "headers": [(b"host", host.encode())], "scheme": "http", "server": ("x", 80), "client": ("1.2.3.4", 1),
             "root_path": ""}
    run_coroutine(TrustedHostMiddleware(app, allowed_hosts=allowed)(scope, receive, send))
    return sent[0]


@pytest.mark.parametrize("raw, base, host", CASES)
def test_the_link_base_and_the_host_check_read_each_form_alike(raw, base, host):
    assert ah.link_base(raw) == base
    hosts = ah.middleware_hosts(raw)
    assert all("://" not in h and ":" not in h for h in hosts), hosts
    assert hosts[-2:] == ["localhost", "127.0.0.1"] or "localhost" in hosts
    assert _status(hosts, host) == 200, (raw, hosts, host)
    assert _status(hosts, "localhost:8000") == 200, "the container's own health probe"
    assert _status(hosts, "evil.example") == 400


def test_a_wildcard_is_never_a_link_base_and_nothing_usable_gives_none():
    assert ah.link_base("*.example.com") == ""
    assert ah.link_base("*,0.0.0.0,.example.com") == ""
    assert ah.link_base("") == "" and ah.middleware_hosts("") == []
    assert ah.link_base("ftp://vault.example.com,vault.example.com") == "https://vault.example.com"


def test_the_ci_value_also_admits_the_sftp_containers_sign_ins():
    hosts = ah.middleware_hosts("http://localhost:8200,vault-api")
    for host in ("localhost:8200", "127.0.0.1:8200", "vault-api:8000"):
        assert _status(hosts, host) == 200, host


def test_both_link_readers_and_the_middleware_use_the_one_rule(monkeypatch):
    from app.core.config import settings
    from app.core import email_actions
    from app.api import email_studio_router
    monkeypatch.setattr(settings, "allowed_hosts", "*.example.com,https://vault.example.com:8443")
    assert email_actions.vault_url() == "https://vault.example.com:8443"
    assert email_studio_router._vault_url() == "https://vault.example.com:8443"
    server = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert "_allowed_hosts = _middleware_hosts(" in server
    assert "split(',')" not in server[server.index("_allowed_hosts = "):server.index("_allowed_hosts = ") + 200]


def _dockvault():
    spec = importlib.util.spec_from_file_location("dockvault_hosts", ROOT / "dockvault.py")
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    return dv


@pytest.mark.parametrize("port, written", [(443, "vault.example.com"), (8443, "https://vault.example.com:8443")])
def test_setup_writes_the_origin_on_a_web_port_other_than_443(monkeypatch, port, written):
    dv = _dockvault()
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    cfg = {**dv.new_set_config({}, "prefix-1", "dep-1"), "server_name": "vault.example.com", "web_host_port": port}
    env = dv.parse_env("\n".join(dv.build_env_lines(cfg)))
    assert env["ALLOWED_HOSTS"] == written
    assert ah.link_base(env["ALLOWED_HOSTS"]) == ("https://vault.example.com" if port == 443
                                                  else "https://vault.example.com:8443")
    assert dv._allowed_hosts_name(env["ALLOWED_HOSTS"]) == "vault.example.com"
