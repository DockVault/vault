"""The host tool says when passkeys stay hidden: browsers make no passkey for an address reached by IP, so on an
install whose address (the first ALLOWED_HOSTS entry that is not a wildcard) is an IP, setup and status say so.
Offline."""
import importlib.util
import io
import types
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
set_bare_api_env()
_spec = importlib.util.spec_from_file_location("dockvault_passkey_address", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)


@pytest.mark.parametrize("name", ["203.0.113.9", "127.0.0.1", "10.0.0.5", "2001:db8::1", "[2001:db8::1]"])
def test_an_address_reached_by_ip_hides_passkeys(name):
    note = dv.passkey_address_note(name)
    assert note and "reached by IP" in note and "host name" in note and "ALLOWED_HOSTS" in note


@pytest.mark.parametrize("name", ["vault.example.com", "localhost", "vault", "", None, "not an address"])
def test_a_host_name_or_nothing_gets_no_note(name):
    assert dv.passkey_address_note(name) is None


@pytest.mark.parametrize("cfg, hidden", [
    ({"server_name": "203.0.113.9", "web_host_port": 443}, True),
    ({"server_name": "203.0.113.9", "web_host_port": 8443}, True),              # written as https://203.0.113.9:8443
    ({"server_name": "vault.example.com", "web_host_port": 8443}, False),
    # Behind a proxy or port forwarding the address people open comes first, and it is the one judged.
    ({"server_name": "203.0.113.9", "web_public_address": "files.example.com", "web_host_port": 443}, False),
    ({"server_name": "vault.example.com", "web_public_address": "https://203.0.113.9:8443", "web_host_port": 443},
     True),
])
def test_the_note_judges_the_address_as_setup_writes_it(cfg, hidden):
    written = dv.allowed_hosts_value(cfg)
    assert bool(dv.passkey_address_note(dv._allowed_hosts_name(written))) is hidden, written


def test_the_rule_the_vault_checks_is_the_tools_too():
    from app.core.public_url import is_ip_address
    for host in ("203.0.113.9", "2001:db8::1", "127.0.0.1"):
        assert is_ip_address(host) and dv.passkey_address_note(host)
    assert not is_ip_address("vault.example.com") and dv.passkey_address_note("vault.example.com") is None


def test_status_says_passkeys_are_hidden_at_an_ip(monkeypatch, tmp_path):
    printed = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: printed.append(" ".join(str(x) for x in a)))
    Tool = next(c for c in vars(dv).values() if isinstance(c, type) and hasattr(c, "_print_status"))
    tool = Tool.__new__(Tool)
    tool.pal = types.SimpleNamespace(paint=lambda text, colour=None: text)
    monkeypatch.setattr(tool, "_is_locked", lambda: False)
    monkeypatch.setattr(tool, "_env_lock_path", lambda: str(tmp_path / "none.lock"))
    monkeypatch.setattr(tool, "_env_archives", lambda: [])
    monkeypatch.setattr(tool, "_env_path", lambda: str(tmp_path / ".env"))
    (tmp_path / ".env").write_text("ALLOWED_HOSTS='https://203.0.113.9:8443'\n", encoding="utf-8")
    monkeypatch.setattr(tool, "_load_env", lambda: {"ALLOWED_HOSTS": "https://203.0.113.9:8443"})
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: None)
    monkeypatch.setattr(dv, "docker_available", lambda: (True, ""))
    tool._print_status("combined")
    assert any("Passkeys: hidden" in line and "reached by IP" in line for line in printed), printed
    for named in ({"ALLOWED_HOSTS": "vault.example.com"}, {"ALLOWED_HOSTS": "*.example.com,vault.example.com"}, {}):
        printed.clear()
        monkeypatch.setattr(tool, "_load_env", lambda env=named: env)
        tool._print_status("combined")
        assert not any("Passkeys" in line for line in printed), (named, printed)


def test_setup_says_it_once_the_address_is_known():
    source = io.open(ROOT / "dockvault.py", encoding="utf-8").read()
    setup = source[source.index("def _collect_setup_config"):source.index("def _resolve_cert_cfg")]
    assert "passkey_address_note(_allowed_hosts_name(allowed_hosts_value(" in setup
    assert setup.index("web_public = public_web_address(") < setup.index("passkey_address_note(")


def test_the_example_environment_says_it_beside_the_address():
    text = io.open(ROOT / ".env.example", encoding="utf-8").read()
    before, _, _after = text.partition("\nALLOWED_HOSTS=")
    tail = before[-2500:]
    assert "Passkeys need a HOST NAME" in tail and "reached by IP" in tail and "dockvault.py setup and status say so" in tail
