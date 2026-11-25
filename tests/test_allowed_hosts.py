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
    # A wildcard written as an origin is still a wildcard: never the link base.
    ("https://*.example.com,https://vault.example.com", "https://vault.example.com", "vault.example.com"),
    # Read as a browser sends the Host: in lower case, a bare name without a path.
    ("Vault.Example.COM", "https://vault.example.com", "vault.example.com"),
    ("vault.example.com/", "https://vault.example.com", "vault.example.com"),
    ("Vault.Example.COM:8443/vault", "https://vault.example.com:8443", "vault.example.com:8443"),
    ("HTTPS://Vault.Example.COM:8443/vault", "https://vault.example.com:8443", "vault.example.com:8443"),
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
    assert ah.link_base("https://*.example.com,http://*:8443,https://*") == ""
    assert ah.link_base("https://*:8443,vault.example.com") == "https://vault.example.com"
    # A wildcard port: the host reads (the Host check gets it), but no link can be built on it.
    assert ah.link_base("https://vault.example.com:*,https://vault.example.com") == "https://vault.example.com"
    assert ah.middleware_hosts("https://vault.example.com:*")[0] == "vault.example.com"
    assert ah.link_base("") == "" and ah.middleware_hosts("") == []
    assert ah.link_base("ftp://vault.example.com,vault.example.com") == "https://vault.example.com"


def test_an_entry_with_no_readable_host_is_named_and_never_a_link_base_or_host():
    raw = "https://,:8443,https://[vault,http://:8443,vault.example.com"
    assert ah.problems(raw) == ["'https://'", "':8443'", "'https://[vault'", "'http://:8443'"]
    assert ah.middleware_hosts(raw) == ["vault.example.com", "localhost", "127.0.0.1"]
    assert ah.link_base(raw) == "https://vault.example.com"
    for good in ("*", "*.example.com", "https://*.example.com", "vault.example.com:8443", "http://localhost:8200",
                 "0.0.0.0", "Vault.Example.COM/"):
        assert ah.problems(good) == [], good


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


_ADMIN_PW = "Strong-Pass-1234"       # setup refuses a weak first password
WEB_QUESTION = "Do people reach the web UI at a different address or port"
ADDRESS_PROMPT = "Address people open in their browser"


def _interactive_setup(monkeypatch, tmp_path, web_port, reached_elsewhere, answers=()):
    """Setup run interactively: the web port chosen, the web question answered, and the address prompt given the
    answers in turn (a blank answer takes the prompt's default, as ask does). Returns the .env and what was asked."""
    import argparse
    dv = _dockvault()
    answers, asked = list(answers), []

    def ask(prompt, pal, default=None):
        if prompt.startswith(ADDRESS_PROMPT):
            asked.append((prompt, default))
            return answers.pop(0).strip() or (default or "")
        return "vault.example.com" if prompt.startswith("Public DNS name") else (default or "")

    def confirm(prompt, pal, default=True):
        if prompt.startswith(WEB_QUESTION):
            asked.append((prompt, default))
            return reached_elsewhere
        return False

    monkeypatch.setattr(dv, "ask", ask)
    monkeypatch.setattr(dv, "ask_secret", lambda prompt, pal: _ADMIN_PW)
    monkeypatch.setattr(dv, "confirm", confirm)
    monkeypatch.setattr(dv, "prompt_free_port", lambda pal, label, default: web_port if label.startswith("Web") else default)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_resolve_setup_image", lambda *a, **k: "dockvault-vault:latest")
    cfg = tool._collect_setup_config(argparse.Namespace(non_interactive=False, min_free_space_gb=0.0))
    assert not answers, "every answer was asked for"
    return dv.parse_env("\n".join(dv.build_env_lines(cfg))), asked


@pytest.mark.parametrize("web_port, written", [(443, "vault.example.com"), (8443, "https://vault.example.com:8443")])
def test_no_other_address_keeps_this_servers_name_on_its_web_port(monkeypatch, tmp_path, web_port, written):
    env, asked = _interactive_setup(monkeypatch, tmp_path, web_port, reached_elsewhere=False)
    assert [prompt for prompt, _default in asked] == [
        "Do people reach the web UI at a different address or port (a reverse proxy, port forwarding)?"]
    assert asked[0][1] is False, "No is the default"
    assert env["ALLOWED_HOSTS"] == written


@pytest.mark.parametrize("answers, written, base", [
    # The README's proxy on this host: the vault on a loopback port, people on https://name.
    ([""], "vault.example.com", "https://vault.example.com"),
    (["https://Vault.Example.com/"], "vault.example.com", "https://vault.example.com"),
    # Port forwarding to another address and port: that address first, this server's name still admitted.
    (["gate.example.net:9443"], "https://gate.example.net:9443,vault.example.com", "https://gate.example.net:9443"),
    (["http://gate.example.net"], "http://gate.example.net,vault.example.com", "http://gate.example.net"),
    # Asked again until it is an address.
    (["ftp://gate.example.net", "gate example.net", "gate.example.net:0", "gate.example.net/vault",
      "gate.example.net"], "gate.example.net,vault.example.com", "https://gate.example.net"),
])
def test_another_address_is_written_first_and_is_the_link_base(monkeypatch, tmp_path, answers, written, base):
    env, asked = _interactive_setup(monkeypatch, tmp_path, 8443, reached_elsewhere=True, answers=answers)
    assert [prompt for prompt, _default in asked].count(ADDRESS_PROMPT) == len(answers)
    assert asked[1][1] == "https://vault.example.com", "the default is this server's name on https"
    assert env["ALLOWED_HOSTS"] == written
    assert ah.link_base(written) == base
    assert {"vault.example.com", ah.host_name(written.split(",")[0])} <= set(ah.middleware_hosts(written))


def test_unattended_setup_takes_the_address_from_its_flag(tmp_path, monkeypatch):
    import argparse
    dv = _dockvault()
    monkeypatch.setattr(dv, "confirm", lambda *a, **k: pytest.fail("an unattended setup asked something"))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_resolve_setup_image", lambda *a, **k: "dockvault-vault:latest")

    def env_for(*flags):
        parsed = dv.build_parser().parse_args(["setup", "--non-interactive", "--web-port", "8443", *flags])
        cfg = tool._collect_setup_config(argparse.Namespace(
            non_interactive=True, server_name="vault.example.com", admin_password=_ADMIN_PW,
            web_port=parsed.web_port, web_public_address=parsed.web_public_address))
        return dv.parse_env("\n".join(dv.build_env_lines(cfg)))["ALLOWED_HOSTS"]

    assert env_for() == "https://vault.example.com:8443"
    assert env_for("--web-public-address", "https://vault.example.com") == "vault.example.com"
    assert env_for("--web-public-address=gate.example.net:9443") == "https://gate.example.net:9443,vault.example.com"
    for bad in ("ftp://gate.example.net", "gate.example.net:70000", "gate.example.net\nADMIN_PASSWORD=x"):
        with pytest.raises(SystemExit):
            env_for("--web-public-address=" + bad)


@pytest.mark.parametrize("current, server_name", [
    ({"ALLOWED_HOSTS": "https://vault.example.com:8443", "WEB_HOST_PORT": "8443"}, "vault.example.com"),
    # Behind a proxy: the address people use is not the published port, and must not become it.
    ({"ALLOWED_HOSTS": "vault.example.com", "WEB_HOST_PORT": "8443"}, "vault.example.com"),
    ({"ALLOWED_HOSTS": "https://gate.example.net:9443,vault.example.com", "WEB_HOST_PORT": "8443"},
     "gate.example.net"),
    ({"ALLOWED_HOSTS": "*.example.com,HTTPS://Vault.Example.com:8443", "WEB_HOST_PORT": "8443"}, "vault.example.com"),
])
def test_a_fresh_volume_set_keeps_allowed_hosts_and_reads_the_name_from_it(current, server_name):
    """With no SERVER_NAME, the name for the certificate and the summary is ALLOWED_HOSTS's first host that is not a
    wildcard, never the entry as written (https://https://name:8443:8443 when an origin was taken for a name); and
    ALLOWED_HOSTS itself is written back as it was."""
    dv = _dockvault()
    cfg = dv.new_set_config(current, "prefix-1", "dep-1")
    assert cfg["server_name"] == server_name
    env = dv.parse_env("\n".join(dv.build_env_lines(cfg)))
    assert env["ALLOWED_HOSTS"] == current["ALLOWED_HOSTS"] and env["SERVER_NAME"] == server_name


def test_every_read_of_allowed_hosts_in_setup_takes_its_name_or_keeps_it_whole():
    """Setup reads ALLOWED_HOSTS at three places for a name (a fresh volume set, a re-run's summary and the
    certificate's) and once to keep it: each name goes through _allowed_hosts_name."""
    import ast
    tree = ast.parse((ROOT / "dockvault.py").read_text(encoding="utf-8"))
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    reads = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "get"
             and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == "ALLOWED_HOSTS"]
    named = [n for n in reads if getattr(getattr(parents[id(n)], "func", None), "id", None) == "_allowed_hosts_name"]
    assert len(reads) == 4 and len(named) == 3, [ast.unparse(parents[id(n)]) for n in reads]
    kept = [n for n in reads if n not in named]
    assert ast.unparse(parents[id(parents[id(kept[0])])]) == "(current_env.get('ALLOWED_HOSTS') or '').strip"


def test_public_web_address_reads_an_address_as_setup_writes_it():
    dv = _dockvault()
    assert dv.public_web_address("") is None and dv.public_web_address("  ") is None
    assert dv.public_web_address("https://Vault.Example.com/") == "vault.example.com"
    assert dv.public_web_address("vault.example.com") == "vault.example.com"
    assert dv.public_web_address("vault.example.com:9443") == "https://vault.example.com:9443"
    assert dv.public_web_address("HTTP://203.0.113.7:8080") == "http://203.0.113.7:8080"
    for bad in ("ftp://vault.example.com", "vault example.com", "vault.example.com:0", "vault.example.com:x",
                "vault.example.com/vault", "https://", "'vault.example.com'", "[::1]:8443",
                # A dot at the name's end: setup would write an address into ALLOWED_HOSTS that the vault builds
                # no sign-in on, and only a note afterwards would say so.
                "vault.example.com.", "https://vault.example.com.:8443", "http://vault.lan./"):
        with pytest.raises(ValueError):
            dv.public_web_address(bad)
    for dotted in ("vault.example.com.", "https://vault.example.com.:8443", "http://vault.lan./"):
        with pytest.raises(ValueError, match="no dot at its end"):
            dv.public_web_address(dotted)


def test_ci_sets_the_public_address_to_the_tests_base_url_in_both_stacks():
    """CI's two stacks set ALLOWED_HOSTS alike; its link base is the tests' base URL, so emailed links in CI point
    where the tests reach the stack."""
    import re
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    values = re.findall(r'echo "ALLOWED_HOSTS=([^"]*)"', workflow)
    assert len(values) == 2 and values[0] == values[1], values
    base_url = re.search(r"--base-url=(\S+)", (ROOT / "pytest.ini").read_text(encoding="utf-8")).group(1)
    assert ah.link_base(values[0]) == base_url.rstrip("/")
    assert "vault-api" in ah.middleware_hosts(values[0])
