"""A range in TRUSTED_PROXIES never trusts the Docker gateway, offline.

Every connection Docker relays to a published port arrives from the container's gateway: an IPv6
client, a client on the host itself, and on Docker Desktop every client. With a range that contains the
gateway in TRUSTED_PROXIES (the 172.16.0.0/12 the example suggested, which covers Docker's default
networks), any of them could send its own X-Forwarded-For and be recorded under the address it chose,
dodging the per-address sign-in limits or spending another address's. Now the gateway is trusted only
by name: the token ``gateway`` (the container's default route, read at start) or its exact address.
A proxy container on the network is trusted by a range as before. The web process says at start when a
range covers the gateway, and once when a request from it arrives with a header it now ignores, naming
the .env lines for a reverse proxy on the host (TRUSTED_PROXIES=gateway with WEB_BIND=127.0.0.1).
The proxy matrix (.github/scripts/proxy_matrix.py, run by the proxy-matrix workflow) proves it on a
running stack: a client on the Docker host, an IPv6 client and an nginx on the host, all relayed through
the gateway.
"""
import importlib.util
import ipaddress
from pathlib import Path

import pytest
from starlette.requests import Request

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import net_utils  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
GATEWAY = "172.18.0.1"
PROXY = "172.18.0.5"
FORGED = "203.0.113.77"


def _request(peer, xff=None, xfp=None):
    headers = []
    if xff:
        headers.append((b"x-forwarded-for", xff.encode()))
    if xfp:
        headers.append((b"x-forwarded-proto", xfp.encode()))
    return Request({"type": "http", "method": "GET", "path": "/", "raw_path": b"/", "query_string": b"",
                    "headers": headers, "client": (peer, 40000), "server": ("vault", 443), "scheme": "https"})


@pytest.fixture
def trust(monkeypatch):
    """Set TRUSTED_PROXIES (and TRUST_ALL_PROXIES) and the container's gateways, as read at start."""
    def _set(spec, gateways=(GATEWAY,), trust_all=False):
        monkeypatch.setattr(net_utils.settings, "trusted_proxies", spec, raising=False)
        monkeypatch.setattr(net_utils.settings, "trust_all_proxies", trust_all, raising=False)
        monkeypatch.setattr(net_utils, "_read_default_gateways",
                            lambda *a, **k: [ipaddress.ip_address(g) for g in gateways])
        net_utils._trusted_networks.cache_clear()
        net_utils._ignored_warned.clear()
    yield _set
    net_utils._trusted_networks.cache_clear()
    net_utils._ignored_warned.clear()


# --------------------------------------------------------------------------- reading the default route

def test_the_default_routes_are_read_from_the_kernels_tables(tmp_path):
    v4 = tmp_path / "route"
    v4.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        "eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
        "eth1\t0000000A\t0101A8C0\t0003\t0\t0\t0\t000000FF\t0\t0\t0\n", encoding="ascii")  # 10/8 via a router
    v6 = tmp_path / "ipv6_route"
    v6.write_text(
        "fd000000000000000000000000000000 40 00000000000000000000000000000000 00 "
        "00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
        "fd000000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n", encoding="ascii")
    assert net_utils._read_default_gateways(str(v4), str(v6)) == [
        ipaddress.ip_address("172.18.0.1"), ipaddress.ip_address("fd00::1")]
    assert net_utils._read_default_gateways(str(tmp_path / "none"), str(tmp_path / "none6")) == []


# --------------------------------------------------------------------------- the rule

def test_a_range_that_contains_the_gateway_does_not_trust_it(trust):
    trust("172.16.0.0/12")
    assert net_utils.client_ip(_request(GATEWAY, FORGED)) == GATEWAY
    assert net_utils.client_ip(_request(PROXY, FORGED)) == FORGED, "a proxy container is still trusted"
    assert not net_utils._is_trusted_peer(GATEWAY) and net_utils._is_trusted_peer(PROXY)


@pytest.mark.parametrize("spec", ["gateway", "GATEWAY", " gateway ,10.9.9.9", f"{GATEWAY}/32", GATEWAY,
                                  "172.16.0.0/12, gateway"])
def test_the_gateway_is_trusted_only_by_name(trust, spec):
    trust(spec)
    assert net_utils.client_ip(_request(GATEWAY, f"{FORGED}, 198.51.100.4")) == "198.51.100.4"


def test_the_token_trusts_nothing_else(trust):
    trust("gateway")
    assert net_utils.client_ip(_request(PROXY, FORGED)) == PROXY


def test_the_rule_covers_an_ipv6_gateway(trust):
    trust("fd00::/8", gateways=("fd00::1",))
    assert net_utils.client_ip(_request("fd00::1", FORGED)) == "fd00::1"
    assert net_utils.client_ip(_request("fd00::5", FORGED)) == FORGED
    trust("gateway", gateways=("fd00::1",))
    assert net_utils.client_ip(_request("fd00::1", FORGED)) == FORGED


def test_the_gateway_in_a_chain_is_not_a_trusted_hop(trust):
    # A proxy container that a relayed client reached appends the gateway: that is the client.
    trust("172.16.0.0/12")
    assert net_utils.client_ip(_request(PROXY, f"{FORGED}, {GATEWAY}")) == GATEWAY


def test_trust_all_still_trusts_every_peer(trust):
    trust("", trust_all=True)
    assert net_utils.client_ip(_request(GATEWAY, FORGED)) == FORGED


def test_outside_a_container_nothing_changes(trust):
    trust("172.16.0.0/12", gateways=())
    assert net_utils.client_ip(_request(GATEWAY, FORGED)) == FORGED


def test_the_scheme_from_the_gateway_follows_the_same_rule(trust):
    trust("172.16.0.0/12")
    assert not net_utils._is_trusted_peer(GATEWAY)
    trust("gateway")
    assert net_utils._is_trusted_peer(GATEWAY)


# --------------------------------------------------------------------------- what is said about it

def test_at_start_a_range_that_covers_the_gateway_is_named_with_the_lines_to_change(trust):
    trust("172.16.0.0/12")
    (warning,) = net_utils.trust_warnings()
    assert GATEWAY in warning and "TRUSTED_PROXIES=gateway" in warning and "WEB_BIND=127.0.0.1" in warning


@pytest.mark.parametrize("spec,gateways", [
    ("gateway", (GATEWAY,)), (f"{GATEWAY}/32", (GATEWAY,)), ("10.0.0.0/8", (GATEWAY,)), ("", (GATEWAY,)),
    ("172.16.0.0/12", ()), (f"172.16.0.0/12, {GATEWAY}", (GATEWAY,)),
])
def test_nothing_is_said_when_nothing_changed(trust, spec, gateways):
    trust(spec, gateways=gateways)
    assert net_utils.trust_warnings() == []


def test_at_start_trust_all_and_a_token_with_no_gateway_are_named(trust):
    trust("", trust_all=True)
    assert [w.startswith("TRUST_ALL_PROXIES=true") for w in net_utils.trust_warnings()] == [True]
    trust("gateway", gateways=())
    (warning,) = net_utils.trust_warnings()
    assert "no default route" in warning


def test_a_header_from_the_gateway_that_is_now_ignored_is_named_once(trust, capsys):
    trust("172.16.0.0/12")
    net_utils.client_ip(_request(GATEWAY))                     # no header: nothing to say
    assert capsys.readouterr().err == ""
    net_utils.client_ip(_request(GATEWAY, FORGED))
    err = capsys.readouterr().err
    assert "X-Forwarded-For" in err and "TRUSTED_PROXIES=gateway" in err and "WEB_BIND=127.0.0.1" in err
    assert FORGED not in err, "the client's own value is not repeated into the log"
    net_utils.client_ip(_request(GATEWAY, FORGED))
    assert capsys.readouterr().err == "", "once per process"


@pytest.mark.parametrize("spec", ["gateway", "10.0.0.0/8"])
def test_nothing_is_named_when_the_header_was_never_trusted_from_the_gateway(trust, capsys, spec):
    trust(spec)
    net_utils.client_ip(_request(GATEWAY, FORGED))
    assert capsys.readouterr().err == ""


def test_the_web_process_prints_the_start_warnings():
    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    main = source[source.index('if __name__ == "__main__":'):]
    assert main.count("for _warning in trust_warnings():") == 1
    assert main.index("for _warning in trust_warnings():") < main.index("uvicorn.run(")


# --------------------------------------------------------------------------- what ships

def test_the_example_no_longer_suggests_a_range_that_covers_the_gateway():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    block = text[text.index("# Trust X-Forwarded-For only from these peers"):text.index("\nTRUSTED_PROXIES=")]
    assert "(e.g. 172.16.0.0/12)" not in block
    assert "`gateway`" in block and "WEB_BIND=127.0.0.1" in block
    assert "\nWEB_BIND=\n" in text


def test_the_image_empties_uvicorns_own_trusted_list():
    assert (ROOT / "Dockerfile").read_text(encoding="utf-8").count('\nENV FORWARDED_ALLOW_IPS=""\n') == 1


def test_the_secure_compose_publishes_the_web_port_on_web_bind():
    text = (ROOT / "deploy" / "docker-compose.secure.yml").read_text(encoding="utf-8")
    assert text.count('- "${WEB_BIND:+${WEB_BIND}:}${WEB_HOST_PORT:-443}:8000"') == 2
    assert '- "${WEB_HOST_PORT:-443}:8000"' not in text


# --------------------------------------------------------------------------- the update pre-check

def _cli():
    spec = importlib.util.spec_from_file_location("dockvault_cli_gateway", ROOT / "dockvault.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    return cli


@pytest.mark.parametrize("trusted,gateways,current,target,flagged", [
    ("172.16.0.0/12", ["172.18.0.1"], "0.33.0", "v0.33.1", True),
    ("172.16.0.0/12", ["172.18.0.1"], "unknown", "0.34.0", True),
    ("172.16.0.0/12", [], "0.33.0", "0.33.1", True),            # the network could not be read
    ("192.168.0.0/16", [], "0.33.0", "0.33.1", True),
    ("172.16.0.0/12", ["172.18.0.1"], "0.33.1", "0.34.0", False),
    ("172.16.0.0/12", ["172.18.0.1"], "0.32.6", "0.33.0", False),
    ("gateway", ["172.18.0.1"], "0.33.0", "0.33.1", False),
    ("172.16.0.0/12, gateway", ["172.18.0.1"], "0.33.0", "0.33.1", False),
    ("172.18.0.1", ["172.18.0.1"], "0.33.0", "0.33.1", False),
    ("172.16.0.0/12, 172.18.0.1", ["172.18.0.1"], "0.33.0", "0.33.1", False),   # named exactly as well
    ("172.18.0.10", ["172.18.0.1"], "0.33.0", "0.33.1", False),  # a proxy container's address
    ("10.0.0.0/8", ["172.18.0.1"], "0.33.0", "0.33.1", False),
    ("10.0.0.0/8", [], "0.33.0", "0.33.1", False),
    ("", ["172.18.0.1"], "0.33.0", "0.33.1", False),
    ("not-an-address", ["172.18.0.1"], "0.33.0", "0.33.1", False),
])
def test_the_update_pre_check_names_a_range_that_covers_the_gateway(trusted, gateways, current, target, flagged):
    note = _cli().gateway_trust_note(trusted, gateways, current, target)
    assert bool(note) == flagged
    if flagged:
        assert "TRUSTED_PROXIES=gateway" in note and "WEB_BIND=127.0.0.1" in note
        assert "127.0.0.1:<port>:8000" in note, "installs that pull images edit the mapping by hand"
