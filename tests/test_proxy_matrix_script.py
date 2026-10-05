"""The real-proxy matrix script: its check table, report, output parsing and cleanup rules.

The matrix itself needs Docker and runs in its own workflow; these are the parts that decide what a
run means -- which address each set-up must record, when a result counts as a failure, what the
exit status is, and which containers cleanup may remove -- tested without Docker.
"""

from __future__ import annotations

import importlib.util
import io
import ipaddress
import json
import random
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml


pytestmark = pytest.mark.unit

_ROOT = Path(__file__).parents[1]
_SCRIPT = _ROOT / ".github" / "scripts" / "proxy_matrix.py"
_SPEC = importlib.util.spec_from_file_location("proxy_matrix_under_test", _SCRIPT)
assert _SPEC and _SPEC.loader
pm = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = pm
_SPEC.loader.exec_module(pm)

_SUBNET = "10.201.7.0/24"


@pytest.fixture
def addr():
    return pm.addresses(_SUBNET)


# --- the check table ---------------------------------------------------------------------------

def test_every_role_has_its_own_address_inside_the_network(addr):
    net = ipaddress.ip_network(_SUBNET)
    roles = list(pm.HOSTS)
    values = [addr[r] for r in roles]
    assert len(set(values)) == len(values)
    assert all(ipaddress.ip_address(v) in net for v in values)
    assert addr["api"] == "10.201.7.2" and addr["client"] == "10.201.7.101"
    assert addr["subnet"] == _SUBNET and addr["loopback"] == "127.0.0.1" and addr["forged"] == pm.FORGED
    assert addr["gateway"] == "10.201.7.1", "Docker's gateway for a network made with --subnet"
    assert addr["gateway"] not in values


@pytest.mark.parametrize("subnet", ["fd00::/64", "10.0.0.0/25", "10.0.0.1/24"])
def test_a_network_the_table_cannot_use_is_refused(subnet):
    with pytest.raises(ValueError):
        pm.addresses(subnet)


def test_each_trust_setting_resolves_to_what_the_vault_is_started_with(addr):
    configs = {c.key: c for c in pm.CONFIGS}
    assert pm.trusted_value(configs["none"], addr) == "" and not configs["none"].trust_all
    assert pm.trusted_value(configs["loopback"], addr) == "127.0.0.1"
    assert pm.trusted_value(configs["proxies"], addr) == "10.201.7.20,10.201.7.21,10.201.7.22"
    assert pm.trusted_value(configs["all"], addr) == "" and configs["all"].trust_all
    assert pm.trusted_value(configs["subnet"], addr) == _SUBNET
    assert pm.trusted_value(configs["gateway"], addr) == "gateway"
    assert [c.key for c in pm.CONFIGS if c.publish] == ["subnet", "gateway"]


def test_every_check_resolves_to_a_concrete_url_and_expectation(addr):
    config_keys = [c.key for c in pm.CONFIGS]
    assert len(set(config_keys)) == len(config_keys)
    publishing = {c.key for c in pm.CONFIGS if c.publish}
    for check in pm.CHECKS:
        assert check.config in config_keys
        url = pm.url_for(check, addr)
        if check.via in pm.HOST_VIAS:
            assert url.startswith(("http://127.0.0.1:", "http://[::1]:")) and pm.probe_role(check) == "host"
            assert check.config in publishing
        elif check.via == "host-proxy":
            assert url.startswith(f"http://{addr['gateway']}:") and pm.probe_role(check) == "client"
            assert check.config in publishing
        else:
            assert url.startswith(("http://10.201.7.", "https://10.201.7.")) and pm.probe_role(check) == "client"
        assert check.ipv6 == (check.via == "relayed6")
        expect = pm.expected_value(check, addr)
        if check.probe == "address":
            ipaddress.ip_address(expect)
        elif check.probe == "scheme":
            assert expect in ("http", "https")
            assert check.via in ("direct", "local-tls", "nginx-tls")
        elif check.probe == "log":
            assert expect == "warned" and check.config == "subnet"
        elif check.probe == "key-proof":
            assert expect == pm.KEY_PROOF_PASSED and check.action == pm.KEY_PROOF_ACTION
        else:
            assert check.probe == "budget" and check.expect == "baseline"
    # every trust setting is exercised, and run in table order (the API restarts once per setting)
    seen = []
    for check in pm.CHECKS:
        if not seen or seen[-1] != check.config:
            seen.append(check.config)
    assert seen == config_keys
    assert len({(c.config, c.setup, c.action) for c in pm.CHECKS}) == len(pm.CHECKS)


def test_the_table_holds_the_set_ups_that_have_mattered():
    """The set-ups that separated a broken release from a fixed one: HAProxy's own header line, the
    passthrough proxy on 127.0.0.1, the TLS scheme through a proxy on another host, and the sign-in
    budget an attacker could spend by typing the victim's address."""
    table = {(c.config, c.via, c.probe, c.xff): c.expect for c in pm.CHECKS}
    assert table[("proxies", "haproxy", "address", pm.FORGED)] == "client"
    assert table[("proxies", "edge", "address", pm.FORGED)] == "client"
    assert table[("proxies", "nginx", "address", pm.FORGED)] == "client"
    assert table[("proxies", "direct", "address", pm.FORGED)] == "client"
    assert table[("none", "direct", "address", pm.FORGED)] == "client"
    assert table[("none", "local-pass", "address", pm.FORGED)] == "loopback"
    assert table[("none", "local-pass", "address", pm.JUNK)] == "loopback"
    assert table[("loopback", "local-append", "address", pm.FORGED)] == "client"
    assert table[("all", "nginx", "address", pm.FORGED)] == "client"
    assert table[("all", "edge", "address", None)] == "edge"
    assert table[("subnet", "edge", "address", None)] == "client"
    assert table[("subnet", "edge", "address", pm.FORGED)] == "forged"
    assert table[("none", "local-tls", "scheme", None)] == "http"
    assert table[("loopback", "local-tls", "scheme", None)] == "https"
    assert table[("proxies", "nginx-tls", "scheme", None)] == "https"
    forged_proto = [c for c in pm.CHECKS if c.xfp]
    assert [(c.config, c.via, c.expect) for c in forged_proto] == [("none", "direct", "http")]
    assert [c.config for c in pm.CHECKS if c.probe == "budget"] == ["none"]


def test_the_table_holds_the_gateway_set_ups():
    """Docker relays every connection to a published port through the network's gateway: a client on
    the Docker host, an IPv6 client, and a reverse proxy on the Docker host. A range that contains the
    gateway must not trust it, and the start-up warning must say what to set; the token `gateway`
    trusts it, and only it."""
    table = {(c.config, c.via, c.probe, c.xff): c.expect for c in pm.CHECKS}
    assert table[("subnet", "relayed", "address", pm.FORGED)] == "gateway"
    assert table[("subnet", "relayed6", "address", pm.FORGED)] == "gateway"
    assert table[("subnet", "host-proxy", "address", None)] == "gateway"
    assert table[("subnet", "direct", "log", None)] == "warned"
    assert table[("gateway", "host-proxy", "address", None)] == "client"
    assert table[("gateway", "host-proxy", "address", pm.FORGED)] == "client"
    assert table[("gateway", "nginx", "address", pm.FORGED)] == "nginx"
    assert pm.GATEWAY_WARNING == ("TRUSTED_PROXIES=gateway", "WEB_BIND=127.0.0.1")


def test_a_forged_address_is_expected_to_be_believed_only_where_the_table_says_why():
    """The one case where the vault records the address a client made up is a client that is itself
    inside a trusted network, and the table has to say so rather than quietly expect it."""
    believed = [c for c in pm.CHECKS if c.probe == "address" and c.expect == "forged"]
    assert [(c.config, c.via) for c in believed] == [("subnet", "edge"), ("gateway", "relayed")]
    assert all(c.xff == pm.FORGED and c.note.startswith("documented:") for c in believed)


# --- judging results ---------------------------------------------------------------------------

def test_budget_counts_sign_ins_until_the_first_refusal():
    assert pm.budget_from_statuses([401, 401, 429, 401]) == 2
    assert pm.budget_from_statuses([429]) == 0
    assert pm.budget_from_statuses([401] * 4) == 4


def _budget_check():
    return next(c for c in pm.CHECKS if c.probe == "budget")


def test_the_victim_keeping_its_whole_allowance_passes():
    base = [401] * 10 + [429] * 6
    result = pm.judge_budget(_budget_check(), base, list(base), [401] * 5)
    assert result.ok and (result.got, result.expect) == ("10", "10")


def test_an_attacker_spending_the_victims_allowance_fails():
    base = [401] * 10 + [429] * 6
    attacked = [401] * 5 + [429] * 11
    result = pm.judge_budget(_budget_check(), base, attacked, [401] * 5)
    assert not result.ok and (result.got, result.expect) == ("5", "10")


def test_a_throttle_that_never_engaged_proves_nothing_and_fails():
    result = pm.judge_budget(_budget_check(), [401] * 16, [401] * 16, [401] * 5)
    assert not result.ok and "never engaged" in result.detail


def test_a_sign_in_that_never_reached_the_vault_fails():
    base = [401] * 10 + [429] * 6
    result = pm.judge_budget(_budget_check(), base, list(base), [0] * 5)
    assert not result.ok and "did not reach" in result.detail


def test_an_address_check_passes_only_on_the_exact_address(addr):
    check = next(c for c in pm.CHECKS if c.via == "haproxy")
    assert pm.judge(check, addr["client"], addr).ok
    assert not pm.judge(check, pm.FORGED, addr).ok
    assert not pm.judge(check, "(no audit row)", addr).ok


# --- parsing what the probes print -----------------------------------------------------------------

def test_the_probe_output_is_its_last_line():
    out = "some warning\n\n" + json.dumps([{"status": 401, "body": "{}"}]) + "\n"
    assert pm.parse_client_output(out) == [{"status": 401, "body": "{}"}]


@pytest.mark.parametrize("out, message", [
    ("", "printed nothing"),
    ("Traceback (most recent call last):\n  boom\n", "not JSON"),
    ('{"status": 200}', "wrong shape"),
    ('[{"status": "200", "body": ""}]', "wrong shape"),
])
def test_unusable_probe_output_is_a_harness_error(out, message):
    with pytest.raises(pm.HarnessError, match=message):
        pm.parse_client_output(out)


@pytest.mark.parametrize("body, scheme", [
    ('{"reset_link": "https://vault.test/?reset=abc"}', "https"),
    ('{"reset_link": "http://10.0.0.2:8000/?reset=abc"}', "http"),
])
def test_the_scheme_is_read_from_the_reset_link(body, scheme):
    assert pm.link_scheme(body) == scheme


def test_a_response_without_a_link_is_described_not_mistaken_for_a_scheme():
    assert pm.link_scheme("<html>").startswith("(not JSON")
    assert pm.link_scheme('{"detail": "x"}').startswith("(no link")
    assert pm.link_scheme('{"reset_link": 5}').startswith("(no link")


# --- cleanup only ever touches its own ---------------------------------------------------------------

def test_cleanup_keeps_only_names_under_the_prefix_and_removes_the_shared_namespace_first():
    listing = "\n".join([
        "dockvault-proxy-matrix-a1b2c3-api",
        "dockvault-proxy-matrix-a1b2c3-local",
        "dockvault-proxy-matrix-a1b2c3-db",
        "dockvault-proxy-matrixed-other",
        "vault-api",
        "someone-dockvault-proxy-matrix-x",
        "",
    ])
    assert pm.owned_names(listing, "dockvault-proxy-matrix") == [
        "dockvault-proxy-matrix-a1b2c3-local",
        "dockvault-proxy-matrix-a1b2c3-api",
        "dockvault-proxy-matrix-a1b2c3-db",
    ]


@pytest.mark.parametrize("prefix", ["", "ab", "Dockvault", "has space", "-lead", "a" * 42, "x;rm"])
def test_a_prefix_that_could_match_too_much_is_refused(prefix):
    with pytest.raises(pm.argparse.ArgumentTypeError):
        pm.check_prefix(prefix)


def test_the_default_prefix_is_accepted():
    assert pm.check_prefix(pm.DEFAULT_PREFIX) == pm.DEFAULT_PREFIX


class _FakeDocker:
    def __init__(self, containers="", networks=""):
        self.calls = []
        self.listings = {"ps": containers, "network ls": networks}

    def __call__(self, *args, check=True, **kwargs):
        self.calls.append(args)
        out = ""
        if args[0] == "ps":
            out = self.listings["ps"]
        elif args[:2] == ("network", "ls"):
            out = self.listings["network ls"]
        return type("R", (), {"returncode": 0, "stdout": out, "stderr": ""})()


def test_cleanup_lists_by_label_and_removes_containers_before_networks():
    docker = _FakeDocker("p-x-1-api\np-x-1-local\nother\n", "p-x-1-net\nbridge\n")
    removed = pm.cleanup(docker, "p-x")
    assert removed == ["p-x-1-local", "p-x-1-api", "p-x-1-net"]
    listings = [c for c in docker.calls if c[0] == "ps" or c[:2] == ("network", "ls")]
    assert all(f"label={pm.LABEL}=p-x" in c for c in listings)
    removals = [c for c in docker.calls if c[0] == "rm" or c[:2] == ("network", "rm")]
    assert removals == [("rm", "-f", "-v", "p-x-1-local"), ("rm", "-f", "-v", "p-x-1-api"),
                        ("network", "rm", "p-x-1-net")]


# --- the rest of what a run is built from ---------------------------------------------------------

def test_the_backing_images_are_the_ones_the_deployment_pins():
    images = pm.compose_images((_ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8"))
    assert images["db"].startswith("postgres:15-alpine@sha256:")
    assert images["redis"].startswith("redis:") and "@sha256:" in images["redis"]
    with pytest.raises(pm.HarnessError, match="redis"):
        pm.compose_images("services:\n  db:\n    image: postgres:15\n")


def test_the_proxy_images_are_pinned_by_digest():
    for ref in (pm.NGINX_IMAGE, pm.HAPROXY_IMAGE):
        name, digest = ref.split("@sha256:")
        assert ":" in name and len(digest) == 64 and int(digest, 16) >= 0


def test_subnet_candidates_are_distinct_private_slash_24s():
    picks = pm.subnet_candidates(random.Random(7))
    assert len(set(picks)) == len(picks) == 24
    pool = ipaddress.ip_network("10.200.0.0/13")
    for subnet in picks:
        net = ipaddress.ip_network(subnet)
        assert net.prefixlen == 24 and net.subnet_of(pool)
        pm.addresses(subnet)


def test_each_proxy_forwards_the_header_the_way_its_set_up_says(addr):
    cfg = pm.proxy_configs(addr)
    assert cfg["nginx"].count("$proxy_add_x_forwarded_for") == 2
    assert "listen 443 ssl" in cfg["nginx"] and "ssl_certificate /etc/nginx/cert.pem" in cfg["nginx"]
    assert cfg["nginx"].count(f"proxy_pass http://{addr['api']}:8000;") == 2
    assert f"proxy_pass http://{addr['nginx']}:80;" in cfg["edge"]
    local = cfg["local"].split("server {")[1:]
    assert "listen 8081;" in local[0] and "X-Forwarded-For $http_x_forwarded_for;" in local[0]
    assert "listen 8082;" in local[1] and "$proxy_add_x_forwarded_for" in local[1]
    assert "listen 8443 ssl;" in local[2] and "$proxy_add_x_forwarded_for" in local[2]
    assert all("proxy_pass http://127.0.0.1:8000;" in s for s in local)
    assert "option forwardfor" in cfg["haproxy"]
    assert f"server vault {addr['api']}:8000" in cfg["haproxy"]
    # The nginx on the Docker host listens on the gateway's address only, and reaches the published port.
    assert f"listen {addr['gateway']}:{addr['hostproxy']};" in cfg["hostproxy"]
    assert f"proxy_pass http://127.0.0.1:{addr['published']};" in cfg["hostproxy"]
    assert "$proxy_add_x_forwarded_for" in cfg["hostproxy"]


def test_configuration_files_are_copied_in_owned_by_root_with_their_modes():
    data = pm.tar_of({"conf.d/default.conf": (b"server {}\n", 0o644), "key.pem": (b"k", 0o600)})
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        members = {m.name: m for m in tar.getmembers()}
        assert set(members) == {"conf.d/default.conf", "key.pem"}
        assert members["key.pem"].mode == 0o600 and members["conf.d/default.conf"].mode == 0o644
        assert all(m.uid == 0 and m.gid == 0 for m in members.values())
        assert tar.extractfile("conf.d/default.conf").read() == b"server {}\n"


# --- the report and the exit status -------------------------------------------------------------

def _results(addr, fail_haproxy=False):
    out = []
    for check in pm.CHECKS:
        if check.probe == "budget":
            out.append(pm.Result(check, "10", "10", True, "attacker got [401]"))
            continue
        got = pm.expected_value(check, addr)
        if fail_haproxy and check.via == "haproxy" and check.probe == "address":
            got = pm.FORGED
        out.append(pm.judge(check, got, addr))
    return out


def test_the_report_names_roles_and_marks_each_failure(addr):
    text = pm.format_report("img:1", _results(addr, fail_haproxy=True), addr)
    assert f"{len(pm.CHECKS)} checks, 1 failed" in text
    failing = [line for line in text.splitlines() if line.strip().startswith("FAIL")]
    assert len(failing) == 1 and "HAProxy" in failing[0]
    assert f"got {pm.FORGED} (forged), expected {addr['client']} (client)" in text
    for config in pm.CONFIGS:
        assert f"== {config.title}" in text


def test_the_step_summary_is_a_table_that_survives_a_pipe_in_a_cell(addr):
    results = _results(addr, fail_haproxy=True)
    results[0] = pm.Result(results[0].check, "a|b", "c", False)
    md = pm.markdown_report("img:1", results, addr)
    assert md.startswith(f"### Proxy matrix: {len(pm.CHECKS)} checks, 2 failed")
    assert "a\\|b" in md and md.count("**FAIL**") == 2
    rows = [line for line in md.splitlines() if line.startswith("| ")]
    assert len(rows) == len(pm.CHECKS) + 1          # header + one per check
    assert all(line.count(" | ") == 5 for line in rows[1:])


def test_a_skipped_check_is_reported_and_is_not_a_failure(addr):
    results = _results(addr)
    six = next(i for i, r in enumerate(results) if r.check.ipv6)
    results[six] = pm.Result(results[six].check, "", "x", False, "no IPv6 here", skipped=True)
    text = pm.format_report("img:1", results, addr)
    assert f"{len(pm.CHECKS)} checks, 0 failed, 1 skipped" in text
    assert [line.split()[0] for line in text.splitlines() if line.startswith("  ") and "|" in line].count("SKIP") == 1
    data = json.loads(pm.results_json("img:1", results, addr))
    assert data["failed"] == 0 and data["skipped"] == 1 and data["results"][six]["skipped"] is True
    assert pm.markdown_report("img:1", results, addr).count("| skip |") == 1


def test_the_json_results_count_failures(addr):
    data = json.loads(pm.results_json("img:1", _results(addr, fail_haproxy=True), addr))
    assert data["checks"] == len(pm.CHECKS) and data["failed"] == 1
    assert {"config", "setup", "check", "got", "expect", "ok", "detail"} <= set(data["results"][0])


class _FakeMatrix:
    """Stands in for the Docker-driven matrix: `outcome` decides what the run produces."""
    outcome = "pass"
    instances = []

    def __init__(self, docker, image, prefix, compose, subnet):
        self.addr = pm.addresses(_SUBNET)
        self.results = []
        _FakeMatrix.instances.append(self)

    def set_up(self):
        if self.outcome == "broken":
            raise pm.HarnessError("the API never answered")

    def run_checks(self):
        self.results.extend(_results(self.addr, fail_haproxy=self.outcome == "fail"))
        if self.outcome == "pass-without-ipv6":
            six = next(i for i, r in enumerate(self.results) if r.check.ipv6)
            self.results[six] = pm.Result(self.results[six].check, "", "x", False, "no IPv6", skipped=True)
        if self.outcome == "crash-midway":
            raise KeyError("access_token")
        return self.results


@pytest.fixture
def fake_run(monkeypatch):
    cleanups = []
    monkeypatch.setattr(pm, "Matrix", _FakeMatrix)
    monkeypatch.setattr(pm, "cleanup", lambda docker, prefix: cleanups.append(prefix) or [])
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    _FakeMatrix.instances = []
    return cleanups


@pytest.mark.parametrize("outcome, status", [
    ("pass", 0), ("fail", 1), ("broken", 2), ("crash-midway", 2), ("pass-without-ipv6", 0),
])
def test_the_exit_status_says_which_kind_of_run_it_was(fake_run, capsys, outcome, status, tmp_path):
    _FakeMatrix.outcome = outcome
    report = tmp_path / "r.json"
    assert pm.main(["--image", "img:1", "--prefix", "unit-matrix", "--json", str(report)]) == status
    # cleanup ran before the run (leftovers) and after it, whatever happened
    assert fake_run == ["unit-matrix", "unit-matrix"]
    out = capsys.readouterr()
    if status == 2:
        assert "could not run" in out.err and not report.exists()
        if outcome == "crash-midway":
            assert "What it saw before it stopped" in out.err
    else:
        assert json.loads(report.read_text(encoding="utf-8"))["failed"] == (status == 1)


def test_a_termination_signal_still_reaches_cleanup_and_the_handler_is_put_back(fake_run):
    """A cancelled CI step sends SIGTERM; it must unwind through the cleanup, and a run must not
    leave its handler behind in whatever process called it."""
    import signal

    with pytest.raises(SystemExit):
        pm._on_sigterm(signal.SIGTERM, None)

    def callers_own(signum, frame):
        pass

    original = signal.signal(signal.SIGTERM, callers_own)
    try:
        _FakeMatrix.outcome = "pass"
        assert pm.main(["--image", "img:1", "--prefix", "unit-matrix"]) == 0
        assert signal.getsignal(signal.SIGTERM) is callers_own
    finally:
        signal.signal(signal.SIGTERM, original)


def test_keep_leaves_the_run_in_place(fake_run, capsys):
    _FakeMatrix.outcome = "pass"
    assert pm.main(["--image", "img:1", "--prefix", "unit-matrix", "--keep"]) == 0
    assert fake_run == ["unit-matrix"]                  # only the start-of-run cleanup
    assert "--cleanup-only --prefix unit-matrix" in capsys.readouterr().out


def test_the_step_summary_is_written_when_actions_provides_one(fake_run, monkeypatch, tmp_path):
    _FakeMatrix.outcome = "fail"
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert pm.main(["--image", "img:1", "--prefix", "unit-matrix"]) == 1
    assert "1 failed" in summary.read_text(encoding="utf-8")


# --- where it runs --------------------------------------------------------------------------------

_WORKFLOWS = _ROOT / ".github" / "workflows"


def test_the_workflow_runs_the_candidate_on_pull_requests_dispatch_and_calls():
    wf = yaml.safe_load((_WORKFLOWS / "proxy-matrix.yml").read_text(encoding="utf-8"))
    triggers = wf[True]                                   # YAML reads the bare key `on` as True
    assert {"pull_request", "workflow_dispatch", "workflow_call"} <= set(triggers)
    assert triggers["workflow_call"]["inputs"]["expected_sha"]["type"] == "string"
    assert wf["permissions"] == {"contents": "read"}
    assert wf["concurrency"]["group"].startswith("proxy-matrix-")
    job = wf["jobs"]["proxy-matrix"]
    assert job["runs-on"] == "ubuntu-latest" and job["timeout-minutes"] <= 15
    steps = job["steps"]
    checkout = steps[0]
    assert checkout["uses"] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    assert checkout["with"] == {"ref": "${{ inputs.expected_sha || github.sha }}",
                                "persist-credentials": False}
    verify = next(s for s in steps if s.get("name") == "Verify requested commit")
    assert verify["if"] == "${{ inputs.expected_sha != '' }}"
    names = [s.get("name", "") for s in steps]
    build = steps[names.index("Build the candidate image")]
    run = steps[names.index("Run the proxy matrix")]
    assert names.index("Build the candidate image") < names.index("Run the proxy matrix")
    assert "docker build --tag dockvault-vault:proxy-matrix ." in build["run"]
    assert ".github/scripts/proxy_matrix.py" in run["run"]
    assert "--image dockvault-vault:proxy-matrix" in run["run"]
    assert "if" not in run and "continue-on-error" not in run
    teardown = steps[-1]
    assert teardown["if"] == "always()" and "--cleanup-only" in teardown["run"]
    for step in steps:
        uses = step.get("uses", "")
        if uses:
            assert "@" in uses and len(uses.split("@")[1]) == 40, uses


def test_a_candidate_or_release_tests_run_includes_the_proxy_matrix():
    tests = yaml.safe_load((_WORKFLOWS / "tests.yml").read_text(encoding="utf-8"))
    job = tests["jobs"]["proxy-matrix"]
    assert job["uses"] == "./.github/workflows/proxy-matrix.yml"
    assert job["if"] == "github.event_name == 'workflow_dispatch' || startsWith(github.ref, 'refs/tags/')"
    assert job["with"] == {"expected_sha": "${{ inputs.expected_sha }}"}
    assert job["permissions"] == {"contents": "read"}
    release = yaml.safe_load((_WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    assert "tests" in release["jobs"]["publish"]["needs"]    # so publication waits for it


# --- the key-proof probe ------------------------------------------------------------------------

def test_a_key_proof_passes_through_every_proxy_on_another_host():
    """A key proof is a MAC over the exact body bytes, carried in a header, so each proxy in front of the
    vault -- nginx plain and over TLS, two nginx in a chain, and HAProxy -- must pass both on unchanged."""
    proved = [c for c in pm.CHECKS if c.probe == "key-proof"]
    assert sorted(c.via for c in proved) == ["edge", "haproxy", "nginx", "nginx-tls"]
    assert all(c.config == "proxies" and c.xff is None and c.xfp is None for c in proved)
    assert all(c.expect == pm.KEY_PROOF_PASSED for c in proved)


def test_the_key_proof_probe_carries_the_suites_own_client():
    script = pm.key_proof_script(_ROOT)
    compile(script, "key-proof-probe", "exec")
    first, _ = script.split("\n", 1)
    assert first.startswith("MODULES = ")
    modules = json.loads(first[len("MODULES = "):])
    assert [name for name, _ in modules] == ["zk_key_proof_reference", "zk_proof_harness"]
    for name, source in modules:
        assert source == (_ROOT / "tests" / f"{name}.py").read_text(encoding="utf-8")
    assert script.endswith(pm.KEY_PROOF_PROBE)


def test_the_key_proof_probe_runs_and_reports_the_step_it_could_not_take(tmp_path):
    """Run the probe as the image would, against an address where nothing listens: its modules load and it
    reports the first step, the sign-in, as the one that failed -- never KEY_PROOF_PASSED."""
    args = {"direct": "http://127.0.0.1:9", "via": "http://127.0.0.1:9", "username": "u",
            "password": "p", "passed": pm.KEY_PROOF_PASSED}
    out = subprocess.run([sys.executable, "-", json.dumps(args)], input=pm.key_proof_script(_ROOT),
                         capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert out.returncode == 0, out.stderr[-600:]
    outcome = pm.key_proof_outcome(out.stdout)
    assert outcome.startswith("(the probe failed:") and "URLError" in outcome, outcome


@pytest.mark.parametrize("out, outcome", [
    ('noise\n{"outcome": "proved"}\n', "proved"),
    ('{"outcome": "rotation: 403 {}"}', "rotation: 403 {}"),
])
def test_the_key_proof_outcome_is_the_probes_last_line(out, outcome):
    assert pm.key_proof_outcome(out) == outcome


@pytest.mark.parametrize("out, message", [
    ("", "printed nothing"),
    ("Traceback (most recent call last):\n  boom\n", "not its outcome"),
    ('{"outcome": ""}', "wrong shape"),
    ('{"status": 200}', "wrong shape"),
])
def test_an_unusable_key_proof_outcome_is_a_harness_error(out, message):
    with pytest.raises(pm.HarnessError, match=message):
        pm.key_proof_outcome(out)
