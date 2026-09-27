#!/usr/bin/env python3
"""Run a vault image behind real reverse proxies and check the client address and scheme it records.

Unit tests prove the address parser on strings; this proves it on the wire. It starts one private
Docker network and puts on it: the vault API, its Postgres and Redis, nginx (plain and TLS), a second
nginx in front of the first (a chain), HAProxy with `option forwardfor` (which adds its own
X-Forwarded-For line instead of appending), and an nginx inside the API container's own network
namespace (it connects from 127.0.0.1). Clients are containers at fixed addresses: the real client,
an attacker, and an operator that signs in as the administrator.

Each address check is a failed sign-in under a new, unique name, sent through one proxy set-up; the
address the vault stored for it is read back from the audit log. Each scheme check mints a
password-reset link through a TLS proxy and reads the scheme the link was built with. The API is
restarted once per trust setting (nothing trusted, 127.0.0.1, the three proxies, trust all, the
whole network).

Usage:
    python3 .github/scripts/proxy_matrix.py --image dockvault-vault:latest
    python3 .github/scripts/proxy_matrix.py --cleanup-only

Needs Docker and Python 3.10+ on the host, nothing else: the probes run inside the image under test
(it has Python), the proxy configurations are copied into their containers, and the TLS certificate
is made inside the image as well. Postgres and Redis are the images deploy/docker-compose.yml pins.

Safety: every container and network it creates carries the label `com.dockvault.proxy-matrix` set
to the prefix, and a name starting with `<prefix>-`. Cleanup (at start, at the end, and with
--cleanup-only) removes only what has BOTH. It creates no named volumes, publishes no ports, and
keeps the databases in memory. Run one matrix per prefix at a time: a second run with the same
prefix clears the first one's containers when it starts.

Exit status: 0 when every check matched, 1 when any check differed, 2 when the matrix could not be
set up (the report says where it stopped).
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import io
import ipaddress
import json
import os
import random
import re
import secrets
import signal
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Callable, Iterable, Optional

LABEL = "com.dockvault.proxy-matrix"
DEFAULT_PREFIX = "dockvault-proxy-matrix"
_PREFIX_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,40}$")

# The proxies under test, pinned like every other image the pipeline runs. They are fixtures, not
# something the vault ships, so they move only when someone updates them here.
NGINX_IMAGE = ("nginx:1.31-alpine@sha256:"
               "df221db836e1754089190208cee7eeda94f233197056426eda74a43ab1abeac2")
HAPROXY_IMAGE = ("haproxy:3.4-alpine@sha256:"
                 "7ffdd3845020aa4c97ffaa56c8cab3ad473ecae0b8ea5e55d2378d663755e092")

FORGED = "9.9.9.9"
JUNK = "not-an-address-junk"
LOGIN_LIMIT = 5              # failed sign-ins per name; the vault allows twice that per address
VICTIM_TRIES = 16            # more than the per-address allowance, so the throttle must show
PROBE_PASSWORD = "not-the-password-1"

# Host numbers inside the test network. The API keeps .2 across restarts, so the proxies in front
# of it never need reconfiguring.
HOSTS = {
    "api": 2, "db": 10, "redis": 11,
    "nginx": 20, "edge": 21, "haproxy": 22,
    "client": 101, "attacker": 102, "operator": 103,
}

# How each set-up is reached. "local-*" is the nginx inside the API's network namespace, which
# listens on the API's own address.
VIA = {
    "direct": "http://{api}:8000",
    "local-pass": "http://{api}:8081",
    "local-append": "http://{api}:8082",
    "local-tls": "https://{api}:8443",
    "nginx": "http://{nginx}",
    "nginx-tls": "https://{nginx}",
    "edge": "http://{edge}",
    "haproxy": "http://{haproxy}",
}


class HarnessError(RuntimeError):
    """The matrix could not be set up or a probe could not run: not a failed check."""


# --- the check table (pure) ---------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Config:
    key: str
    title: str
    trusted: str          # TRUSTED_PROXIES, with {role} placeholders
    trust_all: bool = False


CONFIGS = (
    Config("none", "nothing trusted (the default)", ""),
    Config("loopback", "TRUSTED_PROXIES=127.0.0.1", "127.0.0.1"),
    Config("proxies", "TRUSTED_PROXIES lists the three proxies", "{nginx},{edge},{haproxy}"),
    Config("all", "TRUST_ALL_PROXIES=true", "", trust_all=True),
    Config("subnet", "TRUSTED_PROXIES is the whole network, clients included", "{subnet}"),
)


@dataclasses.dataclass(frozen=True)
class Check:
    config: str
    setup: str
    action: str
    probe: str                        # "address" | "scheme" | "budget"
    via: str                          # a key of VIA
    expect: str                       # a role ("client", "loopback", "forged", "edge"), a scheme,
                                      # or "baseline" for the budget check
    xff: Optional[str] = None         # X-Forwarded-For the client sends
    xfp: Optional[str] = None         # X-Forwarded-Proto the client sends
    note: str = ""


CHECKS = (
    Check("none", "no proxy", "client sends a forged X-Forwarded-For",
          "address", "direct", "client", xff=FORGED),
    Check("none", "proxy on 127.0.0.1 that passes the client's header through",
          "client sends a forged X-Forwarded-For", "address", "local-pass", "loopback", xff=FORGED),
    Check("none", "proxy on 127.0.0.1 that passes the client's header through",
          "client sends junk in X-Forwarded-For", "address", "local-pass", "loopback", xff=JUNK),
    Check("none", "proxy on 127.0.0.1 that appends", "real client",
          "address", "local-append", "loopback"),
    Check("none", "TLS proxy on 127.0.0.1", "reset link scheme",
          "scheme", "local-tls", "http"),
    Check("none", "no proxy", "client sends X-Forwarded-Proto: https, reset link scheme",
          "scheme", "direct", "http", xfp="https"),
    Check("none", "no proxy", f"another client signs in {LOGIN_LIMIT} times as the victim's address",
          "budget", "direct", "baseline",
          note="the victim keeps every sign-in it had without the attacker"),
    Check("loopback", "proxy on 127.0.0.1 that appends, listed",
          "client sends a forged X-Forwarded-For", "address", "local-append", "client", xff=FORGED),
    Check("loopback", "TLS proxy on 127.0.0.1, listed", "reset link scheme",
          "scheme", "local-tls", "https"),
    Check("proxies", "no proxy, while proxies are listed", "client sends a forged X-Forwarded-For",
          "address", "direct", "client", xff=FORGED),
    Check("proxies", "nginx that appends, listed", "client sends a forged X-Forwarded-For",
          "address", "nginx", "client", xff=FORGED),
    Check("proxies", "HAProxy 'option forwardfor' (its own header line), listed",
          "client sends a forged X-Forwarded-For", "address", "haproxy", "client", xff=FORGED),
    Check("proxies", "two nginx in a chain, both listed", "client sends a forged X-Forwarded-For",
          "address", "edge", "client", xff=FORGED),
    Check("proxies", "TLS nginx on another host, listed", "reset link scheme",
          "scheme", "nginx-tls", "https"),
    Check("all", "nginx that appends, trust all", "client sends a forged X-Forwarded-For",
          "address", "nginx", "client", xff=FORGED),
    Check("all", "two nginx in a chain, trust all", "real client",
          "address", "edge", "edge",
          note="documented: trust all takes the address the nearest proxy saw"),
    Check("subnet", "client behind two proxies, whole network listed", "real client",
          "address", "edge", "client"),
    Check("subnet", "client behind two proxies, whole network listed",
          "client sends a forged X-Forwarded-For", "address", "edge", "forged", xff=FORGED,
          note="documented: a client inside a listed network is believed"),
)


def addresses(subnet: str) -> dict[str, str]:
    """Every role's address inside `subnet`, plus the fixed values the checks name."""
    net = ipaddress.ip_network(subnet, strict=True)
    if net.version != 4 or net.prefixlen > 24:
        raise ValueError(f"{subnet}: the matrix needs an IPv4 network of /24 or larger")
    out = {role: str(net.network_address + n) for role, n in HOSTS.items()}
    out.update(subnet=str(net), loopback="127.0.0.1", forged=FORGED)
    return out


def trusted_value(config: Config, addr: dict[str, str]) -> str:
    return config.trusted.format(**addr)


def url_for(check: Check, addr: dict[str, str]) -> str:
    return VIA[check.via].format(**addr)


def expected_value(check: Check, addr: dict[str, str]) -> str:
    """The concrete value a check expects: an address for a role, or the scheme itself."""
    if check.probe == "address":
        return addr[check.expect]
    return check.expect


def role_of(value: str, addr: dict[str, str]) -> str:
    """Name the role an address belongs to, for the report ("10.1.2.101" -> "client")."""
    for role in ("client", "attacker", "operator", "loopback", "forged", "nginx", "edge",
                 "haproxy", "api"):
        if addr.get(role) == value:
            return role
    return ""


def budget_from_statuses(statuses: Iterable[int]) -> int:
    """How many sign-ins a client made before the first 429."""
    allowed = 0
    for status in statuses:
        if status == 429:
            break
        allowed += 1
    return allowed


@dataclasses.dataclass
class Result:
    check: Check
    got: str
    expect: str
    ok: bool
    detail: str = ""


def judge(check: Check, got: str, addr: dict[str, str]) -> Result:
    expect = expected_value(check, addr)
    return Result(check, got, expect, got == expect)


def judge_budget(check: Check, baseline: list[int], attacked: list[int],
                 attacker: list[int]) -> Result:
    """The victim must keep the whole allowance it has without the attacker. A baseline that never
    reached 429 proves nothing (the throttle was not in play), so that fails too."""
    base, got = budget_from_statuses(baseline), budget_from_statuses(attacked)
    detail = f"attacker got {attacker}"
    if base >= len(baseline):
        return Result(check, str(got), str(base), False,
                      f"the throttle never engaged in {len(baseline)} sign-ins; {detail}")
    if any(s == 0 for s in baseline + attacked + attacker):
        return Result(check, str(got), str(base), False, f"a sign-in did not reach the vault; {detail}")
    return Result(check, str(got), str(base), got == base, detail)


def describe(value: str, addr: dict[str, str]) -> str:
    role = role_of(value, addr)
    return f"{value} ({role})" if role else value


def format_report(image: str, results: list[Result], addr: dict[str, str]) -> str:
    lines = [f"Proxy matrix for {image} on {addr['subnet']}"]
    titles = {c.key: c.title for c in CONFIGS}
    current = None
    for r in results:
        if r.check.config != current:
            current = r.check.config
            lines.append(f"== {titles.get(current, current)}")
        mark = "PASS" if r.ok else "FAIL"
        lines.append(f"  {mark}  {r.check.setup} | {r.check.action}")
        lines.append(f"        got {describe(r.got, addr)}, expected {describe(r.expect, addr)}"
                     + (f"  [{r.check.note}]" if r.check.note else "")
                     + (f"  ({r.detail})" if r.detail else ""))
    failed = [r for r in results if not r.ok]
    lines.append(f"{len(results)} checks, {len(failed)} failed")
    return "\n".join(lines)


def markdown_report(image: str, results: list[Result], addr: dict[str, str]) -> str:
    def cell(text: str) -> str:
        return text.replace("|", "\\|")

    titles = {c.key: c.title for c in CONFIGS}
    failed = sum(1 for r in results if not r.ok)
    rows = [f"### Proxy matrix: {len(results)} checks, {failed} failed",
            "", f"Image `{image}`, network `{addr['subnet']}`.", "",
            "| | Trust setting | Set-up | Check | Got | Expected |",
            "|---|---|---|---|---|---|"]
    for r in results:
        rows.append("| " + " | ".join(cell(x) for x in (
            "pass" if r.ok else "**FAIL**", titles.get(r.check.config, r.check.config),
            r.check.setup, r.check.action, describe(r.got, addr),
            describe(r.expect, addr))) + " |")
    return "\n".join(rows) + "\n"


def results_json(image: str, results: list[Result], addr: dict[str, str]) -> str:
    return json.dumps({
        "image": image, "subnet": addr["subnet"],
        "checks": len(results), "failed": sum(1 for r in results if not r.ok),
        "results": [{"config": r.check.config, "setup": r.check.setup, "check": r.check.action,
                     "got": r.got, "expect": r.expect, "ok": r.ok, "detail": r.detail}
                    for r in results],
    }, indent=2)


def parse_client_output(stdout: str) -> list[dict]:
    """The probe prints one JSON list as its last line; anything before it is noise."""
    lines = [line for line in (stdout or "").splitlines() if line.strip()]
    if not lines:
        raise HarnessError("the probe printed nothing")
    try:
        data = json.loads(lines[-1])
    except ValueError as exc:
        raise HarnessError(f"the probe's last line is not JSON: {lines[-1][:200]!r}") from exc
    if not isinstance(data, list) or not all(
            isinstance(d, dict) and isinstance(d.get("status"), int) and isinstance(d.get("body"), str)
            for d in data):
        raise HarnessError(f"the probe's output has the wrong shape: {lines[-1][:200]!r}")
    return data


def link_scheme(body: str) -> str:
    """The scheme of the reset link in a reset-link response, or a description of what came back."""
    try:
        link = json.loads(body).get("reset_link", "")
    except (ValueError, AttributeError):
        return f"(not JSON: {body[:80]})"
    if not isinstance(link, str) or "://" not in link:
        return f"(no link: {str(link)[:60]})"
    return link.split("://", 1)[0]


def owned_names(listing: str, prefix: str) -> list[str]:
    """The names in a `docker ... --format {{.Name}}` listing that belong to this prefix.

    Called only on listings already filtered by this script's label, so a name has to carry BOTH
    the label and the prefix before anything is removed. The container sharing the API's network
    namespace goes first, then the rest."""
    names = [n.strip() for n in listing.splitlines() if n.strip().startswith(prefix + "-")]
    return sorted(names, key=lambda n: (not n.endswith("-local"), n))


def check_prefix(prefix: str) -> str:
    if not _PREFIX_RE.match(prefix or ""):
        raise argparse.ArgumentTypeError(
            "a prefix is 3 to 41 lower-case letters, digits or dashes, starting with a letter or digit")
    return prefix


def compose_images(compose_text: str) -> dict[str, str]:
    """The Postgres and Redis images deploy/docker-compose.yml pins, keyed "db" and "redis"."""
    out: dict[str, str] = {}
    for match in re.finditer(r"^\s*image:\s*(\S+)\s*$", compose_text, re.M):
        ref = match.group(1)
        if ref.startswith("postgres:"):
            out.setdefault("db", ref)
        elif ref.startswith("redis:"):
            out.setdefault("redis", ref)
    missing = {"db", "redis"} - out.keys()
    if missing:
        raise HarnessError(f"deploy/docker-compose.yml pins no image for {', '.join(sorted(missing))}")
    return out


def subnet_candidates(rng: random.Random, count: int = 24) -> list[str]:
    """Random /24s inside 10.200.0.0/13, tried in turn until Docker accepts one."""
    picks = rng.sample(range(8 * 256), count)
    return [f"10.{200 + p // 256}.{p % 256}.0/24" for p in picks]


# --- proxy configurations (pure) ------------------------------------------------------------------

APPEND = "$proxy_add_x_forwarded_for"
PASS_THROUGH = "$http_x_forwarded_for"


def nginx_server(listen: int, upstream: str, xff: str, ssl: bool = False) -> str:
    tls = ("    ssl_certificate /etc/nginx/cert.pem;\n"
           "    ssl_certificate_key /etc/nginx/key.pem;\n") if ssl else ""
    return (f"server {{\n    listen {listen}{' ssl' if ssl else ''};\n{tls}"
            f"    location / {{\n        proxy_pass http://{upstream};\n"
            "        proxy_set_header Host $host;\n"
            f"        proxy_set_header X-Forwarded-For {xff};\n"
            "        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n}\n")


def proxy_configs(addr: dict[str, str]) -> dict[str, str]:
    """Each proxy's configuration, keyed by role ("local" is the nginx in the API's namespace)."""
    api = f"{addr['api']}:8000"
    return {
        "nginx": nginx_server(80, api, APPEND) + nginx_server(443, api, APPEND, ssl=True),
        "edge": nginx_server(80, f"{addr['nginx']}:80", APPEND),
        # 8081 hands the client's own header on untouched (a proxy that does not set it), 8082
        # appends, 8443 appends over TLS.
        "local": (nginx_server(8081, "127.0.0.1:8000", PASS_THROUGH)
                  + nginx_server(8082, "127.0.0.1:8000", APPEND)
                  + nginx_server(8443, "127.0.0.1:8000", APPEND, ssl=True)),
        "haproxy": ("defaults\n  mode http\n  timeout connect 5s\n  timeout client 30s\n"
                    "  timeout server 30s\n"
                    "frontend fe\n  bind :80\n  option forwardfor\n  default_backend be\n"
                    f"backend be\n  server vault {api}\n"),
    }


def tar_of(files: dict[str, tuple[bytes, int]]) -> bytes:
    """An in-memory tar of {path: (content, mode)}, owned by root, for `docker cp -`."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for path, (content, mode) in sorted(files.items()):
            info = tarfile.TarInfo(path)
            info.size, info.mode, info.uid, info.gid = len(content), mode, 0, 0
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


# --- scripts that run inside the image under test -------------------------------------------------

CLIENT_SCRIPT = r'''
import json, ssl, sys, urllib.error, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
out = []
for req in json.loads(sys.argv[1]):
    body = req.get("body")
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(req["url"], data=data, method=req.get("method") or ("POST" if data is not None else "GET"),
                               headers={"Content-Type": "application/json", **req.get("headers", {})})
    try:
        with opener.open(r, timeout=20) as resp:
            out.append({"status": resp.status, "body": resp.read(4000).decode("utf-8", "replace")})
    except urllib.error.HTTPError as e:
        out.append({"status": e.code, "body": e.read(1000).decode("utf-8", "replace")})
    except Exception as e:
        out.append({"status": 0, "body": repr(e)[:300]})
print(json.dumps(out))
'''

WAIT_SCRIPT = r'''
import ssl, sys, time, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
deadline, last = time.monotonic() + float(sys.argv[1]), "never answered"
urls = sys.argv[2:]
while urls and time.monotonic() < deadline:
    try:
        with urllib.request.urlopen(urls[0], timeout=3, context=ctx) as resp:
            if resp.status == 200:
                urls.pop(0)
                continue
            last = f"{urls[0]}: status {resp.status}"
    except Exception as e:
        last = f"{urls[0]}: {e!r}"[:300]
    time.sleep(0.5)
print("ready" if not urls else last)
sys.exit(0 if not urls else 1)
'''

CERT_SCRIPT = r'''
import datetime, json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vault.test")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
print(json.dumps({
    "cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
    "key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode(),
}))
'''


# --- Docker -------------------------------------------------------------------------------------

class Docker:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def __call__(self, *args: str, check: bool = True, input: Optional[bytes | str] = None,
                 timeout: float = 120, env: Optional[dict[str, str]] = None,
                 ) -> subprocess.CompletedProcess:
        if self.verbose:
            print("  $ docker " + " ".join(args)[:200], flush=True)
        text = not isinstance(input, bytes)
        try:
            r = subprocess.run(["docker", *args], capture_output=True, text=text, input=input,
                               timeout=timeout, env=env,
                               **({"encoding": "utf-8", "errors": "replace"} if text else {}))
        except subprocess.TimeoutExpired as exc:
            raise HarnessError(f"docker {' '.join(args[:3])} took longer than {timeout:.0f}s") from exc
        except FileNotFoundError as exc:
            raise HarnessError("the docker command is not installed or not on PATH") from exc
        if check and r.returncode != 0:
            err = r.stderr if text else r.stderr.decode("utf-8", "replace")
            raise HarnessError(f"docker {' '.join(args[:4])} failed: {err.strip()[-600:]}")
        return r


def cleanup(docker: Docker, prefix: str) -> list[str]:
    """Remove this prefix's containers, then its networks. Returns what was removed."""
    removed = []
    listing = docker("ps", "-a", "--filter", f"label={LABEL}={prefix}", "--format", "{{.Names}}",
                     check=False).stdout or ""
    for name in owned_names(listing, prefix):
        if docker("rm", "-f", "-v", name, check=False).returncode == 0:
            removed.append(name)
    listing = docker("network", "ls", "--filter", f"label={LABEL}={prefix}", "--format",
                     "{{.Name}}", check=False).stdout or ""
    for name in owned_names(listing, prefix):
        if docker("network", "rm", name, check=False).returncode == 0:
            removed.append(name)
    return removed


class Matrix:
    def __init__(self, docker: Docker, image: str, prefix: str, compose_path: Path,
                 subnet: Optional[str] = None, log: Callable[[str], None] = print):
        self.docker, self.image, self.prefix, self.log = docker, image, prefix, log
        self.run_id = secrets.token_hex(3)
        self.images = compose_images(compose_path.read_text(encoding="utf-8"))
        self.requested_subnet = subnet
        self.addr: dict[str, str] = {}
        self.admin_password = "Matrix-Admin-" + secrets.token_urlsafe(18)
        self.db_password = secrets.token_hex(16)
        # Values reach `docker run` through its environment (`-e NAME`), never its arguments.
        self.secrets = {
            "ENCRYPTION_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),
            "JWT_SECRET_KEY": secrets.token_hex(32),
            "LOG_TOKEN_PEPPER": secrets.token_hex(32),
            "ADMIN_PASSWORD": self.admin_password,
            "POSTGRES_PASSWORD": self.db_password,
            "DATABASE_URL": "",   # filled once the database has an address
        }
        self.cert: dict[str, str] = {}
        self.results: list[Result] = []

    # names and labels
    def name(self, role: str) -> str:
        return f"{self.prefix}-{self.run_id}-{role}"

    @property
    def labels(self) -> list[str]:
        return ["--label", f"{LABEL}={self.prefix}"]

    def env(self) -> dict[str, str]:
        return {**os.environ, **self.secrets}

    # set-up
    def create_network(self) -> None:
        candidates = ([self.requested_subnet] if self.requested_subnet
                      else subnet_candidates(random.Random()))
        last = ""
        for subnet in candidates:
            r = self.docker("network", "create", *self.labels, "--subnet", subnet,
                            self.name("net"), check=False)
            if r.returncode == 0:
                self.addr = addresses(subnet)
                self.log(f"network {self.name('net')} on {subnet}")
                return
            last = (r.stderr or "").strip()
        raise HarnessError(f"no free network among {len(candidates)} tried: {last[-300:]}")

    def run_container(self, role: str, image: str, options: list[str],
                      command: Iterable[str] = ()) -> None:
        """`docker run -d` one role at its fixed address on the test network."""
        self.docker("run", "-d", "--name", self.name(role), *self.labels,
                    "--network", self.name("net"), "--ip", self.addr[role], *options, image,
                    *command, env=self.env(), timeout=300)

    def start_backing_services(self) -> None:
        # In memory: nothing outlives the containers, and no volume is ever created.
        self.run_container("db", self.images["db"], [
            "--tmpfs", "/var/lib/postgresql/data",
            "-e", "POSTGRES_USER=sftp_user", "-e", "POSTGRES_DB=sftp_db", "-e", "POSTGRES_PASSWORD"])
        self.run_container("redis", self.images["redis"], ["--tmpfs", "/data"])
        self.secrets["DATABASE_URL"] = (
            f"postgresql://sftp_user:{self.db_password}@{self.addr['db']}:5432/sftp_db")
        deadline = time.monotonic() + 90
        while True:
            r = self.docker("exec", self.name("db"), "pg_isready", "-U", "sftp_user", "-d", "sftp_db",
                            check=False)
            if r.returncode == 0:
                return
            if time.monotonic() > deadline:
                raise HarnessError("Postgres never became ready: " + self.logs("db"))
            time.sleep(1)

    def start_clients(self) -> None:
        """Three idle containers of the image under test; each probe is a `docker exec` of its
        Python, so a probe's source address is the container's fixed address."""
        for role in ("client", "attacker", "operator"):
            self.run_container(role, self.image, [
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--entrypoint", "python",
            ], ["-c", "import time\nwhile True: time.sleep(3600)"])

    def make_certificate(self) -> None:
        r = self.docker("exec", "-i", self.name("operator"), "python", "-", input=CERT_SCRIPT,
                        timeout=60)
        self.cert = json.loads(r.stdout.strip().splitlines()[-1])

    def start_proxy(self, role: str, network: Optional[str] = None) -> None:
        configs = proxy_configs(self.addr)
        tls = {"cert.pem": (self.cert["cert"].encode(), 0o644),
               "key.pem": (self.cert["key"].encode(), 0o600)}
        if role == "haproxy":
            image, dest, files = HAPROXY_IMAGE, "/usr/local/etc/haproxy", {
                "haproxy.cfg": (configs["haproxy"].encode(), 0o644)}
        else:
            image, dest = NGINX_IMAGE, "/etc/nginx"
            files = {"conf.d/default.conf": (configs[role].encode(), 0o644), **tls}
        net = ["--network", network] if network else [
            "--network", self.name("net"), "--ip", self.addr[role]]
        self.docker("create", "--name", self.name(role), *self.labels, *net, image, timeout=300)
        self.docker("cp", "-", f"{self.name(role)}:{dest}", input=tar_of(files))
        self.docker("start", self.name(role))

    def start_proxies(self) -> None:
        for role in ("nginx", "edge", "haproxy"):
            self.start_proxy(role)

    def start_api(self, config: Config) -> None:
        for role in ("local", "api"):
            self.docker("rm", "-f", "-v", self.name(role), check=False)
        env = {
            "DOCKER_CONTAINER": "true", "ENVIRONMENT": "development",
            "REDIS_HOST": self.addr["redis"], "REDIS_PORT": "6379",
            "API_HOST": "0.0.0.0", "API_PORT": "8000", "API_USE_HTTPS": "false",
            "ADMIN_USERNAME": "admin", "ADMIN_EMAIL": "admin@proxy-matrix.example.com",
            "RATE_LIMIT_LOGIN_ATTEMPTS": str(LOGIN_LIMIT), "RATE_LIMIT_LOGIN_WINDOW_SECONDS": "300",
            "TRUSTED_PROXIES": trusted_value(config, self.addr),
            "TRUST_ALL_PROXIES": "true" if config.trust_all else "false",
        }
        args = [a for k, v in env.items() for a in ("-e", f"{k}={v}")]
        args += [a for k in ("ENCRYPTION_KEY", "JWT_SECRET_KEY", "LOG_TOKEN_PEPPER",
                             "ADMIN_PASSWORD", "DATABASE_URL") for a in ("-e", k)]
        self.docker("run", "-d", "--name", self.name("api"), *self.labels,
                    "--network", self.name("net"), "--ip", self.addr["api"], *args,
                    self.image, "python", "-m", "app.api.api_server", env=self.env(), timeout=300)
        self.wait("operator", [f"http://{self.addr['api']}:8000/health"], 180, "the API")
        self.reset_throttles()
        self.start_proxy("local", network=f"container:{self.name('api')}")
        base = self.addr["api"]
        self.wait("operator", [f"http://{base}:8081/health", f"http://{base}:8082/health",
                               f"https://{base}:8443/health"], 30, "the proxy on 127.0.0.1")

    def wait(self, role: str, urls: list[str], seconds: float, what: str) -> None:
        r = self.docker("exec", "-i", self.name(role), "python", "-", str(seconds), *urls,
                        input=WAIT_SCRIPT, check=False, timeout=seconds + 30)
        if r.returncode != 0:
            raise HarnessError(f"{what} never answered: {(r.stdout or '').strip()[-300:]}\n"
                               + self.logs("api"))

    def logs(self, role: str) -> str:
        r = self.docker("logs", "--tail", "60", self.name(role), check=False)
        return f"--- last lines from {self.name(role)} ---\n{(r.stdout or '')[-4000:]}{(r.stderr or '')[-4000:]}"

    def reset_throttles(self) -> None:
        self.docker("exec", self.name("redis"), "sh", "-c",
                    "redis-cli --scan --pattern 'rate_limit:*' | xargs -r redis-cli del",
                    check=False)

    # probes
    def requests(self, role: str, requests: list[dict]) -> list[dict]:
        r = self.docker("exec", "-i", self.name(role), "python", "-", json.dumps(requests),
                        input=CLIENT_SCRIPT, timeout=60 + 25 * len(requests))
        return parse_client_output(r.stdout)

    @staticmethod
    def login(url: str, name: str, xff: Optional[str] = None) -> dict:
        return {"url": url + "/auth/login", "body": {"username": name, "password": PROBE_PASSWORD},
                "headers": {"X-Forwarded-For": xff} if xff else {}}

    def recorded_address(self, name: str) -> str:
        if not re.fullmatch(r"[a-z0-9-]+", name):
            raise HarnessError(f"refusing to query for an unexpected name {name!r}")
        for _ in range(20):
            r = self.docker("exec", self.name("db"), "psql", "-U", "sftp_user", "-d", "sftp_db", "-Atc",
                            "select coalesce(ip_address, '(none)') from audit_logs "
                            f"where username = '{name}' order by timestamp desc limit 1")
            if r.stdout.strip():
                return r.stdout.strip()
            time.sleep(0.25)
        return "(no audit row)"

    def probe_address(self, check: Check) -> str:
        name = f"probe-{secrets.token_hex(6)}"
        res = self.requests("client", [self.login(url_for(check, self.addr), name, check.xff)])[0]
        if res["status"] == 0:
            return f"(no answer: {res['body'][:120]})"
        return self.recorded_address(name)

    def admin_token(self) -> str:
        res = self.requests("operator", [{
            "url": f"http://{self.addr['api']}:8000/auth/login",
            "body": {"username": "admin", "password": self.admin_password}}])[0]
        if res["status"] != 200:
            raise HarnessError(f"the administrator could not sign in: {res['status']} {res['body'][:200]}")
        return json.loads(res["body"])["access_token"]

    def probe_scheme(self, check: Check) -> str:
        """Mint a reset link through the check's set-up, for an account made for it alone (so no
        account ever has a second credential change made to it), and return the link's scheme."""
        token = self.admin_token()
        auth = {"Authorization": f"Bearer {token}"}
        name = "linkuser" + secrets.token_hex(5)
        made = self.requests("operator", [{
            "url": f"http://{self.addr['api']}:8000/users", "headers": auth,
            "body": {"username": name, "email": f"{name}@example.com",
                     "password": "Link-User-" + secrets.token_hex(8), "role": "user"}}])[0]
        if made["status"] not in (200, 201):
            raise HarnessError(f"could not create an account: {made['status']} {made['body'][:200]}")
        uid = json.loads(made["body"])["id"]
        headers = dict(auth)
        if check.xfp:
            headers["X-Forwarded-Proto"] = check.xfp
        res = self.requests("client", [{"url": f"{url_for(check, self.addr)}/users/{uid}/reset-link",
                                        "body": {}, "headers": headers}])[0]
        if res["status"] != 200:
            return f"(status {res['status']}: {res['body'][:120]})"
        return link_scheme(res["body"])

    def probe_budget(self, check: Check) -> Result:
        """Sign in as the victim (under new names each time) until refused, first on its own and
        then after an attacker has spent failed sign-ins typing the victim's address as the name."""
        url = url_for(check, self.addr)

        def victim() -> list[int]:
            return [r["status"] for r in self.requests(
                "client", [self.login(url, f"victim-{secrets.token_hex(5)}") for _ in range(VICTIM_TRIES)])]

        self.reset_throttles()
        baseline = victim()
        self.reset_throttles()
        attacker = [r["status"] for r in self.requests(
            "attacker", [self.login(url, self.addr["client"]) for _ in range(LOGIN_LIMIT)])]
        attacked = victim()
        return judge_budget(check, baseline, attacked, attacker)

    def run_checks(self, checks: Iterable[Check] = CHECKS) -> list[Result]:
        """Run the checks one trust setting at a time, collecting into self.results as it goes
        (so a run that stops half way still reports what it saw)."""
        results = self.results
        checks = list(checks)
        for config in CONFIGS:
            mine = [c for c in checks if c.config == config.key]
            if not mine:
                continue
            self.log(f"== {config.title}: starting the API")
            self.start_api(config)
            for check in mine:
                if check.probe == "budget":
                    result = self.probe_budget(check)
                elif check.probe == "scheme":
                    result = judge(check, self.probe_scheme(check), self.addr)
                else:
                    result = judge(check, self.probe_address(check), self.addr)
                results.append(result)
                self.log(f"  {'PASS' if result.ok else 'FAIL'}  {check.setup} | {check.action}: "
                         f"got {describe(result.got, self.addr)}, "
                         f"expected {describe(result.expect, self.addr)}")
        return results

    def set_up(self) -> None:
        self.create_network()
        self.log("starting Postgres and Redis")
        self.start_backing_services()
        self.log("starting the clients")
        self.start_clients()
        self.make_certificate()
        self.log("starting nginx, the nginx chain and HAProxy")
        self.start_proxies()


def _on_sigterm(signum, frame):  # noqa: ARG001 - signal handler signature
    raise SystemExit(128 + signum)


def main(argv: Optional[list[str]] = None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--image", help="the vault image to test (required unless --cleanup-only)")
    parser.add_argument("--prefix", type=check_prefix, default=DEFAULT_PREFIX,
                        help=f"names and label value for everything created (default {DEFAULT_PREFIX})")
    parser.add_argument("--subnet", help="an IPv4 /24 for the test network (default: a free one)")
    parser.add_argument("--compose", type=Path, default=root / "deploy" / "docker-compose.yml",
                        help="the compose file whose Postgres and Redis images to use")
    parser.add_argument("--json", type=Path, help="also write the results to this file")
    parser.add_argument("--keep", action="store_true",
                        help="leave everything running afterwards (remove it with --cleanup-only)")
    parser.add_argument("--cleanup-only", action="store_true",
                        help="remove what an earlier run with this prefix left behind, and exit")
    parser.add_argument("--verbose", action="store_true", help="print every docker command")
    args = parser.parse_args(argv)
    # Progress lines as they happen, not when the run ends: a CI log is a file, not a terminal.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(line_buffering=True)

    docker = Docker(verbose=args.verbose)
    if args.cleanup_only:
        removed = cleanup(docker, args.prefix)
        print(f"removed {len(removed)}: {', '.join(removed) or 'nothing'}")
        return 0
    if not args.image:
        parser.error("--image is required")
    if args.subnet:
        try:
            addresses(args.subnet)
        except ValueError as exc:
            parser.error(str(exc))

    # A cancelled CI step sends SIGTERM: turn it into SystemExit so the cleanup below still runs.
    previous_handler = signal.signal(signal.SIGTERM, _on_sigterm)
    started = time.monotonic()
    leftovers = cleanup(docker, args.prefix)
    if leftovers:
        print(f"removed leftovers of an earlier run: {', '.join(leftovers)}")
    matrix: Optional[Matrix] = None
    try:
        matrix = Matrix(docker, args.image, args.prefix, args.compose, args.subnet)
        matrix.set_up()
        matrix.run_checks()
    except Exception as exc:  # noqa: BLE001 - anything here means the matrix did not run
        detail = str(exc) if isinstance(exc, HarnessError) else repr(exc)
        print(f"\nThe matrix could not run: {detail}", file=sys.stderr)
        if matrix is not None and matrix.results:
            print("\nWhat it saw before it stopped:\n"
                  + format_report(args.image, matrix.results, matrix.addr), file=sys.stderr)
        if not isinstance(exc, HarnessError):
            import traceback
            traceback.print_exc()
        return 2
    finally:
        if args.keep:
            print(f"left running; remove with: --cleanup-only --prefix {args.prefix}")
        else:
            cleanup(docker, args.prefix)
        signal.signal(signal.SIGTERM, previous_handler)

    results = matrix.results
    report = format_report(args.image, results, matrix.addr)
    print("\n" + report + f"\n({time.monotonic() - started:.0f}s)")
    if args.json:
        args.json.write_text(results_json(args.image, results, matrix.addr), encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(markdown_report(args.image, results, matrix.addr))
    return 0 if results and all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
