"""Two addresses in one IPv6 /64 count as one client, in the running web and SFTP containers.

The stack's listeners take IPv4 only, so no IPv6 client can reach them from the test host. These run the
image's own code inside its containers, with their own configuration, Redis and database: the web
application is called through its full ASGI stack (every middleware and the route itself) with the client
address a dual-stack listener or a trusted proxy would hand it; the SFTP server's key-offer limit and its
admission are called as the server calls them. Each check reads the counts back from the live Redis.
test_throttle_subject.py covers every budget offline.
"""
import json
import os
import subprocess
import uuid

import pytest

from _account_change_helpers import in_api_container
from conftest import skip_if_container_absent

pytestmark = pytest.mark.integration

SFTP = os.environ.get("VAULT_SFTP_CONTAINER", "vault-sftp")

# A dual-stack listener or a trusted proxy hands the application these: two addresses in one /64, one in the
# next, and an IPv4 client written as IPv6 and as itself.
WEB = r'''
import asyncio, json, uuid
import app.api.api_server as api
from app.core.rate_limiter import rate_limiter

def call(path, addr):
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET",
             "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
             "headers": [(b"host", b"vault.test")], "client": (addr, 40000), "server": ("127.0.0.1", 8000)}
    sent = []
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}
    async def send(message):
        sent.append(message)
    asyncio.run(api.app(scope, receive, send))
    return sent[0]["status"]

def count(key):
    return rate_limiter.redis.zcard(key)

def clear():
    for pattern in ("*2001:db8:77:*", "*198.51.100.77*"):
        for k in rate_limiter.redis.scan_iter(pattern):
            rate_limiter.redis.delete(k)

clear()
token = "t" * 30 + uuid.uuid4().hex
statuses = [call("/invites/" + token, a) for a in
            ("2001:db8:77:5::1", "2001:db8:77:5:ffff::2", "2001:db8:77:6::1", "::ffff:198.51.100.77", "198.51.100.77")]
keys = sorted(k.decode() if isinstance(k, bytes) else k for k in rate_limiter.redis.scan_iter("*2001:db8:77:*"))
keys += sorted(k.decode() if isinstance(k, bytes) else k for k in rate_limiter.redis.scan_iter("*198.51.100.77*"))
print(json.dumps({"statuses": statuses,
                  "lookup_64": count("invite_lookup:2001:db8:77:5::/64"),
                  "lookup_next_64": count("invite_lookup:2001:db8:77:6::/64"),
                  "lookup_v4": count("invite_lookup:198.51.100.77"),
                  "keys": keys}))
clear()
'''

SFTP_SCRIPT = r'''
import json, uuid
from app.core.config import bootstrap_entrypoint
bootstrap_entrypoint("throttle-subject-test")
from app.sftp import sftp_server as S
from app.core.rate_limiter import rate_limiter
from app.core.config import settings

user = "subject-" + uuid.uuid4().hex[:8]
key = "rate_limit:sftp_pk:2001:db8:77:5::/64:" + user
S._sftp_key_throttled("2001:db8:77:5::1", user)
S._sftp_key_throttled("2001:db8:77:5:ffff::2", user)
charged = rate_limiter.redis.zcard(key)
raw = [k for k in rate_limiter.redis.scan_iter("rate_limit:sftp_pk:2001:db8:77:5::1*")]
S._sftp_key_clear("2001:db8:77:5::3", user)
cleared = rate_limiter.redis.zcard(key)

per_ip = int(settings.sftp_max_connections_per_ip or 0)
adm = S._ConnectionAdmission(max_total=0, max_per_ip=per_ip)
admitted = [adm.admit("2001:db8:77:5::%x" % (i + 1)) for i in range(per_ip + 1)]
other = adm.admit("2001:db8:77:6::1")
print(json.dumps({"charged": charged, "raw": len(raw), "cleared": cleared, "per_ip": per_ip,
                  "admitted": admitted, "other": other}))
'''


def test_the_web_application_counts_a_64_as_one_client():
    r = in_api_container(WEB)
    got = json.loads(r.stdout.strip().splitlines()[-1])
    assert got["statuses"] == [404] * 5, got                    # each request ran the route to its answer
    assert got["lookup_64"] == 2, got                           # two addresses in one /64: one budget
    assert got["lookup_next_64"] == 1 and got["lookup_v4"] == 2, got
    raw = [k for k in got["keys"] if any(a in k for a in ("2001:db8:77:5::1", "2001:db8:77:5:ffff::2",
                                                          "2001:db8:77:6::1", "::ffff:198.51.100.77"))]
    assert raw == [], f"a budget was keyed on a raw address: {raw}"
    # The general API limiter keyed the same subjects (its own prefix), not the raw addresses.
    assert any(k.endswith("ip:2001:db8:77:5::/64") for k in got["keys"]), got["keys"]


def test_the_sftp_server_counts_a_64_as_one_client():
    try:
        r = subprocess.run(["docker", "exec", "-i", SFTP, "python", "-c", SFTP_SCRIPT],
                           capture_output=True, text=True, timeout=90)
    except FileNotFoundError as exc:
        pytest.skip(f"docker unavailable: {exc}")
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"the command did not finish within {exc.timeout} s")
    skip_if_container_absent(r, SFTP)
    assert r.returncode == 0, (r.stderr or r.stdout)[-800:]
    got = json.loads(r.stdout.strip().splitlines()[-1])
    assert got["charged"] == 2 and got["raw"] == 0, got         # key offers from two addresses: one budget
    assert got["cleared"] == 0, got                             # a success from a third clears it
    assert got["per_ip"] > 0, "the stack's SFTP admission has no per-address cap to check"
    assert got["admitted"] == [True] * got["per_ip"] + [False], got   # the /64 shares the pre-auth cap
    assert got["other"] is True, got
