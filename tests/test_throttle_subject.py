"""Every per-address budget counts a client under one throttle subject, offline.

A per-address budget (the API limiter, the route limits, the sign-in limits, the SFTP key-offer limit,
SFTP admission and the rest) must key on ``sign_in_lockout.source_of(address)``, never on the raw
address: an IPv6 client has a whole /64 to pick addresses from, so a budget keyed on the full address
gives it a fresh allowance per address, and an IPv4 client written as IPv6 (``::ffff:a.b.c.d``) would
count apart from the same client written as IPv4. The smart lockout and the socket limiter have keyed
this way since 0.33.0; this file holds every other budget to the same subject.

Two halves:
- a source scan over app/ that flags a throttle key built from a raw address (with a control that
  proves the scan flags one), and pins every known per-address site as keyed on the subject;
- behaviour: for each budget, two addresses in one /64 meet the same bucket, an address in another
  /64 does not, and ``::ffff:198.51.100.7`` counts as ``198.51.100.7``.
"""
import ast
import pathlib
from types import SimpleNamespace

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

pytestmark = pytest.mark.unit

ROOT = pathlib.Path(__file__).resolve().parents[1]

SAME_A, SAME_B = "2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:fffe"   # one /64
OTHER = "2001:db8:1:3::1"                                                 # the next /64
MAPPED, PLAIN = "::ffff:198.51.100.7", "198.51.100.7"


# --------------------------------------------------------------------------------------------------
# The source scan
# --------------------------------------------------------------------------------------------------

# Calls that count a budget, and where their key is (a keyword, else the first positional argument).
SINKS = {"check_rate_limit": "identifier", "_db_throttle_hit": "identifier",
         "_db_throttle_charge": "identifier", "_windowed_count": "redis_key"}
# A call that returns the client's raw address, and parameter names that carry one.
RAW_CALLS = {"get_client_ip", "client_ip", "_client_ip"}
RAW_NAMES = {"ip", "ip_address", "client_ip", "peer", "peer_ip", "address", "addr", "remote_ip"}
SUBJECT = "source_of"


def _call_name(node):
    f = node.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def _own_nodes(fn):
    """The nodes of a function's body, not those of the functions defined inside it."""
    stack = list(fn.body)
    while stack:
        node = stack.pop()
        yield node
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                stack.append(child)


class _Env:
    """What a name inside one function can hold: its parameters, its assignments and its loop targets."""

    def __init__(self, fn):
        a = fn.args
        self.params = {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs}
        self.values = {}
        for node in _own_nodes(fn):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self._bind(target, node.value)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                self._bind(node.target, node.value)
            elif isinstance(node, ast.For):
                if isinstance(node.iter, (ast.Tuple, ast.List)):
                    for elt in node.iter.elts:
                        self._bind(node.target, elt)

    def _bind(self, target, value):
        if isinstance(target, ast.Name):
            self.values.setdefault(target.id, []).append(value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts):
                for t, v in zip(target.elts, value.elts):
                    self._bind(t, v)


class _Scanner:
    def __init__(self, sources):
        """``sources``: {label: source text}."""
        self.trees = {label: ast.parse(text) for label, text in sources.items()}
        self.functions = {}
        for tree in self.trees.values():
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.functions.setdefault(node.name, []).append(node)

    def raw(self, expr, env, seen=frozenset()):
        """The raw-address sources ``expr`` is built from, outside any source_of(...) call."""
        if isinstance(expr, ast.Call):
            name = _call_name(expr)
            if name == SUBJECT:
                return []
            if name in RAW_CALLS:
                return [f"{name}(...)"]
            if name in self.functions and name not in SINKS and name not in seen:
                found = []
                for helper in self.functions[name]:
                    helper_env = _Env(helper)
                    for node in _own_nodes(helper):
                        if isinstance(node, ast.Return) and node.value is not None:
                            found += [f"{name} -> {r}" for r in self.raw(node.value, helper_env, seen | {name})]
                return found
            parts = list(expr.args) + [k.value for k in expr.keywords]
            if isinstance(expr.func, ast.Attribute):
                parts.append(expr.func.value)
            return [r for p in parts for r in self.raw(p, env, seen)]
        if isinstance(expr, ast.Attribute):
            if expr.attr == "host" and isinstance(expr.value, ast.Attribute) and expr.value.attr == "client":
                return ["request.client.host"]
            return self.raw(expr.value, env, seen)
        if isinstance(expr, ast.Name):
            key = ("name", id(env), expr.id)
            if key in seen:
                return []
            if expr.id in env.values:
                return [r for v in env.values[expr.id] for r in self.raw(v, env, seen | {key})]
            if expr.id in env.params and expr.id in RAW_NAMES:
                return [expr.id]
            return []
        return [r for child in ast.iter_child_nodes(expr) for r in self.raw(child, env, seen)]

    def keys(self):
        """[(label, function, sink, raw sources, keyed on the subject)] for every budget counted."""
        out = []
        for label, tree in self.trees.items():
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                env = _Env(fn)
                for node in _own_nodes(fn):
                    if not (isinstance(node, ast.Call) and _call_name(node) in SINKS):
                        continue
                    kw = {k.arg: k.value for k in node.keywords}
                    key = kw.get(SINKS[_call_name(node)]) or (node.args[0] if node.args else None)
                    if key is None:
                        continue
                    out.append((label, fn.name, _call_name(node), self.raw(key, env),
                                self.subject(key, env)))
        return out

    def subject(self, expr, env, seen=frozenset()):
        """Whether a source_of(...) call is reachable from ``expr`` (through names and helpers)."""
        for node in ast.walk(expr):
            if isinstance(node, ast.Call):
                name = _call_name(node)
                if name == SUBJECT:
                    return True
                if name in self.functions and name not in seen:
                    for helper in self.functions[name]:
                        helper_env = _Env(helper)
                        for ret in _own_nodes(helper):
                            if isinstance(ret, ast.Return) and ret.value is not None and \
                                    self.subject(ret.value, helper_env, seen | {name}):
                                return True
            if isinstance(node, ast.Name) and (id(env), node.id) not in seen and node.id in env.values:
                if any(self.subject(v, env, seen | {(id(env), node.id)}) for v in env.values[node.id]):
                    return True
        return False


def _app_sources():
    return {str(p.relative_to(ROOT)).replace("\\", "/"): p.read_text(encoding="utf-8")
            for p in sorted((ROOT / "app").rglob("*.py"))}


@pytest.fixture(scope="module")
def scanned():
    return _Scanner(_app_sources()).keys()


def test_no_budget_is_keyed_on_a_raw_address(scanned):
    raw = [f"{label}:{fn} {sink}: {sources}" for label, fn, sink, sources, _ in scanned if sources]
    assert not raw, ("a per-address budget is keyed on the raw address; key it on "
                     "sign_in_lockout.source_of(address):\n" + "\n".join(raw))


# Every per-address budget known when this file was written, by (file, function, sink). A site that
# stops reaching source_of fails here even if the scan's raw-address rules no longer see it.
KEYED_ON_THE_SUBJECT = {
    ("app/api/api_server.py", "get_invite", "check_rate_limit"),
    ("app/api/api_server.py", "accept_invite", "check_rate_limit"),
    ("app/api/api_server.py", "forgot_password", "check_rate_limit"),
    ("app/api/api_server.py", "get_reset", "check_rate_limit"),
    ("app/api/api_server.py", "do_reset", "check_rate_limit"),
    ("app/api/api_server.py", "self_signup", "check_rate_limit"),
    ("app/api/api_server.py", "second_factor_login_verify", "check_rate_limit"),
    ("app/api/api_server.py", "second_factor_step_up", "check_rate_limit"),
    ("app/api/api_server.py", "redeem_note_link", "check_rate_limit"),
    ("app/api/api_server.py", "redeem_public_link", "check_rate_limit"),
    ("app/api/api_server.py", "download_public_link", "check_rate_limit"),
    ("app/api/api_server.py", "open_receiver_upload_session", "check_rate_limit"),
    ("app/core/rate_limiter.py", "dispatch", "check_rate_limit"),
    ("app/core/rate_limiter.py", "wrapper", "check_rate_limit"),
    ("app/services/auth_service.py", "_redis_rate_limit", "check_rate_limit"),
    ("app/services/auth_service.py", "_db_fallback_rate_limit", "_db_throttle_charge"),
    ("app/services/security_monitor.py", "record_failed_login", "_windowed_count"),
    ("app/sftp/sftp_server.py", "_sftp_key_throttled", "check_rate_limit"),
    ("app/sftp/sftp_server.py", "_sftp_key_throttled", "_db_throttle_hit"),
}


def test_every_known_per_address_budget_reaches_the_subject(scanned):
    keyed = {(label, fn, sink) for label, fn, sink, _raw, subject in scanned if subject}
    missing = sorted(KEYED_ON_THE_SUBJECT - keyed)
    assert not missing, f"these per-address budgets no longer key on source_of: {missing}"
    # Each route with a per-(address, token) bucket keys BOTH of its address buckets on the subject.
    counts = {}
    for label, fn, sink, _raw, subject in scanned:
        if subject and fn in ("redeem_note_link", "redeem_public_link", "open_receiver_upload_session"):
            counts[fn] = counts.get(fn, 0) + 1
    assert counts == {"redeem_note_link": 2, "redeem_public_link": 2, "open_receiver_upload_session": 2}


CONTROL = '''
def get_client_ip(request): ...
def source_of(a): ...
def keyed(ip): return f"k:{ip}"
def route(request, token):
    client_ip = get_client_ip(request)
    for ident, pfx in ((client_ip, "a"), (token, "b")):
        _rl.check_rate_limit(identifier=ident, limit=1, window=1, prefix=pfx)
    _rl.check_rate_limit(identifier=f"{client_ip}:{token}", limit=1, window=1)
    _rl.check_rate_limit(keyed(client_ip), 1, 1)
    bucket, entry = f"x:{request.client.host}", 1
    _rl.check_rate_limit(bucket, 1, 1)
def svc(self, ip_address):
    self._db_throttle_charge(ip_address, "a", 1, 1)
def fine(request, token, ip_address):
    s = source_of(get_client_ip(request))
    _rl.check_rate_limit(identifier=s, limit=1, window=1)
    _rl.check_rate_limit(identifier=f"{source_of(ip_address)}:{token}", limit=1, window=1)
    _rl.check_rate_limit(identifier=str(token), limit=1, window=1)
'''


def test_the_scan_flags_a_raw_address_control():
    """The instrument, checked: every raw shape in CONTROL is flagged, and none of the subject ones."""
    found = _Scanner({"control.py": CONTROL}).keys()
    flagged = [(fn, bool(raw)) for _label, fn, _sink, raw, _subject in found]
    assert flagged == [("route", True), ("route", True), ("route", True), ("route", True),
                       ("svc", True), ("fine", False), ("fine", False), ("fine", False)], flagged


# --------------------------------------------------------------------------------------------------
# Behaviour: each budget, two addresses in one /64
# --------------------------------------------------------------------------------------------------

def _request(address, path="/x"):
    from starlette.requests import Request
    return Request({"type": "http", "method": "POST", "path": path, "raw_path": path.encode(),
                    "query_string": b"", "headers": [], "client": (address, 40000),
                    "server": ("testserver", 80), "scheme": "http", "root_path": ""})


def test_source_of_groups_a_64_and_maps_ipv4():
    from app.core.sign_in_lockout import source_of
    assert source_of(SAME_A) == source_of(SAME_B) == "2001:db8:1:2::/64"
    assert source_of(OTHER) != source_of(SAME_A)
    assert source_of(MAPPED) == source_of(PLAIN) == PLAIN


def test_the_api_limiter_keys_one_subject_per_client():
    from app.core.rate_limiter import RateLimitMiddleware
    mw = RateLimitMiddleware(app=lambda *a: None, rate_limiter=None)
    key = lambda a: mw._get_client_identifier(_request(a))  # noqa: E731
    assert key(SAME_A) == key(SAME_B) == "ip:2001:db8:1:2::/64"
    assert key(OTHER) == "ip:2001:db8:1:3::/64"
    assert key(MAPPED) == key(PLAIN) == "ip:198.51.100.7"


def test_the_route_decorator_keys_one_subject_per_client(monkeypatch):
    from app.core import rate_limiter as RL
    seen = []

    class _Fake:
        def __init__(self, _redis):
            pass

        def check_rate_limit(self, identifier, limit, window, prefix="rate_limit", **_kw):
            seen.append(identifier)
            return True, limit, 0

    monkeypatch.setattr(RL, "RateLimiter", _Fake)

    @RL.rate_limit(limit=5, window=60)
    async def endpoint(request):
        return "ok"

    for a in (SAME_A, SAME_B, OTHER, MAPPED, PLAIN):
        assert run_coroutine(endpoint(request=_request(a))) == "ok"
    assert seen == ["ip:2001:db8:1:2::/64"] * 2 + ["ip:2001:db8:1:3::/64"] + ["ip:198.51.100.7"] * 2


class _Recorder:
    """A limiter that records each bucket it is asked to count and refuses (so a route stops at it)."""

    def __init__(self, allow=True):
        self.calls, self.allow = [], allow

    def check_rate_limit(self, identifier, limit, window, prefix="rate_limit", fail_open=True, entry_id=None):
        self.calls.append((prefix, identifier))
        return self.allow, 0, 0


def test_the_sign_in_limits_key_one_subject_per_client(monkeypatch):
    from app.core import rate_limiter as RL
    from app.services.auth_service import AuthService
    rec = _Recorder()
    monkeypatch.setattr(RL, "rate_limiter", rec)
    svc = AuthService(db=None)
    for a in (SAME_A, SAME_B, OTHER, MAPPED, PLAIN):
        svc._check_rate_limit("someone", a)
    users = [i for p, i in rec.calls if i.startswith("login_user:")]
    ips = [i for p, i in rec.calls if i.startswith("login_ip:")]
    assert ips == ["login_ip:2001:db8:1:2::/64"] * 2 + ["login_ip:2001:db8:1:3::/64"] + \
        ["login_ip:198.51.100.7"] * 2
    assert users[0] == users[1] != users[2] and users[3] == users[4] and users[0].endswith("|2001:db8:1:2::/64")


def test_the_sign_in_limits_durable_fallback_keys_one_subject_per_client(monkeypatch):
    from app.core import rate_limiter as RL
    from app.services.auth_service import AuthService

    class _Down:
        def check_rate_limit(self, *a, **kw):
            raise RL.RateLimiterUnavailable("down")

    charged = []
    monkeypatch.setattr(RL, "rate_limiter", _Down())
    monkeypatch.setattr(AuthService, "_db_throttle_charge",
                        lambda self, ident, action, limit, window: (charged.append((action, ident)) or
                                                                    (True, 0, (action, ident))))
    svc = AuthService(db=None)
    for a in (SAME_A, SAME_B, MAPPED, PLAIN):
        svc._check_rate_limit("someone", a)
    ips = [i for action, i in charged if action == "login_ip"]
    users = [i for action, i in charged if action == "login_user"]
    assert ips == ["2001:db8:1:2::/64"] * 2 + ["198.51.100.7"] * 2
    assert users[0] == users[1] and users[2] == users[3] and users[0] != users[2]


def test_the_failed_sign_in_alert_counts_one_subject_per_client(monkeypatch):
    from app.services.security_monitor import SecurityMonitor
    keys = []
    mon = SecurityMonitor.__new__(SecurityMonitor)
    mon._login_attempts = __import__("collections").defaultdict(__import__("collections").deque)
    mon.failed_login_window_minutes = 15
    mon.failed_login_threshold = 10 ** 6

    def _count(self, redis_key, window_seconds, fallback, amount=1):
        keys.append(redis_key)
        return 1

    monkeypatch.setattr(SecurityMonitor, "_windowed_count", _count)
    for a in (SAME_A, SAME_B, MAPPED, PLAIN):
        try:
            mon.record_failed_login("someone", a, "wrong password")
        except Exception:
            pass  # only the counter's key matters here
    assert len(keys) == 4 and keys[0] == keys[1] and keys[2] == keys[3] and keys[0] != keys[2]
    assert keys[0].endswith(":2001:db8:1:2::/64") and keys[2].endswith(":198.51.100.7")


def test_the_sftp_key_offer_limit_keys_one_subject_per_client(monkeypatch):
    from app.core import rate_limiter as RL
    from app.sftp import sftp_server as S
    rec = _Recorder()
    monkeypatch.setattr(RL, "rate_limiter", rec)
    for a in (SAME_A, SAME_B, OTHER, MAPPED, PLAIN):
        assert S._sftp_key_throttled(a, "alice") is False
    assert [i for _p, i in rec.calls] == ["sftp_pk:2001:db8:1:2::/64:alice"] * 2 + \
        ["sftp_pk:2001:db8:1:3::/64:alice"] + ["sftp_pk:198.51.100.7:alice"] * 2


def test_the_sftp_key_offer_limit_fallback_and_clear_use_the_same_subject(monkeypatch):
    from app.core import rate_limiter as RL
    from app.core import database, redis_guard
    from app.sftp import sftp_server as S

    class _Down:
        def check_rate_limit(self, *a, **kw):
            raise RL.RateLimiterUnavailable("down")

    hits, deleted, filtered = [], [], []
    monkeypatch.setattr(RL, "rate_limiter", _Down())
    monkeypatch.setattr(S.AuthService, "_db_throttle_hit",
                        staticmethod(lambda ident, action, limit, window: (hits.append(ident) or (True, 0))))
    monkeypatch.setattr(database, "redis_client", SimpleNamespace(delete=lambda key: deleted.append(key)))
    monkeypatch.setattr(redis_guard, "best_effort", lambda _name, fn, *a, **kw: fn())

    class _Query:
        def filter(self, *conds):
            filtered.extend(str(c.right.value) for c in conds if hasattr(c, "right") and
                            getattr(c.left, "key", "") == "identifier")
            return self

        def delete(self, **_kw):
            return 0

    class _Db:
        def query(self, _model):
            return _Query()

    class _Ctx:
        def __enter__(self):
            return _Db()

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(database, "get_db_context", lambda: _Ctx())
    S._sftp_key_throttled(SAME_A, "alice")
    S._sftp_key_clear(SAME_B, "alice")
    assert hits == ["2001:db8:1:2::/64:alice"]
    assert deleted == ["rate_limit:sftp_pk:2001:db8:1:2::/64:alice"], "the cache key cleared is the one charged"
    assert filtered == ["2001:db8:1:2::/64:alice"], "the durable row cleared is the one charged"


def test_sftp_admission_counts_one_subject_per_client():
    from app.sftp.sftp_server import _ConnectionAdmission
    adm = _ConnectionAdmission(max_total=0, max_per_ip=1, max_authenticated_per_ip=1)
    assert adm.admit(SAME_A) is True
    assert adm.admit(SAME_B) is False, "a second address in the same /64 shares the pre-auth cap"
    assert adm.admit(OTHER) is True, "another /64 has its own"
    assert adm.admit(PLAIN) is True and adm.admit(MAPPED) is False, "IPv4 written as IPv6 is the same client"
    assert adm.authenticated(SAME_B) is True        # moves the /64's connection to the session count
    assert adm.admit(SAME_A) is True                # which frees the /64's pre-auth slot
    assert adm.authenticated(SAME_A) is False, "the /64 shares the authenticated cap too"
    adm.release(SAME_B, authenticated=True)         # released under another address of the /64
    assert adm.authenticated(SAME_A) is True
    adm.release(SAME_A, authenticated=True)
    adm.release(MAPPED)
    assert adm.admit(PLAIN) is True, "a release under the mapped form frees the IPv4 slot"


# The public routes with a per-address budget: (function, extra arguments, the bucket prefixes keyed by
# address). Each is called with a limiter that refuses, so it stops at its limit before any other work.
def _routes():
    from app.api import api_server as A
    user = SimpleNamespace(id="u-1", _is_temp_session=False)
    return [
        (A.get_invite, {"token": "t" * 40}, ["invite_lookup"]),
        (A.accept_invite, {"token": "t" * 40, "payload": A.InviteAccept(password="p" * 12)}, ["invite_accept_ip"]),
        (A.forgot_password, {"body": A.ForgotPasswordRequest(identifier="x")}, ["forgot_password_ip"]),
        (A.get_reset, {"token": "t" * 40}, ["reset_lookup_ip"]),
        (A.do_reset, {"token": "t" * 40, "body": A.ResetPasswordRequest(new_password="p" * 12)}, ["reset_do_ip"]),
        (A.self_signup, {"payload": A.SignupRequest.model_construct(username="newbie", password="p" * 12,
                                                                    email=None)}, ["signup_ip"]),
        (A.second_factor_login_verify, {"body": A.SecondFactorVerifyRequest(), "principal": (user, None)},
         ["sf_login_verify"]),
        (A.second_factor_step_up, {"body": A.SecondFactorStepUpRequest(action="public_link.create"),
                                   "current_user": user}, ["sf_step_up"]),
        (A.redeem_note_link, {"token": "t" * 40, "payload": A.NoteLinkRedeem()},
         ["notelink_redeem", "notelink_redeem_ip"]),
        (A.redeem_public_link, {"token": "t" * 40, "payload": A.PublicLinkRedeem()},
         ["publiclink_redeem", "publiclink_redeem_ip"]),
        (A.download_public_link, {"token": "t" * 40, "file_id": "f", "x_download_grant": "g"},
         ["publiclink_download_ip"]),
        (A.open_receiver_upload_session,
         {"token": "t" * 40, "payload": A.ReceiverUploadOpen(filename="a", total_size=1, total_chunks=1)},
         ["receiver_open", "receiver_open_ip"]),
    ]


def _route_keys(monkeypatch, fn, kwargs, address):
    from fastapi import HTTPException
    from app.core import rate_limiter as RL
    rec = _Recorder(allow=False)
    monkeypatch.setattr(RL.rate_limiter, "check_rate_limit", rec.check_rate_limit)
    with pytest.raises(HTTPException) as refused:
        run_coroutine(fn(request=_request(address), db=None, **kwargs))
    assert refused.value.status_code == 429, (fn.__name__, refused.value.status_code, refused.value.detail)
    return dict(rec.calls)


def test_every_public_route_budget_keys_one_subject_per_client(monkeypatch):
    for fn, kwargs, prefixes in _routes():
        a, b, other = (_route_keys(monkeypatch, fn, kwargs, x) for x in (SAME_A, SAME_B, OTHER))
        m, p = (_route_keys(monkeypatch, fn, kwargs, x) for x in (MAPPED, PLAIN))
        for prefix in prefixes:
            assert prefix in a, (fn.__name__, prefix, a)
            assert a[prefix] == b[prefix], f"{fn.__name__} {prefix}: one /64 must share the bucket"
            assert a[prefix] != other[prefix], f"{fn.__name__} {prefix}: another /64 has its own"
            assert "2001:db8:1:2::/64" in a[prefix] and SAME_A not in a[prefix]
            assert m[prefix] == p[prefix] and "198.51.100.7" in p[prefix], (fn.__name__, prefix, m, p)


def test_every_compliance_step_up_counts_one_subject_per_client(monkeypatch):
    """The steps of compliance access are earned at the same step-up route as any other action, on the same
    budget: two addresses in one /64 share it and another /64 has its own, for each of the steps."""
    from app.api import api_server as A
    from app.core import second_factor_actions as acts
    user = SimpleNamespace(id="u-1", _is_temp_session=False)
    assert len(acts.COMPLIANCE_STEP_UPS) >= 8
    for action in acts.COMPLIANCE_STEP_UPS:
        kwargs = {"body": A.SecondFactorStepUpRequest(action=action), "current_user": user}
        a, b, other = (_route_keys(monkeypatch, A.second_factor_step_up, kwargs, x) for x in (SAME_A, SAME_B, OTHER))
        assert a["sf_step_up"] == b["sf_step_up"], (action, a, b)
        assert a["sf_step_up"] != other["sf_step_up"], (action, a, other)
        assert "2001:db8:1:2::/64" in a["sf_step_up"] and SAME_A not in a["sf_step_up"], (action, a)
