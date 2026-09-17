"""The app update-check gains a security block for the deployment's OWN version, merged ADD-ONLY
from the copy on main into the bundled copy.

A version's own shipped (and tag-frozen) matrix self-declares secure forever, so an insecure verdict
found after the tag was cut reaches an old deployment only from the copy on main. These pin that the
merge is add-only in every direction (the remote can only tighten -- never flip a local insecure to
secure, never remove a local vulnerability, never clear a local eol), the credibility ceiling (a fix
in a newer RELEASE is kept; one above the newest release the app can see is dropped), the fail-safe
path (source "bundled" when main is unreachable, never a false secure), and that the block is always
attached. The fetch is stubbed -- no network.
"""
import pytest

from app.services import update_check as U

pytestmark = pytest.mark.unit

V = "0.29.0"


def _matrix(version, *, secure=None, eol=None, vulns=None, code_support=None, security_support=None):
    support = {}
    if secure is not None:
        support["secure"] = secure
    if eol is not None:
        support["eol"] = eol
    if code_support:
        support["code_support"] = code_support
    if security_support:
        support["security_support"] = security_support
    meta = {}
    if support:
        meta["support"] = support
    if vulns is not None:
        meta["vulnerabilities"] = vulns
    return {"versions": {version: meta}}


# ---- add-only merge, every direction -------------------------------------------------------------
def test_a_remote_secure_true_never_flips_a_local_insecure():
    b = U.merged_security(V, "0.30.0", local_matrix=_matrix(V, secure=False),
                          main_matrix=_matrix(V, secure=True))
    assert b["secure"] is False
    assert b["source"] == "main"


def test_a_remote_can_add_an_insecure_verdict_the_bundled_copy_lacked():
    b = U.merged_security(V, "0.29.1", local_matrix=_matrix(V, secure=True),
                          main_matrix=_matrix(V, secure=False, vulns=[{"title": "RCE", "fixed_in": "0.29.1"}]))
    assert b["secure"] is False
    assert {"title": "RCE", "fixed_in": "0.29.1"} in b["vulnerabilities"]


def test_a_remote_secure_false_flag_alone_makes_it_insecure():
    # No vulnerabilities listed anywhere: the insecure verdict rides purely on the secure flag, so the
    # merge must carry a remote secure:false into a version the bundled copy still calls secure.
    b = U.merged_security(V, "0.30.0", local_matrix=_matrix(V, secure=True),
                          main_matrix=_matrix(V, secure=False))
    assert b["secure"] is False


def test_a_remote_dropping_a_local_vulnerability_never_removes_it():
    b = U.merged_security(V, "0.29.1", local_matrix=_matrix(V, vulns=[{"title": "A", "fixed_in": "0.29.1"}]),
                          main_matrix=_matrix(V, vulns=[]))
    assert {"title": "A", "fixed_in": "0.29.1"} in b["vulnerabilities"]
    assert b["secure"] is False   # a listed vulnerability means insecure


def test_a_remote_eol_false_never_clears_a_local_eol_true():
    merged = U._merge_support({"eol": True}, {"eol": False})
    assert merged["eol"] is True


def test_vulnerabilities_are_a_union_deduped_by_title_and_fixed_in():
    b = U.merged_security(V, "0.29.1",
                          local_matrix=_matrix(V, vulns=[{"title": "A", "fixed_in": "0.29.1"}]),
                          main_matrix=_matrix(V, vulns=[{"title": "A", "fixed_in": "0.29.1"},
                                                        {"title": "B", "fixed_in": "0.29.1"}]))
    assert sorted(v["title"] for v in b["vulnerabilities"]) == ["A", "B"]


def test_support_end_dates_take_the_earlier():
    merged = U._merge_support({"security_support": "2026-06-01"}, {"security_support": "2026-01-01"})
    assert merged["security_support"] == "2026-01-01"


# ---- the credibility ceiling is the newest RELEASE, not the running version ----------------------
def test_ceiling_keeps_a_fix_in_a_newer_release_but_drops_an_unreleased_one():
    # Running 0.29.0; the newest RELEASE the app can see is 0.30.0. A fix in 0.30.0 is newer than the
    # running version but real, so it is kept; a fix claiming 0.99.0 is above the newest release and
    # not a credible disclosure, so it is dropped. Were the ceiling the running version, the real
    # 0.30.0 fix would be dropped -- the exact silent-fallback this rule prevents.
    b = U.merged_security(V, "0.30.0", local_matrix=_matrix(V),
                          main_matrix=_matrix(V, secure=False,
                                              vulns=[{"title": "kept", "fixed_in": "0.30.0"},
                                                     {"title": "dropped", "fixed_in": "0.99.0"}]))
    titles = {v["title"] for v in b["vulnerabilities"]}
    assert "kept" in titles and "dropped" not in titles


def test_a_vulnerability_with_no_fix_stated_is_kept_regardless_of_ceiling():
    b = U.merged_security(V, "0.30.0", local_matrix=_matrix(V),
                          main_matrix=_matrix(V, secure=False, vulns=[{"title": "unpatched", "fixed_in": None}]))
    assert any(v["title"] == "unpatched" for v in b["vulnerabilities"])


# ---- fail-safe + honest source -------------------------------------------------------------------
def test_fail_safe_is_bundled_and_never_a_false_secure():
    b = U.merged_security(V, "0.30.0",
                          local_matrix=_matrix(V, secure=False, vulns=[{"title": "X", "fixed_in": "0.29.1"}]),
                          main_matrix=None)
    assert b["source"] == "bundled"
    assert b["secure"] is False


def test_secure_true_only_when_nothing_says_otherwise():
    b = U.merged_security(V, "0.30.0", local_matrix=_matrix(V), main_matrix=_matrix(V))
    assert b["secure"] is True and b["vulnerabilities"] == []


# ---- bounded, fail-safe fetch of the fixed main URL ----------------------------------------------
def test_fetch_main_matrix_fails_safe_to_none(monkeypatch):
    def _boom(url):
        raise RuntimeError("no egress")
    monkeypatch.setattr(U, "_http_json", _boom)
    assert U.fetch_main_matrix() is None


def test_fetch_main_matrix_rejects_a_wrong_shape(monkeypatch):
    monkeypatch.setattr(U, "_http_json", lambda url: {"no_versions": 1})
    assert U.fetch_main_matrix() is None


def test_fetch_main_matrix_uses_the_fixed_main_url_not_a_tag(monkeypatch):
    seen = {}
    monkeypatch.setattr(U, "_http_json", lambda url: seen.update(url=url) or {"versions": {}})
    U.fetch_main_matrix()
    assert seen["url"] == U.MAIN_MATRIX_URL
    assert "/main/" in seen["url"] and "%s" not in seen["url"]


# ---- the block is always attached to the status --------------------------------------------------
def _reset_cache():
    U._cache.update({"checked_at": 0.0, "latest": None, "url": None, "notes": None,
                     "matrix": None, "main_matrix": None, "main_fetched_at": None})


def test_get_update_status_always_carries_the_security_block(monkeypatch):
    monkeypatch.setattr(U, "_fetch_latest", lambda: ("0.30.0", "http://example/rel", "notes"))
    monkeypatch.setattr(U, "_fetch_matrix", lambda tag: None)
    monkeypatch.setattr(U, "fetch_main_matrix",
                        lambda: _matrix(V, secure=False, vulns=[{"title": "RCE", "fixed_in": "0.30.0"}]))
    monkeypatch.setattr(U, "_read_bundled_matrix", lambda: _matrix(V, secure=True))
    _reset_cache()
    st = U.get_update_status(current_version=V, enabled=True, managed=False, force=True)
    assert "security" in st
    sec = st["security"]
    assert sec["source"] == "main" and sec["secure"] is False
    assert any(v["title"] == "RCE" for v in sec["vulnerabilities"])


def test_get_update_status_security_block_fails_safe_to_bundled(monkeypatch):
    monkeypatch.setattr(U, "_fetch_latest", lambda: ("0.30.0", "http://example/rel", "notes"))
    monkeypatch.setattr(U, "_fetch_matrix", lambda tag: None)
    monkeypatch.setattr(U, "fetch_main_matrix", lambda: None)   # main unreachable
    monkeypatch.setattr(U, "_read_bundled_matrix", lambda: _matrix(V, secure=True))
    _reset_cache()
    st = U.get_update_status(current_version=V, enabled=True, managed=False, force=True)
    assert st["security"]["source"] == "bundled"
    assert st["security"]["secure"] is True   # honest bundled verdict; never fabricated


# ---- (a) a bundled verdict has no fetch time -----------------------------------------------------
def test_fetched_at_is_none_when_the_verdict_is_bundled():
    # A failed or skipped fetch has no fetch time; even a stamp passed in is ignored for a bundled
    # verdict, so it can never misread as fresh.
    b = U.merged_security(V, "0.30.0", local_matrix=_matrix(V, secure=False),
                          main_matrix=None, fetched_at=12345.0)
    assert b["source"] == "bundled"
    assert b["fetched_at"] is None


# ---- (b) untrusted title/fixed_in are coerced to str and length-capped ---------------------------
def test_the_block_bounds_an_oversized_or_nonstring_title_and_fixed_in():
    b = U.merged_security(V, "0.30.0", local_matrix=_matrix(V),
                          main_matrix=_matrix(V, secure=False,
                                              vulns=[{"title": "x" * 5000, "fixed_in": 12345}]))
    v = b["vulnerabilities"][0]
    assert isinstance(v["title"], str) and len(v["title"]) <= 200
    assert v["fixed_in"] == "12345"   # a non-string coerced to str


# ---- (c) disabled / managed still return the bundled block, with NO fetch of any kind ------------
def test_disabled_and_managed_return_a_bundled_block_without_any_fetch(monkeypatch):
    calls = []
    monkeypatch.setattr(U, "fetch_main_matrix", lambda *a, **k: calls.append("main") or None)
    monkeypatch.setattr(U, "_fetch_latest", lambda: calls.append("latest") or (None, None, None))
    monkeypatch.setattr(U, "_read_bundled_matrix",
                        lambda: _matrix(V, secure=False, vulns=[{"title": "X", "fixed_in": "0.29.1"}]))
    for kwargs in ({"enabled": False, "managed": False}, {"enabled": True, "managed": True}):
        _reset_cache()
        st = U.get_update_status(V, **kwargs)
        assert "security" in st, kwargs
        assert st["security"]["source"] == "bundled"
        assert st["security"]["fetched_at"] is None
        assert st["security"]["secure"] is False   # the bundled insecure verdict is still shown
    assert calls == [], "disabled/managed must not fetch anything over the network"


# ---- (d) secure is three-valued: None when neither source knows the version ----------------------
def test_secure_is_none_when_neither_source_knows_the_version():
    # Reachable only as a failure state (unreadable bundled copy AND a silent main): a positive with
    # no evidence must not be asserted.
    b = U.merged_security(V, "0.30.0", local_matrix=None, main_matrix=None)
    assert b["secure"] is None
    assert b["source"] == "bundled"


def test_secure_is_true_when_a_source_lists_the_version_and_nothing_is_wrong():
    b = U.merged_security(V, "0.30.0", local_matrix=_matrix(V), main_matrix=None)
    assert b["secure"] is True   # the bundled copy vouches for a version it actually lists
