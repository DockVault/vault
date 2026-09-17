"""The host tool reads a version's DISPLAY lifecycle from its bundled copy merged ADD-ONLY with the
copy on main, so a vulnerability found AFTER a tag was cut still shows for an old checkout.

Pins the same add-only directions the app pins (the remote can only tighten), the credibility ceiling
(a fix in a newer RELEASE is kept, one above the newest release is dropped), and the fail-safe fetch.
A final test feeds the TOOL's merge and the APP's merge the same matrices and asserts they agree --
the two live apart (the tool is stdlib-only, host-side), so a drift would otherwise go unnoticed.
The hard upgrade-path gates are NOT touched here: they keep reading the tag-pinned matrices.
"""
import pytest

import dockvault as dv
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


def _merged(local, main, ceiling="0.30.0"):
    merged, source = dv.merge_lifecycle_matrix(local, main, ceiling)
    return merged, source


# ---- add-only merge, every direction -------------------------------------------------------------
def test_a_remote_secure_true_never_flips_a_local_insecure():
    merged, source = _merged(_matrix(V, secure=False), _matrix(V, secure=True))
    assert dv.version_support(merged, V).get("secure") is False
    assert source == "main"


def test_a_remote_secure_false_alone_makes_it_insecure():
    merged, _ = _merged(_matrix(V, secure=True), _matrix(V, secure=False))
    assert dv.version_support(merged, V).get("secure") is False


def test_a_remote_dropping_a_local_vulnerability_never_removes_it():
    # The remote lists a DIFFERENT vulnerability (not the bundled copy's A): the union must still keep
    # A. A disjoint remote is deliberate -- the merge starts from a copy of the local matrix, so a
    # merge that dropped local but produced a non-empty remote-only list would overwrite and lose A,
    # while an empty or overlapping result could hide the bug.
    merged, _ = _merged(_matrix(V, vulns=[{"title": "A", "fixed_in": "0.29.1"}]),
                        _matrix(V, vulns=[{"title": "B", "fixed_in": "0.29.1"}]))
    got = sorted((x.get("title"), x.get("fixed_in")) for x in dv.version_vulnerabilities(merged, V))
    assert got == [("A", "0.29.1"), ("B", "0.29.1")]


def test_a_remote_eol_false_never_clears_a_local_eol_true():
    merged, _ = _merged(_matrix(V, eol=True), _matrix(V, eol=False))
    assert dv.version_support(merged, V).get("eol") is True


def test_vulnerabilities_are_a_union_deduped_by_title_and_fixed_in():
    merged, _ = _merged(_matrix(V, vulns=[{"title": "A", "fixed_in": "0.29.1"}]),
                        _matrix(V, vulns=[{"title": "A", "fixed_in": "0.29.1"},
                                          {"title": "B", "fixed_in": "0.29.1"}]))
    assert sorted(x.get("title") for x in dv.version_vulnerabilities(merged, V)) == ["A", "B"]


def test_support_end_dates_take_the_earlier():
    merged, _ = _merged(_matrix(V, eol=True, security_support="2026-06-01"),
                        _matrix(V, eol=True, security_support="2026-01-01"))
    assert dv.version_support(merged, V).get("security_support") == "2026-01-01"


# ---- ceiling is the newest RELEASE, not the running version --------------------------------------
def test_ceiling_keeps_a_fix_in_a_newer_release_but_drops_an_unreleased_one():
    merged, _ = _merged(_matrix(V),
                        _matrix(V, secure=False, vulns=[{"title": "kept", "fixed_in": "0.30.0"},
                                                        {"title": "dropped", "fixed_in": "0.99.0"}]),
                        ceiling="0.30.0")
    titles = {x.get("title") for x in dv.version_vulnerabilities(merged, V)}
    assert "kept" in titles and "dropped" not in titles


# ---- fail-safe fetch of the fixed main URL -------------------------------------------------------
def test_fetch_main_uses_the_fixed_main_url_not_a_tag():
    captured = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *a):
            return b'{"versions": {}}'

    def _opener(url, timeout=None):
        captured["url"] = url
        return _Resp()

    dv.fetch_main_lifecycle_matrix(opener=_opener)
    assert captured["url"] == dv._MAIN_MATRIX_URL
    assert "/main/" in captured["url"] and "vmain" not in captured["url"]


def test_fetch_main_fails_safe_to_none_on_error():
    def _boom(url, timeout=None):
        raise OSError("no egress")
    assert dv.fetch_main_lifecycle_matrix(opener=_boom) is None


def test_merge_falls_back_to_local_when_main_is_none():
    local = _matrix(V, secure=False)
    merged, source = dv.merge_lifecycle_matrix(local, None, "0.30.0")
    assert source == "local"
    assert merged is local   # untouched; the offline path is the copy we already have


# ---- the two consumers agree ---------------------------------------------------------------------
def test_the_tool_and_the_app_merge_the_same_lifecycle():
    # A rich case exercising every merge axis at once: bundled says secure with one vuln; main adds an
    # insecure verdict, a second vuln, an eol, an earlier support date, AND an unreleased fix that the
    # ceiling must drop. Both consumers must reach the identical merged lifecycle.
    ceiling = "0.30.0"
    local = _matrix(V, secure=True, eol=False, security_support="2026-06-01",
                    vulns=[{"title": "A", "fixed_in": "0.29.1"}])
    main = _matrix(V, secure=False, eol=True, security_support="2026-01-01",
                   vulns=[{"title": "A", "fixed_in": "0.29.1"},
                          {"title": "B", "fixed_in": "0.30.0"},
                          {"title": "unreleased", "fixed_in": "0.99.0"}])

    merged, _ = dv.merge_lifecycle_matrix(local, main, ceiling)
    tool_vulns = sorted((x.get("title"), x.get("fixed_in")) for x in dv.version_vulnerabilities(merged, V))
    tool_insecure = dv.version_support(merged, V).get("secure") is False
    tool_eol = dv.version_support(merged, V).get("eol") is True
    tool_secsupport = dv.version_support(merged, V).get("security_support")

    block = U.merged_security(V, ceiling, local_matrix=local, main_matrix=main)
    app_vulns = sorted((x["title"], x["fixed_in"]) for x in block["vulnerabilities"])
    app_support = U._merge_support(U._version_support(local, V), U._version_support(main, V))

    assert tool_vulns == app_vulns
    assert tool_insecure == (block["secure"] is False)
    assert tool_eol == (app_support.get("eol") is True)
    assert tool_secsupport == app_support.get("security_support")
    # and both dropped the unreleased fix by the ceiling
    assert ("unreleased", "0.99.0") not in tool_vulns


def test_the_merge_bounds_an_oversized_or_nonstring_title_and_fixed_in():
    # (b) The untrusted scalars are coerced to str and capped once in the merge, so every downstream
    # print is bounded; clean_matrix_text still strips escapes at the print sites.
    merged, _ = _merged(_matrix(V),
                        _matrix(V, secure=False, vulns=[{"title": "y" * 5000, "fixed_in": 999}]))
    vs = dv.version_vulnerabilities(merged, V)
    assert len(vs) == 1
    assert isinstance(vs[0]["title"], str) and len(vs[0]["title"]) <= 200
    assert vs[0]["fixed_in"] == "999"
