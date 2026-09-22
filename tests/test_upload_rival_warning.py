"""Every upload that reaches its commit is told about an earlier upload of its name still alive.

The fire point used to be gated on "this upload replaces something, OR it has live rivals": it
warned, or it cancelled. Narrowing the gate to "replaces" was right for the cancel -- an upload
nobody was asked about must cancel nothing -- but it took the warning with it. Tab B drops X before
its tray has refreshed tab A's session in; B's upload commits without a word; A's older bytes land
last and replace B's newer copy by name.

The rule is now written in the code and held here: warn on what we know, cancel only what we
displayed. These tests drive the shipped send loop in the Node harness: a plain upload with a live
earlier rival commits WITH the warning and without a cancel; a replacing upload still cancels and
does not warn twice; an upload with no rival says nothing; and a signed-out run says nothing at all.
"""
import pytest

pytestmark = pytest.mark.unit

from _js_source import strip_comments  # noqa: E402
from test_upload_tray_controls import (  # noqa: E402
    APP_JS, _method, _serve, COMPLETE, DEL_OLD, CANCELLED_ONLY, REPLACED, WARN_OTHER,
)


def test_a_plain_upload_with_a_live_earlier_rival_is_warned_and_cancels_nothing():
    out = _serve("""
    // An earlier upload of X (order 1, alive, its session open) that OURS was never asked about.
    fresh(victim(), ours({ replaces: null }));
    await um._run('o'); out.warned = snap();
    // The same with the server's count of our bytes not yet confirmed: a plain upload commits as
    // it always has -- the confirmation step belongs to replacements, which have something to lose.
    fresh(victim(), ours({ replaces: null, lastPut: { complete: false, bytes_received: 5 } }));
    server.held = { received_chunks: [0], bytes_received: 5 };
    await um._run('o'); out.unconfirmed = snap();
    """)
    w = out["warned"]
    # (mutation: the warning branch removed -> [COMPLETE] alone -> red. mutation: the old wide
    #  gate back (`replaces || liveRivals`) -> the plain upload enters the replacement step -> the
    #  unconfirmed case throws instead of committing -> red.)
    assert w["log"] == [WARN_OTHER, COMPLETE], w
    assert DEL_OLD not in w["log"] and w["v"] is not None and w["v"]["cancelled"] is False, w
    assert w["o"]["status"] == "done"
    u = out["unconfirmed"]
    assert u["log"] == [WARN_OTHER, "POST /vaults/V/uploads/new-sess/complete"], u
    assert u["o"]["status"] == "done", u


def test_a_replacing_upload_still_cancels_what_it_was_shown_and_is_not_warned_twice():
    out = _serve("""
    fresh(victim(), ours());                                  // replaces: the victim was shown
    await um._run('o'); out.replacing = snap();
    // A replacement beside ANOTHER earlier upload it was not shown: cancels the one, warns of the
    // other -- once, from the replacement step, not again from the plain branch.
    fresh(victim(), sent('u', 'unseen-sess', { order: 1, replaces: null }), ours());
    await um._run('o'); out.mixed = snap();
    """)
    r = out["replacing"]
    assert r["log"] == [DEL_OLD, CANCELLED_ONLY, COMPLETE, REPLACED] and r["v"] is None, r
    m = out["mixed"]
    assert m["log"].count(WARN_OTHER) == 1, m["log"]
    assert m["log"] == [DEL_OLD, CANCELLED_ONLY, WARN_OTHER, COMPLETE, REPLACED], m


def test_an_upload_with_no_live_rival_is_told_nothing():
    out = _serve("""
    fresh(ours({ replaces: null }));
    await um._run('o'); out.alone = snap();
    // A later upload of the name is not an EARLIER one: nothing to warn about.
    fresh(ours({ replaces: null }), sent('later', 'later-sess', { order: 9, replaces: null }));
    await um._run('o'); out.laterOnly = snap();
    // A finished one is not alive.
    fresh(ours({ replaces: null }), victim({ status: 'done' }));
    await um._run('o'); out.doneOnly = snap();
    """)
    for key in ("alone", "laterOnly", "doneOnly"):
        assert out[key]["log"] == [COMPLETE], (key, out[key]["log"])


def test_a_signed_out_run_does_not_say_it():
    out = _serve("""
    // Signed out before the fire point: the warning would name the last account's file on the
    // next person's screen. A plain upload makes no request between its last chunk and the fire
    // point, so the sign-out is landed on the sync a restored row does first.
    // The next account signs in with an upload of the SAME NAME in its tray, dropped earlier than
    // ours by its clock -- everything the resolver needs to call it a live rival of the stale run.
    fresh(victim(), ours({ replaces: null, needsServerSync: true }));
    server.onRequest = async () => { um.reset(); um.items = new Map([['b', sent('b', 'b-sess', { order: 1, replaces: null })]]); };
    await um._run('o'); out.signedOut = snap();
    """)
    s = out["signedOut"]
    assert s["log"] == ["GET /vaults/V/uploads/new-sess"], s["log"]     # the sync; then nothing
    # (mutation: the warning not gated -> "Another upload of X is still in progress" on the next
    #  account's screen, naming the last account's file -> red.)
    assert not any(e.startswith("toast") for e in s["log"]), s["log"]


def test_the_rule_is_written_where_the_next_person_meets_the_fork():
    # Smoke alarm: the cancel step stays gated on `replaces`; the warning branch stands beside it,
    # reads every upload's live rivals, and the rule is said in the code in so many words.
    js = APP_JS.read_text(encoding="utf-8")
    run = _method(js, "async _run(id) {")
    assert "WARN ON WHAT WE KNOW; CANCEL ONLY WHAT WE DISPLAYED." in run
    code = strip_comments(run)
    assert code.count("if (it.replaces) {") == 1
    assert code.count("} else if (this._liveRivals(it).length) {") == 1
    assert code.index("if (it.replaces) {") < code.index("await this._fireReplacement(it);") \
        < code.index("} else if (this._liveRivals(it).length) {") < code.index("it.status = 'completing';")
    assert "it.replaces || this._liveRivals(it).length" not in code
