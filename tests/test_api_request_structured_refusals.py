"""A refusal the server words as {reason, message}, through the page's own request code (static/js/app.js run in
Node with the stand-ins of test_session_watch_refusals).

The server answers some refusals with a sentence and others with a structured detail: the sentence to show and a
reason the caller may branch on. Both reach the person as the sentence, whatever the status: a 403 and a 401 read the
detail as text before looking into it, carry the reason on the error, and a structured refusal, which is about the
action asked, never signs the person out for a word its message happens to use.
"""
import json

import pytest

from test_session_told_renewal_and_retry import CHANNEL, REQUESTS, TOLD, _node

pytestmark = pytest.mark.unit

REFUSED = TOLD + r"""
globalThis.SIGNED_OUT_REASONS = { ended: 'Your session has ended. Sign in again.' };
vm.runInThisContext(CHANNEL_SRC, { filename: 'app-channel.js' });
const json = (status, body) => ({ ...answer(status, body),
    headers: { get: (h) => (h.toLowerCase() === 'content-type' ? 'application/json' : null) } });
route = (url) => Promise.resolve(url.endsWith('/auth/temp-credentials') ? json(STATUS, BODY) : answer(200, {}));
console.error = () => {};
console.warn = () => {};
const shown = [];
globalThis.showPermissionDenied = (m) => shown.push(m);
let got = null;
await _apiRequestNow('/auth/temp-credentials', { method: 'POST', body: '{}', silent: SILENT })
    .then(() => { got = { settled: 'resolved' }; },
          (e) => { got = { settled: 'rejected', message: e.message, kind: e.constructor.name,
                           reason: e.reason === undefined ? null : e.reason,
                           status: e.status === undefined ? null : e.status }; });
await settle();
out({ ...got, shown, signed_out: logouts, held: authToken === mine });
"""

LAPSED = {"reason": "sso_freshness_lapsed",
          "message": "Sign in through Contoso again before you make a temporary credential."}


def _refused(status: int, body: dict, silent: bool = False) -> dict:
    return _node(REFUSED.replace("STATUS", str(status)).replace("BODY", json.dumps(body))
                 .replace("SILENT", "true" if silent else "false").replace("CHANNEL_SRC", json.dumps(CHANNEL)),
                 REQUESTS)


def test_a_403_with_a_structured_detail_is_shown_as_its_sentence_and_keeps_its_reason():
    out = _refused(403, {"detail": LAPSED})
    assert out["settled"] == "rejected" and out["kind"] == "Error", out
    assert out["message"] == LAPSED["message"] and out["reason"] == "sso_freshness_lapsed" and out["status"] == 403
    assert out["shown"] == [LAPSED["message"]]
    assert out["signed_out"] == 0 and out["held"] is True
    # A caller that asked for silence shows nothing and still gets the sentence and the reason.
    quiet = _refused(403, {"detail": LAPSED}, silent=True)
    assert quiet["shown"] == [] and quiet["message"] == LAPSED["message"] and quiet["reason"] == "sso_freshness_lapsed"


@pytest.mark.parametrize("word", ["inactive", "terminated", "locked"])
def test_a_structured_403_never_signs_out_for_a_word_in_its_message(word):
    """The account sentences ('User account is inactive', 'is locked') are plain ones about this session's account.
    A structured refusal is about the action asked: the same word in its message ends nothing."""
    message = f"That account is {word}; choose another."
    out = _refused(403, {"detail": {"reason": "target_unusable", "message": message}})
    assert out["signed_out"] == 0 and out["held"] is True, out
    assert out["message"] == message and out["reason"] == "target_unusable" and out["status"] == 403
    assert out["shown"] == [message]


@pytest.mark.parametrize("sentence", ["User account is inactive", "User account is locked",
                                      "Session has been terminated by an administrator"])
def test_the_plain_account_sentence_still_signs_the_session_out(sentence):
    out = _refused(403, {"detail": sentence})
    assert out["settled"] == "rejected" and out["message"] == sentence, out
    assert out["signed_out"] == 1 and out["shown"] == []


def test_a_plain_403_and_a_reason_beside_the_detail_are_as_before():
    out = _refused(403, {"detail": "You may not do that.", "reason": "not_yours"})
    assert out["message"] == "You may not do that." and out["reason"] == "not_yours" and out["status"] == 403
    assert out["shown"] == ["You may not do that."] and out["signed_out"] == 0
    # No detail at all: the page's own sentence, no reason.
    bare = _refused(403, {})
    assert bare["message"] == "Permission denied" and bare["reason"] is None and bare["signed_out"] == 0
    assert bare["shown"] == ["You do not have permission to perform this action."]
    # A structured detail without a message is no sentence: the page's own, with the reason it names.
    wordless = _refused(403, {"detail": {"reason": "password_proof_required"}})
    assert wordless["message"] == "Permission denied" and wordless["reason"] == "password_proof_required"


def test_a_401_with_a_structured_detail_about_a_password_is_its_sentence_with_its_reason():
    message = "Type your password to go on."
    out = _refused(401, {"detail": {"reason": "password_proof_required", "message": message}})
    assert out["settled"] == "rejected" and out["kind"] == "Error", out
    assert out["message"] == message and out["reason"] == "password_proof_required"
    assert out["signed_out"] == 0 and out["held"] is True


def test_a_401_with_any_other_structured_detail_ends_the_session_as_a_401_does_and_never_crashes():
    out = _refused(401, {"detail": {"reason": "ended", "message": "This sign-in was ended."}})
    assert out["settled"] == "rejected" and out["kind"] == "Error", out
    assert out["message"] == "Session expired. Please log in again."
    assert out["signed_out"] == 1 and out["held"] is False


def test_a_404_with_a_structured_detail_is_its_sentence_with_its_reason():
    """A route's own refusal answered 404 (a sign-in method that is turned off) names its reason inside the detail:
    the person reads its sentence, and a caller can tell it from a route the server does not have."""
    message = "This sign-in method is not available."
    out = _refused(404, {"detail": {"reason": "provider_disabled", "message": message}})
    assert out["settled"] == "rejected" and out["kind"] == "Error", out
    assert out["message"] == message and out["reason"] == "provider_disabled" and out["status"] == 404
    assert out["signed_out"] == 0 and out["held"] is True
    # A plain 404 is as before: its sentence, no reason; with no detail the page's own words.
    plain = _refused(404, {"detail": "Not Found"})
    assert plain["message"] == "Not Found" and plain["reason"] is None and plain["status"] == 404
    bare = _refused(404, {})
    assert bare["message"] == "Resource not found" and bare["reason"] is None and bare["status"] == 404
    beside = _refused(404, {"detail": "No such vault", "reason": "gone"})
    assert beside["message"] == "No such vault" and beside["reason"] == "gone"
