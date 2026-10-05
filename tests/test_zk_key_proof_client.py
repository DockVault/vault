"""The web app's side of the key proof, pinned in its source.

Every request that changes a zero-knowledge vault's keys -- a zero-knowledge create, a share, a rotation, the
name-index key -- goes through zkKeyProofRequest, which serializes the body once and proves and sends that
same string. What the browser tests (test_ui_zk_key_proof.py) cannot see is a request that does not exist yet:
a new call site sending one of these requests some other way would carry no proof, and the server would
refuse it (or, with enforcement off, take it unproved). These pins keep every such request inside the helper,
and pin the plumbing the helper depends on: apiRequest's status and reason on a 404 (how an older server is
told apart), the one unlock shared by concurrent callers, and the caches the lock empties.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

APP_JS = Path(__file__).resolve().parent.parent / "static" / "js" / "app.js"
APP = APP_JS.read_text(encoding="utf-8")

# A path to one of the guarded routes inside a template literal: /ecc/vaults/${...}/rekey` and so on.
_GUARDED_PATH = re.compile(r"/ecc/vaults/\$\{[^}]+\}/(rekey|members|index-key|key-proof)`")


def _function(name: str) -> str:
    """One top-level function of app.js, from its declaration to the next top-level declaration."""
    decl = re.search(r"^(async )?function " + re.escape(name) + r"\(", APP, re.M)
    assert decl, f"{name} is gone"
    assert len(re.findall(r"^(async )?function " + re.escape(name) + r"\(", APP, re.M)) == 1, name
    rest = APP[decl.end():]
    nxt = re.search(r"^(async )?function |^(const|let|var) |^// =====", rest, re.M)
    return APP[decl.start():decl.end() + (nxt.start() if nxt else len(rest))]


def _enclosing_call(src: str, at: int) -> str:
    """The name of the innermost call whose argument list contains offset `at`."""
    depth = 0
    for i in range(at, -1, -1):
        c = src[i]
        if c == ")":
            depth += 1
        elif c == "(":
            if depth == 0:
                m = re.search(r"([A-Za-z_$][\w$]*)\s*$", src[:i])
                return m.group(1) if m else ""
            depth -= 1
    return ""


def _guarded_sites(src: str):
    """(route, the call it is an argument of, whether it names a method) for every guarded path."""
    sites = []
    for m in _GUARDED_PATH.finditer(src):
        call = _enclosing_call(src, m.start())
        after = src[m.end():m.end() + 200]
        sites.append((m.group(1), call, "method:" in after.split(")")[0]))
    return sites


def test_every_request_that_changes_a_vaults_keys_goes_through_the_proving_helper():
    helper = _function("zkKeyProofRequest")
    sites = _guarded_sites(APP)
    assert {route for route, _, _ in sites} >= {"rekey", "members", "index-key", "key-proof"}
    for route, call, has_method in sites:
        if call == "apiRequest":
            # Reading the name-index key is the one plain request to these paths: a GET.
            assert route == "index-key" and not has_method, (route, call)
        else:
            assert call == "zkKeyProofRequest", (route, call)
    # A zero-knowledge create is proved; a standard one is an ordinary request, and only that.
    create = APP[APP.index("document.getElementById('create-vault-form').addEventListener('submit'"):]
    create = create[:create.index("\n});\n")]
    proved = create.index("zkKeyProofRequest(payload.id, 'create', {")
    plain = create.index("apiRequest('/vaults', {")
    assert create.count("apiRequest('/vaults'") == 1
    assert "const created = zkPendingDek\n            ? await zkKeyProofRequest(" in create
    assert proved < plain, "the create's ordinary request is not the standard-vault arm"
    # The helper itself sends the request, with the proof header, and nowhere else builds that header.
    assert helper.count("[ZK_KEY_PROOF_HEADER]: header") == 1
    assert APP.count("ZK_KEY_PROOF_HEADER]") == 1


def test_the_detector_sees_an_unproved_request():
    """Guards the guard: a guarded request sent with apiRequest is reported."""
    sneaky = "await apiRequest(`/ecc/vaults/${vaultId}/rekey`, { method: 'POST', body: '{}' });"
    assert _guarded_sites(sneaky) == [("rekey", "apiRequest", True)]
    ok = "await zkKeyProofRequest(vaultId, 'rekey', { method: 'POST', path: `/ecc/vaults/${vaultId}/rekey`, body });"
    assert [call for _, call, _ in _guarded_sites(ok)] == ["zkKeyProofRequest"]


def test_the_string_proved_is_the_string_sent():
    helper = _function("zkKeyProofRequest")
    assert helper.count("JSON.stringify(") == 1
    assert "const bodyString = JSON.stringify(opts.body);" in helper
    sends = re.findall(r"apiRequest\(opts\.path, \{[^}]*\}", helper)
    assert len(sends) == 2 and all("body: bodyString" in s for s in sends), sends
    proof = helper[helper.index("computeKeyProof({"):]
    assert "bodyString" in proof[:proof.index("}, {")]


def test_an_older_server_is_told_apart_by_a_404_without_a_reason():
    api = _function("apiRequest")
    branch = api[api.index("if (response.status === 404) {"):]
    branch = branch[:branch.index("\n        }\n")]
    assert "err.status = 404;" in branch and "err.reason =" in branch
    assert branch.index("err.status = 404;") < branch.index("throw err;")
    assert "throw new Error(" not in branch, "a 404 thrown without its status"
    challenge = _function("zkKeyProofChallenge")
    assert "if (e && e.status === 404 && !e.reason) return null;" in challenge
    # The other refusals carry their reason too, so the helper can act on it.
    assert api.count("err.reason = (data && typeof data.reason === 'string') ? data.reason : undefined;") == 3


def test_concurrent_callers_share_one_unlock():
    unlock = _function("zkEnsureUnlocked")
    assert "if (!_zkUnlockInFlight) {" in unlock
    assert "_zkUnlockInFlight = _zkUnlockOnce().finally(() => { _zkUnlockInFlight = null; });" in unlock
    assert "return _zkUnlockInFlight;" in unlock
    assert "showPrompt(" not in unlock and "showPrompt(" in _function("_zkUnlockOnce")


def test_locking_empties_the_proof_key_cache():
    reset = APP[APP.index("function zkResetKeys() {"):]
    reset = reset[:reset.index("\n")]
    assert "zkState.keyProofKeys = {};" in reset
    assert "keyProofKeys: {}" in APP[APP.index("const zkState = {"):][:200]


def test_removing_someone_is_never_held_up_by_the_proof():
    revoke = _function("revokeVaultPermission")
    fallback = revoke[revoke.index("await zkRekeyForRevoke(state.currentVault.id, userId);"):]
    fallback = fallback[:fallback.index("await apiRequest(`/vaults/${state.currentVault.id}/permissions/${userId}`")]
    assert "zkIsKeyProofRefusal(e) && await showConfirm(" in fallback
    assert "'Remove access now without rotating'" in fallback
    assert "rotate = false;" in fallback and "Access was NOT revoked" in fallback


def test_the_owner_is_offered_a_reset_when_the_key_check_will_not_open():
    rekey = _function("zkRekeyForRevoke")
    assert "e.reason === 'zk-key-proof-material-unusable'" in rekey
    assert "e.reason === 'zk-key-proof-verifier-unusable'" in rekey
    assert "damaged && !ownerReset && zkIsCurrentVaultOwner(vaultId)" in rekey
    assert "zkRekeyForRevoke(vaultId, revokedUserId, { ownerReset: true })" in rekey
    for name in ("zkRotateDirectForRevoke", "zkRotateTeamForRevoke"):
        fn = _function(name)
        assert "ownerReset ? 'owner_reset' : 'rekey'" in fn and "if (ownerReset) body.owner_reset = true;" in fn
