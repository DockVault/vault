"""The web app's member-side checks of a zero-knowledge key, pinned in its source.

What the checks conclude is tested on real keys in test_zk_key_checks.py; what the browser shows is tested
in test_ui_zk_member_checks.py. What neither can see is a write that does not ask: a new place that encrypts
under a vault's key with a key it fetched some other way would write with a key nobody checked. These pins
keep every encryption under a vault's key behind zkGetWriteDek, and pin the plumbing the checks rely on.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")

# The calls that encrypt under a key (the name blind index is a MAC, not an encryption, and never
# decides what a member can read).
_ENCRYPT = re.compile(r"\b(encryptName|encryptFile|startContentV2Encryption|resumeContentV2Encryption)\(")
_DECL = re.compile(r"^(?:async )?function [A-Za-z_$][\w$]*\(|^    (?:async )?_?[A-Za-z_$][\w$]*\([^)]*\) \{$", re.M)


def _function(name: str) -> str:
    decl = re.search(r"^(async )?function " + re.escape(name) + r"\(", APP, re.M)
    assert decl, f"{name} is gone"
    rest = APP[decl.end():]
    nxt = re.search(r"^(async )?function |^(const|let|var) |^// =====", rest, re.M)
    return APP[decl.start():decl.end() + (nxt.start() if nxt else len(rest))]


def _enclosing_start(at: int) -> int:
    """Where the function or method around offset `at` is declared."""
    starts = [m.start() for m in _DECL.finditer(APP, 0, at)]
    assert starts, at
    return starts[-1]


def test_every_encryption_under_a_vaults_key_takes_its_key_from_the_checked_path():
    offenders = []
    for m in _ENCRYPT.finditer(APP):
        line_start = APP.rindex("\n", 0, m.start()) + 1
        line = APP[line_start:APP.index("\n", m.start())]
        if line.lstrip().startswith(("//", "*")) or re.search(r"^\s*async \w+\(", line):
            continue                                  # a comment, or the crypto module's own definition
        before = APP[_enclosing_start(m.start()):m.start()]
        if "zkGetWriteDek(" in before or "generateVaultDEK()" in before:
            continue
        offenders.append(line.strip())
    assert not offenders, "encrypted with a key that was not checked:\n  " + "\n  ".join(offenders)
    assert APP.count("await zkGetWriteDek(") == 8


def test_the_detector_sees_an_unchecked_write():
    """Guards the guard: the same write with the key fetched directly is reported."""
    global APP
    saved = APP
    try:
        APP = saved.replace("const dek = await zkGetWriteDek(vid, epoch);\n                const lib = eccLib();\n"
                            "                // Client-generate the folder id",
                            "const dek = await zkGetVaultDek(vid, epoch);\n                const lib = eccLib();\n"
                            "                // Client-generate the folder id", 1)
        assert APP != saved
        with pytest.raises(AssertionError, match="encrypted with a key that was not checked"):
            test_every_encryption_under_a_vaults_key_takes_its_key_from_the_checked_path()
    finally:
        APP = saved


def test_a_mismatch_blocks_and_everything_else_writes():
    write = _function("zkGetWriteDek")
    assert "if (verdict.verdict === ZkKeyChecks.WRITE_MISMATCH) {" in write
    assert write.count("throw ") == 1 and "err.zkKeyMismatch = true;" in write
    # A check that cannot run never blocks.
    assert "verdict = { verdict: ZkKeyChecks.WRITE_UNCHECKED };   // a check that cannot run never blocks" in write
    verdict = _function("zkWriteKeyVerdict")
    assert "} catch (_) { /* not verifiable */ }" in verdict
    # The refusal reaches the person, where the write sites used to say only "encryption failed".
    assert APP.count("showError(zkWriteFailureMessage(e));") == 3
    assert "if (e && e.zkKeyMismatch) return e.message;" in _function("zkWriteFailureMessage")


def test_the_team_key_is_compared_only_at_the_current_epoch_as_it_is_unwrapped():
    dek = _function("zkGetVaultDek")
    assert "version === keys.current_dek_version ? keys.team_public_key : null, noPrompt);" in dek
    team = _function("zkGetTeamPrivKey")
    assert "unwrapTeamPrivateKeyWithCheck(" in team
    # Three answers kept as they came, by the module's own mapping (tests/js/zk_key_checks.js runs it on real keys):
    # a comparison that could not run (null) is not recorded as a mismatch. It is the one place the answer is
    # recorded, and nothing after it changes what was recorded; test_ui_zk_member_checks.py has a team vault whose
    # stored public key cannot be read still taking an upload.
    assert team.count("compared[teamEpoch] = { pem, matches: ZkKeyChecks.teamKeyAnswer(out.matchesPublic) };") == 1
    assert team.count("compared[teamEpoch] =") == 1 and team.count("out.matchesPublic") == 1
    assert ".matches =" not in team and "matchesPublic === true }" not in team


def test_the_checks_run_on_open_and_never_ask_for_the_passphrase():
    check = _function("zkCheckVaultKey")
    assert "if (!vault || !isZkVault(vault) || !zkKeyUnlocked()) return null;" in check
    assert "zkEnsureUnlocked(" not in check and "showPrompt(" not in check
    # Nor when the key is locked while the check runs: each key it unwraps comes with the key held now, or ends it.
    assert re.findall(r"zkGetVaultDek\(([^)]*)\)", check) == ["vid, epoch, { noPrompt: true }",
                                                              "vid, epoch - 1, { noPrompt: true }"]
    held = _function("zkHeldPrivateKey")
    assert "throw new Error(" in held and "zkEnsureUnlocked(" not in held and "showPrompt(" not in held
    dek = _function("zkGetVaultDek")
    assert dek.count("const priv = noPrompt ? zkHeldPrivateKey() : await zkEnsureUnlocked();") == 1
    assert dek.count("zkEnsureUnlocked(") == 1
    assert "version === keys.current_dek_version ? keys.team_public_key : null, noPrompt);" in dek
    team = _function("zkGetTeamPrivKey")
    assert team.count("const priv = noPrompt ? zkHeldPrivateKey() : await zkEnsureUnlocked();") == 1
    assert team.count("zkEnsureUnlocked(") == 1
    open_vault = _function("openVault")
    assert open_vault.index("refreshZkRekeyNotice();") < open_vault.index("refreshZkKeyChecks();")
    assert "refreshZkKeyChecks();" in _function("loadVaultInfo")
    for fn in ("zkUnlockAllVaults", "zkLockAllVaults", "revokeVaultPermission", "refreshZkRekeyNotice"):
        assert "refreshZkKeyChecks();" in _function(fn), fn


def test_each_finding_is_reported_once_a_session_and_the_caches_go_with_the_keys():
    report = _function("zkReportKeyFinding")
    assert "if (reported[key]) return;" in report and "/key-proof/report`" in report
    reset = APP[APP.index("function zkResetKeys() {"):]
    reset = reset[:reset.index("\n")]
    assert "zkState.keyChecks = {};" in reset and "zkState.teamKeyMatches = {};" in reset


def test_the_owner_reset_is_offered_to_the_owner_only():
    details = _function("zkRenderKeyDetails")
    assert "if (zkIsCurrentVaultOwner(vault.id)) {" in details
    reset = _function("zkOwnerResetFromDetails")
    assert "if (!vault || !zkIsCurrentVaultOwner(vault.id)) return;" in reset
    assert "await zkRekeyForRevoke(vault.id, remove, { ownerReset: true });" in reset


def test_the_key_details_and_warning_are_built_as_text():
    for fn in ("zkRenderKeyDetails", "refreshZkKeyChecks", "showGrantRecipientKey"):
        body = _function(fn)
        assert "innerHTML" not in body and "textContent" in body, fn
