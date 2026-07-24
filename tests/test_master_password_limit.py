"""bcrypt's 72-byte input limit on the master password.

bcrypt hashes at most the first 72 BYTES of its input. bcrypt < 5.0 dropped the excess
silently; bcrypt >= 5.0 raises ValueError instead. Two consequences the code has to handle,
both covered here:

* Verification (app/core/startup_security.py) must CLAMP, not reject. A hash written by the
  old library encodes only the first 72 bytes, so feeding it the full password under the new
  library raises -> the except returns False -> "Failed to unlock credentials. Server cannot
  start." on a correct password, with no route back in.
* Setup (scripts/setup_master_password.py) must REJECT, not truncate. Silently dropping the
  tail lets an operator believe a 100-character passphrase is protecting them when only the
  first 72 bytes are.

The limit is BYTES, not characters — UTF-8 spends 2 on Greek/accented letters and up to 4 on
emoji — so the byte/character distinction is asserted explicitly.

Pure helpers: no running vault, no network. The module's ``unit`` marker bypasses the live-stack
guard, which matters more here than elsewhere: the running stack never calls verify_password (a
plain-env deployment sets no MASTER_PASSWORD_HASH, so check_legacy_mode() short-circuits), so
this file is the only coverage of the clamp and must run with the stack down.
"""
import importlib.util
import os
import sys

import bcrypt
import pytest

pytestmark = pytest.mark.unit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.startup_security import (  # noqa: E402
    BCRYPT_MAX_PASSWORD_BYTES,
    CredentialManager,
    bcrypt_password_bytes,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 21 chars / 21 bytes, and strong enough to clear the setup script's strength check
# (upper + lower + digit + symbol) so the prompt never falls through to input().
GOOD_PASSWORD = "Correct-Horse-Batt9!!"



_SETUP_MODULE = None


def _load_setup_script():
    """Import scripts/setup_master_password.py by path (there is no scripts/ package).

    Cached: the script runs `sys.path.insert(0, repo_root)` at import, so re-executing it once
    per test would pile duplicate entries onto sys.path for the rest of the session.
    """
    global _SETUP_MODULE
    if _SETUP_MODULE is None:
        path = os.path.join(REPO_ROOT, "scripts", "setup_master_password.py")
        spec = importlib.util.spec_from_file_location("_setup_master_password", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _SETUP_MODULE = module
    return _SETUP_MODULE


# ---- the clamp helper ------------------------------------------------------------------------

def test_short_password_is_passed_through_unchanged():
    assert bcrypt_password_bytes(GOOD_PASSWORD) == GOOD_PASSWORD.encode("utf-8")


def test_long_password_is_clamped_to_the_byte_limit():
    password = "a" * 200
    clamped = bcrypt_password_bytes(password)
    assert len(clamped) == BCRYPT_MAX_PASSWORD_BYTES
    assert clamped == password.encode("utf-8")[:BCRYPT_MAX_PASSWORD_BYTES]


def test_limit_counts_bytes_not_characters():
    """A Greek passphrase well under 72 CHARACTERS is already over 72 BYTES."""
    password = "Κωδικός" * 8          # 56 characters, 2 bytes per Greek letter
    assert len(password) < BCRYPT_MAX_PASSWORD_BYTES          # under the limit by characters
    assert len(password.encode("utf-8")) > BCRYPT_MAX_PASSWORD_BYTES   # over it by bytes
    assert len(bcrypt_password_bytes(password)) == BCRYPT_MAX_PASSWORD_BYTES


# ---- verification: clamp, so old hashes keep working -----------------------------------------

def test_over_limit_password_verifies_against_a_legacy_hash(monkeypatch):
    """THE regression: a hash written by bcrypt < 5.0 must still verify.

    Without the clamp, bcrypt >= 5.0 raises on the full password, verify_password's except
    swallows it, and a correct master password reads as wrong -> the container refuses to boot.
    """
    password = GOOD_PASSWORD * 6                              # 126 chars, comfortably over 72 bytes
    assert len(password.encode("utf-8")) > BCRYPT_MAX_PASSWORD_BYTES
    # Exactly what bcrypt < 5.0 stored: a hash over the first 72 bytes only.
    legacy_hash = bcrypt.hashpw(
        password.encode("utf-8")[:BCRYPT_MAX_PASSWORD_BYTES], bcrypt.gensalt()
    ).decode()

    monkeypatch.setenv("MASTER_PASSWORD_HASH", legacy_hash)
    assert CredentialManager().verify_password(password) is True


def test_wrong_password_still_fails(monkeypatch):
    """Non-vacuity guard: the clamp must not turn verify_password into 'always true'."""
    stored = bcrypt.hashpw(bcrypt_password_bytes(GOOD_PASSWORD), bcrypt.gensalt()).decode()
    monkeypatch.setenv("MASTER_PASSWORD_HASH", stored)
    assert CredentialManager().verify_password(GOOD_PASSWORD) is True
    assert CredentialManager().verify_password("not-the-master-password-at-all") is False


def test_two_passwords_sharing_a_72_byte_prefix_both_verify(monkeypatch):
    """Documents the real cost of the limit, so it is a decision and not a surprise.

    bcrypt cannot distinguish inputs that agree on their first 72 bytes. This is why setup
    rejects over-limit passwords rather than truncating them.
    """
    base = "z" * BCRYPT_MAX_PASSWORD_BYTES
    stored = bcrypt.hashpw(bcrypt_password_bytes(base), bcrypt.gensalt()).decode()
    monkeypatch.setenv("MASTER_PASSWORD_HASH", stored)
    assert CredentialManager().verify_password(base + "-different-tail") is True


def test_missing_hash_returns_false(monkeypatch):
    monkeypatch.delenv("MASTER_PASSWORD_HASH", raising=False)
    assert CredentialManager().verify_password(GOOD_PASSWORD) is False


# ---- setup: reject, so a new password is never silently weakened ------------------------------

def _answer_prompts_with(monkeypatch, setup, answers):
    """Feed getpass() a fixed sequence. monkeypatch restores it — `setup.getpass` is the real
    stdlib module, so a bare assignment would leak the stub into every later test.

    Running past the end of the sequence means the prompt looped more times than the test
    expected, i.e. the validation under test rejected something it should have accepted. Raise a
    named failure rather than letting a bare StopIteration surface, which reads like a broken
    test rather than the regression it actually is.
    """
    supply = iter(answers)

    def _next_answer(*_args, **_kwargs):
        try:
            return next(supply)
        except StopIteration:
            raise AssertionError(
                f"the prompt asked for more input than the {len(answers)} answers supplied — "
                "it rejected a password it should have accepted"
            ) from None

    monkeypatch.setattr(setup.getpass, "getpass", _next_answer)


def test_setup_prompt_rejects_an_over_limit_password(monkeypatch, capsys):
    """The prompt loops on an over-limit password and explains the limit in bytes."""
    setup = _load_setup_script()
    over_limit = "Κωδικός" * 8        # 56 characters but 112 bytes -> must be refused
    assert len(over_limit.encode("utf-8")) == 112
    _answer_prompts_with(monkeypatch, setup, [over_limit, GOOD_PASSWORD, GOOD_PASSWORD])

    assert setup.get_master_password() == GOOD_PASSWORD

    out = capsys.readouterr().out
    assert "112 bytes" in out                     # the actual measured size, not a generic error
    assert f"maximum is {BCRYPT_MAX_PASSWORD_BYTES} bytes" in out
    assert "BYTES, not characters" in out         # the trap that catches non-ASCII passphrases


def test_setup_prompt_still_rejects_a_short_password(monkeypatch, capsys):
    """Non-vacuity guard: the new check did not displace the existing minimum-length one."""
    setup = _load_setup_script()
    _answer_prompts_with(monkeypatch, setup, ["short", GOOD_PASSWORD, GOOD_PASSWORD])

    assert setup.get_master_password() == GOOD_PASSWORD
    assert "at least 16 characters" in capsys.readouterr().out


def test_setup_hash_is_verifiable_by_the_runtime(monkeypatch):
    """End to end: a hash the setup script writes must verify through the runtime checker."""
    setup = _load_setup_script()
    _content, _salt, password_hash = setup.create_secure_env(
        GOOD_PASSWORD, {"ENCRYPTION_KEY": "some-value"}
    )

    monkeypatch.setenv("MASTER_PASSWORD_HASH", password_hash)
    assert CredentialManager().verify_password(GOOD_PASSWORD) is True
    assert CredentialManager().verify_password(GOOD_PASSWORD + "x") is False


def test_setup_hashes_an_over_limit_password_without_raising(monkeypatch):
    """create_secure_env must clamp too, not just the interactive prompt.

    The prompt is the only caller today, so its rejection makes this path unreachable in normal
    use — which is exactly why an unclamped hashpw() here would go unnoticed until someone drove
    create_secure_env() directly and got a bare ValueError from bcrypt >= 5.0 instead of a
    usable .env.secure. GOOD_PASSWORD alone cannot catch that: it is under the limit, so clamped
    and unclamped are identical.
    """
    setup = _load_setup_script()
    over_limit = GOOD_PASSWORD * 6                            # 126 chars, over 72 bytes
    assert len(over_limit.encode("utf-8")) > BCRYPT_MAX_PASSWORD_BYTES

    _content, _salt, password_hash = setup.create_secure_env(
        over_limit, {"ENCRYPTION_KEY": "some-value"}
    )
    monkeypatch.setenv("MASTER_PASSWORD_HASH", password_hash)
    assert CredentialManager().verify_password(over_limit) is True


def test_bcrypt_raises_on_over_limit_input_without_the_clamp():
    """Pins WHY the clamp exists: raw bcrypt refuses over-limit input on the installed version.

    Skips on bcrypt < 5.0, where the old silent-truncation behaviour is still in effect — so
    this test starts asserting for real the moment the dependency upgrade lands.
    """
    major = int(bcrypt.__version__.split(".")[0])
    if major < 5:
        pytest.skip(f"bcrypt {bcrypt.__version__} still truncates silently; clamp is a no-op")
    with pytest.raises(ValueError):
        bcrypt.hashpw(("x" * 200).encode("utf-8"), bcrypt.gensalt())
