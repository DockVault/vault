"""RO2-3 Phase 1 — pure helpers behind GET /logs (log_pull.py). Security-critical: token
hashing, scope validation, per-service filtering, the enable gate, and redaction. Pure stdlib,
no app import, no running vault.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import log_pull  # noqa: E402


# ---- token mint / hash / match --------------------------------------------------------------

def test_mint_token_returns_plaintext_and_matching_prefix():
    plaintext, prefix = log_pull.mint_token()
    assert isinstance(plaintext, str) and len(plaintext) >= 32
    assert prefix == plaintext[:12]
    # Two mints differ (entropy).
    assert log_pull.mint_token()[0] != log_pull.mint_token()[0]


def test_hash_is_deterministic_and_pepper_dependent():
    t = "some-token-value"
    assert log_pull.hash_log_token(t, "pepperA") == log_pull.hash_log_token(t, "pepperA")
    assert log_pull.hash_log_token(t, "pepperA") != log_pull.hash_log_token(t, "pepperB")
    # 64 hex chars (SHA-256).
    assert len(log_pull.hash_log_token(t, "pepperA")) == 64


def test_tokens_match_is_correct_and_pepper_scoped():
    t = "abc123token"
    h = log_pull.hash_log_token(t, "pep-1234567890")
    assert log_pull.tokens_match(t, "pep-1234567890", h) is True
    assert log_pull.tokens_match("wrong", "pep-1234567890", h) is False
    # A truncation/prefix of the real token must NOT match (full-hash compare).
    assert log_pull.tokens_match(t[:-1], "pep-1234567890", h) is False
    # Right token, wrong pepper -> no match (a stolen DB hash without the pepper is useless).
    assert log_pull.tokens_match(t, "other-pepper", h) is False


# ---- scope validation (the substring-scope bug guard) ---------------------------------------

def test_validate_scope_keeps_known_dedupes_and_drops_junk():
    assert log_pull.validate_scope(["web", "sftp"]) == ["web", "sftp"]
    assert log_pull.validate_scope(["web", "web", "sftp"]) == ["web", "sftp"]  # de-dup
    assert log_pull.validate_scope(["web", "bogus", "db-diag"]) == ["web", "db-diag"]  # drop unknown
    assert log_pull.validate_scope([]) == []
    # A raw STRING scope (the substring-match footgun) is rejected, not treated as chars.
    assert log_pull.validate_scope("web") == []
    assert log_pull.validate_scope(None) == []
    assert log_pull.validate_scope(["", 5, {"x": 1}]) == []


# ---- two-layer enable gate ------------------------------------------------------------------

def test_pepper_ok_requires_32_chars():
    assert log_pull.pepper_ok("x" * 32) is True
    assert log_pull.pepper_ok("x" * 31) is False
    assert log_pull.pepper_ok("") is False
    assert log_pull.pepper_ok(None) is False
    assert log_pull.pepper_ok("   " + "x" * 31 + "   ") is False  # stripped before length check


def test_effective_ceiling_needs_plan_AND_strong_pepper():
    strong = "a" * 40
    # plan on + strong pepper -> ON
    assert log_pull.effective_ceiling(True, strong) is True
    # plan on but weak/absent pepper -> DISABLED (fail-safe, not bricked)
    assert log_pull.effective_ceiling(True, "") is False
    assert log_pull.effective_ceiling(True, "short") is False
    assert log_pull.effective_ceiling(True, None) is False
    # plan off -> off regardless of pepper
    assert log_pull.effective_ceiling(False, strong) is False


def test_is_pull_enabled_two_layer_and_fail_safe():
    # ceiling OFF -> always False, even if the flag is on.
    assert log_pull.is_pull_enabled(False, {"web": True}, "web") is False
    # ceiling ON, flag OFF / missing -> False (per-component default off).
    assert log_pull.is_pull_enabled(True, {}, "web") is False
    assert log_pull.is_pull_enabled(True, {"web": False}, "web") is False
    # ceiling ON, flag ON -> True.
    assert log_pull.is_pull_enabled(True, {"web": True}, "web") is True
    # unknown component / non-dict flags -> False.
    assert log_pull.is_pull_enabled(True, {"web": True}, "sftp") is False
    assert log_pull.is_pull_enabled(True, None, "web") is False


# ---- per-service filtering (anchored, no cross-contamination) --------------------------------

def test_filter_service_lines_keeps_only_that_service():
    lines = ["[web] up", "[sftp] listening", "[web] GET /health 200"]
    assert log_pull.filter_service_lines(lines, "web") == ["[web] up", "[web] GET /health 200"]
    assert log_pull.filter_service_lines(lines, "sftp") == ["[sftp] listening"]


def test_filter_service_lines_no_cross_contamination_from_body():
    # A tenant filename containing the other tag text must not leak across services.
    lines = ['[sftp] uploaded "report[web].pdf"', "[web] ok"]
    assert log_pull.filter_service_lines(lines, "web") == ["[web] ok"]
    assert log_pull.filter_service_lines(lines, "sftp") == ['[sftp] uploaded "report[web].pdf"']


def test_filter_service_lines_unknown_service_is_empty():
    lines = ["[web] up", "[sftp] listening"]
    assert log_pull.filter_service_lines(lines, "db") == []        # not a known component
    assert log_pull.filter_service_lines(lines, "") == []
    assert log_pull.filter_service_lines(lines, "db-diag") == []   # known but no such lines


def test_exotic_separator_in_content_does_not_smuggle_across_services():
    """The sink writer delimits records by '\\n' only, and api_server._read_sink_lines splits the
    sink on '\\n' only (NOT str.splitlines()). So a [sftp] record whose (tenant-influenced) content
    embeds a line/paragraph separator must NOT be re-split into a fragment served under
    ?service=web. This locks the intent of the splitlines()->split('\\n') fix."""
    content = "[sftp] uploaded  [web] SMUGGLED\n[web] legit\n"
    # what _read_sink_lines now does: split on '\n' only -> the [sftp] record stays whole.
    web_safe = log_pull.filter_service_lines(content.split("\n"), "web")
    assert web_safe == ["[web] legit"], web_safe
    assert "SMUGGLED" not in "\n".join(web_safe)
    # contrast: str.splitlines() (the old behavior) WOULD have smuggled the fragment.
    assert any("SMUGGLED" in ln for ln in log_pull.filter_service_lines(content.splitlines(), "web"))


# ---- redaction ------------------------------------------------------------------------------

def test_redaction_scrubs_known_secrets():
    secret = "SuperSecretSigningKey_ABCDEF"
    text = f"[web] config loaded key={secret} done"
    out = log_pull.redact_log_text(text, [secret])
    assert secret not in out and "«redacted»" in out


def test_redaction_empty_secret_does_not_corrupt():
    # A blank secret in the list must NOT trigger str.replace('', ...) inserting the placeholder
    # between every character.
    text = "[web] a normal line"
    out = log_pull.redact_log_text(text, ["", None, "x"])  # all below the len>=8 guard
    assert out == "[web] a normal line"


def test_redaction_scrubs_bearer_and_kv_and_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-DEF_123"
    text = ("[web] Authorization: Bearer sometoken-xyz\n"
            "[web] GET /x?token=leakyvalue123 password=hunter2secret\n"
            f"[web] issued {jwt}")
    out = log_pull.redact_log_text(text, [])
    assert "sometoken-xyz" not in out       # Bearer scrubbed
    assert "leakyvalue123" not in out       # token= scrubbed
    assert "hunter2secret" not in out       # password= scrubbed
    assert jwt not in out                   # JWT scrubbed
    assert "«redacted" in out


def test_redaction_scrubs_the_pull_token_if_it_echoes_in_a_bearer_line():
    # Feedback-leak guard: if the caller's own pull token lands in a [web] access-log line as a
    # Bearer header, redaction removes it before the response is served.
    pull_token, _ = log_pull.mint_token()
    text = f"[web] 127.0.0.1 - Authorization: Bearer {pull_token} GET /logs"
    out = log_pull.redact_log_text(text, [])
    assert pull_token not in out
