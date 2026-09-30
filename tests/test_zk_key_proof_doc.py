"""The public specification of the zero-knowledge key proof says what the code does.

``docs/design/vault-zk-key-proof-v1.md`` is what someone writing another client, or reading the advisory,
works from. These pin the facts in it that the code decides -- the labels and salts, the header, the
operation and mode bytes, the sealed key's header and bounds, the challenge's lifetime, cap and budget, the
refusal table, the audit actions and the switch -- so that changing one of them in the code without the
document fails here.
"""
import ast
import re
from pathlib import Path

import pytest

from app.core import audit_catalog
from app.services import zk_key_proof as kp

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "design" / "vault-zk-key-proof-v1.md"
DOC_PATH = "docs/design/vault-zk-key-proof-v1.md"


def _doc() -> str:
    return DOC.read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    """One section, from its heading to the next heading of the same or a higher level."""
    start = text.index(heading)
    level = len(heading) - len(heading.lstrip("#"))
    rest = text[start + len(heading):]
    m = re.search(r"\n#{1,%d} " % level, rest)
    return text[start:start + len(heading) + (m.start() if m else len(rest))]


def test_the_server_module_points_at_its_specification():
    assert DOC.is_file()
    assert DOC_PATH in (ROOT / "app" / "services" / "zk_key_proof.py").read_text(encoding="utf-8")


def test_the_labels_salts_and_header_are_the_codes():
    doc = _doc()
    js = (ROOT / "static" / "js" / "ecc_crypto.js").read_text(encoding="utf-8")
    for name in ("V2_INFO_KEY_PROOF_KEY", "V2_INFO_DEK_CHECK", "V2_INFO_KEY_LINEAGE", "KEY_PROOF_LABEL",
                 "KEY_PROOF_SALT"):
        value = re.search(r"this\.%s = '([^']+)';" % name, js).group(1)
        assert f'"{value}"' in doc, f"{name} ({value}) is not in the specification"
    salt = re.search(r"this\.V2_HKDF_SALT = new TextEncoder\(\)\.encode\('([^']+)'\)", js).group(1)
    assert f'"{salt}"' in doc
    assert f'"{kp.PROOF_LABEL.decode()}"' in doc and f'"{kp.PROOF_SALT.decode()}"' in doc
    for role in kp.ROLES:
        assert f'"{role}"' in doc
    transcript = _section(doc, "### 5.3 MACs and header")
    assert f"{kp.HEADER_NAME}: {kp.HEADER_VERSION}.<challenge id>.<mac_identity>.<mac_current or ->." \
           "<mac_new or ->" in transcript


def test_the_operation_and_mode_bytes_are_the_codes():
    block = _section(_doc(), "### 5.2 Transcript")
    ops = re.search(r"^op +1 byte: (.+)$", block, re.M).group(1)
    assert ops == ", ".join(f"0x{byte:02x} {op}" for op, byte in kp.OPS.items())
    modes = re.search(r"^mode +1 byte: (.+)$", block, re.M).group(1)
    assert modes == ", ".join(f"0x{byte:02x} {mode}" for mode, byte in kp.MODES.items())
    without = re.search(r"operation that proves no current key\n +\(([^)]+)\)", block).group(1)
    assert set(without.split(", ")) == set(kp.OPS_WITHOUT_CURRENT_KEY)


def test_the_sealed_key_header_and_bounds_are_the_codes():
    doc = _doc()
    magic = kp.SEALED_KEY_HEADER[:4].decode("ascii")
    rest = " ".join(f"0x{b:02x}" for b in kp.SEALED_KEY_HEADER[4:])
    assert f'header   = "{magic}" {rest}' in doc
    assert f"{kp.SEALED_KEY_MIN_BYTES}..{kp.SEALED_KEY_MAX_BYTES} bytes" in doc


def test_the_challenges_lifetime_cap_and_budget_are_the_codes():
    doc = _doc()
    router = (ROOT / "app" / "api" / "ecc_router.py").read_text(encoding="utf-8")
    cap = int(re.search(r"^_KEY_PROOF_MAX_LIVE_CHALLENGES = (\d+)", router, re.M).group(1))
    per, window = map(int, re.search(r'"key_proof_challenge": \((\d+), (\d+)\)', router).groups())
    assert window == 60
    assert f"a challenge lives {kp.CHALLENGE_TTL_SECONDS} seconds" in doc
    assert f"Up to {cap} live challenges per account" in doc and f"Issuing the {cap + 1}" in doc
    assert f"{per} per minute per account" in doc


def test_the_refusal_table_is_the_codes():
    table = _section(_doc(), "### 5.7 Refusal contract")
    rows = {}
    for line in table.splitlines():
        m = re.fullmatch(r"\| (\d{3}) \| .+ \| (.+) \| `([a-z-]+)` \|", line)
        if m:
            rows.setdefault(m.group(3), []).append((int(m.group(1)), m.group(2)))
    assert set(rows) == set(kp.REFUSALS)
    for slug, (status, sentence) in kp.REFUSALS.items():
        (doc_status, doc_detail), = rows[slug]
        assert doc_status == status, slug
        if slug != "zk-key-proof-malformed":          # the only refusal with a specific sentence
            assert doc_detail == f'"{sentence}"', slug
    for word in kp.FORBIDDEN_IN_REFUSALS:
        assert word in table.lower(), f"the forbidden word {word!r} is not named"


def test_the_audit_actions_and_their_levels_are_the_catalogs():
    table = _section(_doc(), "### 6.3 Audit")
    documented = dict(re.findall(r"^\| `(zk_[a-z_]+)` \| (\w+) \|", table, re.M))
    catalogued = {a.name: a.severity for a in audit_catalog.ACTIONS
                  if a.name.startswith(("zk_key_proof_", "zk_envelope_"))
                  or a.name in ("zk_owner_key_reset", "zk_key_check_mismatch")}
    assert documented == catalogued
    for action in ("zk_vault_rekeyed", "zk_member_key_granted", "zk_index_key_wrapped"):
        assert f"`{action}`" in table and audit_catalog.lookup(action) is not None


def test_the_switch_is_documented_as_the_code_ships_it():
    doc = _doc()
    config = (ROOT / "app" / "core" / "config.py").read_text(encoding="utf-8")
    assert "zk_key_proof_enforce: bool = Field(default=True)" in config
    assert "`ZK_KEY_PROOF_ENFORCE` in `.env`, **default `true`**" in doc
    assert "ZK_KEY_PROOF_ENFORCE=true" in (ROOT / ".env.example").read_text(encoding="utf-8")


def test_every_file_the_specification_names_exists_and_it_names_no_line():
    """The document names files, never lines: a line number drifts with the next change to the file."""
    doc = _doc()
    named = set(re.findall(r"`((?:app|static|tests|docs|\.github)/[A-Za-z0-9_./-]+)`", doc))
    assert len(named) >= 20, "the file references were not found"
    missing = sorted(path for path in named if not (ROOT / path).exists())
    assert not missing, missing
    assert not re.search(r"\.(?:py|js|md|yml):\d", doc), "the specification points at a line"


def test_the_security_policy_and_the_readme_tell_operators_what_the_proof_needs():
    """What an operator must know without reading the specification: the switch and what turning it off
    does, what older clients lose, that a proxy must pass the header and the body unchanged, and which
    audit entries to check for changes made before the upgrade."""
    policy = _section((ROOT / ".github" / "SECURITY.md").read_text(encoding="utf-8"),
                      "## Zero-knowledge key changes need proof of the key")
    assert f"]({'../' + DOC_PATH})" in policy
    assert "**`ZK_KEY_PROOF_ENFORCE`** (`.env` only, default `true`)" in policy
    assert "reopens the problem" in policy and "Rolling back below 0.33.2 has the same" in policy
    assert "cannot remove a\n  member from one (removal rotates the key first)" in policy
    assert f"`{kp.HEADER_NAME}` request header and the request body on\n  unchanged" in policy
    for action in ("zk_key_proof_absent", "zk_vault_rekeyed", "zk_member_key_granted", "zk_index_key_wrapped"):
        assert f"`{action}`" in policy and audit_catalog.lookup(action) is not None, action
    checklist = _section((ROOT / "README.md").read_text(encoding="utf-8"), "## Production checklist")
    assert f"forward the `{kp.HEADER_NAME}` request header and\n  the request body as they are" in checklist


def test_both_documents_name_every_audit_entry_a_key_change_before_the_upgrade_left():
    """What an operator checks for key changes made through a taken-over account before 0.33.2: the entries
    the four operations wrote. A rotation and a share have always been recorded; a zero-knowledge create is
    recorded as the vault's creation, like any other; setting a name-index key only from 0.33.0."""
    policy = _section((ROOT / ".github" / "SECURITY.md").read_text(encoding="utf-8"),
                      "## Zero-knowledge key changes need proof of the key")
    spec = _section(_doc(), "### 2.3 What this does not remove")
    for bullet in (policy[policy.index("- **Keys changed before the upgrade.**"):],
                   spec[spec.index("- **History.**"):]):
        flat = " ".join(bullet.split())
        for action in ("zk_vault_rekeyed", "zk_member_key_granted", "vault_created", "zk_index_key_wrapped"):
            assert f"`{action}`" in flat and audit_catalog.lookup(action) is not None, action
        assert "`vault_created` for a zero-knowledge vault made by that member's account" in flat
        assert "do not upload to a zero-knowledge vault its owner did not create" in flat
        assert "`zk_index_key_wrapped`, only from 0.33.0; before that it left no entry" in flat
    # The create route records every vault it makes, a zero-knowledge one included, as vault_created.
    source = (ROOT / "app" / "services" / "audit_logger.py").read_text(encoding="utf-8")
    logger = source[source.index("    def log_vault_created("):source.index("    def log_vault_updated(")]
    assert 'action="vault_created"' in logger
    server = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert server.count("audit_logger.log_vault_created(") == 1
    assert "\n    audit_logger.log_vault_created(" in server, "the create no longer records every vault it makes"
    create = server[server.index("zk_hierarchical = (vault_create.key_wrapping_mode == 'hierarchical')"):]
    create = create[:create.index("audit_logger.log_vault_created(")]
    assert "\n    if vault_type == 'zero_knowledge':" in create and not re.search(r"\n +return\b", create)
    # ... as a statement of its own in the create's body, so no condition can decide whether it runs.
    calls = [(func, node) for func in ast.walk(ast.parse(server))
             if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(func)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
             and node.func.attr == "log_vault_created"]
    assert len({id(node) for _, node in calls}) == 1, "the vault_created call is not the only one"
    func, call = calls[-1]
    assert any(isinstance(stmt, ast.Expr) and stmt.value is call for stmt in func.body), \
        "the create's vault_created entry is no longer a plain statement of the create"


# ------------------------------------------------------------------------------------ what 0.34.0 added

def test_the_member_checks_section_is_the_codes():
    from app.api import ecc_router
    section = _section(_doc(), "## 11. What members check (0.34.0)")
    report = _section(section, "### 11.3 The report")
    findings = re.search(r'"finding": ([^}]+)\}', report).group(1)
    assert re.findall(r'"([a-z_]+)"', findings) == list(ecc_router.KEY_CHECK_FINDINGS)
    assert "`POST /ecc/vaults/{id}/key-proof/report`" in report and "once a day for each vault" in report
    states = _section(section, "### 11.2 When a vault is opened")
    js = (ROOT / "static" / "js" / "zk_key_checks.js").read_text(encoding="utf-8")
    shown = {"verified": "verified", "not-verifiable": "not verifiable", "reset-by-owner": "reset by the owner",
             "failed": "failed", "first": "first"}
    for const in ("LINEAGE_VERIFIED", "LINEAGE_UNVERIFIABLE", "LINEAGE_RESET", "LINEAGE_FAILED", "LINEAGE_FIRST"):
        value = re.search(r"const %s = '([a-z-]+)';" % const, js).group(1)
        assert f"| {shown[value]} |" in states, value
    assert "`unwrapTeamPrivateKeyWithCheck`" in section and "**Only a positive mismatch blocks.**" in section


def test_the_notices_section_is_the_codes():
    from datetime import timedelta
    from app.core import email_actions
    from app.services import zk_notices
    section = _section(_doc(), "## 12. Who is told (0.34.0)")
    assert zk_notices.FAILED_PROOF_EVERY == timedelta(hours=1) and "at most once an hour" in section
    assert email_actions.SPEC_BY_KEY[zk_notices.EMAIL_ACTION]["name"] == "Encryption key notice"
    assert '"Encryption key notice"' in section and "once a day for each vault" in section


def test_the_passphrase_section_is_the_codes():
    from app.core import envelope_hold
    from app.core.config import Settings
    section = _section(_doc(), "## 13. The passphrase and its envelope (0.34.0)")
    js = (ROOT / "static" / "js" / "zk_passphrase.js").read_text(encoding="utf-8")
    minimum = int(re.search(r"const MIN_LENGTH = (\d+);", js).group(1))
    assert f"must be at least {minimum} characters" in section
    assert Settings.model_fields["zk_envelope_hold_days"].default == 14 == envelope_hold.MAX_DAYS
    assert "`ZK_ENVELOPE_HOLD_DAYS` days (in `.env` only, default 14, 0 turns it off, at most 14)" in section
    assert f"(it lives {envelope_hold.CODE_TTL_MINUTES} minutes" in section
    router = (ROOT / "app" / "api" / "ecc_router.py").read_text(encoding="utf-8")
    for route in ("/keys/private/hold/code", "/keys/private/hold/release"):
        assert f'@router.post("{route}")' in router and f"`POST /ecc{route}`" in section
    assert "`python dockvault.py accounts --action" in section and "release-key-hold`" in section


# What a public document must not carry: a work-item or decision label (capitals then a number, such as
# "AB12", "AB-1" or "X-Y3"; the format names the document uses are allowed), a path on someone's machine,
# or a commit trailer.
_PRIVATE = (r"\b(?!(?:V2|DVZ2|UTF-8)\b)[A-Z]{1,3}-?[0-9]{1,2}[a-z]?\b",
            r"\b[A-Z]-[A-Z]{1,3}[0-9]", r"(?i)\b[a-z]:[\\/]", r"(?:^|[\s(`])/tmp/", r"(?i)co-authored-by")


def test_the_public_documents_name_nothing_private():
    policy = _section((ROOT / ".github" / "SECURITY.md").read_text(encoding="utf-8"),
                      "## Zero-knowledge key changes need proof of the key")
    for name, text in (("specification", _doc()), ("SECURITY.md", policy)):
        for pattern in _PRIVATE:
            hit = re.search(pattern, text)
            assert not hit, (name, pattern, text[max(0, hit.start() - 40):hit.end() + 40])


def test_the_leak_check_sees_a_leak():
    """Guards the guard."""
    for sample in ("as QX4 says", "see K-QW2", "item W-12", "C:\\work\\notes", "in /tmp/scratch",
                   "Co-Authored-By: someone"):
        assert any(re.search(pattern, sample) for pattern in _PRIVATE), sample
