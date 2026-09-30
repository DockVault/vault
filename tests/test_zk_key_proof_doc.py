"""The public specification of the zero-knowledge key proof says what the code does.

``docs/design/vault-zk-key-proof-v1.md`` is what someone writing another client, or reading the advisory,
works from. These pin the facts in it that the code decides -- the labels and salts, the header, the
operation and mode bytes, the sealed key's header and bounds, the challenge's lifetime, cap and budget, the
refusal table, the audit actions and the switch -- so that changing one of them in the code without the
document fails here.
"""
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
                  if a.name.startswith("zk_key_proof_") or a.name == "zk_owner_key_reset"}
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
