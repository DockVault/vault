"""The key-proof challenge route: what it checks, in what order, and how it stores its one-time key.

Offline. The ordering is the security property in several places -- a refused temporary credential never
spends its owner's budget, issuance is serialized so the cap holds, the one-time key is sealed before it
is stored -- so it is pinned from the source, in the house shape (each anchor exactly once, the body
sliced at the next top-level definition). tests/test_zk_key_proof_challenge_live.py drives the route.
"""
import re
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import ecc_router  # noqa: E402
from app.core import security  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
ROUTER = (ROOT / "app" / "api" / "ecc_router.py").read_text(encoding="utf-8")
SERVER = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")


def _body(src: str, anchor: str) -> str:
    assert src.count(anchor) == 1, anchor
    start = src.index(anchor)
    m = re.search(r"\n(?:@|def |async def |class )", src[start + len(anchor):])
    return src[start:start + len(anchor) + m.start()] if m else src[start:]


ROUTE = _body(ROUTER, "async def key_proof_challenge(")


def test_the_route_is_where_the_protocol_puts_it():
    i = ROUTER.index("async def key_proof_challenge(")
    assert '@router.post("/vaults/{vault_id}/key-proof/challenge")' in ROUTER[i - 200:i]


def test_a_malformed_operation_and_a_refused_temporary_credential_cost_no_budget():
    """A temporary session is the owner's own row, and the limiter keys on the user id: charging a
    refused request would let a leaked credential hold the owner out of this route."""
    charge = ROUTE.index('_ecc_rate_limit(current_user, "key_proof_challenge")')
    assert ROUTE.count("_ecc_rate_limit(") == 1
    assert ROUTE.index("if op not in zk_key_proof.OPS:") < charge
    assert ROUTE.index('KeyProofRefusal("zk-key-proof-interactive-only")') < charge
    assert '"key_proof_challenge": (400, 60),' in ROUTER


def test_every_gate_precedes_issuance():
    issue = ROUTE.index("ZkKeyProofChallenge(\n")
    for gate in ("_reaches_vault(db, vault, current_user.id)", "may_release_vault_key(db, current_user, vault)",
                 "enforce_vault(current_user, str(vid))",
                 'check_endpoint_permission(db, current_user, "VAULT_PERMISSIONS"',
                 "_can_manage_vault(db, vault, current_user)", "_holds_current_key(db, vault, current_user.id)",
                 'check_endpoint_permission(db, current_user, "VAULT_CREATE")',
                 '_check_create_vault_type(db, current_user, "zero_knowledge")',
                 "_require_vault_id_unused(db, vid)"):
        assert ROUTE.count(gate) == 1, gate
        assert ROUTE.index(gate) < issue, gate


def test_issuance_is_serialized_on_the_account_row_and_applies_the_cap():
    lock = ROUTE.index("db.query(User).filter(User.id == current_user.id).with_for_update().first()")
    assert lock < ROUTE.index(".delete(synchronize_session=False)") < ROUTE.index("ZkKeyProofChallenge(\n")
    assert ecc_router._KEY_PROOF_MAX_LIVE_CHALLENGES == 32
    assert "excess = len(live) - (_KEY_PROOF_MAX_LIVE_CHALLENGES - 1)" in ROUTE
    assert "order_by(ZkKeyProofChallenge.created_at.asc()" in ROUTE, "the oldest goes first"


def test_the_one_time_key_is_stored_sealed_and_only_the_strict_decrypt_opens_it():
    assert ROUTE.count("server_private_key_sealed=encrypt_secret(server_private_pem)") == 1
    assert "server_private_key=" not in ROUTE
    helper = _body(ROUTER, "def _unseal_challenge_key(")
    assert "decrypt_secret_strict(" in helper and "decrypt_secret(" not in helper.replace("decrypt_secret_strict(", "")


def test_a_planted_plaintext_key_does_not_unseal(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(security, "_runtime_settings", lambda: type("S", (), {"encryption_key": key})())
    pem = "-----BEGIN PRIVATE KEY-----\nMIG2AgEA\n-----END PRIVATE KEY-----\n"
    assert ecc_router._unseal_challenge_key(security.encrypt_secret(pem)) == pem
    with pytest.raises(ValueError):
        ecc_router._unseal_challenge_key(pem)


def test_one_reachability_check_serves_every_key_route():
    """Three routes answer a stranger the same 403 whether or not the vault exists. One helper, so they
    cannot drift apart."""
    assert "_reaches_vault = " not in ROUTER, "an inline copy of the reachability check is back"
    for anchor in ("async def get_vault_keys(", "async def get_vault_index_key(", "async def key_proof_challenge("):
        assert _body(ROUTER, anchor).count("_reaches_vault(db, vault, current_user.id)") == 1, anchor


def test_create_uses_the_same_checks_as_creating_a_vault():
    create = _body(SERVER, "async def create_vault(")
    assert create.count("_check_create_vault_type(db, current_user, vault_create.type)") == 1
    assert create.count("_require_vault_id_unused(db, vault_create.id)") == 1
    assert "RetiredObjectId.id ==" not in create, "an inline copy of the id check is back"
    helper = _body(SERVER, "def _check_create_vault_type(")
    for step in ("require_permission(current_user, PermissionEnum.VAULT_CREATE)",
                 "_resolve_vault_type_for_create(current_user, requested, db)",
                 "require_create_vault_type(current_user, vault_type)"):
        assert helper.count(step) == 1, step


def test_the_verifier_releases_the_sealed_key_only_on_the_direct_path():
    helper = _body(ROUTER, "def _challenge_verifier(")
    hierarchical, direct = helper.split("if row is None:", 1)
    assert "sealed_private_key" not in hierarchical
    assert '"sealed_private_key": row.sealed_private_key' in direct


def test_the_route_records_nothing_and_says_why():
    coverage = (ROOT / "tests" / "test_audit_route_coverage.py").read_text(encoding="utf-8")
    assert '("app/api/ecc_router.py", "POST /vaults/{vault_id}/key-proof/challenge")' in coverage
    assert "_audit_zk(" not in ROUTE and "log_action(" not in ROUTE
