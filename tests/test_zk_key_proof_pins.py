"""Source pins for the key proof: where each guarded handler checks what, and that no other code installs key
material.

The behaviour is tested against the handlers themselves (test_zk_key_proof_handler.py) and against a running
deployment (test_zk_key_proof_live.py). What those cannot see is the order of steps that pass or fail the same
way whatever their order, and code that does not exist yet. These pins keep both:

* in every guarded handler the header and the material's shape come before the challenge is consumed, the
  challenge is consumed before the vault row lock, and under the lock the key-holder check, the state pin and
  the MACs come first -- before the change is written and with no commit in between;
* every write of key material -- a member's wrapped key, a name-index key wrap, a proof row, a vault's team
  key, team epoch or DEK epoch -- is in one of the guarded handlers, or is one of the listed prunes and
  migrations. A new writer cannot ship ungated without failing here;
* only the operations that install a vault's first verifier or replace damaged material skip the current-key
  proof.
"""
import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
ECC = (ROOT / "app" / "api" / "ecc_router.py").read_text(encoding="utf-8")
API = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
PROOF = (ROOT / "app" / "services" / "zk_key_proof.py").read_text(encoding="utf-8")


def _function(source: str, name: str) -> str:
    """The source of one top-level function: from its `def` to the next top-level statement."""
    tree = ast.parse(source)
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name]
    assert len(nodes) == 1, f"{name} is defined {len(nodes)} times"
    return ast.get_source_segment(source, nodes[0])


def _once(text: str, needle: str, where: str) -> int:
    assert text.count(needle) == 1, f"{needle!r} appears {text.count(needle)} times in {where}"
    return text.index(needle)


# (router source, handler, operation, the shape checks that must precede consumption)
GUARDED = (
    (ECC, "rekey_vault", "rekey", ("_direct_proof_material(", "_lineage_tag_or_none(")),
    (ECC, "bootstrap_key_proof", "bootstrap", ("_direct_proof_material(",)),
    (ECC, "grant_member_key", "share", ("dek_version is required with a key proof",)),
    (ECC, "put_vault_index_key", "index_key", ()),
)


@pytest.mark.parametrize("source,name,op,shapes", GUARDED, ids=[g[1] for g in GUARDED])
def test_each_guarded_handler_checks_in_the_design_order(source, name, op, shapes):
    fn = _function(source, name)
    header = _once(fn, "_key_proof_header(http_request", name)
    consume = _once(fn, "_consume_key_proof_challenge(", name)
    assert (f'op="{op}"' in fn[consume:consume + 200] or "op=op" in fn[consume:consume + 200]), \
        f"{name} consumes a challenge for another operation"
    for shape in shapes:
        at = fn.find(shape)
        assert header < at < consume, f"{name}: {shape!r} is not checked between the header and consumption"
    lock = _once(fn, "with_for_update()", name)
    assert consume < lock, f"{name} consumes its challenge after taking the vault lock"
    holds = fn.index("_holds_current_key(db, locked", lock)
    pin = _once(fn, "_pin_key_proof_state(db, ch, locked)", name)
    verify = _once(fn, "_verify_key_proof(", name)
    assert lock < holds < pin < verify, f"{name}: under the lock the holder check, pin and MACs are out of order"
    # Nothing in the body is used between the lock and the state pin.
    assert not re.search(r"\b(request|body)\.", fn[lock:pin]), f"{name} uses the body before the proof is checked"
    # The first commit after the lock is the change itself, after the checks.
    first_commit = min(i for i in (fn.find("db.commit()", lock), fn.find("_commit_rotation(db)", lock)) if i >= 0)
    assert verify < first_commit, f"{name} commits under the lock before the proof is checked"
    assert "_reconcile_orphan_member_keys(" not in fn[lock:], f"{name} commits (the orphan sweep) under the lock"


def test_a_zero_knowledge_create_checks_everything_before_the_vault_is_built():
    fn = _function(API, "create_vault")
    header = _once(fn, "_ecc._key_proof_header(request", "create_vault")
    material = _once(fn, '_ecc._direct_proof_material(vault_create.key_proof, "key_proof")', "create_vault")
    consume = _once(fn, "_ecc._consume_key_proof_challenge(", "create_vault")
    assert 'op="create"' in fn[consume:consume + 200]
    verify = _once(fn, "_ecc._verify_key_proof(", "create_vault")
    build = _once(fn, "vault_service.create_vault(", "create_vault")
    keypair = _once(fn, "Set up your encryption key before creating a zero-knowledge vault.", "create_vault")
    assert keypair < header < material < consume < verify < build
    # Nothing is created and then deleted again.
    assert "db.delete(vault)" not in fn


# Functions allowed to write key material, and why. The guarded handlers write it after a proof; the rest
# prune or relabel what a guarded handler wrote and install nothing new.
KEY_MATERIAL_WRITERS = {
    ("app/api/api_server.py", "create_vault"): "guarded (create)",
    ("app/api/ecc_router.py", "rekey_vault"): "guarded (rekey, owner reset)",
    ("app/api/ecc_router.py", "bootstrap_key_proof"): "guarded (bootstrap)",
    ("app/api/ecc_router.py", "grant_member_key"): "guarded (share)",
    ("app/api/ecc_router.py", "put_vault_index_key"): "guarded (index key)",
    ("app/api/ecc_router.py", "retire_dek_versions"): "prunes the team-wrap entries of retired epochs",
    ("app/core/models.py", "wrapped_dek"): "the member key model's alias for its own column",
    ("app/core/name_index_label_migration.py", "relabel_name_index_keys"):
        "a boot migration that corrects the label on existing name-index wraps",
}
_CONSTRUCTORS = {"VaultMemberKey", "VaultMemberIndexKey", "VaultKeyProof"}
_ATTRIBUTES = {"team_public_key", "team_key", "team_key_version", "dek_version", "wrapped_dek", "encrypted_dek",
               "encrypted_index_key", "proof_public_key", "sealed_private_key", "dek_check", "lineage_tag"}


def _writers():
    found = {}
    for path in sorted((ROOT / "app").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                what = None
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _CONSTRUCTORS:
                    what = node.func.id
                elif isinstance(node, (ast.Assign, ast.AugAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    what = next((t.attr for t in targets
                                 if isinstance(t, ast.Attribute) and t.attr in _ATTRIBUTES), None)
                elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                      and node.func.attr == "update"
                      and any(c in ast.unparse(node.func.value) for c in _CONSTRUCTORS)):
                    what = "bulk update"
                if what:
                    found.setdefault((rel, fn.name), set()).add(what)
    return found


def test_only_the_guarded_handlers_install_key_material():
    """Deactivating a member's key (is_active) is not an install and is not listed; raw SQL in the boot
    migrations is not seen by this scan."""
    found = _writers()
    unexpected = {k: sorted(v) for k, v in found.items() if k not in KEY_MATERIAL_WRITERS}
    assert not unexpected, f"key material is written outside the guarded handlers: {unexpected}"
    stale = [k for k in KEY_MATERIAL_WRITERS if k not in found]
    assert not stale, f"listed writers that no longer write key material: {stale}"


def test_the_scan_sees_a_new_writer():
    """The scan is not vacuous: a function that builds a member key row is reported."""
    src = "def sneaky(db):\n    db.add(VaultMemberKey(vault_id=1))\n    v.team_public_key = 'x'\n"
    tree = ast.parse(src)
    hits = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id in _CONSTRUCTORS]
    assigns = [t.attr for n in ast.walk(tree) if isinstance(n, ast.Assign) for t in n.targets
               if isinstance(t, ast.Attribute) and t.attr in _ATTRIBUTES]
    assert hits and assigns == ["team_public_key"]


def test_only_the_first_verifier_and_the_owner_reset_skip_the_current_key():
    assert re.search(r'OPS_WITHOUT_CURRENT_KEY = frozenset\(\{"bootstrap", "create", "owner_reset"\}\)', PROOF)
    verify = _function(ECC, "_verify_key_proof")
    _once(verify, "if ch.op in zk_key_proof.OPS_WITHOUT_CURRENT_KEY:\n        current_pem = None", "_verify_key_proof")
    # The handlers for operations that must prove the current key take it from the vault, never from the body.
    for name in ("grant_member_key", "put_vault_index_key"):
        assert "current_pem=_current_key_verifier(db, locked)" in _verify_call(_function(ECC, name)), name
    # A rotation skips it only as an owner reset, which only the vault's owner may make, with a challenge
    # issued for that operation (checked under the lock, before the MACs).
    rekey = _function(ECC, "rekey_vault")
    assert "current_pem=(None if owner_reset else _current_key_verifier(db, locked))" in _verify_call(rekey)
    _once(rekey, 'op = "owner_reset" if owner_reset else "rekey"', "rekey_vault")
    owner_check = _once(rekey, "if owner_reset and str(current_user.id) != str(locked.owner_id):", "rekey_vault")
    assert owner_check < rekey.index("_verify_key_proof(")
    # The two doors that set up a verifier prove the key they install and no current key.
    assert "current_pem=None, new_pem=material[\"public_key\"]" in _verify_call(_function(ECC, "bootstrap_key_proof"))
    assert "current_pem=None, new_pem=new_pem" in _verify_call(_function(API, "create_vault"))


def _verify_call(fn: str) -> str:
    call = fn[fn.index("_verify_key_proof("):]
    depth = 0
    for i, c in enumerate(call):
        depth += c == "("
        depth -= c == ")"
        if depth == 0 and c == ")":
            return call[:i + 1]
    raise AssertionError("unbalanced call")


def test_the_owner_reset_step_up_is_fixed_and_outside_the_admins_matrix():
    """Every catalogued step-up action but two ships off, so the owner reset is not one of them: its
    step-up is required whenever the owner has a second factor, whatever the matrix says."""
    from app.core import second_factor_actions as acts
    assert acts.OWNER_KEY_RESET not in acts.ACTION_KEYS
    assert acts.OWNER_KEY_RESET in acts.FIXED_STEP_UP_ACTIONS and acts.is_step_up_action(acts.OWNER_KEY_RESET)
    requirement = _function(API, "_sf_requirement_for")
    fixed = _once(requirement, "if action in acts.FIXED_STEP_UP_ACTIONS:", "_sf_requirement_for")
    assert fixed < requirement.index("_sf_action_toggles(")
    assert 'return {"password": False, "otp": has_active, "must_enroll": False}, has_active' in requirement
    rekey = _function(ECC, "rekey_vault")
    step_up = _once(rekey, "_enforce_step_up(db, current_user, http_request, OWNER_KEY_RESET)", "rekey_vault")
    assert step_up < rekey.index("_ecc_rate_limit(") < rekey.index("_consume_key_proof_challenge(")


def test_the_step_up_boot_contract_still_holds():
    """The server refuses to start when the catalogued step-up actions and the guarded ones differ; the
    owner reset's fixed step-up is in neither."""
    from _bare_api_env import set_bare_api_env
    set_bare_api_env()
    import app.api.api_server as S
    from app.core.second_factor_actions import OWNER_KEY_RESET
    S._assert_step_up_boot_contract()
    assert OWNER_KEY_RESET not in S.GUARDED_STEP_UP_ACTIONS
