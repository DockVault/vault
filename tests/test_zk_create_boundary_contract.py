"""Static security contract for zero-knowledge vault creation in the browser.

The live Playwright gate proves the request trace against the exact candidate image. These
source-level assertions fail faster and make the least-privilege boundary explicit for reviewers:
creating a vault needs the registered public identity key, never the private identity envelope.
"""

from pathlib import Path

import pytest


APP_JS = (
    Path(__file__).resolve().parent.parent / "static" / "js" / "app.js"
).read_text(encoding="utf-8")
UI_GATE_SOURCES = {
    path.name: path.read_text(encoding="utf-8")
    for path in (
        Path(__file__).with_name("test_ui_crypto_compatibility.py"),
        Path(__file__).with_name("test_ui_zk_create_boundary.py"),
    )
}
pytestmark = pytest.mark.unit


def _between(start_marker: str, end_marker: str) -> str:
    start = APP_JS.index(start_marker)
    end = APP_JS.index(end_marker, start)
    return APP_JS[start:end]


def test_create_public_key_helper_refuses_keyless_and_never_touches_private_key():
    helper = _between(
        "async function zkEnsurePublicKeyForCreate()",
        '// --- Standalone "set up my encryption key"',
    )

    # Reads ONLY the public identity endpoint, exactly once (no refetch loop).
    assert helper.count("apiRequest('/ecc/keys/public'") == 1

    # The has-keypair path returns the PUBLIC key and the account id that arrived with it (a
    # version-2 lock stamps the account it was made for), from the PUBLIC endpoint and nothing else.
    assert "pem: pub.public_key" in helper
    assert "userId: pub.user_id" in helper

    # REFUSE + GUIDE: a keyless user is NOT silently registered mid-create. Registering there
    # presented the account encryption-key passphrase prompt at create time, which users confused
    # with a vault password. The helper now throws a coded, guiding error instead — the encryption
    # key must be set up deliberately first, via the standalone flow.
    assert "await zkRegisterNewKeypair()" not in helper
    assert "zk_no_encryption_key" in helper

    # The actual boundary, untouched: this helper must never reach for the private identity key.
    assert "zkEnsureUnlocked" not in helper
    assert "/ecc/keys/private" not in helper
    assert "zkState.privateKey" not in helper


def test_create_submit_wraps_a_fresh_dek_to_the_server_public_key():
    create_flow = _between(
        "document.getElementById('create-vault-form').addEventListener('submit'",
        "// Keep the password + team-mode visibility",
    )

    # The helper now returns { pem, userId } rather than a bare string: a version-2 lock stamps
    # the account it was made for, and the account id arrives in the same response as the key.
    # Only the names change here -- every ordering and every negative below is as it was.
    public_lookup = "const identity = await zkEnsurePublicKeyForCreate();"
    public_import = "const myPub = await lib.importPublicKeyPEM(identity.pem);"
    fresh_dek = "const dek = await lib.generateVaultDEK();"
    create_request = "const created = await apiRequest('/vaults'"

    assert public_lookup in create_flow
    assert public_import in create_flow
    assert create_flow.count(fresh_dek) == 1
    assert public_lookup not in APP_JS[: APP_JS.index(create_flow)]
    assert create_flow.index(public_lookup) < create_flow.index(public_import)
    assert create_flow.index(public_import) < create_flow.index(fresh_dek)
    assert create_flow.index(fresh_dek) < create_flow.index(create_request)

    # One more ordering, new with the client-chosen vault id: the id must be minted BEFORE the key
    # is locked. The lock is stamped with it, so the other order stamps `undefined`, which throws
    # rather than producing a bad lock -- but only once someone enables the version-2 writer, so
    # until then this assertion is the only thing holding the order.
    mint_id = "payload.id = zkNewObjId();"
    stamp = "vaultId: payload.id"
    assert mint_id in create_flow
    assert create_flow.index(mint_id) < create_flow.index(stamp)

    assert "zkEnsureKeypair" not in create_flow
    assert "zkEnsureUnlocked" not in create_flow
    assert "/ecc/keys/private" not in create_flow


def test_first_identity_key_registration_remains_interactive_and_pop_bound():
    registration = _between(
        "async function zkRegisterNewKeypair()",
        "// Change the encryption passphrase",
    )

    warning = registration.index("await showConfirm(")
    first_prompt = registration.index("await showPrompt(")
    key_generation = registration.index("await lib.generateKeypair()")
    challenge = registration.index("'/ecc/keys/register/challenge'")
    proof = registration.index("await lib.computeRegistrationPoP(")
    register = registration.index("'/ecc/keys/register'")

    assert registration.count("await showPrompt(") >= 2
    assert warning < first_prompt < key_generation < challenge < proof < register


@pytest.mark.parametrize("module_name", sorted(UI_GATE_SOURCES))
def test_live_browser_gate_fails_closed_on_exact_candidate_provenance(module_name):
    source = UI_GATE_SOURCES[module_name]
    assert (
        "from test_live_crypto_compatibility import _inspect_exact_candidate" in source
    )
    fixture_start = source.index("def _live_container_health():")
    fixture_end = source.index("\n\n", fixture_start)
    fixture = source[fixture_start:fixture_end]

    assert 'return _inspect_exact_candidate()["health"]' in fixture
    assert "pytest.skip" not in fixture
    assert '@pytest.fixture(scope="module", autouse=True)' in source[:fixture_start]


class _VaultListResponse:
    status_code = 200
    text = ""

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _VaultListOwner:
    def __init__(self, payload):
        self._payload = payload
        self.paths = []

    def get(self, path):
        self.paths.append(path)
        return _VaultListResponse(self._payload)


def test_cleanup_rediscovers_randomized_vault_names_and_deduplicates_ids():
    from test_ui_crypto_compatibility import _collect_vault_ids_for_cleanup

    owner = _VaultListOwner(
        [
            {"id": "known", "name": "target-one"},
            {"id": "new", "name": "target-two"},
            {"id": "foreign", "name": "not-ours"},
        ]
    )
    errors = []

    result = _collect_vault_ids_for_cleanup(
        owner, {"target-one", "target-two"}, ["known", "known"], errors
    )

    assert result == ["known", "new"]
    assert owner.paths == ["/vaults"]
    assert errors == []


def test_cleanup_preserves_known_ids_and_reports_invalid_discovery_response():
    from test_ui_crypto_compatibility import _collect_vault_ids_for_cleanup

    owner = _VaultListOwner(ValueError("invalid vault list"))
    errors = []

    result = _collect_vault_ids_for_cleanup(owner, {"target"}, ["known"], errors)

    assert result == ["known"]
    assert owner.paths == ["/vaults"]
    assert len(errors) == 1
    assert errors[0].startswith(
        "rediscover created vaults for cleanup: invalid response"
    )
