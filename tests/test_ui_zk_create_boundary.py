"""Live browser gates for least-privilege zero-knowledge vault creation.

These tests intentionally use the exact JavaScript served by the candidate container. They prove
that create-only operations need the account's registered public key, not its encrypted private
identity envelope, including the first-registration cross-tab race.
"""

import hashlib
import json
from urllib.parse import urlsplit
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, compute_registration_pop
from crypto_reference_vectors import (
    decode_direct_dek_wrap,
    decode_private_envelope,
    decode_team_private_wrap,
)
from test_live_crypto_compatibility import _inspect_exact_candidate
from test_ui_crypto_compatibility import (
    _collect_vault_ids_for_cleanup,
    _cleanup_contexts,
    _cleanup_temp_credential,
    _cleanup_user,
    _cleanup_vault,
    _complete_first_key_prompts,
    _login,
    _open_create_vault,
    _raise_cleanup_errors,
    _restore_settings,
    _exact_admin_client,
    _set_up_account_key,
)


pytestmark = [pytest.mark.ui, pytest.mark.crypto_compatibility]


@pytest.fixture(scope="module", autouse=True)
def _live_container_health():
    """Bind this destructive live gate to the exact labeled candidate image."""
    return _inspect_exact_candidate()["health"]


@pytest.fixture(scope="module")
def admin():
    return _exact_admin_client()


def _unique(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def _private_scalar_hex(private_key: ec.EllipticCurvePrivateKey) -> str:
    return f"{private_key.private_numbers().private_value:096x}"


def _registered_private_scalar(owner: ApiClient, passphrase: str) -> str:
    response = owner.get("/ecc/keys/private")
    assert response.status_code == 200, response.text
    envelope = json.loads(response.json()["encrypted_private_key"])
    private_pem = decode_private_envelope(envelope, password=passphrase)
    private_key = serialization.load_pem_private_key(
        private_pem.encode("utf-8"), password=None
    )
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    return _private_scalar_hex(private_key)


def _install_dek_evidence_probe(page: Page) -> None:
    page.evaluate(
        """
        () => {
            window.__zkCreateDekEvidence = [];
            const original = ECCCryptoLibrary.prototype.generateVaultDEK;
            ECCCryptoLibrary.prototype.generateVaultDEK = async function (...args) {
                const dek = await original.apply(this, args);
                const raw = await window.crypto.subtle.exportKey('raw', dek);
                const digest = await window.crypto.subtle.digest('SHA-256', raw);
                const digestHex = Array.from(new Uint8Array(digest))
                    .map(byte => byte.toString(16).padStart(2, '0')).join('');
                window.__zkCreateDekEvidence.push({
                    byteLength: raw.byteLength,
                    digest: digestHex,
                });
                return dek;
            };
        }
        """
    )


def _dek_evidence(page: Page) -> list[dict]:
    return page.evaluate("() => window.__zkCreateDekEvidence.slice()")


def _unwrap_descriptor_dek(descriptor: dict, identity_scalar: str) -> bytes:
    recipient_scalar = identity_scalar
    if descriptor.get("mode") == "hierarchical":
        team_private = decode_team_private_wrap(
            descriptor["wrapped_team_privkey"],
            ephemeral_public_key_b64=descriptor["team_ephemeral_public_key"],
            member_private_scalar_hex=identity_scalar,
        )
        recipient_scalar = _private_scalar_hex(team_private)
    return decode_direct_dek_wrap(
        descriptor["wrapped_dek"],
        ephemeral_public_key_b64=descriptor["ephemeral_public_key"],
        recipient_private_scalar_hex=recipient_scalar,
    )


def _assert_persisted_dek_matches(
    owner: ApiClient, vault_id: str, identity_scalar: str, expected_digest: str
) -> None:
    response = owner.get(f"/ecc/vaults/{vault_id}/keys")
    assert response.status_code == 200, response.text
    raw_dek = _unwrap_descriptor_dek(response.json(), identity_scalar)
    if len(raw_dek) != 32:
        raise AssertionError("persisted vault wrap did not unwrap to an AES-256 DEK")
    if hashlib.sha256(raw_dek).hexdigest() != expected_digest:
        raise AssertionError(
            "persisted vault wrap does not match the browser-generated DEK"
        )


def _register_concurrent_identity(owner: ApiClient) -> str:
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    response = owner.post(
        "/ecc/keys/register",
        json={
            "public_key": public_pem,
            "encrypted_private_key": json.dumps(
                {
                    "encrypted": "concurrent-winner-envelope",
                    "salt": "concurrent-winner-salt",
                    "iterations": 600000,
                }
            ),
            "pop": compute_registration_pop(owner, private_key, public_pem),
        },
    )
    assert response.status_code == 201, response.text
    return _private_scalar_hex(private_key)


def _security_request(request) -> tuple[str, str] | None:
    path = urlsplit(request.url).path
    if path == "/vaults" and request.method != "POST":
        return None
    if path in {
        "/ecc/keys/public",
        "/ecc/keys/private",
        "/ecc/keys/register/challenge",
        "/ecc/keys/register",
        "/vaults",
    }:
        return request.method, path
    return None


def test_existing_identity_create_only_uses_fresh_deks_without_private_key(
    browser, admin
):
    settings_before = None
    user = None
    owner = None
    temp_username = None
    vault_ids = []
    contexts = {}
    cleanup_errors = []
    passphrase = "zk-create-existing-key-passphrase"
    vault_specs = [
        (_unique("zk_create_direct"), False),
        (_unique("zk_create_hierarchical"), True),
    ]

    try:
        current_settings = admin.get("/settings")
        assert current_settings.status_code == 200, current_settings.text
        settings_before = {
            "zero_knowledge_enabled": current_settings.json()["zero_knowledge_enabled"],
            "temp_cred_allow_zk_vaults": current_settings.json()[
                "temp_cred_allow_zk_vaults"
            ],
        }
        changed = admin.put(
            "/settings",
            json={"zero_knowledge_enabled": True, "temp_cred_allow_zk_vaults": True},
        )
        assert changed.status_code == 200, changed.text

        user = admin.create_user(role="admin")
        owner = ApiClient()
        owner.login(user["_username"], user["_password"])

        setup_context = browser.new_context(base_url=owner.base_url)
        contexts["interactive key setup"] = setup_context
        setup_page = setup_context.new_page()
        _login(setup_page, user["_username"], user["_password"])
        _set_up_account_key(setup_page, passphrase)
        identity_scalar = _registered_private_scalar(owner, passphrase)
        setup_context.close()
        contexts.pop("interactive key setup")

        minted = owner.post(
            "/auth/temp-credentials",
            json={
                "validity_minutes": 30,
                "scope": {
                    "v": 1,
                    "pages": ["vaults"],
                    "caps": ["vault.create"],
                    "vault_caps_default": [],
                    "temp": {},
                },
                "vault_access_mode": "all",
            },
        )
        assert minted.status_code == 200, minted.text
        credential = minted.json()
        temp_username = credential["temp_username"]

        temp_context = browser.new_context(base_url=owner.base_url)
        contexts["create-only temporary credential"] = temp_context
        page = temp_context.new_page()
        _login(page, temp_username, credential["credential"])
        _install_dek_evidence_probe(page)

        requests_seen = []

        def record_request(request):
            event = _security_request(request)
            if event is not None:
                requests_seen.append(event)

        page.on("request", record_request)

        for vault_name, hierarchical in vault_specs:
            _open_create_vault(page)
            page.fill("#vault-name", vault_name)
            expect(page.locator("#vault-type-group")).to_be_visible(timeout=5_000)
            page.select_option("#vault-type", "zero_knowledge")
            if hierarchical:
                expect(page.locator("#vault-hierarchical-wrap")).to_be_visible(
                    timeout=5_000
                )
                page.check("#vault-hierarchical")

            assert page.evaluate("() => zkState.privateKey === null") is True
            page.click("#create-vault-form button[type=submit]")
            expect(page.locator("#create-vault-modal")).to_be_hidden(timeout=20_000)
            expect(page.locator("#confirm-modal")).to_be_hidden()
            assert page.evaluate("() => zkState.privateKey === null") is True

            matches = [
                vault
                for vault in owner.get("/vaults").json()
                if vault["name"] == vault_name
            ]
            assert len(matches) == 1, f"zero-knowledge vault mismatch: {matches!r}"
            vault_ids.append(matches[0]["id"])

        assert requests_seen == [
            ("GET", "/ecc/keys/public"),
            ("POST", "/vaults"),
            ("GET", "/ecc/keys/public"),
            ("POST", "/vaults"),
        ], requests_seen

        evidence = _dek_evidence(page)
        if len(evidence) != 2:
            raise AssertionError("each vault create must generate exactly one DEK")
        if any(item["byteLength"] != 32 for item in evidence):
            raise AssertionError("vault creation must generate AES-256 DEKs")
        if len({item["digest"] for item in evidence}) != 2:
            raise AssertionError("separate vault creates reused the same DEK")
        for vault_id, item in zip(vault_ids, evidence, strict=True):
            _assert_persisted_dek_matches(
                owner, vault_id, identity_scalar, item["digest"]
            )
    finally:
        _cleanup_contexts(contexts, cleanup_errors)
        if temp_username is not None:
            _cleanup_temp_credential(owner, temp_username, cleanup_errors)
        vault_ids = _collect_vault_ids_for_cleanup(
            owner,
            {vault_name for vault_name, _ in vault_specs},
            vault_ids,
            cleanup_errors,
        )
        for vault_id in vault_ids:
            _cleanup_vault(owner, vault_id, cleanup_errors)
        if user is not None:
            _cleanup_user(admin, user["id"], cleanup_errors)
        if settings_before is not None:
            _restore_settings(admin, settings_before, cleanup_errors)
        _raise_cleanup_errors(cleanup_errors)


def test_first_key_registration_race_refetches_public_key_without_private_unlock(
    browser, admin
):
    settings_before = None
    user = None
    owner = None
    vault_id = None
    contexts = {}
    cleanup_errors = []
    browser_passphrase = "zk-create-race-loser-passphrase"
    vault_name = _unique("zk_create_registration_race")

    try:
        current_settings = admin.get("/settings")
        assert current_settings.status_code == 200, current_settings.text
        settings_before = {
            "zero_knowledge_enabled": current_settings.json()["zero_knowledge_enabled"]
        }
        changed = admin.put("/settings", json={"zero_knowledge_enabled": True})
        assert changed.status_code == 200, changed.text

        user = admin.create_user(role="admin")
        owner = ApiClient()
        owner.login(user["_username"], user["_password"])
        assert owner.get("/ecc/keys/public").json()["has_keypair"] is False

        context = browser.new_context(base_url=owner.base_url)
        contexts["registration race browser"] = context
        page = context.new_page()
        _login(page, user["_username"], user["_password"])
        _install_dek_evidence_probe(page)

        requests_seen = []
        responses_seen = []

        def record_request(request):
            event = _security_request(request)
            if event is not None:
                requests_seen.append(event)

        def record_response(response):
            event = _security_request(response.request)
            if event is not None:
                responses_seen.append((*event, response.status))

        page.on("request", record_request)
        page.on("response", record_response)

        _open_create_vault(page)
        page.fill("#vault-name", vault_name)
        expect(page.locator("#vault-type-group")).to_be_visible(timeout=5_000)
        page.select_option("#vault-type", "zero_knowledge")
        page.click("#create-vault-form button[type=submit]")

        expect(page.locator("#confirm-modal")).to_be_visible(timeout=8_000)
        assert requests_seen == [("GET", "/ecc/keys/public")], requests_seen

        winner_scalar = _register_concurrent_identity(owner)
        _complete_first_key_prompts(page, browser_passphrase)
        expect(page.locator("#create-vault-modal")).to_be_hidden(timeout=20_000)
        expect(page.locator("#confirm-modal")).to_be_hidden()

        assert requests_seen == [
            ("GET", "/ecc/keys/public"),
            ("POST", "/ecc/keys/register/challenge"),
            ("POST", "/ecc/keys/register"),
            ("GET", "/ecc/keys/public"),
            ("POST", "/vaults"),
        ], requests_seen
        assert [
            status
            for method, path, status in responses_seen
            if method == "POST" and path == "/ecc/keys/register"
        ] == [409]
        assert not any(path == "/ecc/keys/private" for _, path in requests_seen)
        assert page.evaluate("() => zkState.privateKey === null") is True

        matches = [
            vault
            for vault in owner.get("/vaults").json()
            if vault["name"] == vault_name
        ]
        assert len(matches) == 1, f"registration-race vault mismatch: {matches!r}"
        vault_id = matches[0]["id"]

        evidence = _dek_evidence(page)
        if len(evidence) != 1 or evidence[0]["byteLength"] != 32:
            raise AssertionError(
                "registration-race create did not generate one AES-256 DEK"
            )
        _assert_persisted_dek_matches(
            owner, vault_id, winner_scalar, evidence[0]["digest"]
        )
    finally:
        _cleanup_contexts(contexts, cleanup_errors)
        vault_ids = _collect_vault_ids_for_cleanup(
            owner,
            {vault_name},
            [vault_id] if vault_id is not None else [],
            cleanup_errors,
        )
        for discovered_vault_id in vault_ids:
            _cleanup_vault(owner, discovered_vault_id, cleanup_errors)
        if user is not None:
            _cleanup_user(admin, user["id"], cleanup_errors)
        if settings_before is not None:
            _restore_settings(admin, settings_before, cleanup_errors)
        _raise_cleanup_errors(cleanup_errors)
