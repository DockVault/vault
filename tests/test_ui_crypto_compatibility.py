"""Live-browser crypto compatibility and request-order gates.

The vector reader in this module executes the JavaScript served by the candidate container.  It
therefore proves compatibility at the deployed browser boundary, while the independent readers in
the vector suite provide a second implementation of the same pinned formats.
"""

import base64
import hashlib
from pathlib import Path
from urllib.parse import urlsplit
import uuid

import pytest
import requests
from playwright.sync_api import Page, expect

from conftest import ADMIN_PASS, ADMIN_USER, ApiClient, BASE_URL
from crypto_reference_vectors import load_vector, p384_private_der, p384_private_pem


pytestmark = [pytest.mark.ui, pytest.mark.crypto_compatibility]

_REPO_ROOT = Path(__file__).resolve().parent.parent
_VECTOR_DIR = Path(__file__).resolve().parent / "fixtures" / "crypto" / "v0.10.0"


@pytest.fixture(scope="module")
def _live_container_health():
    """Override the suite's local-development skip: compatibility requires a live candidate."""
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        response.raise_for_status()
        health = response.json()
    except Exception as exc:  # noqa: BLE001 - required infrastructure must fail, never skip
        pytest.fail(
            f"crypto compatibility candidate is not reachable at {BASE_URL}: {exc}"
        )
    if health.get("database") != "connected":
        pytest.fail(
            f"crypto compatibility candidate database is not connected: {health}"
        )
    return health


@pytest.fixture(scope="module")
def admin():
    """Use an explicit failure instead of conftest's optional local credential skip."""
    if not ADMIN_PASS:
        pytest.fail(
            "crypto compatibility browser gates require VAULT_ADMIN_PASS "
            "or ADMIN_PASSWORD in .env"
        )
    client = ApiClient()
    try:
        client.login(ADMIN_USER, ADMIN_PASS)
    except Exception as exc:  # noqa: BLE001 - authentication is required infrastructure
        pytest.fail(
            f"crypto compatibility admin login failed for {ADMIN_USER!r}: {exc}"
        )
    return client


def _load_browser_vectors() -> dict:
    names = {
        "content": "zk-content-unversioned.json",
        "private_envelope": "zk-private-envelope-legacy.json",
        "direct_wrap": "zk-direct-dek-wrap-legacy.json",
        "team_wrap": "zk-team-private-wrap-v1.json",
        "name_zk1": "zk-name-zk1.json",
        "name_zk2": "zk-name-zk2.json",
    }
    missing = [
        filename
        for filename in names.values()
        if not (_VECTOR_DIR / filename).is_file()
    ]
    if missing:
        pytest.fail(f"required browser crypto vectors are absent: {missing}")
    vectors = {
        key: load_vector(_VECTOR_DIR / filename) for key, filename in names.items()
    }
    vectors["private_envelope"]["private_key_pem"] = p384_private_pem(
        vectors["private_envelope"]["inputs"]["identity_private_scalar_hex"]
    ).removesuffix("\n")
    vectors["direct_wrap"]["recipient_private_pem"] = p384_private_pem(
        vectors["direct_wrap"]["inputs"]["recipient_private_scalar_hex"]
    )
    vectors["team_wrap"]["member_private_pem"] = p384_private_pem(
        vectors["team_wrap"]["inputs"]["member_private_scalar_hex"]
    )
    vectors["team_wrap"]["team_private_pkcs8_b64"] = base64.b64encode(
        p384_private_der(vectors["team_wrap"]["inputs"]["team_private_scalar_hex"])
    ).decode("ascii")
    return vectors


def _unique(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def _record_cleanup_response(errors, label, response, expected_status=200) -> None:
    if response.status_code != expected_status:
        errors.append(
            f"{label}: expected HTTP {expected_status}, got "
            f"{response.status_code}: {response.text}"
        )


def _record_cleanup_call(errors, label, operation, expected_status=200):
    try:
        response = operation()
    except Exception as exc:  # noqa: BLE001 - every later cleanup must still run
        errors.append(f"{label}: raised {type(exc).__name__}: {exc}")
        return None
    _record_cleanup_response(errors, label, response, expected_status)
    return response


def _cleanup_contexts(contexts, errors) -> None:
    """Close every still-open exact context, without one failure blocking the next."""
    for label, context in reversed(list(contexts.items())):
        try:
            context.close()
        except Exception as exc:  # noqa: BLE001 - later resources still require cleanup
            errors.append(
                f"close browser context {label}: raised {type(exc).__name__}: {exc}"
            )


def _cleanup_temp_credential(owner, username, errors) -> None:
    if owner is None:
        errors.append(
            f"delete temporary credential {username}: owner client is unavailable"
        )
        return
    _record_cleanup_call(
        errors,
        f"delete temporary credential {username}",
        lambda: owner.post(f"/temp-creds/{username}/delete"),
    )
    listed = _record_cleanup_call(
        errors,
        f"verify temporary credential {username} deletion",
        lambda: owner.get("/temp-creds/list"),
    )
    if listed is not None and listed.status_code == 200:
        try:
            remains = any(row.get("temp_username") == username for row in listed.json())
        except Exception as exc:  # noqa: BLE001 - later cleanup must still run
            errors.append(
                f"verify temporary credential {username} deletion: "
                f"invalid response ({type(exc).__name__}: {exc})"
            )
        else:
            if remains:
                errors.append(
                    f"verify temporary credential {username} deletion: row remains"
                )


def _cleanup_vault(owner, vault_id, errors) -> None:
    if owner is None:
        errors.append(f"delete vault {vault_id}: owner client is unavailable")
        return
    _record_cleanup_call(
        errors,
        f"delete vault {vault_id}",
        lambda: owner.delete_vault(vault_id),
    )
    _record_cleanup_call(
        errors,
        f"verify vault {vault_id} deletion",
        lambda: owner.get(f"/vaults/{vault_id}"),
        expected_status=404,
    )


def _cleanup_user(admin, user_id, errors) -> None:
    _record_cleanup_call(
        errors,
        f"delete user {user_id}",
        lambda: admin.delete_user(user_id),
    )
    _record_cleanup_call(
        errors,
        f"verify user {user_id} deletion",
        lambda: admin.get(f"/users/{user_id}"),
        expected_status=404,
    )


def _restore_settings(admin, before, errors) -> None:
    """Restore exact values and independently read them back; this always runs last."""
    _record_cleanup_call(
        errors,
        "restore crypto compatibility settings",
        lambda: admin.put("/settings", json=before),
    )
    read_back = _record_cleanup_call(
        errors,
        "read restored crypto compatibility settings",
        lambda: admin.get("/settings"),
    )
    if read_back is not None and read_back.status_code == 200:
        try:
            actual = read_back.json()
        except Exception as exc:  # noqa: BLE001 - aggregate the final validation failure
            errors.append(
                "read restored crypto compatibility settings: "
                f"invalid response ({type(exc).__name__}: {exc})"
            )
        else:
            mismatches = {
                key: {"expected": expected, "actual": actual.get(key)}
                for key, expected in before.items()
                if actual.get(key) != expected
            }
            if mismatches:
                errors.append(
                    "read restored crypto compatibility settings: values differ "
                    f"{mismatches}"
                )


def _raise_cleanup_errors(errors) -> None:
    if errors:
        raise AssertionError("cleanup failures:\n" + "\n".join(errors))


def _login(page: Page, username: str, password: str) -> None:
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15_000)


def _set_up_account_key(page: Page, passphrase: str) -> None:
    """Register the account's first identity key through the interactive-only UI path."""
    page.click("#profile-btn")
    page.click("#encryption-key-btn")
    expect(page.locator("#encryption-key-modal")).to_be_visible(timeout=5_000)
    expect(page.locator("#encryption-key-setup-btn")).to_be_visible()
    page.click("#encryption-key-setup-btn")

    expect(page.locator("#confirm-modal")).to_be_visible(timeout=5_000)
    page.click("#confirm-modal-confirm-btn")
    for value in (passphrase, passphrase):
        expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=5_000)
        page.fill("#confirm-modal-input", value)
        page.click("#confirm-modal-confirm-btn")
    expect(page.locator("#encryption-key-status")).to_contain_text(
        "set up and active", timeout=15_000
    )


def _open_create_vault(page: Page) -> None:
    page.click('.sidebar-item[data-section="vaults"]')
    page.click("#create-vault-btn")
    expect(page.locator("#create-vault-modal")).to_be_visible(timeout=8_000)


def _complete_first_key_prompts(page: Page, passphrase: str) -> None:
    """Complete the warning plus two password prompts used for first-key registration."""
    expect(page.locator("#confirm-modal")).to_be_visible(timeout=5_000)
    page.click("#confirm-modal-confirm-btn")
    for value in (passphrase, passphrase):
        expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=5_000)
        page.fill("#confirm-modal-input", value)
        page.click("#confirm-modal-confirm-btn")


def test_candidate_served_browser_reads_all_pinned_zero_knowledge_formats(browser):
    """Read every pinned browser format through the exact JavaScript served by the candidate."""
    vectors = _load_browser_vectors()
    context = browser.new_context(base_url=BASE_URL)
    try:
        served = context.request.get(
            f"{BASE_URL}/static/js/ecc_crypto.js?crypto-compatibility"
        )
        assert served.ok, f"candidate crypto script returned HTTP {served.status}"
        assert (
            hashlib.sha256(served.body()).hexdigest()
            == hashlib.sha256(
                (_REPO_ROOT / "static" / "js" / "ecc_crypto.js").read_bytes()
            ).hexdigest()
        ), "candidate served crypto script differs from the source checkout"

        page = context.new_page()
        response = page.goto("/")
        assert response is not None and response.ok, (
            "candidate did not serve the browser shell"
        )
        page.wait_for_function(
            "typeof ECCCryptoLibrary !== 'undefined' && typeof eccLib === 'function'",
            timeout=10_000,
        )
        results = page.evaluate(
            """
            async vectors => {
                const lib = eccLib();
                const fromB64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
                const toB64 = value => {
                    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
                    let binary = '';
                    for (const byte of bytes) binary += String.fromCharCode(byte);
                    return btoa(binary);
                };
                const toHex = value => Array.from(new Uint8Array(value))
                    .map(byte => byte.toString(16).padStart(2, '0')).join('');
                const importDek = hex => window.crypto.subtle.importKey(
                    'raw',
                    Uint8Array.from(hex.match(/../g), byte => parseInt(byte, 16)),
                    { name: 'AES-GCM', length: 256 },
                    true,
                    ['encrypt', 'decrypt'],
                );

                const contentKey = await importDek(vectors.content.inputs.dek_hex);
                const contentPlaintext = await lib.decryptFile(
                    fromB64(vectors.content.encoded_b64), contentKey);

                const envelope = vectors.private_envelope.expected.envelope;
                const privatePem = await lib.decryptPrivateKey(
                    envelope.encrypted,
                    vectors.private_envelope.inputs.password,
                    envelope.salt,
                    envelope.iterations,
                );

                const recipientPrivate = await lib.importPrivateKeyPEM(
                    vectors.direct_wrap.recipient_private_pem, false);
                const directKey = await lib.unwrapVaultDEK(
                    vectors.direct_wrap.expected.wrapped_dek_b64,
                    vectors.direct_wrap.expected.ephemeral_public_key_b64,
                    recipientPrivate,
                );
                const directRaw = await window.crypto.subtle.exportKey('raw', directKey);

                const memberPrivate = await lib.importPrivateKeyPEM(
                    vectors.team_wrap.member_private_pem, false);
                const teamPrivate = await lib.unwrapPrivateKeyFromWrapped(
                    vectors.team_wrap.expected.wrapped_key_b64,
                    vectors.team_wrap.expected.ephemeral_public_key_b64,
                    memberPrivate,
                    true,
                );
                const teamPkcs8 = await window.crypto.subtle.exportKey('pkcs8', teamPrivate);

                const nameOneKey = await importDek(vectors.name_zk1.inputs.dek_hex);
                const nameOne = await lib.decryptName(
                    vectors.name_zk1.expected.token,
                    nameOneKey,
                    vectors.name_zk1.inputs.vault_id,
                    vectors.name_zk1.inputs.field,
                    vectors.name_zk1.inputs.epoch,
                );
                const prefixlessNameOne = await lib.decryptName(
                    vectors.name_zk1.encoded_b64,
                    nameOneKey,
                    vectors.name_zk1.inputs.vault_id,
                    vectors.name_zk1.inputs.field,
                    vectors.name_zk1.inputs.epoch,
                );
                const nameOneBlind = await lib.nameBlindIndex(
                    nameOne,
                    nameOneKey,
                    vectors.name_zk1.inputs.vault_id,
                    vectors.name_zk1.inputs.epoch,
                );

                const nameTwoKey = await importDek(vectors.name_zk2.inputs.dek_hex);
                const nameTwo = await lib.decryptName(
                    vectors.name_zk2.expected.token,
                    nameTwoKey,
                    vectors.name_zk2.inputs.vault_id,
                    vectors.name_zk2.inputs.field,
                    vectors.name_zk2.inputs.epoch,
                    vectors.name_zk2.inputs.object_id,
                );
                const nameTwoBlind = await lib.nameBlindIndex(
                    nameTwo,
                    nameTwoKey,
                    vectors.name_zk2.inputs.vault_id,
                    vectors.name_zk2.inputs.epoch,
                );

                return {
                    content_plaintext_b64: toB64(contentPlaintext),
                    private_pem: privatePem,
                    direct_dek_hex: toHex(directRaw),
                    team_private_pkcs8_b64: toB64(teamPkcs8),
                    name_zk1: nameOne,
                    name_zk1_prefixless: prefixlessNameOne,
                    name_zk1_blind: nameOneBlind,
                    name_zk2: nameTwo,
                    name_zk2_blind: nameTwoBlind,
                };
            }
            """,
            vectors,
        )

        assert results == {
            "content_plaintext_b64": vectors["content"]["expected"]["plaintext_b64"],
            "private_pem": vectors["private_envelope"]["private_key_pem"],
            "direct_dek_hex": vectors["direct_wrap"]["inputs"]["dek_hex"],
            "team_private_pkcs8_b64": vectors["team_wrap"]["team_private_pkcs8_b64"],
            "name_zk1": vectors["name_zk1"]["inputs"]["plaintext"],
            "name_zk1_prefixless": vectors["name_zk1"]["inputs"]["plaintext"],
            "name_zk1_blind": vectors["name_zk1"]["expected"]["blind_index"],
            "name_zk2": vectors["name_zk2"]["inputs"]["plaintext"],
            "name_zk2_blind": vectors["name_zk2"]["expected"]["blind_index"],
        }
    finally:
        context.close()


@pytest.mark.characterization
def test_create_only_temp_existing_key_fetches_private_blob_before_vault_create(
    browser, admin
):
    """Freeze the release-baseline create-only request order without endorsing it as the target.

    At the pinned release a create-only temporary session can create a zero-knowledge vault when
    the account already owns an identity key.  The official client nevertheless fetches and
    unlocks the encrypted private-key blob before wrapping a fresh DEK to the public account key.
    A later least-privilege change is expected to flip this characterization to no private fetch.
    """
    settings_before = None
    user = None
    owner = None
    temp_username = None
    vault_id = None
    contexts = {}
    cleanup_errors = []
    passphrase = "crypto-create-only-test-passphrase"
    vault_name = _unique("crypto_create_only")

    try:
        settings_response = admin.get("/settings")
        assert settings_response.status_code == 200, settings_response.text
        current_settings = settings_response.json()
        settings_before = {
            "zero_knowledge_enabled": current_settings["zero_knowledge_enabled"],
            "temp_cred_allow_zk_vaults": current_settings["temp_cred_allow_zk_vaults"],
        }
        changed = admin.put(
            "/settings",
            json={"zero_knowledge_enabled": True, "temp_cred_allow_zk_vaults": True},
        )
        assert changed.status_code == 200, changed.text

        user = admin.create_user(role="admin")
        owner = ApiClient()
        owner.login(user["_username"], user["_password"])

        setup_context = browser.new_context(base_url=BASE_URL)
        contexts["interactive key setup"] = setup_context
        setup_page = setup_context.new_page()
        _login(setup_page, user["_username"], user["_password"])
        _set_up_account_key(setup_page, passphrase)
        assert owner.get("/ecc/keys/public").json().get("has_keypair") is True
        setup_context.close()

        scope = {
            "v": 1,
            "pages": ["vaults"],
            "caps": ["vault.create"],
            "vault_caps_default": [],
            "temp": {},
        }
        minted = owner.post(
            "/auth/temp-credentials",
            json={"validity_minutes": 30, "scope": scope, "vault_access_mode": "all"},
        )
        assert minted.status_code == 200, minted.text
        credential = minted.json()
        temp_username = credential["temp_username"]

        temp_context = browser.new_context(base_url=BASE_URL)
        contexts["temporary credential"] = temp_context
        page = temp_context.new_page()
        _login(page, temp_username, credential["credential"])
        _open_create_vault(page)
        page.fill("#vault-name", vault_name)
        expect(page.locator("#vault-type-group")).to_be_visible(timeout=5_000)
        page.select_option("#vault-type", "zero_knowledge")

        requests_seen = []

        def record_request(request):
            path = urlsplit(request.url).path
            if path in {
                "/ecc/keys/public",
                "/ecc/keys/private",
                "/ecc/keys/register/challenge",
                "/ecc/keys/register",
                "/vaults",
            }:
                requests_seen.append((request.method, path))

        page.on("request", record_request)
        page.click("#create-vault-form button[type=submit]")
        expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=8_000)
        page.fill("#confirm-modal-input", passphrase)
        page.click("#confirm-modal-confirm-btn")
        expect(page.locator("#create-vault-modal")).to_be_hidden(timeout=20_000)

        matches = [v for v in owner.get("/vaults").json() if v["name"] == vault_name]
        assert len(matches) == 1, (
            f"create-only zero-knowledge vault mismatch: {matches!r}"
        )
        vault_id = matches[0]["id"]

        public_positions = [
            index
            for index, event in enumerate(requests_seen)
            if event == ("GET", "/ecc/keys/public")
        ]
        private_position = requests_seen.index(("GET", "/ecc/keys/private"))
        create_position = requests_seen.index(("POST", "/vaults"))
        assert len(public_positions) >= 2, requests_seen
        assert (
            public_positions[0]
            < private_position
            < public_positions[-1]
            < create_position
        ), requests_seen
        assert not any(
            path.startswith("/ecc/keys/register") for _, path in requests_seen
        ), requests_seen
    finally:
        _cleanup_contexts(contexts, cleanup_errors)
        if temp_username is not None:
            _cleanup_temp_credential(owner, temp_username, cleanup_errors)
        if vault_id is not None:
            _cleanup_vault(owner, vault_id, cleanup_errors)
        if user is not None:
            _cleanup_user(admin, user["id"], cleanup_errors)
        if settings_before is not None:
            _restore_settings(admin, settings_before, cleanup_errors)
        _raise_cleanup_errors(cleanup_errors)


def test_hierarchical_zero_knowledge_upload_download_survives_fresh_login(
    browser, admin
):
    """Create/write a hierarchical vault, then unwrap and download in a fresh context."""
    settings_before = None
    user = None
    owner = None
    vault_id = None
    contexts = {}
    cleanup_errors = []
    passphrase = "crypto-hierarchical-test-passphrase"
    vault_name = _unique("crypto_hierarchical")
    file_name = _unique("crypto_hierarchical_file") + ".txt"
    marker = _unique("CRYPTO_HIERARCHICAL_PAYLOAD")
    plaintext = (f"{marker} hierarchical fresh-login round-trip\n".encode("utf-8")) * 5

    try:
        settings_response = admin.get("/settings")
        assert settings_response.status_code == 200, settings_response.text
        current_settings = settings_response.json()
        settings_before = {
            "zero_knowledge_enabled": current_settings["zero_knowledge_enabled"]
        }
        changed = admin.put("/settings", json={"zero_knowledge_enabled": True})
        assert changed.status_code == 200, changed.text

        user = admin.create_user(role="admin")
        owner = ApiClient()
        owner.login(user["_username"], user["_password"])

        writer_context = browser.new_context(base_url=BASE_URL)
        contexts["hierarchical writer"] = writer_context
        writer = writer_context.new_page()
        _login(writer, user["_username"], user["_password"])
        _open_create_vault(writer)
        writer.fill("#vault-name", vault_name)
        expect(writer.locator("#vault-type-group")).to_be_visible(timeout=5_000)
        writer.select_option("#vault-type", "zero_knowledge")
        expect(writer.locator("#vault-hierarchical-wrap")).to_be_visible(timeout=5_000)
        writer.check("#vault-hierarchical")
        writer.click("#create-vault-form button[type=submit]")
        _complete_first_key_prompts(writer, passphrase)
        expect(writer.locator("#create-vault-modal")).to_be_hidden(timeout=20_000)

        matches = [v for v in owner.get("/vaults").json() if v["name"] == vault_name]
        assert len(matches) == 1, f"hierarchical vault mismatch: {matches!r}"
        vault_id = matches[0]["id"]
        keys = owner.get(f"/ecc/vaults/{vault_id}/keys")
        assert keys.status_code == 200, keys.text
        descriptor = keys.json()
        assert descriptor.get("mode") == "hierarchical", descriptor
        assert descriptor.get("wrapped_team_privkey"), descriptor
        assert descriptor.get("team_ephemeral_public_key"), descriptor

        writer.click('.sidebar-item[data-section="vaults"]')
        writer.wait_for_selector(
            f'.open-vault-btn[data-vault-id="{vault_id}"]', timeout=10_000
        )
        writer.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
        expect(writer.locator("#vault-view-section")).to_be_visible(timeout=10_000)
        writer.set_input_files(
            "#file-upload-input",
            files=[{"name": file_name, "mimeType": "text/plain", "buffer": plaintext}],
        )

        file_id = None
        for _ in range(50):
            items = owner.get(f"/vaults/{vault_id}/files").json()["items"]
            hit = [item for item in items if item["type"] == "file"]
            if hit:
                file_id = hit[0]["id"]
                break
            writer.wait_for_timeout(400)
        assert file_id, "hierarchical browser upload never completed"
        stored = owner.get(f"/vaults/{vault_id}/files/{file_id}/download").content
        assert stored != plaintext
        assert marker.encode("utf-8") not in stored

        writer_context.close()

        reader_context = browser.new_context(base_url=BASE_URL, accept_downloads=True)
        contexts["fresh-login reader"] = reader_context
        reader = reader_context.new_page()
        _login(reader, user["_username"], user["_password"])
        reader_requests = []

        def record_reader_request(request):
            path = urlsplit(request.url).path
            if path.startswith("/ecc/") or path.endswith("/download"):
                reader_requests.append((request.method, path))

        reader.on("request", record_reader_request)
        reader.click('.sidebar-item[data-section="vaults"]')
        reader.wait_for_selector(
            f'.open-vault-btn[data-vault-id="{vault_id}"]', timeout=10_000
        )
        reader.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
        expect(reader.locator("#confirm-modal-input")).to_be_visible(timeout=10_000)
        reader.fill("#confirm-modal-input", passphrase)
        reader.click("#confirm-modal-confirm-btn")
        reader.wait_for_selector(
            f'.file-name[data-file-name="{file_name}"]', timeout=15_000
        )

        reader.click(f'.file-name[data-file-name="{file_name}"]')
        expect(reader.locator("#file-preview-modal")).to_be_visible(timeout=10_000)
        expect(reader.locator("#file-preview-body")).to_contain_text(
            marker, timeout=10_000
        )
        with reader.expect_download(timeout=15_000) as download_info:
            reader.click("#file-preview-download")
        downloaded_path = download_info.value.path()
        assert downloaded_path, "browser produced no downloaded file path"
        assert Path(downloaded_path).read_bytes() == plaintext

        assert ("GET", "/ecc/keys/private") in reader_requests, reader_requests
        assert ("GET", f"/ecc/vaults/{vault_id}/keys") in reader_requests, (
            reader_requests
        )
        assert (
            "GET",
            f"/vaults/{vault_id}/files/{file_id}/download",
        ) in reader_requests, reader_requests
    finally:
        _cleanup_contexts(contexts, cleanup_errors)
        if vault_id is not None:
            _cleanup_vault(owner, vault_id, cleanup_errors)
        if user is not None:
            _cleanup_user(admin, user["id"], cleanup_errors)
        if settings_before is not None:
            _restore_settings(admin, settings_before, cleanup_errors)
        _raise_cleanup_errors(cleanup_errors)
