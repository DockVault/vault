"""Temporary-credential / zero-knowledge key-boundary compatibility matrix.

The ordinary tests pin security invariants that already hold. Tests marked
``characterization`` record a permissive compatibility baseline that temp
key-scope hardening or private-envelope replacement proof is expected to
reverse. A temporary credential never receives a zero-knowledge passphrase:
the server can return only the opaque private-key envelope that the owner
previously encrypted in the browser.
"""

from contextlib import contextmanager
import json
import os
import subprocess
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from conftest import (
    ZK_EPHEMERAL_STUB,
    ZK_WRAPPED_DEK_STUB,
    compute_registration_pop,
    create_zk_vault,
    ensure_ecc_keypair,
    unique,
    zk_chunked_upload,
    zk_encrypt_name,
    zk_name_blind_index,
)


pytestmark = pytest.mark.crypto_compatibility


_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_TEMP_PERMS_OFF = {
    "view": False,
    "create": False,
    "invalidate": False,
    "clear": False,
    "delegate": False,
}


def _opaque_envelope(label: str) -> str:
    """A unique, syntactically realistic ciphertext envelope (never a secret)."""
    return json.dumps(
        {
            "encrypted": unique(f"cipher_{label}"),
            "salt": unique(f"salt_{label}"),
            "iterations": 600000,
        },
        sort_keys=True,
    )


def _registration_payload(client, envelope: str) -> dict:
    """Build a valid P-384 registration request, including proof of possession."""
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return {
        "public_key": public_key,
        "encrypted_private_key": envelope,
        "pop": compute_registration_pop(client, private_key, public_key),
    }


def _register_identity(client, envelope: str) -> dict:
    response = client.post(
        "/ecc/keys/register",
        json=_registration_payload(client, envelope),
    )
    assert response.status_code == 201, response.text
    identity = client.get("/ecc/keys/public")
    assert identity.status_code == 200, identity.text
    return identity.json()


def _scope(*, pages=("vaults",), global_caps=(), default_caps=()) -> dict:
    return {
        "v": 1,
        "pages": list(pages),
        "caps": list(global_caps),
        "vault_caps_default": list(default_caps),
        "temp": dict(_TEMP_PERMS_OFF),
    }


def _selected(vault_id, caps, *, scope_ids=None) -> dict:
    selected = {"vault_id": str(vault_id), "caps": list(caps)}
    if scope_ids is not None:
        selected["scope_ids"] = scope_ids
    return selected


def _stored_scope(temp_username: str):
    """Read the normalized selected-vault object scope persisted for a temp credential."""
    safe_username = str(temp_username).replace("'", "''")
    sql = (
        "SELECT tcva.scope_ids FROM temp_credential_vault_access tcva "
        "JOIN temporary_credentials tc ON tc.id = tcva.temp_credential_id "
        f"WHERE tc.temp_username = '{safe_username}';"
    )
    result = subprocess.run(
        [
            "docker",
            "exec",
            _DB_CONTAINER,
            "psql",
            "-U",
            "sftp_user",
            "-d",
            "sftp_db",
            "-tAc",
            sql,
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    value = (result.stdout or "").strip()
    return json.loads(value) if value else None


def _record_cleanup_response(errors, label, response, expected_status=200) -> None:
    if response.status_code != expected_status:
        errors.append(
            f"{label}: expected {expected_status}, got "
            f"{response.status_code}: {response.text}"
        )


def _record_cleanup_call(errors, label, operation) -> None:
    try:
        response = operation()
    except Exception as exc:  # noqa: BLE001 - cleanup must continue to later resources
        errors.append(f"{label}: raised {type(exc).__name__}: {exc}")
        return
    _record_cleanup_response(errors, label, response)


def _cleanup_temp_credentials(owner, usernames, errors=None) -> None:
    """Attempt every exact credential deletion; no missing row is expected or accepted."""
    own_errors = errors is None
    errors = [] if errors is None else errors
    for username in dict.fromkeys(str(value) for value in usernames if value):
        _record_cleanup_call(
            errors,
            f"delete temporary credential {username}",
            lambda username=username: owner.post(f"/temp-creds/{username}/delete"),
        )
    if own_errors and errors:
        raise AssertionError("cleanup failures:\n" + "\n".join(errors))


def _cleanup_owned_vaults(owner, vault_ids, errors=None) -> None:
    """Attempt every exact owned-vault deletion before reporting any failure."""
    own_errors = errors is None
    errors = [] if errors is None else errors
    for vault_id in dict.fromkeys(str(value) for value in vault_ids if value):
        _record_cleanup_call(
            errors,
            f"delete vault {vault_id}",
            lambda vault_id=vault_id: owner.delete_vault(vault_id),
        )
    if own_errors and errors:
        raise AssertionError("cleanup failures:\n" + "\n".join(errors))


def _restore_private_envelope(owner, envelope: str, errors) -> None:
    """Attempt restoration and its independent read-back before later cleanup proceeds."""
    try:
        restored = owner.put(
            "/ecc/keys/private",
            json={"encrypted_private_key": envelope},
        )
        _record_cleanup_response(errors, "restore private-key envelope", restored)
    except Exception as exc:  # noqa: BLE001 - the read-back and vault cleanup must still run
        errors.append(
            f"restore private-key envelope: raised {type(exc).__name__}: {exc}"
        )

    try:
        read_back = owner.get("/ecc/keys/private")
        _record_cleanup_response(
            errors, "read restored private-key envelope", read_back
        )
        if read_back.status_code == 200:
            actual = read_back.json().get("encrypted_private_key")
            if actual != envelope:
                errors.append(
                    "read restored private-key envelope: ciphertext did not match "
                    "the original envelope"
                )
    except Exception as exc:  # noqa: BLE001 - vault cleanup must still run
        errors.append(
            f"read restored private-key envelope: raised {type(exc).__name__}: {exc}"
        )


def _raise_cleanup_errors(errors) -> None:
    if errors:
        raise AssertionError("cleanup failures:\n" + "\n".join(errors))


@contextmanager
def _settings(admin, **updates):
    """Apply global settings and restore the exact prior values on every exit."""
    before_response = admin.get("/settings")
    assert before_response.status_code == 200, before_response.text
    before = before_response.json()
    restore = {key: before[key] for key in updates}

    changed = admin.put("/settings", json=updates)
    assert changed.status_code == 200, changed.text
    try:
        yield
    finally:
        restored = admin.put("/settings", json=restore)
        assert restored.status_code == 200, restored.text


@contextmanager
def _minted_temp(
    owner,
    *,
    mode="selected",
    pages=("vaults",),
    global_caps=(),
    default_caps=(),
    selected=(),
):
    """Mint, log in, then require exact deletion of one scoped temp credential."""
    response = owner.post(
        "/auth/temp-credentials",
        json={
            "validity_minutes": 60,
            "scope": _scope(
                pages=pages,
                global_caps=global_caps,
                default_caps=default_caps,
            ),
            "vault_access_mode": mode,
            "selected_vaults": list(selected),
        },
    )
    assert response.status_code == 200, response.text
    credential = response.json()
    temp = owner.clone_anonymous()
    try:
        temp.login(credential["temp_username"], credential["credential"])
        yield temp, credential
    finally:
        _cleanup_temp_credentials(owner, [credential["temp_username"]])


@contextmanager
def _minted_unscoped(owner):
    """Mint, log in, then require exact deletion of a legacy/unscoped credential."""
    response = owner.post(
        "/auth/temp-credentials",
        json={"validity_minutes": 60},
    )
    assert response.status_code == 200, response.text
    credential = response.json()
    temp = owner.clone_anonymous()
    try:
        temp.login(credential["temp_username"], credential["credential"])
        yield temp, credential
    finally:
        _cleanup_temp_credentials(owner, [credential["temp_username"]])


def _temp_names(owner) -> set:
    response = owner.get("/temp-creds/list")
    assert response.status_code == 200, response.text
    return {row["temp_username"] for row in response.json()}


def _assert_private_envelope(temp, envelope: str, case: str) -> None:
    response = temp.get("/ecc/keys/private")
    assert response.status_code == 200, f"{case}: {response.text}"
    assert response.json() == {
        "has_keypair": True,
        "encrypted_private_key": envelope,
    }, case


def _assert_wrapped_dek(temp, vault_id, wrapped_dek, case: str) -> None:
    response = temp.get(f"/ecc/vaults/{vault_id}/keys")
    assert response.status_code == 200, f"{case}: {response.text}"
    assert response.json()["has_access"] is True, case
    assert response.json()["wrapped_dek"] == wrapped_dek, case


def _assert_paired_key_access(
    temp,
    vault_id,
    envelope,
    wrapped_dek,
    *,
    expected_status,
    case,
) -> None:
    """Exercise both key-release halves through one deliberately flippable assertion.

    Characterization calls use 200 today. Once new conflicting mints are denied,
    the legacy-row fixture remains and this single expected status changes to the
    access-denial status for both endpoints; neither half can silently disappear.
    """
    private_response = temp.get("/ecc/keys/private")
    wrapped_response = temp.get(f"/ecc/vaults/{vault_id}/keys")
    assert private_response.status_code == expected_status, (
        f"{case} private envelope: {private_response.text}"
    )
    assert wrapped_response.status_code == expected_status, (
        f"{case} wrapped DEK: {wrapped_response.text}"
    )
    if expected_status == 200:
        assert private_response.json()["encrypted_private_key"] == envelope, case
        assert wrapped_response.json()["has_access"] is True, case
        assert wrapped_response.json()["wrapped_dek"] == wrapped_dek, case


def _assert_selected_session_caps(temp, vault_id, expected_caps, case: str) -> None:
    """Prove a cap-denial case reached the endpoint with the intended persisted grant."""
    response = temp.get("/auth/session")
    assert response.status_code == 200, f"{case}: {response.text}"
    session = response.json()
    exact_caps = sorted(expected_caps)
    assert session["vault_access_mode"] == "selected", case
    assert session["vault_caps"] == {str(vault_id): exact_caps}, case
    assert session["vault_caps_default"] == exact_caps, case
    assert session["caps"] == [], case


def _assert_all_session_caps(
    temp, *, expected_global_caps, expected_default_caps, case: str
) -> None:
    """Prove an all-mode principal exposes exactly the requested effective scope."""
    response = temp.get("/auth/session")
    assert response.status_code == 200, f"{case}: {response.text}"
    session = response.json()
    assert session["vault_access_mode"] == "all", case
    assert session["caps"] == sorted(expected_global_caps), case
    assert session["vault_caps_default"] == sorted(expected_default_caps), case
    assert session["vault_caps"] == {}, case


def _create_zk_folder(client, vault_id, name_key: bytes) -> str:
    name = unique("zk_folder")
    response = client.post(
        f"/vaults/{vault_id}/folders",
        json={
            "enc_name": zk_encrypt_name(name, name_key, vault_id, "name", 1),
            "name_bi": zk_name_blind_index(name, name_key, vault_id, 1),
            "name_key_version": 1,
        },
    )
    assert response.status_code == 200, response.text
    return str(response.json()["folder"]["id"])


def test_temp_zk_selected_scope_fetches_opaque_identity_and_only_granted_wrap(
    admin, temp_user_client
):
    """A qualifying ZK grant returns ciphertext + its own wrap, never another vault's."""
    owner = temp_user_client
    envelope = _opaque_envelope("selected")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            granted = create_zk_vault(owner, name=unique("zk_granted"))
            vault_ids.append(granted["id"])
            other = create_zk_vault(owner, name=unique("zk_other"))
            vault_ids.append(other["id"])
            caps = ["vault.see_files"]
            with _minted_temp(
                owner,
                selected=[_selected(granted["id"], caps)],
                default_caps=caps,
            ) as (temp, _):
                _assert_private_envelope(temp, envelope, "qualifying selected ZK")
                _assert_wrapped_dek(
                    temp,
                    granted["id"],
                    ZK_WRAPPED_DEK_STUB,
                    "qualifying selected ZK",
                )
                assert temp.get(f"/ecc/vaults/{other['id']}/keys").status_code == 403
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


@pytest.mark.characterization
def test_private_blob_scope_policy_and_object_id_compatibility_matrix(
    admin, temp_user_client
):
    """Record the complete pre-hardening private-envelope read matrix.

    Current behavior returns the account envelope for every authenticated temp
    shape below. Required hardening excludes create-only, Standard-only, ZK
    grants without a qualifying read/manage capability, and every explicit
    file/folder ID map, including stale IDs.
    """
    owner = temp_user_client
    envelope = _opaque_envelope("private_matrix")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            zk_vault = create_zk_vault(owner, name=unique("zk_private_matrix"))
            vault_ids.append(zk_vault["id"])
            standard_vault = owner.create_vault(name=unique("standard_private_matrix"))
            vault_ids.append(standard_vault["id"])
            name_key = b"p" * 32
            file_id = str(
                zk_chunked_upload(
                    owner,
                    zk_vault["id"],
                    "private-matrix.txt",
                    b"opaque-private-matrix",
                    name_key,
                )
            )
            folder_id = _create_zk_folder(owner, zk_vault["id"], name_key)
            stale_id = str(uuid.uuid4())

            with _minted_unscoped(owner) as (temp, _):
                _assert_private_envelope(temp, envelope, "legacy/unscoped")

            with _minted_temp(
                owner,
                mode="all",
                global_caps=["vault.create.zero_knowledge"],
            ) as (temp, _):
                _assert_all_session_caps(
                    temp,
                    expected_global_caps=["vault.create.zero_knowledge"],
                    expected_default_caps=[],
                    case="all-vault create-only",
                )
                _assert_private_envelope(temp, envelope, "all-vault create-only")

            for case, caps, expanded_caps in (
                ("ZK no cap", [], []),
                ("ZK see_info", ["vault.see_info"], ["vault.see_info"]),
                (
                    "ZK see_files",
                    ["vault.see_files"],
                    ["vault.see_files", "vault.see_info"],
                ),
                (
                    "ZK change_permissions",
                    ["vault.change_permissions"],
                    ["vault.change_permissions", "vault.see_info"],
                ),
            ):
                with _minted_temp(
                    owner,
                    selected=[_selected(zk_vault["id"], caps)],
                    default_caps=caps,
                ) as (temp, _):
                    _assert_selected_session_caps(
                        temp,
                        zk_vault["id"],
                        expanded_caps,
                        case,
                    )
                    _assert_private_envelope(temp, envelope, case)

            for case, scope_ids in (
                ("explicit file ID", {"files": [file_id], "folders": []}),
                ("explicit folder ID", {"files": [], "folders": [folder_id]}),
                ("explicit stale ID", {"files": [stale_id], "folders": []}),
            ):
                caps = ["vault.see_files"]
                with _minted_temp(
                    owner,
                    selected=[_selected(zk_vault["id"], caps, scope_ids=scope_ids)],
                    default_caps=caps,
                ) as (temp, credential):
                    assert _stored_scope(credential["temp_username"]) == scope_ids
                    _assert_private_envelope(temp, envelope, case)

            disabled = admin.put("/settings", json={"temp_cred_allow_zk_vaults": False})
            assert disabled.status_code == 200, disabled.text
            standard_caps = ["vault.see_info"]
            with _minted_temp(
                owner,
                selected=[_selected(standard_vault["id"], standard_caps)],
                default_caps=standard_caps,
            ) as (temp, _):
                _assert_selected_session_caps(
                    temp,
                    standard_vault["id"],
                    ["vault.see_info"],
                    "Standard-only while ZK temp policy is disabled",
                )
                _assert_private_envelope(
                    temp,
                    envelope,
                    "Standard-only while ZK temp policy is disabled",
                )
                assert temp.get(f"/ecc/vaults/{zk_vault['id']}/keys").status_code == 403
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_no_key_ordinary_and_temp_reads_and_temp_identity_write_denials(
    temp_user_client,
):
    """No-key reads are stable, while temp sessions cannot plant or replace identity state."""
    owner = temp_user_client
    absent = {"has_keypair": False, "encrypted_private_key": None}

    ordinary = owner.get("/ecc/keys/private")
    assert ordinary.status_code == 200, ordinary.text
    assert ordinary.json() == absent

    with _minted_temp(owner, pages=("dashboard",)) as (temp, _):
        temporary = temp.get("/ecc/keys/private")
        assert temporary.status_code == 200, temporary.text
        assert temporary.json() == absent

        planted = temp.post(
            "/ecc/keys/register",
            json=_registration_payload(temp, _opaque_envelope("temp_plant")),
        )
        assert planted.status_code == 403, planted.text
        assert owner.get("/ecc/keys/public").json()["has_keypair"] is False

        owner_envelope = _opaque_envelope("owner_after_denial")
        _register_identity(owner, owner_envelope)
        replaced = temp.put(
            "/ecc/keys/private",
            json={"encrypted_private_key": _opaque_envelope("temp_replace")},
        )
        assert replaced.status_code == 403, replaced.text
        assert (
            owner.get("/ecc/keys/private").json()["encrypted_private_key"]
            == owner_envelope
        )


@pytest.mark.characterization
def test_ordinary_recovery_rewrap_preserves_identity_without_fresh_proof(
    admin, temp_user_client
):
    """Current weakness: an ordinary bearer replaces the envelope without fresh proof.

    Rewrapping preserves the registered public identity and its vault wraps. The
    original envelope is restored with an independent read-back in ``finally``;
    vault cleanup is attempted even if either restoration check fails.
    """
    owner = temp_user_client
    original = _opaque_envelope("ordinary_original")
    identity = _register_identity(owner, original)
    replacement = _opaque_envelope("ordinary_unproven")
    vault_ids = []
    replacement_applied = False

    with _settings(admin, zero_knowledge_enabled=True):
        try:
            vault = create_zk_vault(owner, name=unique("zk_recovery_identity"))
            vault_ids.append(vault["id"])
            before_keys = owner.get(f"/ecc/vaults/{vault['id']}/keys")
            assert before_keys.status_code == 200, before_keys.text

            changed = owner.put(
                "/ecc/keys/private",
                json={"encrypted_private_key": replacement},
            )
            assert changed.status_code == 200, changed.text
            replacement_applied = True
            assert (
                owner.get("/ecc/keys/private").json()["encrypted_private_key"]
                == replacement
            )

            after_identity = owner.get("/ecc/keys/public").json()
            assert after_identity["user_id"] == identity["user_id"]
            assert after_identity["public_key"] == identity["public_key"]
            assert after_identity["fingerprint"] == identity["fingerprint"]
            after_keys = owner.get(f"/ecc/vaults/{vault['id']}/keys")
            assert after_keys.status_code == 200, after_keys.text
            assert after_keys.json()["wrapped_dek"] == before_keys.json()["wrapped_dek"]
        finally:
            cleanup_errors = []
            if replacement_applied:
                _restore_private_envelope(owner, original, cleanup_errors)
            _cleanup_owned_vaults(owner, vault_ids, cleanup_errors)
            _raise_cleanup_errors(cleanup_errors)


def test_wrapped_dek_capability_vault_and_legacy_compatibility_matrix(
    admin, temp_user_client
):
    """Pin cap qualification, wrong-vault confinement, and legacy compatibility."""
    owner = temp_user_client
    _register_identity(owner, _opaque_envelope("wrapped_matrix"))
    vault_ids = []
    cap_cases = (
        ("no cap", [], [], 403),
        ("see_info", ["vault.see_info"], ["vault.see_info"], 403),
        (
            "file.download",
            ["file.download"],
            ["file.download", "vault.see_info"],
            403,
        ),
        (
            "vault.rotate_key",
            ["vault.rotate_key"],
            ["vault.rotate_key", "vault.see_info"],
            403,
        ),
        (
            "see_files",
            ["vault.see_files"],
            ["vault.see_files", "vault.see_info"],
            200,
        ),
        (
            "change_permissions",
            ["vault.change_permissions"],
            ["vault.change_permissions", "vault.see_info"],
            200,
        ),
        (
            "see_files + change_permissions",
            ["vault.see_files", "vault.change_permissions"],
            [
                "vault.change_permissions",
                "vault.see_files",
                "vault.see_info",
            ],
            200,
        ),
    )

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            granted = create_zk_vault(owner, name=unique("zk_wrapped_granted"))
            vault_ids.append(granted["id"])
            other = create_zk_vault(owner, name=unique("zk_wrapped_other"))
            vault_ids.append(other["id"])

            with _minted_unscoped(owner) as (temp, _):
                _assert_wrapped_dek(
                    temp,
                    granted["id"],
                    ZK_WRAPPED_DEK_STUB,
                    "legacy/unscoped",
                )

            for case, requested_caps, expanded_caps, expected_status in cap_cases:
                with _minted_temp(
                    owner,
                    selected=[_selected(granted["id"], requested_caps)],
                    default_caps=requested_caps,
                ) as (temp, _):
                    _assert_selected_session_caps(
                        temp,
                        granted["id"],
                        expanded_caps,
                        case,
                    )
                    response = temp.get(f"/ecc/vaults/{granted['id']}/keys")
                    assert response.status_code == expected_status, (
                        f"{case}: {response.text}"
                    )
                    if expected_status == 200:
                        assert response.json()["has_access"] is True, case
                        assert response.json()["wrapped_dek"] == ZK_WRAPPED_DEK_STUB, (
                            case
                        )

            caps = ["vault.see_files"]
            expanded_caps = ["vault.see_files", "vault.see_info"]
            with _minted_temp(
                owner,
                selected=[_selected(granted["id"], caps)],
                default_caps=caps,
            ) as (temp, _):
                _assert_selected_session_caps(
                    temp,
                    granted["id"],
                    expanded_caps,
                    "wrong vault",
                )
                assert temp.get(f"/ecc/vaults/{other['id']}/keys").status_code == 403
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


@pytest.mark.characterization
def test_new_zk_object_scoped_mint_currently_persists_before_hardening(
    admin, temp_user_client
):
    """Characterize today's successful object-scoped ZK mints and persisted rows.

    Required mint hardening flips each file-only, folder-only, and stale-ID case
    to 4xx before persistence and changes its exact temp-name assertion to
    equality with that attempt's before_names. Access-time denial for rows stored
    before transition remains independently exercised below.
    """
    owner = temp_user_client
    _register_identity(owner, _opaque_envelope("new_object_mint"))
    vault_ids = []
    minted_usernames = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = create_zk_vault(owner, name=unique("zk_new_object_mint"))
            vault_ids.append(vault["id"])
            name_key = b"m" * 32
            file_id = str(
                zk_chunked_upload(
                    owner,
                    vault["id"],
                    "new-object-mint.txt",
                    b"opaque-new-object-mint",
                    name_key,
                )
            )
            folder_id = _create_zk_folder(owner, vault["id"], name_key)
            caps = ["vault.see_files"]

            for case, scope_ids in (
                ("file-only", {"files": [file_id], "folders": []}),
                ("folder-only", {"files": [], "folders": [folder_id]}),
                ("stale-ID", {"files": [str(uuid.uuid4())], "folders": []}),
            ):
                before_names = _temp_names(owner)
                response = owner.post(
                    "/auth/temp-credentials",
                    json={
                        "validity_minutes": 60,
                        "scope": _scope(default_caps=caps),
                        "vault_access_mode": "selected",
                        "selected_vaults": [
                            _selected(vault["id"], caps, scope_ids=scope_ids)
                        ],
                    },
                )
                assert response.status_code == 200, f"{case}: {response.text}"
                minted_username = response.json()["temp_username"]
                minted_usernames.append(minted_username)
                assert _stored_scope(minted_username) == scope_ids, case
                assert _temp_names(owner) == before_names | {minted_username}, case
        finally:
            cleanup_errors = []
            _cleanup_temp_credentials(owner, minted_usernames, cleanup_errors)
            _cleanup_owned_vaults(owner, vault_ids, cleanup_errors)
            _raise_cleanup_errors(cleanup_errors)


@pytest.mark.characterization
def test_existing_object_scoped_credentials_reach_paired_key_endpoints_today(
    admin, temp_user_client
):
    """Exercise stored file, folder, and stale-ID conflicts through both key endpoints.

    Today the public mint endpoint seeds these pre-hardening rows. Once new rows
    are rejected, this setup must seed the equivalent legacy access row directly;
    ``_assert_paired_key_access`` then flips from 200 to the denial status for both
    the account envelope and wrapped DEK. Exact root visibility proves that each
    persisted object scope is active before the key-release assertions.
    """
    owner = temp_user_client
    envelope = _opaque_envelope("existing_object_scope")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = create_zk_vault(owner, name=unique("zk_existing_object_scope"))
            vault_ids.append(vault["id"])
            name_key = b"i" * 32
            file_id = str(
                zk_chunked_upload(
                    owner,
                    vault["id"],
                    "allowed.txt",
                    b"opaque-a",
                    name_key,
                )
            )
            hidden_file_id = str(
                zk_chunked_upload(
                    owner,
                    vault["id"],
                    "hidden.txt",
                    b"opaque-b",
                    name_key,
                )
            )
            folder_id = _create_zk_folder(owner, vault["id"], name_key)
            stale_id = str(uuid.uuid4())
            cases = (
                ("file ID", {"files": [file_id], "folders": []}, {file_id}),
                ("folder ID", {"files": [], "folders": [folder_id]}, {folder_id}),
                ("stale ID", {"files": [stale_id], "folders": []}, set()),
            )

            for case, scope_ids, expected_visible in cases:
                caps = ["vault.see_files"]
                with _minted_temp(
                    owner,
                    selected=[_selected(vault["id"], caps, scope_ids=scope_ids)],
                    default_caps=caps,
                ) as (temp, credential):
                    assert _stored_scope(credential["temp_username"]) == scope_ids
                    listing = temp.get(f"/vaults/{vault['id']}/files")
                    assert listing.status_code == 200, f"{case}: {listing.text}"
                    visible_ids = {str(item["id"]) for item in listing.json()["items"]}
                    assert visible_ids == expected_visible, case
                    assert hidden_file_id not in visible_ids, case
                    _assert_paired_key_access(
                        temp,
                        vault["id"],
                        envelope,
                        ZK_WRAPPED_DEK_STUB,
                        expected_status=200,
                        case=case,
                    )
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


@pytest.mark.characterization
def test_id_scoped_change_permissions_allows_vault_wide_safe_noop(
    admin, temp_user_client
):
    """Current weakness: an object-scoped manager cap reaches vault-wide key controls."""
    owner = temp_user_client
    _register_identity(owner, _opaque_envelope("id_manager"))
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = create_zk_vault(owner, name=unique("zk_id_manager"))
            vault_ids.append(vault["id"])
            caps = ["vault.change_permissions"]
            scope_ids = {"files": [str(uuid.uuid4())], "folders": []}
            with _minted_temp(
                owner,
                selected=[_selected(vault["id"], caps, scope_ids=scope_ids)],
                default_caps=caps,
            ) as (temp, credential):
                assert _stored_scope(credential["temp_username"]) == scope_ids
                _assert_wrapped_dek(
                    temp,
                    vault["id"],
                    ZK_WRAPPED_DEK_STUB,
                    "ID-scoped change_permissions",
                )
                retired = temp.post(f"/ecc/vaults/{vault['id']}/retire-version")
                assert retired.status_code == 200, retired.text
                assert retired.json()["rows_deleted"] == 0
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


@pytest.mark.characterization
def test_reader_manager_cap_wrap_exposure_preserves_real_manager_mutation_check(
    admin, temp_user, temp_user_client
):
    """Record the current distinction between lexical temp caps and live vault role."""
    reader = temp_user_client
    ensure_ecc_keypair(reader)
    ensure_ecc_keypair(admin)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = create_zk_vault(admin, name=unique("zk_reader_role"))
            vault_ids.append(vault["id"])
            wrapped_for_reader = "cmVhZGVyLXdyYXBwZWQtZGVr"
            shared = admin.post(
                f"/ecc/vaults/{vault['id']}/members",
                json={
                    "user_id": str(temp_user["id"]),
                    "wrapped_dek": wrapped_for_reader,
                    "ephemeral_public_key": ZK_EPHEMERAL_STUB,
                },
            )
            assert shared.status_code == 200, shared.text
            granted = admin.post(
                f"/vaults/{vault['id']}/permissions",
                json={"user_id": str(temp_user["id"]), "level": "read"},
            )
            assert granted.status_code == 200, granted.text

            caps = ["vault.change_permissions"]
            with _minted_temp(
                reader,
                selected=[_selected(vault["id"], caps)],
                default_caps=caps,
            ) as (temp, _):
                _assert_wrapped_dek(
                    temp,
                    vault["id"],
                    wrapped_for_reader,
                    "read member with lexical manager cap",
                )
                mutation = temp.post(
                    f"/vaults/{vault['id']}/permissions",
                    json={"user_id": str(uuid.uuid4()), "level": "read"},
                )
                assert mutation.status_code == 403, mutation.text
        finally:
            _cleanup_owned_vaults(admin, vault_ids)


def test_zk_policy_denies_new_selected_all_and_unrestricted_mints(
    admin, temp_user_client
):
    """The deny policy rejects every new credential shape that can reach a live ZK vault."""
    owner = temp_user_client
    _register_identity(owner, _opaque_envelope("policy_deny"))
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=False,
    ):
        try:
            vault = create_zk_vault(owner, name=unique("zk_policy_deny"))
            vault_ids.append(vault["id"])
            before_names = _temp_names(owner)
            caps = ["vault.see_files"]
            attempts = (
                {
                    "validity_minutes": 60,
                    "scope": _scope(default_caps=caps),
                    "vault_access_mode": "selected",
                    "selected_vaults": [_selected(vault["id"], caps)],
                },
                {
                    "validity_minutes": 60,
                    "scope": _scope(default_caps=caps),
                    "vault_access_mode": "all",
                    "selected_vaults": [],
                },
                {"validity_minutes": 60},
            )
            for request_body in attempts:
                denied = owner.post("/auth/temp-credentials", json=request_body)
                assert denied.status_code == 400, denied.text
                assert "zero-knowledge" in denied.text.lower()
            assert _temp_names(owner) == before_names
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


@pytest.mark.characterization
def test_policy_flip_existing_temp_currently_retains_private_and_wrapped_keys(
    admin, temp_user_client
):
    """Current weakness: the ZK temp-policy switch is checked only at mint time.

    Required hardening is live denial: after the setting becomes false, every
    later private-envelope and wrapped-DEK request from an existing temporary
    session must be denied. This test records the pre-hardening 200 responses
    while also proving that a new mint is rejected without persistence.
    """
    owner = temp_user_client
    envelope = _opaque_envelope("policy_flip")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = create_zk_vault(owner, name=unique("zk_policy_flip"))
            vault_ids.append(vault["id"])
            caps = ["vault.see_files"]
            with _minted_temp(
                owner,
                selected=[_selected(vault["id"], caps)],
                default_caps=caps,
            ) as (temp, _):
                disabled = admin.put(
                    "/settings", json={"temp_cred_allow_zk_vaults": False}
                )
                assert disabled.status_code == 200, disabled.text

                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=200,
                    case="post-policy-flip",
                )

                before_names = _temp_names(owner)
                denied = owner.post(
                    "/auth/temp-credentials",
                    json={
                        "validity_minutes": 60,
                        "scope": _scope(default_caps=caps),
                        "vault_access_mode": "selected",
                        "selected_vaults": [_selected(vault["id"], caps)],
                    },
                )
                assert denied.status_code == 400, denied.text
                assert _temp_names(owner) == before_names
        finally:
            _cleanup_owned_vaults(owner, vault_ids)
