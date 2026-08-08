"""Temporary-credential / zero-knowledge key-boundary compatibility matrix.

These tests pin security invariants that hold today: the whole-vault temporary key-access
boundary, and proof-bound replacement of the private-key envelope. No ``characterization``
tests remain -- the last one recorded that an ordinary bearer could replace the envelope
without proof, and it has been flipped now that the replacement path requires one. A temporary
credential never receives a zero-knowledge passphrase: the server can return only the opaque
private-key envelope that the owner previously encrypted in the browser.
"""

from contextlib import contextmanager
import json
import os
import subprocess
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from app.core.zk_temp_access import TEMP_ZK_KEY_ACCESS_DENIED
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
_REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
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


def _scope(*, pages=("vaults",), global_caps=(), default_caps=(), temp_perms=None) -> dict:
    return {
        "v": 1,
        "pages": list(pages),
        "caps": list(global_caps),
        "vault_caps_default": list(default_caps),
        "temp": dict(_TEMP_PERMS_OFF if temp_perms is None else temp_perms),
    }


def _selected(vault_id, caps, *, scope_ids=None) -> dict:
    selected = {"vault_id": str(vault_id), "caps": list(caps)}
    if scope_ids is not None:
        selected["scope_ids"] = scope_ids
    return selected


def _psql(sql: str) -> str:
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
    return (result.stdout or "").strip()


def _redis_temp_keys() -> set:
    result = subprocess.run(
        [
            "docker",
            "exec",
            _REDIS_CONTAINER,
            "redis-cli",
            "--scan",
            "--pattern",
            "temp_cred:*",
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _db_temp_counts(user_id) -> tuple:
    safe_user_id = str(user_id).replace("'", "''")
    credentials = int(
        _psql(
            "SELECT count(*) FROM temporary_credentials "
            f"WHERE user_id = '{safe_user_id}';"
        )
    )
    access_rows = int(
        _psql(
            "SELECT count(*) FROM temp_credential_vault_access tcva "
            "JOIN temporary_credentials tc ON tc.id = tcva.temp_credential_id "
            f"WHERE tc.user_id = '{safe_user_id}';"
        )
    )
    return credentials, access_rows


def _persisted_temp_state(owner) -> tuple:
    return (
        frozenset(_temp_names(owner)),
        _db_temp_counts(owner.user["id"]),
        frozenset(_redis_temp_keys()),
    )


def _set_stored_scope_sql(temp_username, vault_id, sql_value: str) -> None:
    safe_username = str(temp_username).replace("'", "''")
    safe_vault_id = str(vault_id).replace("'", "''")
    result = _psql(
        "UPDATE temp_credential_vault_access AS tcva "
        f"SET scope_ids = {sql_value} "
        "FROM temporary_credentials AS tc "
        "WHERE tc.id = tcva.temp_credential_id "
        f"AND tc.temp_username = '{safe_username}' "
        f"AND tcva.vault_id = '{safe_vault_id}';"
    )
    assert result == "UPDATE 1", result


def _set_stored_scope(temp_username, vault_id, scope) -> None:
    encoded = json.dumps(scope, sort_keys=True).replace("'", "''")
    _set_stored_scope_sql(temp_username, vault_id, f"'{encoded}'::json")


def _stored_scope(temp_username: str, vault_id=None):
    """Read the normalized selected-vault object scope persisted for a temp credential."""
    safe_username = str(temp_username).replace("'", "''")
    sql = (
        "SELECT tcva.scope_ids FROM temp_credential_vault_access tcva "
        "JOIN temporary_credentials tc ON tc.id = tcva.temp_credential_id "
        f"WHERE tc.temp_username = '{safe_username}'"
    )
    if vault_id is not None:
        safe_vault_id = str(vault_id).replace("'", "''")
        sql += f" AND tcva.vault_id = '{safe_vault_id}'"
    sql += ";"
    value = _psql(sql)
    return json.loads(value) if value else None


def _set_stored_caps(temp_username, vault_id, caps) -> None:
    safe_username = str(temp_username).replace("'", "''")
    safe_vault_id = str(vault_id).replace("'", "''")
    encoded = json.dumps(caps, sort_keys=True).replace("'", "''")
    result = _psql(
        "UPDATE temp_credential_vault_access AS tcva "
        f"SET vault_caps = '{encoded}'::json "
        "FROM temporary_credentials AS tc "
        "WHERE tc.id = tcva.temp_credential_id "
        f"AND tc.temp_username = '{safe_username}' "
        f"AND tcva.vault_id = '{safe_vault_id}';"
    )
    assert result == "UPDATE 1", result


def _stored_caps(temp_username, vault_id):
    safe_username = str(temp_username).replace("'", "''")
    safe_vault_id = str(vault_id).replace("'", "''")
    value = _psql(
        "SELECT tcva.vault_caps FROM temp_credential_vault_access tcva "
        "JOIN temporary_credentials tc ON tc.id = tcva.temp_credential_id "
        f"WHERE tc.temp_username = '{safe_username}' "
        f"AND tcva.vault_id = '{safe_vault_id}';"
    )
    return json.loads(value)


def _set_credential_scope(temp_username, scope) -> None:
    safe_username = str(temp_username).replace("'", "''")
    encoded = json.dumps(scope, sort_keys=True).replace("'", "''")
    result = _psql(
        "UPDATE temporary_credentials "
        f"SET scope = '{encoded}'::json "
        f"WHERE temp_username = '{safe_username}';"
    )
    assert result == "UPDATE 1", result


def _stored_credential_scope(temp_username):
    safe_username = str(temp_username).replace("'", "''")
    value = _psql(
        "SELECT scope FROM temporary_credentials "
        f"WHERE temp_username = '{safe_username}';"
    )
    return json.loads(value)


def _set_current_member_key_active(vault_id, user_id, active: bool) -> None:
    safe_vault_id = str(vault_id).replace("'", "''")
    safe_user_id = str(user_id).replace("'", "''")
    sql_bool = "TRUE" if active else "FALSE"
    result = _psql(
        "UPDATE vault_member_keys AS vmk "
        f"SET is_active = {sql_bool} "
        "FROM vaults AS v "
        "WHERE vmk.vault_id = v.id "
        f"AND vmk.vault_id = '{safe_vault_id}' "
        f"AND vmk.user_id = '{safe_user_id}' "
        "AND vmk.key_version = v.dek_version;"
    )
    assert result == "UPDATE 1", result


def _set_current_teampriv_active(vault_id, user_id, active: bool) -> None:
    safe_vault_id = str(vault_id).replace("'", "''")
    safe_user_id = str(user_id).replace("'", "''")
    sql_bool = "TRUE" if active else "FALSE"
    result = _psql(
        "UPDATE vault_member_keys AS vmk "
        f"SET is_active = {sql_bool} "
        "FROM vaults AS v "
        "WHERE vmk.vault_id = v.id "
        f"AND vmk.vault_id = '{safe_vault_id}' "
        f"AND vmk.user_id = '{safe_user_id}' "
        "AND vmk.key_version = v.team_key_version "
        "AND vmk.wrapping_algorithm = "
        "'ECDH-P384-AES-GCM-TEAMPRIV';"
    )
    assert result == "UPDATE 1", result


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
    temp_perms=None,
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
                temp_perms=temp_perms,
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
    """Exercise both key-release halves through one shared expectation.

    The account envelope and a vault's wrapped key are governed by a single eligibility
    decision, so every caller asserts ONE status for both endpoints. That is the point of
    this helper: a change that starts serving one artifact while denying the other cannot
    pass, in either direction, and neither half can silently disappear from a case.
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
    else:
        private_body = private_response.json()
        wrapped_body = wrapped_response.json()
        assert private_body == wrapped_body, case
        assert set(private_body) == {"detail"}, case
        # Pin the VALUE, not just the shape. A shape-only check accepts a future
        # "friendlier" denial that names its reason -- and the reason a temporary session is
        # refused must never reveal whether the account has registered a keypair.
        if expected_status == 403:
            assert private_body["detail"] == TEMP_ZK_KEY_ACCESS_DENIED, case
        serialized = json.dumps(private_body).lower()
        for secret_field in (
            "encrypted_private_key", "wrapped_dek", "wrapped_team_privkey"
        ):
            assert secret_field not in serialized, case


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


def test_private_blob_whole_vault_scope_and_policy_matrix(
    admin, temp_user_client
):
    """Only a live whole-vault ZK authority may release account key material.

    Legacy credentials remain compatible, while create-only, Standard-only,
    and non-qualifying ZK grants receive the same generic denial as wrapped keys.
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
                _assert_paired_key_access(
                    temp,
                    zk_vault["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=403,
                    case="all-vault create-only",
                )

            for case, caps in (
                ("all-vault see_files", ["vault.see_files"]),
                ("all-vault change_permissions", ["vault.change_permissions"]),
            ):
                with _minted_temp(
                    owner, mode="all", default_caps=caps
                ) as (temp, _):
                    _assert_paired_key_access(
                        temp, zk_vault["id"], envelope, ZK_WRAPPED_DEK_STUB,
                        expected_status=200, case=case,
                    )

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
                    expected_status = (
                        200
                        if case in {"ZK see_files", "ZK change_permissions"}
                        else 403
                    )
                    _assert_paired_key_access(
                        temp, zk_vault["id"], envelope, ZK_WRAPPED_DEK_STUB,
                        expected_status=expected_status, case=case,
                    )


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
                _assert_paired_key_access(
                    temp, zk_vault["id"], envelope, ZK_WRAPPED_DEK_STUB,
                    expected_status=403,
                    case="Standard-only while ZK temp policy is disabled",
                )
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
        assert temporary.status_code == 403, temporary.text
        # This account has NO keypair. The denial must be byte-identical to the one a
        # keypair-holding account gets (pinned by _assert_paired_key_access), or the
        # refusal itself becomes an oracle for which accounts have registered an identity.
        assert temporary.json() == {"detail": TEMP_ZK_KEY_ACCESS_DENIED}
        assert "encrypted_private_key" not in temporary.text

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


def test_ordinary_bearer_cannot_replace_the_envelope_without_proving_possession(
    admin, temp_user_client
):
    """An unproven replacement is refused, and the account is left exactly as it was.

    This test previously documented the OPPOSITE as a known weakness: any ordinary session for
    the account could overwrite the stored envelope. Nothing leaked -- the server cannot read
    either blob -- but the owner lost access to every vault, permanently, because registration
    refuses a second keypair and removing the first would orphan every wrapped key. The
    expectation is flipped here now that replacement requires proof of possession.

    Legitimate replacement still works and is covered by the passphrase-change and recovery
    suites; what is pinned here is the refusal and, just as importantly, that a refused attempt
    changes nothing.
    """
    owner = temp_user_client
    original = _opaque_envelope("ordinary_original")
    identity = _register_identity(owner, original)
    replacement = _opaque_envelope("ordinary_unproven")
    vault_ids = []

    with _settings(admin, zero_knowledge_enabled=True):
        try:
            vault = create_zk_vault(owner, name=unique("zk_recovery_identity"))
            vault_ids.append(vault["id"])
            before_keys = owner.get(f"/ecc/vaults/{vault['id']}/keys")
            assert before_keys.status_code == 200, before_keys.text

            # No proof at all.
            unproven = owner.put(
                "/ecc/keys/private",
                json={"encrypted_private_key": replacement},
            )
            assert unproven.status_code == 400, unproven.text

            # A well-formed but bogus proof, and a proof naming a challenge that never existed.
            for pop in (
                {"challenge_id": str(uuid.uuid4()), "mac": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
                {"challenge_id": "not-a-uuid", "mac": "AAAA"},
            ):
                bogus = owner.put(
                    "/ecc/keys/private",
                    json={"encrypted_private_key": replacement, "pop": pop},
                )
                assert bogus.status_code == 400, bogus.text

            # Nothing moved: the envelope, the registered identity and the vault wrap are intact.
            assert (
                owner.get("/ecc/keys/private").json()["encrypted_private_key"] == original
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


def test_new_zk_object_scoped_mint_is_rejected_atomically(
    admin, temp_user_client
):
    """Every explicit/malformed ZK object scope fails before DB or Redis state."""
    owner = temp_user_client
    _register_identity(owner, _opaque_envelope("new_object_mint"))
    vault_ids = []

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
                ("empty-object", {}),
                ("stale-ID", {"files": [str(uuid.uuid4())], "folders": []}),
                ("malformed-list", []),
                ("malformed-string", "whole-vault"),
            ):
                before = _persisted_temp_state(owner)
                response = owner.post(
                    "/auth/temp-credentials",
                    json={
                        "validity_minutes": 60,
                        "scope": _scope(default_caps=caps),
                        "vault_access_mode": "selected",
                        "selected_vaults": [
                            {
                                "vault_id": vault["id"],
                                "caps": caps,
                                "scope_ids": scope_ids,
                            }
                        ],
                    },
                )
                assert response.status_code == 400, f"{case}: {response.text}"
                assert set(response.json()) == {"detail"}, case
                assert _persisted_temp_state(owner) == before, case
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_standard_selected_grant_refuses_malformed_restriction_instead_of_widening_it(
    temp_user_client,
):
    """A malformed Standard restriction is refused, never silently widened to whole-vault.

    ``normalize_id_scope`` maps any non-dict to ``None``, and ``None`` means WHOLE VAULT. A
    caller that meant to restrict but sent the wrong shape therefore used to receive an
    UNRESTRICTED grant -- the restriction failed open. Resolving every selected grant before
    persistence lets the mint refuse that input instead. Duplicate selections are refused for a
    related reason: two rows for one vault left the effective grant dependent on input order.

    This covers Standard vaults specifically; the zero-knowledge equivalents live in the
    object-scope mint test, where any object map is rejected outright.
    """
    owner = temp_user_client
    vault_ids = []
    try:
        vault = owner.create_vault(name=unique("standard_malformed_scope"))
        vault_ids.append(vault["id"])
        uploaded = owner.post(
            f"/vaults/{vault['id']}/files",
            files=[("files", ("scoped.txt", b"standard-scope-target", "text/plain"))],
        )
        assert uploaded.status_code == 200, uploaded.text
        file_id = str(uploaded.json()["files"][0]["id"])
        caps = ["file.download"]

        for case, selected in (
            ("list scope_ids", [_selected(vault["id"], caps, scope_ids=[file_id])]),
            ("string scope_ids", [_selected(vault["id"], caps, scope_ids=file_id)]),
            ("integer scope_ids", [_selected(vault["id"], caps, scope_ids=7)]),
            (
                "duplicate vault",
                [_selected(vault["id"], caps), _selected(vault["id"], caps)],
            ),
        ):
            before = _persisted_temp_state(owner)
            response = owner.post(
                "/auth/temp-credentials",
                json={
                    "validity_minutes": 60,
                    "scope": _scope(default_caps=caps),
                    "vault_access_mode": "selected",
                    "selected_vaults": selected,
                },
            )
            assert response.status_code == 400, f"{case}: {response.text}"
            assert set(response.json()) == {"detail"}, case
            assert _persisted_temp_state(owner) == before, case

        # Positive control: the well-formed restriction still mints AND is actually stored as a
        # restriction. Without it a blanket rejection would satisfy every assertion above.
        minted = owner.post(
            "/auth/temp-credentials",
            json={
                "validity_minutes": 60,
                "scope": _scope(default_caps=caps),
                "vault_access_mode": "selected",
                "selected_vaults": [
                    _selected(
                        vault["id"], caps, scope_ids={"files": [file_id], "folders": []}
                    )
                ],
            },
        )
        assert minted.status_code == 200, minted.text
        credential = minted.json()
        try:
            safe_username = str(credential["temp_username"]).replace("'", "''")
            stored = _psql(
                "SELECT tcva.scope_ids::text FROM temp_credential_vault_access AS tcva "
                "JOIN temporary_credentials AS tc ON tc.id = tcva.temp_credential_id "
                f"WHERE tc.temp_username = '{safe_username}';"
            )
            assert stored not in ("", "NULL"), stored
            assert file_id in stored, stored
        finally:
            _cleanup_temp_credentials(owner, [credential["temp_username"]])
    finally:
        _cleanup_owned_vaults(owner, vault_ids)


def test_live_scope_change_to_zk_object_scope_denies_further_key_release(
    admin, temp_user_client
):
    """A DB-live object-scope transition cuts off both key-release endpoints."""
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
                    selected=[_selected(vault["id"], caps)],
                    default_caps=caps,
                ) as (temp, credential):
                    _assert_paired_key_access(
                        temp,
                        vault["id"],
                        envelope,
                        ZK_WRAPPED_DEK_STUB,
                        expected_status=200,
                        case=f"{case} before live scope change",
                    )
                    _set_stored_scope(
                        credential["temp_username"], vault["id"], scope_ids
                    )
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
                        expected_status=403,
                        case=case,
                    )
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_id_scoped_change_permissions_allows_vault_wide_safe_noop(
    admin, temp_user_client
):
    """Legacy conflict denies key release without broadening into key mutators."""
    owner = temp_user_client
    envelope = _opaque_envelope("id_manager")
    _register_identity(owner, envelope)
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
                selected=[_selected(vault["id"], caps)],
                default_caps=caps,
            ) as (temp, credential):
                _set_stored_scope(
                    credential["temp_username"], vault["id"], scope_ids
                )
                assert _stored_scope(credential["temp_username"]) == scope_ids
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=403,
                    case="ID-scoped change_permissions",
                )
                retired = temp.post(f"/ecc/vaults/{vault['id']}/retire-version")
                assert retired.status_code == 200, retired.text
                assert retired.json()["rows_deleted"] == 0
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_change_permissions_key_release_tracks_live_manager_role(
    admin, temp_user, temp_user_client
):
    """A lexical manager cap qualifies only while the underlying role is Manager."""
    reader = temp_user_client
    ensure_ecc_keypair(reader)
    envelope = reader.get("/ecc/keys/private").json()["encrypted_private_key"]
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
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    wrapped_for_reader,
                    expected_status=403,
                    case="read member with lexical manager cap",
                )
                mutation = temp.post(
                    f"/vaults/{vault['id']}/permissions",
                    json={"user_id": str(uuid.uuid4()), "level": "read"},
                )
                assert mutation.status_code == 403, mutation.text

                promoted = admin.post(
                    f"/vaults/{vault['id']}/permissions",
                    json={"user_id": str(temp_user["id"]), "level": "manage"},
                )
                assert promoted.status_code == 200, promoted.text
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    wrapped_for_reader,
                    expected_status=200,
                    case="live Manager with manager cap",
                )

                downgraded = admin.post(
                    f"/vaults/{vault['id']}/permissions",
                    json={"user_id": str(temp_user["id"]), "level": "read"},
                )
                assert downgraded.status_code == 200, downgraded.text
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    wrapped_for_reader,
                    expected_status=403,
                    case="live Reader after Manager downgrade",
                )
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


def test_policy_flip_cuts_off_authenticated_selected_all_and_legacy_sessions(
    admin, temp_user_client
):
    """Every authenticated temp shape honors a policy flip on its next key read."""
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
            ) as (selected_temp, _):
                with _minted_temp(
                    owner,
                    mode="all",
                    default_caps=caps,
                ) as (all_temp, _):
                    with _minted_unscoped(owner) as (legacy_temp, _):
                        sessions = (
                            ("selected", selected_temp),
                            ("all-vault", all_temp),
                            ("legacy/unrestricted", legacy_temp),
                        )
                        for case, temp in sessions:
                            _assert_paired_key_access(
                                temp,
                                vault["id"],
                                envelope,
                                ZK_WRAPPED_DEK_STUB,
                                expected_status=200,
                                case=f"{case} before policy flip",
                            )

                        disabled = admin.put(
                            "/settings",
                            json={"temp_cred_allow_zk_vaults": False},
                        )
                        assert disabled.status_code == 200, disabled.text

                        for case, temp in sessions:
                            _assert_paired_key_access(
                                temp,
                                vault["id"],
                                envelope,
                                ZK_WRAPPED_DEK_STUB,
                                expected_status=403,
                                case=f"{case} after policy flip",
                            )

                        before = _persisted_temp_state(owner)
                        denied = owner.post(
                            "/auth/temp-credentials",
                            json={
                                "validity_minutes": 60,
                                "scope": _scope(default_caps=caps),
                                "vault_access_mode": "selected",
                                "selected_vaults": [
                                    _selected(vault["id"], caps)
                                ],
                            },
                        )
                        assert denied.status_code == 400, denied.text
                        assert _persisted_temp_state(owner) == before
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_mixed_standard_and_zk_selection_rejects_conflicts_and_duplicates_atomically(
    admin, temp_user_client
):
    """A valid Standard grant cannot make a conflicting/duplicate ZK input partial."""
    owner = temp_user_client
    envelope = _opaque_envelope("mixed_atomic")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            zk_vault = create_zk_vault(owner, name=unique("zk_mixed_atomic"))
            vault_ids.append(zk_vault["id"])
            standard_vault = owner.create_vault(name=unique("standard_mixed_atomic"))
            vault_ids.append(standard_vault["id"])

            content = b"standard-object-scope-survives"
            uploaded = owner.post(
                f"/vaults/{standard_vault['id']}/files",
                files=[("files", ("allowed.txt", content, "text/plain"))],
            )
            assert uploaded.status_code == 200, uploaded.text
            file_id = str(uploaded.json()["files"][0]["id"])

            zk_caps = ["vault.see_files"]
            standard_caps = ["vault.see_files", "file.download"]
            standard_scope = {"files": [file_id], "folders": []}
            zk_object_scope = {
                "files": [str(uuid.uuid4())],
                "folders": [],
            }
            standard_grant = _selected(
                standard_vault["id"],
                standard_caps,
                scope_ids=standard_scope,
            )
            zk_whole = _selected(zk_vault["id"], zk_caps)
            zk_object = _selected(
                zk_vault["id"],
                zk_caps,
                scope_ids=zk_object_scope,
            )

            cases = (
                ("Standard then conflicting ZK", [standard_grant, zk_object]),
                ("conflicting ZK then Standard", [zk_object, standard_grant]),
                ("duplicate ZK whole", [zk_whole, zk_whole]),
                ("duplicate ZK whole then object", [zk_whole, zk_object]),
                ("duplicate ZK object then whole", [zk_object, zk_whole]),
            )
            for case, selected in cases:
                before = _persisted_temp_state(owner)
                denied = owner.post(
                    "/auth/temp-credentials",
                    json={
                        "validity_minutes": 60,
                        "scope": _scope(default_caps=standard_caps),
                        "vault_access_mode": "selected",
                        "selected_vaults": selected,
                    },
                )
                assert denied.status_code == 400, f"{case}: {denied.text}"
                assert set(denied.json()) == {"detail"}, case
                assert _persisted_temp_state(owner) == before, case

            with _minted_temp(
                owner,
                selected=[standard_grant, zk_whole],
                default_caps=standard_caps,
            ) as (temp, credential):
                username = credential["temp_username"]
                assert _stored_scope(username, standard_vault["id"]) == standard_scope
                assert _stored_scope(username, zk_vault["id"]) is None
                _assert_paired_key_access(
                    temp,
                    zk_vault["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=200,
                    case="valid mixed Standard-object and ZK-whole selection",
                )
                downloaded = temp.get(
                    f"/vaults/{standard_vault['id']}/files/{file_id}/download"
                )
                assert downloaded.status_code == 200, downloaded.text
                assert downloaded.content == content
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_one_live_zk_object_conflict_poisons_all_key_release_not_standard_access(
    admin, temp_user_client
):
    """One conflicting ZK row blocks account/ZK keys globally, not Standard data."""
    owner = temp_user_client
    envelope = _opaque_envelope("global_conflict")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            poisoned = create_zk_vault(owner, name=unique("zk_poisoned"))
            vault_ids.append(poisoned["id"])
            unaffected_zk = create_zk_vault(owner, name=unique("zk_other_whole"))
            vault_ids.append(unaffected_zk["id"])
            standard = owner.create_vault(name=unique("standard_not_poisoned"))
            vault_ids.append(standard["id"])

            content = b"standard-access-remains-usable"
            uploaded = owner.post(
                f"/vaults/{standard['id']}/files",
                files=[("files", ("standard.txt", content, "text/plain"))],
            )
            assert uploaded.status_code == 200, uploaded.text
            file_id = str(uploaded.json()["files"][0]["id"])
            zk_caps = ["vault.see_files"]
            standard_caps = ["vault.see_files", "file.download"]
            standard_scope = {"files": [file_id], "folders": []}

            with _minted_temp(
                owner,
                selected=[
                    _selected(poisoned["id"], zk_caps),
                    _selected(unaffected_zk["id"], zk_caps),
                    _selected(
                        standard["id"],
                        standard_caps,
                        scope_ids=standard_scope,
                    ),
                ],
                default_caps=standard_caps,
            ) as (temp, credential):
                username = credential["temp_username"]
                for vault in (poisoned, unaffected_zk):
                    _assert_paired_key_access(
                        temp,
                        vault["id"],
                        envelope,
                        ZK_WRAPPED_DEK_STUB,
                        expected_status=200,
                        case=f"{vault['id']} before global conflict",
                    )

                conflict = {"files": [str(uuid.uuid4())], "folders": []}
                _set_stored_scope(username, poisoned["id"], conflict)
                assert _stored_scope(username, poisoned["id"]) == conflict

                for vault in (poisoned, unaffected_zk):
                    _assert_paired_key_access(
                        temp,
                        vault["id"],
                        envelope,
                        ZK_WRAPPED_DEK_STUB,
                        expected_status=403,
                        case=f"{vault['id']} after global conflict",
                    )

                downloaded = temp.get(
                    f"/vaults/{standard['id']}/files/{file_id}/download"
                )
                assert downloaded.status_code == 200, downloaded.text
                assert downloaded.content == content
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_sql_and_json_null_are_whole_vault_but_malformed_persisted_scope_denies(
    admin, temp_user_client
):
    """Both database null encodings mean whole-vault; any other shape fails closed."""
    owner = temp_user_client
    envelope = _opaque_envelope("stored_nulls")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = create_zk_vault(owner, name=unique("zk_stored_nulls"))
            vault_ids.append(vault["id"])
            caps = ["vault.see_files"]
            with _minted_temp(
                owner,
                selected=[_selected(vault["id"], caps)],
                default_caps=caps,
            ) as (temp, credential):
                username = credential["temp_username"]

                _set_stored_scope_sql(username, vault["id"], "NULL")
                assert _stored_scope(username, vault["id"]) is None
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=200,
                    case="SQL NULL whole-vault scope",
                )

                _set_stored_scope_sql(username, vault["id"], "'null'::json")
                assert _stored_scope(username, vault["id"]) is None
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=200,
                    case="JSON null whole-vault scope",
                )

                _set_stored_scope_sql(username, vault["id"], "'[]'::json")
                assert _stored_scope(username, vault["id"]) == []
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=403,
                    case="malformed persisted list scope",
                )
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_key_release_tracks_live_current_member_key_state(admin, temp_user_client):
    """An otherwise qualifying grant stops releasing secrets without a live current key."""
    owner = temp_user_client
    envelope = _opaque_envelope("live_current_key")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = create_zk_vault(owner, name=unique("zk_live_current_key"))
            vault_ids.append(vault["id"])
            caps = ["vault.see_files"]
            with _minted_temp(
                owner,
                selected=[_selected(vault["id"], caps)],
                default_caps=caps,
            ) as (temp, _):
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=200,
                    case="active current member key",
                )

                _set_current_member_key_active(
                    vault["id"], owner.user["id"], False
                )
                try:
                    _assert_paired_key_access(
                        temp,
                        vault["id"],
                        envelope,
                        ZK_WRAPPED_DEK_STUB,
                        expected_status=403,
                        case="inactive current member key",
                    )
                finally:
                    _set_current_member_key_active(
                        vault["id"], owner.user["id"], True
                    )

                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=200,
                    case="reactivated current member key",
                )
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_delegated_child_cannot_inherit_or_request_zk_object_scope(
    admin, temp_user_client
):
    """A live object-conflicted parent cannot mint a child that inherits whole access."""
    owner = temp_user_client
    envelope = _opaque_envelope("delegated_conflict")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = create_zk_vault(owner, name=unique("zk_delegated_conflict"))
            vault_ids.append(vault["id"])
            caps = ["vault.see_files"]
            delegating_perms = {
                "view": True,
                "create": True,
                "invalidate": True,
                "clear": False,
                "delegate": True,
            }
            with _minted_temp(
                owner,
                pages=("vaults", "temp_creds"),
                selected=[_selected(vault["id"], caps)],
                default_caps=caps,
                temp_perms=delegating_perms,
            ) as (parent, parent_credential):
                _assert_paired_key_access(
                    parent,
                    vault["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=200,
                    case="delegating parent before conflict",
                )
                conflict = {"files": [str(uuid.uuid4())], "folders": []}
                parent_username = parent_credential["temp_username"]
                _set_stored_scope(parent_username, vault["id"], conflict)
                assert _stored_scope(parent_username, vault["id"]) == conflict
                _assert_paired_key_access(
                    parent,
                    vault["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=403,
                    case="delegating parent after conflict",
                )

                child_scope = _scope(default_caps=caps)
                child_selections = (
                    ("omitted child scope", {"vault_id": vault["id"], "caps": caps}),
                    (
                        "explicit child null scope",
                        {
                            "vault_id": vault["id"],
                            "caps": caps,
                            "scope_ids": None,
                        },
                    ),
                )
                for case, child_selection in child_selections:
                    before = _persisted_temp_state(owner)
                    denied = parent.post(
                        "/auth/temp-credentials",
                        json={
                            "validity_minutes": 30,
                            "scope": child_scope,
                            "vault_access_mode": "selected",
                            "selected_vaults": [child_selection],
                        },
                    )
                    assert denied.status_code == 400, f"{case}: {denied.text}"
                    assert set(denied.json()) == {"detail"}, case
                    assert _persisted_temp_state(owner) == before, case
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_hierarchical_old_epoch_key_release_is_denied_by_live_object_conflict(
    admin, temp_user_client
):
    """The central conflict gate also covers hierarchical and explicit old epochs."""
    from test_zk_team_key import _create_hier_vault, _routine_rotate

    owner = temp_user_client
    envelope = _opaque_envelope("hierarchical_old_epoch")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = _create_hier_vault(owner)
            vault_ids.append(vault["id"])
            rotated = _routine_rotate(owner, vault["id"], 1)
            assert rotated.status_code == 200, rotated.text
            assert rotated.json()["dek_version"] == 2

            owner_current = owner.get(f"/ecc/vaults/{vault['id']}/keys")
            assert owner_current.status_code == 200, owner_current.text
            owner_old = owner.get(f"/ecc/vaults/{vault['id']}/keys?key_version=1")
            assert owner_old.status_code == 200, owner_old.text
            assert owner_current.json()["mode"] == "hierarchical"
            assert owner_current.json()["current_dek_version"] == 2
            assert owner_old.json()["key_version"] == 1

            caps = ["vault.see_files"]
            with _minted_temp(
                owner,
                selected=[_selected(vault["id"], caps)],
                default_caps=caps,
            ) as (temp, credential):
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    owner_current.json()["wrapped_dek"],
                    expected_status=200,
                    case="hierarchical current epoch before conflict",
                )
                temp_old = temp.get(
                    f"/ecc/vaults/{vault['id']}/keys?key_version=1"
                )
                assert temp_old.status_code == 200, temp_old.text
                assert temp_old.json()["wrapped_dek"] == owner_old.json()["wrapped_dek"]
                assert (
                    temp_old.json()["wrapped_team_privkey"]
                    == owner_old.json()["wrapped_team_privkey"]
                )

                conflict = {"files": [str(uuid.uuid4())], "folders": []}
                username = credential["temp_username"]
                _set_stored_scope(username, vault["id"], conflict)
                assert _stored_scope(username, vault["id"]) == conflict
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    owner_current.json()["wrapped_dek"],
                    expected_status=403,
                    case="hierarchical current epoch after conflict",
                )
                denied_old = temp.get(
                    f"/ecc/vaults/{vault['id']}/keys?key_version=1"
                )
                assert denied_old.status_code == 403, denied_old.text
                assert set(denied_old.json()) == {"detail"}
                serialized = json.dumps(denied_old.json()).lower()
                for secret_field in (
                    "encrypted_private_key",
                    "wrapped_dek",
                    "wrapped_team_privkey",
                ):
                    assert secret_field not in serialized
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_global_admin_manager_cap_requires_live_direct_relationship_not_key_only(
    admin, temp_user_client
):
    """Global Admin elevates a Reader relationship, but an orphan wrap grants nothing."""
    owner = temp_user_client
    assert str(owner.user["id"]) != str(admin.user["id"])
    ensure_ecc_keypair(owner)
    ensure_ecc_keypair(admin)
    admin_envelope_response = admin.get("/ecc/keys/private")
    assert admin_envelope_response.status_code == 200, admin_envelope_response.text
    admin_envelope = admin_envelope_response.json()["encrypted_private_key"]
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = create_zk_vault(owner, name=unique("zk_global_admin_reader"))
            vault_ids.append(vault["id"])
            wrapped_for_admin = "YWRtaW4td3JhcHBlZC1kZWs="
            shared = owner.post(
                f"/ecc/vaults/{vault['id']}/members",
                json={
                    "user_id": str(admin.user["id"]),
                    "wrapped_dek": wrapped_for_admin,
                    "ephemeral_public_key": ZK_EPHEMERAL_STUB,
                },
            )
            assert shared.status_code == 200, shared.text
            reader = owner.post(
                f"/vaults/{vault['id']}/permissions",
                json={"user_id": str(admin.user["id"]), "level": "read"},
            )
            assert reader.status_code == 200, reader.text

            safe_vault_id = str(vault["id"]).replace("'", "''")
            safe_admin_id = str(admin.user["id"]).replace("'", "''")
            reader_state = _psql(
                "SELECT read_permission::text || '|' || manage_permission::text "
                "FROM vault_members "
                f"WHERE vault_id = '{safe_vault_id}' "
                f"AND user_id = '{safe_admin_id}';"
            )
            assert reader_state == "true|false"

            caps = ["vault.change_permissions"]
            with _minted_temp(
                admin,
                selected=[_selected(vault["id"], caps)],
                default_caps=caps,
            ) as (temp, _):
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    admin_envelope,
                    wrapped_for_admin,
                    expected_status=200,
                    case="global Admin with direct Reader relationship",
                )

                deleted = _psql(
                    "DELETE FROM vault_members "
                    f"WHERE vault_id = '{safe_vault_id}' "
                    f"AND user_id = '{safe_admin_id}';"
                )
                assert deleted == "DELETE 1", deleted
                active_current_wraps = _psql(
                    "SELECT count(*) FROM vault_member_keys AS vmk "
                    "JOIN vaults AS v ON v.id = vmk.vault_id "
                    f"WHERE vmk.vault_id = '{safe_vault_id}' "
                    f"AND vmk.user_id = '{safe_admin_id}' "
                    "AND vmk.key_version = v.dek_version "
                    "AND vmk.is_active IS TRUE;"
                )
                assert active_current_wraps == "1"

                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    admin_envelope,
                    wrapped_for_admin,
                    expected_status=403,
                    case="global Admin key-only after direct relationship removal",
                )
                assert _psql(
                    "SELECT count(*) FROM vault_member_keys AS vmk "
                    "JOIN vaults AS v ON v.id = vmk.vault_id "
                    f"WHERE vmk.vault_id = '{safe_vault_id}' "
                    f"AND vmk.user_id = '{safe_admin_id}' "
                    "AND vmk.key_version = v.dek_version "
                    "AND vmk.is_active IS TRUE;"
                ) == "1"
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_object_scope_conflict_poisons_other_valid_zk_when_current_wrap_is_inactive(
    admin, temp_user_client
):
    """Exact-cap object conflicts remain global even if their own wrap is inactive."""
    owner = temp_user_client
    envelope = _opaque_envelope("inactive_conflict_wrap")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            conflicting = create_zk_vault(
                owner, name=unique("zk_inactive_object_conflict")
            )
            vault_ids.append(conflicting["id"])
            otherwise_valid = create_zk_vault(
                owner, name=unique("zk_other_valid_whole")
            )
            vault_ids.append(otherwise_valid["id"])
            caps = ["vault.see_files"]

            with _minted_temp(
                owner,
                selected=[
                    _selected(conflicting["id"], caps),
                    _selected(otherwise_valid["id"], caps),
                ],
                default_caps=caps,
            ) as (temp, credential):
                _assert_paired_key_access(
                    temp,
                    otherwise_valid["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=200,
                    case="other whole-vault ZK before inactive conflict",
                )

                conflict = {"files": [str(uuid.uuid4())], "folders": []}
                username = credential["temp_username"]
                _set_stored_scope(username, conflicting["id"], conflict)
                assert _stored_scope(username, conflicting["id"]) == conflict
                _set_current_member_key_active(
                    conflicting["id"], owner.user["id"], False
                )
                try:
                    safe_vault_id = str(conflicting["id"]).replace("'", "''")
                    safe_user_id = str(owner.user["id"]).replace("'", "''")
                    assert _psql(
                        "SELECT count(*) FROM vault_member_keys AS vmk "
                        "JOIN vaults AS v ON v.id = vmk.vault_id "
                        f"WHERE vmk.vault_id = '{safe_vault_id}' "
                        f"AND vmk.user_id = '{safe_user_id}' "
                        "AND vmk.key_version = v.dek_version "
                        "AND vmk.is_active IS TRUE;"
                    ) == "0"

                    _assert_paired_key_access(
                        temp,
                        otherwise_valid["id"],
                        envelope,
                        ZK_WRAPPED_DEK_STUB,
                        expected_status=403,
                        case="inactive-wrap object conflict poisons other valid ZK",
                    )

                    _set_stored_scope_sql(
                        username, conflicting["id"], "NULL"
                    )
                    assert _stored_scope(username, conflicting["id"]) is None
                    _assert_paired_key_access(
                        temp,
                        otherwise_valid["id"],
                        envelope,
                        ZK_WRAPPED_DEK_STUB,
                        expected_status=200,
                        case="inactive unrelated wrap without object conflict",
                    )
                finally:
                    _set_current_member_key_active(
                        conflicting["id"], owner.user["id"], True
                    )
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_conflicted_parent_cannot_mint_zk_subset_but_can_mint_standard_child(
    admin, temp_user_client
):
    """A child cannot select around its parent's global ZK object conflict."""
    owner = temp_user_client
    envelope = _opaque_envelope("delegated_subset_conflict")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            conflicting = create_zk_vault(
                owner, name=unique("zk_parent_object_conflict")
            )
            vault_ids.append(conflicting["id"])
            otherwise_valid = create_zk_vault(
                owner, name=unique("zk_parent_other_whole")
            )
            vault_ids.append(otherwise_valid["id"])
            standard = owner.create_vault(name=unique("standard_child_allowed"))
            vault_ids.append(standard["id"])

            content = b"standard-child-remains-usable"
            uploaded = owner.post(
                f"/vaults/{standard['id']}/files",
                files=[("files", ("allowed.txt", content, "text/plain"))],
            )
            assert uploaded.status_code == 200, uploaded.text
            file_id = str(uploaded.json()["files"][0]["id"])

            zk_caps = ["vault.see_files"]
            standard_caps = ["vault.see_files", "file.download"]
            standard_scope = {"files": [file_id], "folders": []}
            create_only_temp_perms = {
                "view": True,
                "create": True,
                "invalidate": False,
                "clear": False,
                "delegate": False,
            }
            with _minted_temp(
                owner,
                pages=("vaults", "temp_creds"),
                selected=[
                    _selected(conflicting["id"], zk_caps),
                    _selected(otherwise_valid["id"], zk_caps),
                    _selected(
                        standard["id"],
                        standard_caps,
                        scope_ids=standard_scope,
                    ),
                ],
                default_caps=standard_caps,
                temp_perms=create_only_temp_perms,
            ) as (parent, parent_credential):
                conflict = {"files": [str(uuid.uuid4())], "folders": []}
                parent_username = parent_credential["temp_username"]
                _set_stored_scope(
                    parent_username, conflicting["id"], conflict
                )
                assert (
                    _stored_scope(parent_username, conflicting["id"])
                    == conflict
                )
                _assert_paired_key_access(
                    parent,
                    otherwise_valid["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=403,
                    case="parent-wide object conflict before child mint",
                )

                explicit_child_scope = _scope(default_caps=zk_caps)
                b_only = _selected(otherwise_valid["id"], zk_caps)
                denied_requests = (
                    (
                        "explicit selected B-only child",
                        {
                            "validity_minutes": 30,
                            "scope": explicit_child_scope,
                            "vault_access_mode": "selected",
                            "selected_vaults": [b_only],
                        },
                    ),
                    (
                        "requested-all B-only child",
                        {
                            "validity_minutes": 30,
                            "scope": explicit_child_scope,
                            "vault_access_mode": "all",
                            "selected_vaults": [b_only],
                        },
                    ),
                    (
                        "inherited-scope B-only child",
                        {
                            "validity_minutes": 30,
                            "vault_access_mode": "selected",
                            "selected_vaults": [b_only],
                        },
                    ),
                )
                for case, request_body in denied_requests:
                    before = _persisted_temp_state(owner)
                    denied = parent.post(
                        "/auth/temp-credentials", json=request_body
                    )
                    if denied.status_code == 200:
                        leaked_username = denied.json().get("temp_username")
                        _cleanup_temp_credentials(owner, [leaked_username])
                        pytest.fail(
                            f"{case}: parent conflict was bypassed by child "
                            f"{leaked_username}"
                        )
                    assert denied.status_code == 400, f"{case}: {denied.text}"
                    assert set(denied.json()) == {"detail"}, case
                    assert _persisted_temp_state(owner) == before, case

                standard_child = parent.post(
                    "/auth/temp-credentials",
                    json={
                        "validity_minutes": 30,
                        "scope": _scope(default_caps=standard_caps),
                        "vault_access_mode": "selected",
                        "selected_vaults": [
                            _selected(
                                standard["id"],
                                standard_caps,
                                scope_ids=standard_scope,
                            )
                        ],
                    },
                )
                assert standard_child.status_code == 200, standard_child.text
                child_credential = standard_child.json()
                child_username = child_credential["temp_username"]
                child = owner.clone_anonymous()
                try:
                    assert (
                        _stored_scope(child_username, standard["id"])
                        == standard_scope
                    )
                    child.login(
                        child_username, child_credential["credential"]
                    )
                    downloaded = child.get(
                        f"/vaults/{standard['id']}/files/{file_id}/download"
                    )
                    assert downloaded.status_code == 200, downloaded.text
                    assert downloaded.content == content
                    assert child.get("/ecc/keys/private").status_code == 403
                finally:
                    _cleanup_temp_credentials(owner, [child_username])
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_nonqualifying_object_caps_do_not_poison_until_live_cap_becomes_qualifying(
    admin, temp_user_client
):
    """Live persisted caps control conflict poisoning without implicit cap grants."""
    owner = temp_user_client
    envelope = _opaque_envelope("live_object_caps")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            object_scoped = create_zk_vault(
                owner, name=unique("zk_nonqualifying_object_caps")
            )
            vault_ids.append(object_scoped["id"])
            valid_whole = create_zk_vault(
                owner, name=unique("zk_valid_whole_caps")
            )
            vault_ids.append(valid_whole["id"])
            conflict = {"files": [str(uuid.uuid4())], "folders": []}
            qualifying = ["vault.see_files"]
            restored_nonqualifying = [
                "vault.see_info",
                "file.download",
                "vault.rotate_key",
            ]

            with _minted_temp(
                owner,
                selected=[
                    _selected(object_scoped["id"], ["vault.see_info"]),
                    _selected(valid_whole["id"], qualifying),
                ],
                default_caps=qualifying,
            ) as (temp, credential):
                username = credential["temp_username"]
                _set_stored_scope(username, object_scoped["id"], conflict)
                assert _stored_scope(username, object_scoped["id"]) == conflict

                for case, caps in (
                    ("see_info only", ["vault.see_info"]),
                    (
                        "download plus see_info",
                        ["vault.see_info", "file.download"],
                    ),
                    (
                        "rotate plus see_info",
                        ["vault.see_info", "vault.rotate_key"],
                    ),
                    (
                        "all nonqualifying caps",
                        restored_nonqualifying,
                    ),
                ):
                    _set_stored_caps(username, object_scoped["id"], caps)
                    assert _stored_caps(username, object_scoped["id"]) == caps
                    _assert_paired_key_access(
                        temp,
                        valid_whole["id"],
                        envelope,
                        ZK_WRAPPED_DEK_STUB,
                        expected_status=200,
                        case=f"nonqualifying object caps: {case}",
                    )

                _set_stored_caps(
                    username, object_scoped["id"], qualifying
                )
                assert _stored_caps(username, object_scoped["id"]) == qualifying
                _assert_paired_key_access(
                    temp,
                    valid_whole["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=403,
                    case="live exact qualifying object cap",
                )

                _set_stored_caps(
                    username, object_scoped["id"], restored_nonqualifying
                )
                assert (
                    _stored_caps(username, object_scoped["id"])
                    == restored_nonqualifying
                )
                _assert_paired_key_access(
                    temp,
                    valid_whole["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=200,
                    case="live cap mutation restored to nonqualifying",
                )

                malformed_qualifying = {"vault.see_files": True}
                _set_stored_caps(
                    username, object_scoped["id"], malformed_qualifying
                )
                assert (
                    _stored_caps(username, object_scoped["id"])
                    == malformed_qualifying
                )
                _assert_paired_key_access(
                    temp,
                    valid_whole["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=403,
                    case="malformed qualifying object-cap mapping",
                )

                _set_stored_caps(
                    username, object_scoped["id"], restored_nonqualifying
                )
                _assert_paired_key_access(
                    temp,
                    valid_whole["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=200,
                    case="restored after malformed object-cap mapping",
                )

            with _minted_temp(
                owner,
                selected=[
                    _selected(object_scoped["id"], ["vault.see_info"])
                ],
                default_caps=["vault.see_info"],
            ) as (malformed_whole_temp, credential):
                username = credential["temp_username"]
                assert _stored_scope(username, object_scoped["id"]) is None
                malformed_qualifying = {"vault.see_files": True}
                _set_stored_caps(
                    username, object_scoped["id"], malformed_qualifying
                )
                assert (
                    _stored_caps(username, object_scoped["id"])
                    == malformed_qualifying
                )
                _assert_paired_key_access(
                    malformed_whole_temp,
                    object_scoped["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=403,
                    case="malformed whole-vault caps never authorize",
                )
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_direct_mode_old_epoch_cannot_substitute_for_inactive_current_epoch(
    admin, temp_user_client
):
    """A direct old-epoch wrap is unusable when the current-epoch wrap is inactive."""
    from test_zk_dek_rotation import _mk

    owner = temp_user_client
    envelope = _opaque_envelope("direct_old_epoch")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = create_zk_vault(owner, name=unique("zk_direct_old_epoch"))
            vault_ids.append(vault["id"])
            rotated = owner.post(
                f"/ecc/vaults/{vault['id']}/rekey",
                json={
                    "from_version": 1,
                    "to_version": 2,
                    "revoke_user_id": None,
                    "member_keys": [_mk(owner.user["id"])],
                },
            )
            assert rotated.status_code == 200, rotated.text

            current = owner.get(f"/ecc/vaults/{vault['id']}/keys")
            old = owner.get(f"/ecc/vaults/{vault['id']}/keys?key_version=1")
            assert current.status_code == 200, current.text
            assert old.status_code == 200, old.text
            assert current.json()["mode"] == "direct"
            assert current.json()["current_dek_version"] == 2
            assert current.json()["key_version"] == 2
            assert old.json()["key_version"] == 1

            caps = ["vault.see_files"]
            with _minted_temp(
                owner,
                selected=[_selected(vault["id"], caps)],
                default_caps=caps,
            ) as (temp, _):
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    current.json()["wrapped_dek"],
                    expected_status=200,
                    case="direct current epoch active",
                )
                old_before = temp.get(
                    f"/ecc/vaults/{vault['id']}/keys?key_version=1"
                )
                assert old_before.status_code == 200, old_before.text
                assert old_before.json()["wrapped_dek"] == old.json()["wrapped_dek"]

                _set_current_member_key_active(
                    vault["id"], owner.user["id"], False
                )
                try:
                    safe_vault_id = str(vault["id"]).replace("'", "''")
                    safe_user_id = str(owner.user["id"]).replace("'", "''")
                    active_versions = _psql(
                        "SELECT string_agg(key_version::text, ',' "
                        "ORDER BY key_version) FROM vault_member_keys "
                        f"WHERE vault_id = '{safe_vault_id}' "
                        f"AND user_id = '{safe_user_id}' "
                        "AND is_active IS TRUE;"
                    )
                    assert active_versions == "1"

                    _assert_paired_key_access(
                        temp,
                        vault["id"],
                        envelope,
                        current.json()["wrapped_dek"],
                        expected_status=403,
                        case="only direct old epoch remains active",
                    )
                    denied_old = temp.get(
                        f"/ecc/vaults/{vault['id']}/keys?key_version=1"
                    )
                    assert denied_old.status_code == 403, denied_old.text
                    assert set(denied_old.json()) == {"detail"}
                    serialized = json.dumps(denied_old.json()).lower()
                    assert "wrapped_dek" not in serialized
                finally:
                    _set_current_member_key_active(
                        vault["id"], owner.user["id"], True
                    )

                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    current.json()["wrapped_dek"],
                    expected_status=200,
                    case="direct current epoch restored",
                )
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_key_release_requires_vaults_page_for_selected_and_all_scoped_sessions(
    admin, temp_user_client
):
    """Exact ZK caps cannot bypass the scoped credential's coarse page boundary."""
    owner = temp_user_client
    envelope = _opaque_envelope("vaults_page_boundary")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = create_zk_vault(owner, name=unique("zk_vaults_page"))
            vault_ids.append(vault["id"])
            caps = ["vault.see_files"]

            for case, mode, selected in (
                (
                    "dashboard-only selected",
                    "selected",
                    [_selected(vault["id"], caps)],
                ),
                ("dashboard-only all", "all", []),
            ):
                with _minted_temp(
                    owner,
                    mode=mode,
                    pages=("dashboard",),
                    selected=selected,
                    default_caps=caps,
                ) as (temp, _):
                    assert temp.get(f"/vaults/{vault['id']}").status_code == 403
                    _assert_paired_key_access(
                        temp,
                        vault["id"],
                        envelope,
                        ZK_WRAPPED_DEK_STUB,
                        expected_status=403,
                        case=case,
                    )

            for case, mode, selected in (
                (
                    "vaults-page selected",
                    "selected",
                    [_selected(vault["id"], caps)],
                ),
                ("vaults-page all", "all", []),
            ):
                with _minted_temp(
                    owner,
                    mode=mode,
                    pages=("vaults",),
                    selected=selected,
                    default_caps=caps,
                ) as (temp, _):
                    _assert_paired_key_access(
                        temp,
                        vault["id"],
                        envelope,
                        ZK_WRAPPED_DEK_STUB,
                        expected_status=200,
                        case=case,
                    )

            with _minted_unscoped(owner) as (legacy, _):
                _assert_paired_key_access(
                    legacy,
                    vault["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=200,
                    case="legacy NULL-scope compatibility",
                )
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_malformed_persisted_credential_scope_shapes_fail_closed_live(
    admin, temp_user_client
):
    """Malformed live credential documents never inherit legacy key authority."""
    owner = temp_user_client
    envelope = _opaque_envelope("malformed_credential_scope")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = create_zk_vault(owner, name=unique("zk_malformed_scope"))
            vault_ids.append(vault["id"])
            caps = ["vault.see_files"]
            with _minted_temp(
                owner,
                selected=[_selected(vault["id"], caps)],
                default_caps=caps,
            ) as (temp, credential):
                username = credential["temp_username"]
                valid_scope = _stored_credential_scope(username)
                assert isinstance(valid_scope, dict)
                assert valid_scope["pages"] == ["vaults"]
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    ZK_WRAPPED_DEK_STUB,
                    expected_status=200,
                    case="valid persisted credential scope",
                )

                missing_pages = {
                    key: value
                    for key, value in valid_scope.items()
                    if key != "pages"
                }
                malformed_cases = (
                    ("empty object", {}),
                    ("missing pages", missing_pages),
                    (
                        "non-list pages",
                        {**valid_scope, "pages": "vaults"},
                    ),
                    ("JSON scalar", "vaults"),
                )
                for case, malformed_scope in malformed_cases:
                    _set_credential_scope(username, malformed_scope)
                    assert (
                        _stored_credential_scope(username)
                        == malformed_scope
                    )
                    _assert_paired_key_access(
                        temp,
                        vault["id"],
                        envelope,
                        ZK_WRAPPED_DEK_STUB,
                        expected_status=403,
                        case=case,
                    )

                    _set_credential_scope(username, valid_scope)
                    assert _stored_credential_scope(username) == valid_scope
                    _assert_paired_key_access(
                        temp,
                        vault["id"],
                        envelope,
                        ZK_WRAPPED_DEK_STUB,
                        expected_status=200,
                        case=f"restored after {case}",
                    )
        finally:
            _cleanup_owned_vaults(owner, vault_ids)


def test_direct_reader_see_files_qualifies_only_while_zk_vault_is_active(
    admin, temp_user, temp_user_client
):
    """A direct Reader with the exact cap qualifies only for a live ZK vault."""
    reader = temp_user_client
    ensure_ecc_keypair(reader)
    envelope_response = reader.get("/ecc/keys/private")
    assert envelope_response.status_code == 200, envelope_response.text
    reader_envelope = envelope_response.json()["encrypted_private_key"]
    ensure_ecc_keypair(admin)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = create_zk_vault(admin, name=unique("zk_direct_reader_active"))
            vault_ids.append(vault["id"])
            wrapped_for_reader = "cmVhZGVyLXNlZS1maWxlcy13cmFw"
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
            owner_keys = admin.get(f"/ecc/vaults/{vault['id']}/keys")
            assert owner_keys.status_code == 200, owner_keys.text
            assert owner_keys.json()["mode"] == "direct"

            caps = ["vault.see_files"]
            with _minted_temp(
                reader,
                selected=[_selected(vault["id"], caps)],
                default_caps=caps,
            ) as (temp, _):
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    reader_envelope,
                    wrapped_for_reader,
                    expected_status=200,
                    case="direct Reader with see_files on active ZK vault",
                )

                safe_vault_id = str(vault["id"]).replace("'", "''")
                deactivated = _psql(
                    "UPDATE vaults SET is_active = FALSE "
                    f"WHERE id = '{safe_vault_id}';"
                )
                assert deactivated == "UPDATE 1", deactivated
                try:
                    assert _psql(
                        "SELECT is_active::text FROM vaults "
                        f"WHERE id = '{safe_vault_id}';"
                    ) == "false"
                    _assert_paired_key_access(
                        temp,
                        vault["id"],
                        reader_envelope,
                        wrapped_for_reader,
                        expected_status=403,
                        case="direct Reader after live ZK vault deactivation",
                    )
                finally:
                    reactivated = _psql(
                        "UPDATE vaults SET is_active = TRUE "
                        f"WHERE id = '{safe_vault_id}';"
                    )
                    assert reactivated == "UPDATE 1", reactivated

                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    reader_envelope,
                    wrapped_for_reader,
                    expected_status=200,
                    case="direct Reader after ZK vault reactivation",
                )
        finally:
            _cleanup_owned_vaults(admin, vault_ids)


def test_hierarchical_key_release_tracks_live_current_teampriv_state(
    admin, temp_user_client
):
    """A hierarchical grant requires an active current-epoch TEAMPRIV wrap."""
    from test_zk_team_key import _create_hier_vault

    owner = temp_user_client
    envelope = _opaque_envelope("hierarchical_teampriv_state")
    _register_identity(owner, envelope)
    vault_ids = []

    with _settings(
        admin,
        zero_knowledge_enabled=True,
        temp_cred_allow_zk_vaults=True,
    ):
        try:
            vault = _create_hier_vault(owner)
            vault_ids.append(vault["id"])
            current = owner.get(f"/ecc/vaults/{vault['id']}/keys")
            assert current.status_code == 200, current.text
            assert current.json()["mode"] == "hierarchical"
            caps = ["vault.see_files"]

            with _minted_temp(
                owner,
                selected=[_selected(vault["id"], caps)],
                default_caps=caps,
            ) as (temp, _):
                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    current.json()["wrapped_dek"],
                    expected_status=200,
                    case="active current TEAMPRIV",
                )

                _set_current_teampriv_active(
                    vault["id"], owner.user["id"], False
                )
                try:
                    safe_vault_id = str(vault["id"]).replace("'", "''")
                    safe_user_id = str(owner.user["id"]).replace("'", "''")
                    active_current = _psql(
                        "SELECT count(*) FROM vault_member_keys AS vmk "
                        "JOIN vaults AS v ON v.id = vmk.vault_id "
                        f"WHERE vmk.vault_id = '{safe_vault_id}' "
                        f"AND vmk.user_id = '{safe_user_id}' "
                        "AND vmk.key_version = v.team_key_version "
                        "AND vmk.wrapping_algorithm = "
                        "'ECDH-P384-AES-GCM-TEAMPRIV' "
                        "AND vmk.is_active IS TRUE;"
                    )
                    assert active_current == "0"
                    _assert_paired_key_access(
                        temp,
                        vault["id"],
                        envelope,
                        current.json()["wrapped_dek"],
                        expected_status=403,
                        case="inactive current TEAMPRIV",
                    )
                finally:
                    _set_current_teampriv_active(
                        vault["id"], owner.user["id"], True
                    )

                _assert_paired_key_access(
                    temp,
                    vault["id"],
                    envelope,
                    current.json()["wrapped_dek"],
                    expected_status=200,
                    case="reactivated current TEAMPRIV",
                )
        finally:
            _cleanup_owned_vaults(owner, vault_ids)
