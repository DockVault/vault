"""Live authorization for releasing zero-knowledge secrets to temporary sessions.

A temporary credential authenticates as its account user, but that alone must not
unlock the account-wide private-key envelope or a vault's wrapped key.  These helpers
re-read the persisted grant, organization policy, membership, role, and current key
state on every release.  They deliberately do not trust the transient attributes on
the request's ``User`` object for security decisions.
"""

import json

from sqlalchemy import or_, select

from app.core.models import (
    RoleEnum,
    SystemSetting,
    TempCredentialVaultAccess,
    TemporaryCredential,
    Vault,
    VaultMemberKey,
    vault_members,
)
from app.core.temp_passcode_policy import effective_policy


# Re-exported from the module that owns the vocabulary, so the label is declared once.
from app.core.key_wrap_algorithms import (  # noqa: F401  (re-export)
    TEAMPRIV_ALGO,
    TEAMPRIV_ALGOS,
)
QUALIFYING_ZK_CAPS = {"vault.see_files", "vault.change_permissions"}
TEMP_ZK_KEY_ACCESS_DENIED = (
    "Temporary credential is not eligible for zero-knowledge key access"
)


def temp_zk_policy_allows(db) -> bool:
    """Return the live organization switch, preserving its documented default.

    A malformed settings blob is treated like an empty blob instead of crashing the
    authorization path.  The existing policy intentionally defaults ZK temporary
    access to allowed and only an explicit ``False`` disables it.
    """
    row = db.query(SystemSetting).filter(SystemSetting.key == "global").first()
    raw = row.value if row is not None else {}
    if not isinstance(raw, dict):
        raw = {}
    return effective_policy(raw)["temp_cred_allow_zk_vaults"]


def _is_admin(user) -> bool:
    role = getattr(user, "role", None)
    return role == RoleEnum.ADMIN or getattr(role, "value", role) == "admin"


def _member_permissions(db, vault, user_id):
    return db.execute(
        select(
            vault_members.c.read_permission,
            vault_members.c.manage_permission,
        ).where(
            vault_members.c.vault_id == vault.id,
            vault_members.c.user_id == user_id,
        )
    ).first()


def _team_key_map(vault) -> dict:
    raw = getattr(vault, "team_key", None)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _has_current_key(db, vault, user_id) -> bool:
    """Require usable wrapped material at the vault's current crypto epochs."""
    current_dek = getattr(vault, "dek_version", 1) or 1
    if getattr(vault, "key_wrapping_mode", "direct") == "hierarchical":
        entry = _team_key_map(vault).get(str(current_dek))
        if not isinstance(entry, dict):
            return False
        if not entry.get("wrapped_dek") or not entry.get("ephemeral_public_key"):
            return False
        try:
            team_epoch = int(entry.get("team_key_version"))
        except (TypeError, ValueError):
            return False
        if team_epoch < 1:
            return False
        team_private = (
            db.query(VaultMemberKey)
            .filter(
                VaultMemberKey.vault_id == vault.id,
                VaultMemberKey.user_id == user_id,
                VaultMemberKey.key_version == team_epoch,
                VaultMemberKey.wrapping_algorithm.in_(TEAMPRIV_ALGOS),
                VaultMemberKey.is_active == True,  # noqa: E712
            )
            .first()
        )
        return bool(
            team_private
            and team_private.encrypted_dek
            and team_private.ephemeral_public_key
        )

    member_key = (
        db.query(VaultMemberKey)
        .filter(
            VaultMemberKey.vault_id == vault.id,
            VaultMemberKey.user_id == user_id,
            VaultMemberKey.key_version == current_dek,
            VaultMemberKey.is_active == True,  # noqa: E712
        )
        .first()
    )
    return bool(
        member_key and member_key.encrypted_dek and member_key.ephemeral_public_key
    )


def zk_grant_has_key_authority(db, user, vault, caps=None, *, legacy=False) -> bool:
    """Combine exact capability, live role, membership, and current-key checks."""
    if (
        vault is None
        or getattr(vault, "type", "standard") != "zero_knowledge"
        or getattr(vault, "is_active", False) is not True
    ):
        return False

    owner = str(vault.owner_id) == str(user.id)
    # DELIBERATELY stricter than ``_can_manage_vault``: that helper gates a MUTATION the admin
    # can already perform, while this gate releases KEY MATERIAL. A global admin elevates an
    # existing membership (below) but never manufactures one, so an orphaned wrap left behind by
    # a removed relationship grants nothing. Relaxing this to mirror ``_can_manage_vault`` would
    # expand wrapped-DEK authorization; the paired-endpoint matrix pins the 403.
    member = None if owner else _member_permissions(db, vault, user.id)
    if not owner and member is None:
        return False
    if not _has_current_key(db, vault, user.id):
        return False
    if legacy:
        return True

    cap_set = (
        {cap for cap in caps if isinstance(cap, str)}
        if isinstance(caps, (list, tuple, set))
        else set()
    )
    # Both branches require a live relationship first (checked above). ``see_files`` needs a
    # readable one; ``change_permissions`` needs the Manager authority the real grant/rekey
    # operation uses, which a global admin supplies on top of any existing membership.
    can_read = owner or bool(member and member.read_permission)
    can_manage = owner or bool(member and (member.manage_permission or _is_admin(user)))
    return ("vault.see_files" in cap_set and can_read) or (
        "vault.change_permissions" in cap_set and can_manage
    )


def _reachable_zk_vaults(db, user, credential=None):
    """Active zero-knowledge vaults this account can reach.

    When a credential is supplied, vaults created AFTER it are excluded. That bound is the whole
    point: eligibility for the account-wide private-key envelope must reflect what the OWNER
    granted, never what the holder went on to create.

    Without it a credential carrying zero-knowledge CREATE authority plus whole-account vault
    access can manufacture its own eligibility -- denied the envelope while the account owns no
    such vault, it creates one (which inserts its own wrapped key at the current epoch) and asks
    again, now qualifying. Refusing creation instead is not an option: a scoped credential is
    legitimately allowed to create these vaults, and a test pins that.

    A credential with no creation timestamp is treated as qualifying for nothing, because this
    gate releases an offline-attackable copy of the account identity and an unknown age cannot be
    reasoned about.
    """
    member_vaults = select(vault_members.c.vault_id).where(
        vault_members.c.user_id == user.id
    )
    query = db.query(Vault).filter(
        Vault.type == "zero_knowledge",
        Vault.is_active == True,  # noqa: E712
        or_(Vault.owner_id == user.id, Vault.id.in_(member_vaults)),
    )
    if credential is not None:
        created = getattr(credential, "created_at", None)
        if created is None:
            return []
        query = query.filter(Vault.created_at < created)
    return query.all()


def _credential(db, user):
    cred_id = getattr(user, "_temp_cred_id", None)
    if not cred_id:
        return None
    return (
        db.query(TemporaryCredential).filter(TemporaryCredential.id == cred_id).first()
    )


def _selected_rows(db, credential):
    return (
        db.query(TempCredentialVaultAccess)
        .filter(TempCredentialVaultAccess.temp_credential_id == credential.id)
        .all()
    )


def _selected_state(db, user, credential):
    rows = _selected_rows(db, credential)
    vault_ids = {row.vault_id for row in rows}
    vaults = (
        {
            vault.id: vault
            for vault in db.query(Vault).filter(Vault.id.in_(vault_ids)).all()
        }
        if vault_ids
        else {}
    )
    return rows, vaults


def has_selected_zk_object_conflict(rows, vaults) -> bool:
    """Whether a selected object grant can conflict with cached ZK material.

    Live role and key state govern positive releases, but cannot revoke a wrapped
    key that a client may already have cached.  Persisted ZK object scope with an
    exact key capability therefore remains a session-wide conflict.

    This is deliberately CAP-AWARE while the mint-time rejection is CAP-BLIND, and the
    asymmetry is intentional: minting is prospective, so no new zero-knowledge grant may
    carry an object map at all (a later capability widening must not be able to turn a
    dormant row into a key release), whereas this path judges credentials that already
    exist and must not retroactively break one whose capabilities never qualified.
    """
    for row in rows:
        if row.scope_ids is None:
            continue
        vault = vaults.get(row.vault_id)
        cap_set = (
            {cap for cap in row.vault_caps if isinstance(cap, str)}
            if isinstance(row.vault_caps, (list, tuple, set, dict))
            else set()
        )
        # Older runtime scope attachment interpreted a JSON object's keys as
        # capabilities. Conservatively preserve that interpretation only for this
        # negative boundary; malformed caps can never positively authorize release.
        if (
            vault is not None
            and vault.type == "zero_knowledge"
            and cap_set & QUALIFYING_ZK_CAPS
        ):
            return True
    return False


def credential_has_zk_object_conflict(db, credential_id) -> bool:
    """Read a parent's persisted grants and preserve its negative ZK boundary."""
    rows = (
        db.query(TempCredentialVaultAccess)
        .filter(TempCredentialVaultAccess.temp_credential_id == credential_id)
        .all()
    )
    vault_ids = {row.vault_id for row in rows}
    vaults = (
        {
            vault.id: vault
            for vault in db.query(Vault).filter(Vault.id.in_(vault_ids)).all()
        }
        if vault_ids
        else {}
    )
    return has_selected_zk_object_conflict(rows, vaults)


def _scope_allows_vaults(scope) -> bool:
    """Honor the same coarse vault-page boundary as ordinary scoped endpoints."""
    pages = scope.get("pages")
    return isinstance(pages, list) and "vaults" in pages


def may_release_private_envelope(db, user) -> bool:
    """Whether this request may receive the account-wide private-key envelope."""
    if not getattr(user, "_is_temp_session", False):
        return True
    if not temp_zk_policy_allows(db):
        return False
    credential = _credential(db, user)
    if credential is None:
        return False

    if credential.scope is None:
        return any(
            zk_grant_has_key_authority(db, user, vault, legacy=True)
            for vault in _reachable_zk_vaults(db, user, credential)
        )
    if not isinstance(credential.scope, dict):
        return False
    if not _scope_allows_vaults(credential.scope):
        return False

    mode = credential.vault_access_mode or "selected"
    if mode == "all":
        caps = credential.scope.get("vault_caps_default", [])
        return any(
            zk_grant_has_key_authority(db, user, vault, caps)
            for vault in _reachable_zk_vaults(db, user, credential)
        )
    if mode != "selected":
        return False

    rows, vaults = _selected_state(db, user, credential)
    if has_selected_zk_object_conflict(rows, vaults):
        return False
    return any(
        row.scope_ids is None
        and zk_grant_has_key_authority(
            db, user, vaults.get(row.vault_id), row.vault_caps
        )
        for row in rows
    )


def may_release_vault_key(db, user, vault) -> bool:
    """Whether this request may receive wrapped key material for ``vault``."""
    if not getattr(user, "_is_temp_session", False):
        return True
    if not temp_zk_policy_allows(db):
        return False
    credential = _credential(db, user)
    if credential is None:
        return False

    if credential.scope is None:
        return zk_grant_has_key_authority(db, user, vault, legacy=True)
    if not isinstance(credential.scope, dict):
        return False
    if not _scope_allows_vaults(credential.scope):
        return False

    mode = credential.vault_access_mode or "selected"
    if mode == "all":
        return zk_grant_has_key_authority(
            db, user, vault, credential.scope.get("vault_caps_default", [])
        )
    if mode != "selected":
        return False

    rows, vaults = _selected_state(db, user, credential)
    if has_selected_zk_object_conflict(rows, vaults):
        return False
    return any(
        row.vault_id == vault.id
        and row.scope_ids is None
        and zk_grant_has_key_authority(db, user, vault, row.vault_caps)
        for row in rows
    )
