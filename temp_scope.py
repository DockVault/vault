"""
Least-privilege scoping for temporary credentials.

A temporary credential may carry a `scope` document that RESTRICTS (never expands)
what its creating user can do. This module is the single source of truth for:
  * the capability/page vocabulary,
  * the map from endpoint-permission GROUPS to the page/cap they require,
  * the runtime checks (page gate, per-vault cap gate, vault membership gate),
  * delegation intersection (a temp-created cred's scope must be a subset).

Back-compat rule (critical): a credential whose `scope` is None is LEGACY and is
treated as fully unrestricted (it behaves exactly as before scoping existed). Every
helper here no-ops when the principal is not a scoped temp session.

The principal (a `User` object) is tagged elsewhere (auth_service /
get_current_user) with these transient attributes:
    _is_temp_session : bool
    _temp_scope      : dict | None     (the scope document, or None = legacy)
    _temp_vault_mode : 'all' | 'selected'
    _temp_cred_id    : uuid | None
    _temp_vault_caps : { str(vault_id): [cap, ...] }   (only for mode 'selected')
"""
from typing import Optional, List, Dict
import uuid

from fastapi import HTTPException, status

from authorization import PermissionDeniedError

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------
PAGES = {"dashboard", "vaults", "temp_creds"}

# Per-vault capabilities (stored in scope.vault_caps_default for mode 'all', or
# per vault in temp_credential_vault_access.vault_caps for mode 'selected').
VAULT_CAPS = {
    "vault.see_info", "vault.see_files",
    "file.download", "file.upload",
    "folder.create", "folder.delete",
    "file.rename", "file.delete",
    "vault.see_permissions", "vault.change_permissions",
    "vault.change_info", "vault.change_password", "vault.change_expiry",
    "vault.delete",
}
# Global (non-per-vault) capabilities, stored in scope.caps. `vault.create` is the legacy,
# type-agnostic create cap (any vault type); the per-type caps let an operator mint a credential
# that may create ONLY standard OR ONLY zero-knowledge vaults. Holding `vault.create` implies both.
GLOBAL_CAPS = {"vault.create", "vault.create.standard", "vault.create.zero_knowledge"}
TEMP_PERMS = {"view", "create", "invalidate", "clear", "delegate"}

# Endpoint-permission group -> page it belongs to. "__infra__" = always allowed
# (health/login), "__deny__" = never grantable to a temp credential (admin pages).
GROUP_PAGE = {
    "SYSTEM_HEALTH": "__infra__",
    "AUTH_LOGIN": "__infra__",
    "DASHBOARD_VIEW": "dashboard",
    "VAULT_VIEW": "vaults",
    "VAULT_CREATE": "vaults",
    "VAULT_DELETE": "vaults",
    "VAULT_SETTINGS": "vaults",
    "VAULT_PERMISSIONS": "vaults",
    "FILE_VIEW": "vaults",
    "FILE_DOWNLOAD": "vaults",
    "FILE_UPLOAD": "vaults",
    "FILE_DELETE": "vaults",
    "FOLDER_MANAGE": "vaults",
    "TEMP_CREDS_VIEW": "temp_creds",
    "TEMP_CREDS_MANAGE": "temp_creds",
    # Admin-only — never available to a temporary credential.
    "USER_VIEW": "__deny__",
    "USER_MANAGE": "__deny__",
    "AUDIT_VIEW": "__deny__",
}


# ---------------------------------------------------------------------------
# Principal helpers
# ---------------------------------------------------------------------------
def is_scoped(user) -> bool:
    """True only for a temp session that actually carries a (non-legacy) scope."""
    return bool(getattr(user, "_is_temp_session", False)) and getattr(user, "_temp_scope", None) is not None


def _scope(user) -> Optional[dict]:
    return getattr(user, "_temp_scope", None)


def effective_vault_caps(user, vault_id) -> List[str]:
    """The capability list this scoped credential holds on a specific vault."""
    scope = _scope(user) or {}
    if getattr(user, "_temp_vault_mode", "selected") == "all":
        return list(scope.get("vault_caps_default", []))
    return list((getattr(user, "_temp_vault_caps", {}) or {}).get(str(vault_id), []))


def attach_scope(db, user, temp_cred) -> None:
    """Tag a principal (User) with its temp credential's scope context so every
    enforcement helper here can read it. Used by BOTH the auth path (web login +
    SFTP) and the web get_current_user (JWT replay). Safe for any temp_cred —
    a NULL scope leaves the principal effectively unrestricted (legacy)."""
    user._is_temp_session = True
    user._temp_cred_id = temp_cred.id
    user._temp_scope = temp_cred.scope
    user._temp_vault_mode = getattr(temp_cred, "vault_access_mode", "selected") or "selected"
    user._temp_can_create = bool(getattr(temp_cred, "can_create_temp_credentials", False))
    caps_map: Dict[str, List[str]] = {}
    pw_fp_map: Dict[str, Optional[str]] = {}
    if temp_cred.scope is not None and user._temp_vault_mode == "selected":
        from models import TempCredentialVaultAccess
        rows = db.query(TempCredentialVaultAccess).filter(
            TempCredentialVaultAccess.temp_credential_id == temp_cred.id
        ).all()
        for r in rows:
            caps_map[str(r.vault_id)] = list(r.vault_caps or [])
            pw_fp_map[str(r.vault_id)] = getattr(r, "vault_password_fingerprint", None)
    user._temp_vault_caps = caps_map
    # Per-vault fingerprint of the password proven at mint; the SFTP layer compares it to
    # the vault's live password hash so a rotation voids the standing proof.
    user._temp_vault_pw_fp = pw_fp_map


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------
def temp_session_allows_group(user, group_name: str, kwargs: dict) -> bool:
    """Decorator-level coarse gate: page access + a few global/temp caps. Per-vault
    capability and vault-membership are enforced downstream (enforce_vault /
    require_cap). Returns True for legacy (unscoped) credentials."""
    # __infra__ (health/login) is always allowed; __deny__ (admin-only groups: USER_*, AUDIT_VIEW) is
    # NEVER available to ANY temporary credential — scoped OR legacy/NULL-scope. Evaluate these BEFORE
    # the NULL-scope early-return so a legacy "unrestricted" temp cred can't reach an admin group via
    # @require_endpoint_permission (keeping this consistent with require_interactive_admin, which
    # rejects every temp session). For all other groups a NULL-scope cred stays unrestricted (legacy).
    page = GROUP_PAGE.get(group_name, "__deny__")
    if page == "__infra__":
        return True
    if page == "__deny__":
        return False

    scope = _scope(user)
    if scope is None:
        return True  # legacy / not a scoped temp session (non-deny, non-infra groups)

    if page not in set(scope.get("pages", [])):
        return False

    if group_name == "VAULT_CREATE":
        # Any create cap (legacy type-agnostic OR a per-type one) passes the coarse page/nav gate;
        # the specific vault TYPE is enforced in the handler via require_create_vault_type().
        return any(c == "vault.create" or c.startswith("vault.create.") for c in scope.get("caps", []))
    if group_name == "TEMP_CREDS_VIEW":
        return bool(scope.get("temp", {}).get("view"))
    if group_name == "TEMP_CREDS_MANAGE":
        temp = scope.get("temp", {})
        return bool(temp.get("create") or temp.get("invalidate") or temp.get("clear"))

    # Vault/file groups: page is enough here; the specific vault + capability are
    # checked by enforce_vault() and require_cap() at the data layer / handler.
    return True


def enforce_vault(user, vault_id) -> None:
    """Vault-membership gate (called inside VaultService.get_vault, so it also
    covers SFTP). For mode 'selected', the vault must be in the credential's
    granted set. Raises PermissionDeniedError (handlers already map it to 403)."""
    if not is_scoped(user):
        return
    if getattr(user, "_temp_vault_mode", "selected") == "all":
        return  # any vault the creator can already reach is allowed
    granted = getattr(user, "_temp_vault_caps", {}) or {}
    if str(vault_id) not in granted:
        raise PermissionDeniedError("Temporary credential has no access to this vault")


def require_cap(user, vault_id, cap: str) -> None:
    """Fine per-action gate at a handler. No-op for non-scoped principals. Raises
    HTTPException(403) for a scoped temp session lacking the capability."""
    if not is_scoped(user):
        return
    scope = _scope(user) or {}
    allowed = set(effective_vault_caps(user, vault_id)) | set(scope.get("caps", []))
    if cap not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Temporary credential scope does not permit this action",
        )


def require_create_vault_type(user, vault_type: str) -> None:
    """Gate vault creation by TYPE for a scoped temp session. It may create `vault_type` if it
    holds the legacy type-agnostic `vault.create` OR the per-type `vault.create.<type>` cap.
    No-op for non-scoped principals (a legacy/unscoped credential is unrestricted). This runs at
    the create handler AFTER the type is resolved, since the coarse VAULT_CREATE gate can't see it."""
    if not is_scoped(user):
        return
    caps = set((_scope(user) or {}).get("caps", []))
    if "vault.create" in caps or f"vault.create.{vault_type}" in caps:
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Temporary credential scope does not permit creating a {vault_type} vault",
    )


def require_vault_cap(cap: str):
    """Decorator (stacks UNDER @require_endpoint_permission) enforcing a per-vault
    capability for scoped temp sessions. Reads current_user + vault_id from kwargs.
    No-op for normal users / legacy credentials."""
    from functools import wraps

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user = kwargs.get("current_user")
            if user is not None:
                require_cap(user, kwargs.get("vault_id"), cap)
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_temp_perm(user, perm: str) -> None:
    """Gate a temp-credentials-page sub-permission (view/create/invalidate/clear/
    delegate). No-op for non-scoped principals."""
    if not is_scoped(user):
        return
    if not (_scope(user) or {}).get("temp", {}).get(perm):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Temporary credential scope does not permit this action",
        )


# ---------------------------------------------------------------------------
# Normalisation + delegation intersection
# ---------------------------------------------------------------------------
def normalize_scope(raw: Optional[dict]) -> Optional[dict]:
    """Coerce a client-supplied scope into the canonical, validated shape. None
    stays None (legacy/unrestricted). Unknown caps/pages are dropped."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        return None
    temp_in = raw.get("temp", {}) if isinstance(raw.get("temp"), dict) else {}
    return {
        "v": 1,
        "pages": sorted(p for p in raw.get("pages", []) if p in PAGES),
        "caps": sorted(c for c in raw.get("caps", []) if c in GLOBAL_CAPS),
        "vault_caps_default": sorted(c for c in raw.get("vault_caps_default", []) if c in VAULT_CAPS),
        "temp": {k: bool(temp_in.get(k, False)) for k in TEMP_PERMS},
    }


def _filter_caps(caps, allowed_set):
    return sorted(set(caps) & set(allowed_set))


def intersect_scope(parent: Optional[dict], child: Optional[dict]) -> Optional[dict]:
    """Return the largest scope that is within BOTH parent and child. Used when a
    temp session delegates: the child can never exceed its parent. A None parent
    means the parent is unrestricted, so the child stands as-is."""
    child = normalize_scope(child)
    if child is None:
        return None
    if parent is None:
        return child
    p_temp = parent.get("temp", {})
    return {
        "v": 1,
        "pages": _filter_caps(child["pages"], parent.get("pages", [])),
        "caps": _filter_caps(child["caps"], parent.get("caps", [])),
        "vault_caps_default": _filter_caps(child["vault_caps_default"], parent.get("vault_caps_default", [])),
        "temp": {k: bool(child["temp"].get(k) and p_temp.get(k)) for k in TEMP_PERMS},
    }
