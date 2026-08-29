# Temporary credentials — model & enforcement

A **temporary credential** is a short-lived, scoped, revocable secondary login that acts *as* a real
user account but sees only the slice of that account the issuer granted. It is the platform's
least-privilege delegation primitive: an account holder (or an admin) mints one to hand a contractor,
a script, or a one-off task exactly the vaults and actions it needs, for a bounded time, without
sharing their real password.

This document is the written model the code implements. It exists so the coverage question — *"have
we tested every edge?"* — becomes mechanical: a row per capability × enforcement-path × expected
outcome. The vocabulary lives in `app/core/temp_scope.py`; the two enforcement paths are the REST API
(`app/api/api_server.py`) and the SFTP server (`app/sftp/`). Where this doc and the code disagree, the
code wins — treat this as the map, not the territory.

## Vocabulary

A credential carries a **scope** document (`scope`, schema-versioned `v: 1`) plus lifecycle fields
(validity window, one-time / multi-use, optional per-vault passcode). The scope is the whole of what
the credential may do; anything not granted is denied.

### Per-vault capabilities (`VAULT_CAPS`)

Fifteen fine-grained actions, checked at the vault chokepoint:

| Group | Capabilities |
|---|---|
| Read | `vault.see_info` (open the vault), `vault.see_files` (list/enumerate) |
| Files | `file.download`, `file.upload`, `file.rename`, `file.delete` |
| Folders | `folder.create`, `folder.delete` |
| Permissions | `vault.see_permissions`, `vault.change_permissions` |
| Administration | `vault.change_info`, `vault.change_password`, `vault.change_expiry`, `vault.rotate_key`, `vault.delete` |

**Implication graph (`CAP_IMPLIES`).** Every capability implies `vault.see_info` (you must be able to
open a vault to act on it), and `expand_vault_caps()` adds the prerequisites so any granted
combination is actually usable. Crucially, **`vault.see_files` (listing) is NOT implied** by the
per-file capabilities: the single-file endpoints (REST and SFTP) address a known file by id/path and
never enumerate, so a "download this known file" credential does **not** also hand out the ability to
list everything in the vault. Enumeration is a separate, deliberate grant.

### Global capabilities (`GLOBAL_CAPS`) and temp-management permissions (`TEMP_PERMS`)

- `vault.create`, `vault.create.standard`, `vault.create.zero_knowledge` — creating vaults (the typed
  caps let an issuer grant creation of only one vault type; `vault.create` implies both).
- `view`, `create`, `invalidate`, `clear`, `delegate` — what the credential may do to the
  *temporary-credential* system itself (e.g. `delegate` = may mint further, narrower credentials).

### Access modes

`vault_access_mode` selects how per-vault capabilities are resolved:

- **`all`** — `scope.vault_caps_default` applies uniformly to every vault the underlying account can
  already reach.
- **`selected`** — the credential names specific vaults (`temp_credential_vault_access`), each with
  its own capability list; vaults not named are invisible.

### Pages

`GROUP_PAGE` maps each endpoint-permission group to a UI page. `__infra__` groups (health, login) are
always allowed; `__deny__` groups (admin surfaces) are never grantable to a temporary credential, so
a temp credential can never reach an admin-only endpoint regardless of scope.

## Enforcement

Two decorator gates, plus an in-handler confinement check:

1. **`require_endpoint_permission(GROUP)`** (decorator, outer — runs first) — does the credential's
   page scope reach this endpoint group at all? A `__deny__` group, or a page the credential lacks,
   is refused here.
2. **`require_vault_cap(CAP)`** (decorator, inner; delegates to `require_cap(user, vault_id, cap)`) —
   does the credential hold the fine-grained capability for this vault? A credential that reaches the
   endpoint but lacks the cap is refused here and the refusal is audited (`vault_cap_denied`).
3. **`enforce_vault(user, vault_id)`** — temp-scope confinement, called **in the handler** on routes
   that address a specific vault's data: is this vault in the credential's scope? Out-of-scope vaults
   are filtered from listings and 403/404 on direct access. It is not a fixed third decorator; its
   position relative to the cap check varies by handler, but on a data route both must pass.

Both the **REST API and the SFTP server** apply the same scope. SFTP enforces the eight file/folder
capabilities (the seven vault-administration capabilities have no SFTP equivalent — correct by
construction, not a gap). A **malformed or unrecognised scope fails closed**: it denies everything,
including capabilities it nominally lists, rather than defaulting open.

### Delegation

A credential holding `delegate` may mint child credentials, but only ever **narrower** ones: the
child's scope is intersected with the parent's, so a read-only parent cannot mint a child that gains
write, an out-of-scope vault, mode `all`, or a legacy-unrestricted scope. All are refused at mint time
with a clear 400.

### Passcode second factor & zero-knowledge

A credential may carry a per-vault **passcode** (a second server-side factor to open a
password-protected Standard vault). **Zero-knowledge** vaults release wrapped key material only under
`may_release_vault_key`, which additionally refuses to hand the vault DEK to a credential restricted to
specific files — a credential scoped below the vault never receives the whole-vault key.

## Non-goals & deliberate boundaries

These read like findings but are decisions with a recorded rationale; do not "fix" them without an
explicit call.

- **Favouriting is keyed to the real user, not to temp-credential scope.** `PUT /vaults/{id}/favorite`
  checks the underlying account's real READ access (a uniform 404 otherwise, so no cross-tenant
  existence oracle); `DELETE /vaults/{id}/favorite` performs no access check at all but is harmless —
  it removes only the caller's own favourite row (keyed to their user id), so un-favouriting a vault
  they never favourited is a no-op and there is no cross-user or cross-tenant effect. Neither applies
  `enforce_vault`. A favourite is a personal bookmark of the real user, so a temp session favouriting a
  vault the real user genuinely owns is the user's own action, not a scope bypass.
- **Directory search** (`/users/search`) resolves against the real account's directory reach, not the
  credential's vault scope, and can be confined to the searcher's department via
  `directory_search_scope`.
- **The active-server threat is out of model.** Temp-credential confinement protects against a holder
  trying to widen its own grant; it does not defend against a compromised server that substitutes
  ciphertext or serves hostile crypto JavaScript — that adversary already defeats browser-delivered
  zero-knowledge.

## Coverage

Every capability that gates an endpoint has a **denial test** (a credential lacking it is refused,
with a positive control), and `tests/test_vault_cap_denial_coverage.py` walks the `require_vault_cap`
decorators and fails if any capability ships without one — so capability sixteen cannot ship
unguarded. Delegation intersection, malformed-scope fail-closed, and the SFTP path each have dedicated
tests; the passcode axis alone has dozens.
