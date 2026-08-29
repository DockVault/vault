# Design: login MFA and step-up verification (one action-scoped OTP core)

> ## ⚑ Reviewer notes — grade B+ (audit 2026-08-29)
>
> Strong, honest, well-grounded spec. Verified sound: the action-binding (a login OTP genuinely can't
> authorize `vault.delete` because the store key differs), the pre-auth-token confinement (all three
> session-less decode sites refuse a token with no `session_token`), the encryption-key-lockout handling
> (§7.4/§9), and the computed enrollment state (no stored flag → no stale-flag bugs). Mandatory recovery
> codes via the state machine are a correct choice. **Resolve before building:**
>
> **Should-fix**
> - **§3.1/§6.2 — the rate-limit claim is wrong (security), verified.** `/challenge`+`/verify` are said to
>   ride a fail-*closed* bucket, but the RateLimitMiddleware auth bucket defaults `fail_open=True` (fails OPEN
>   on a Redis outage) and keys on `user:{sub}`/`ip`, not `(ip,user_id)`. The fail-*closed* property is the
>   login throttle (`_check_rate_limit`, `fail_open=False` + DB fallback). Wire /verify to a fail-closed
>   limiter and correct the text. The OTP-service 3-strike applies to `method=email` only.
> - **§3/§5.3/§6.2 — step-up brute-force (security).** Step-up has no durable per-user attempt counter
>   (`pending_logins.attempts` is login-only). The `password` step-up method calls `verify_password` without
>   account lockout, so a stolen un-enrolled-admin bearer could brute-force the password (worse than a 6-digit
>   TOTP), effectively unbounded during a Redis outage. Route `password` through the login lockout + give
>   `totp` step-up a durable cap. (Q4's admin-optional→required path removes `password` entirely.)
> - **§4.1 vs §4.2 — catalog references unbuilt routes (buildability).** `receiver.create` (POST /receivers)
>   and the `/public-links` half of `public_link.create` don't exist yet, so seeding them trips §4.2's own
>   boot contract. Scope them as "added when secure-send ships."
> - **§1.4/§7.2/§10 — factual: password-change revocation IS already built.** The spec says three times it
>   isn't, but 0.19.1 (`PATCH /users/me` + admin `PATCH /users/{id}`) already durably revokes sessions on a
>   password change. Drop the caveat/non-goal — it strengthens the enrollment-revokes-sessions design.
>
> **Consider**
> - §5.5 — `_user_requires_temp_cred_for_sftp` keys strictly on GROUP membership; state it's EXTENDED to
>   return True when the second factor is in effect, and confirm its fail-open behaviour.
> - §3 recovery — up to 10 argon2 verifies per presented code + a fail-open limiter = a CPU-DoS lever; add a
>   cheap non-secret lookup prefix so at most one argon2 runs per attempt.
> - §3.2/§9 (nit) receipt/session compare needs the raw session token at decorator time; §6/§3.1 (nit)
>   concurrent logins for one account collide on the single-active `sf:login` email key (scope it to the
>   pending-login id).
>
> _(Review comments added on top of the authoring session's spec; the author's text is unchanged below.)_

Status: **proposed — design only, nothing in this document is implemented** · Scope:
`app/core/otp_service.py`, `app/core/email_actions.py`, `app/core/account_policy.py`,
`app/api/api_server.py` (`/auth/login`, `get_current_user`, the `/ws/monitor` handshake, the high-risk
routes), `app/api/user_management_api.py`, Settings → Accounts & Access, the profile menu · Audience:
self-hosters + admins + whoever builds it

Today the vault has **no second factor of any kind on login**. `enable_2fa` in `app/config/branding.py`
is documented in its own field description as an advertising flag — *"no built-in TOTP yet; kept as a
forward-compatible flag / for a front-door MFA proxy"* — and `GET /features` (`app/routers/info.py`)
reports it as `authentication.2fa_enabled`. `POST /auth/login` (`app/api/api_server.py`) calls
`AuthService.authenticate_user`, gets `(user, session_token)` back, and mints the JWT on the spot with
`sub`, `username`, `session_token` and `is_temporary`. Nothing between the password check and the token
asks for anything else.

This document designs one **action-scoped one-time-code core** that serves two jobs with one mechanism:
a second factor at login (once per session) and **step-up** re-verification before a high-risk action.
It reuses the OTP substrate and the action-registry shape the vault already has, adds TOTP (RFC 6238)
with mandatory recovery codes, an admin policy matrix (action → require a second factor), and a
global → department → user requirement resolution. Everything is a new table or a new settings key;
no new secret is introduced.

**The honesty point, stated first.** `enable_2fa` must stay `false` and `/features` must keep reporting
`2fa_enabled: false` until the login path in this document actually refuses a session without the
second factor — on every surface the flag would be read to cover, SFTP included (§8.5). A deployment
that advertises 2FA it does not enforce is worse than one that says nothing. §9 pins this with a test.

---

## 1. What exists, and what this reuses

### 1.1 The OTP substrate (`app/core/otp_service.py`)

Already a generalized service, not an email-change special case. Read from the source:

- `issue(db, *, purpose, user_id, destination, ttl_minutes, ...)` mints a 12-hex-char code
  (`secrets.token_hex(6)`, ~48 bits), stores only a peppered HMAC-SHA256 of it, in Redis
  (`otp:{purpose}:{user_id}`, TTL + 15 s grace) with a durable `otp_codes` row as the fallback when
  Redis is down. Issuing invalidates any prior code for the same `(purpose, user_id)` in **both** stores.
- `verify(db, *, purpose, user_id, code)` consults both stores, lets the newer generation win, compares
  in constant time, **consumes on success with a single winner** (Redis delete-count / a conditional
  `UPDATE … WHERE consumed_at IS NULL`), counts wrong guesses and invalidates after `max_attempts` (3).
  It returns an `OtpResult` whose `destination` is the value the code was bound to.
- `invalidate(...)` drops the active code from both stores.
- The pepper is `settings.jwt_secret_key` (`_resolve_pepper`) — an existing secret.

The binding is `(purpose, user_id, destination)`. That is exactly the "action-bound" property required
here: a code issued under `purpose="login"` cannot verify under `purpose="vault.delete"` because the store
key differs and `verify` is always called with the purpose the caller is enforcing. The one consumer today
is the email-change flow (`POST /users/me/request-email-change` → `POST /users/me/confirm-email-change`),
with its TTL in the account-policy blob (`email_change_otp_ttl_minutes`, bounded 1..60 by
`app/core/account_policy.py`).

One thing to notice for later: the code is **hexadecimal**. A hand-typed second factor is conventionally
six digits; §8.1 and Q11 deal with that.

### 1.2 The action-registry pattern (`app/core/email_actions.py`)

`ACTION_CATALOG` is a tuple of dicts (`key`, `name`, `description`, `category`) built from a fixed
`_ACTION_META`; `seed_email_actions(db)` idempotently materializes one `EmailAction` row per key (stable
string primary key, `enabled`, metadata refreshed from code, an admin's choices never overwritten);
`send_action_email(db, key, ...)` is the single helper every trigger calls; `PUT /email/actions/{key}`
is the admin toggle. `DEFAULT_TEMPLATES` carries a required dynamic token (`{{action.code}}`) that
`_fallback_body_if_missing_required_token` restores if an admin's template drops it.

This document copies that shape for a **second-factor action catalog** (§4): a pure catalog in code, a
seeded table keyed by the action string, one decorator every guarded route uses, and an admin matrix.

### 1.3 Policy blobs and their validation (`app/core/account_policy.py`)

The account-onboarding policy is one validated block in `SystemSetting('global')`: `DEFAULTS` chosen so an
untouched install behaves exactly as before, `effective_account_policy` overlays defaults on read,
`validate_account_policy` is pure and takes DB-derived facts as arguments (for example
`email_login_locks_out_all_admins`, which makes the validator refuse a setting that would strand every
admin). `GET /auth/policy` exposes a deliberately small allowlist of those keys to the pre-auth login
screen. The MFA policy (§5) follows the same construction and rides in the same blob.

### 1.4 Sessions and the places that decode a token

`AuthService._create_session` inserts an `ActiveSession` row (token hashed at rest) and caches
`session:{hash}` in Redis for 30 minutes. **Three** places decode a bearer, and every one of them
refuses a token that carries no `session_token`:

- `get_current_user` (`app/api/api_server.py`) — verifies the JWT, refuses a missing `session_token`
  ("can only be a forgery or a stripped/legacy token"), checks the Redis logout denylist, and for
  regular users re-reads `ActiveSession.revoked` on every request (fail closed on a missing row);
- the `/ws/monitor` handshake — decodes the bearer itself for parity with `get_current_user`
  (`sub`, `username`, `session_token`, denylist, `revoked`), so a live monitor socket cannot be opened
  by a revoked token;
- `POST /api/logout` — the logout route, which sets `ActiveSession.revoked` and denylists the token.

Because all three key on `session_token`, the safest way to keep a *partially* authenticated token out
of every one of them is to mint it **without** a session at all (§6.1). Note also what the shipped
tree does **not** do: a self-service password change (`PATCH /users/me`) does not revoke the account's
other sessions — the only password-driven revocation is the reset path, which calls
`_revoke_sessions` — and there is no absolute session lifetime beyond JWT expiry (`session_timeout`
feeds `exp`). §6.3 and §7.2 state what this design assumes about both.

### 1.5 Secrets at rest — nothing new needed

- A reversible secret (the TOTP seed) is sealed with `encrypt_secret` / `decrypt_secret`
  (`app/core/security.py`): Fernet under the deployment `ENCRYPTION_KEY`, the same helper the SMTP
  password already uses.
- A verify-only secret (a recovery code) is hashed with `hash_password` (argon2), the same helper as
  account passwords, note-link secrets and temporary credentials.
- Email codes and step-up receipts are peppered HMACs under `jwt_secret_key` via the OTP service.

So the design adds **no new key material** to `.env`, and therefore no new entry for `dockvault.py`'s
setup flow. The policy keys in §5.1 live in the settings blob, not in `config.py`, so the
config ⇄ `.env.example` ⇄ `dockvault.py` sync rule in `CLAUDE.md` is not triggered.

### 1.6 Where the profile lives

The profile dropdown in `static/index.html` (`#profile-dropdown`) carries **Encryption key**
(`#encryption-key-btn` → `#encryption-key-modal`, driven by `refreshEncryptionKeyStatus` in
`static/js/app.js`, which reads `GET /ecc/keys/public` and renders one of three states: key set up and
active, no key yet, or could not check), **Settings** and **Logout**. The second factor goes directly
beside Encryption key, built the same way: a status-first modal, every DOM node created with
`createElement`/`textContent`.

### 1.7 Departments

`Group` rows (`app/core/models.py`, hierarchical via `parent_id`) with membership in `user_groups`. A
user may belong to several. Existing per-group policy switches already store a **list of group ids in
the global blob**; the API layer validates the ids exist with `_validate_group_id_list(payload, key, db)`
in `app/api/api_server.py` (used for `sftp_require_temp_cred_groups` and
`standard_vault_allowed_groups`). The department tier of the MFA requirement uses the same shape and
the same helper, called from the same place.

---

## 2. Requirements

1. **One core, keyed to (account, action).** A code (or a TOTP proof, or a recovery code) is accepted at
   most once, for exactly one action, within a short TTL. A login proof can never authorize
   `vault.delete`.
2. **TOTP enrollment** (RFC 6238, SHA-1, 6 digits, 30 s — the parameters every authenticator app
   defaults to), a QR code, and **mandatory recovery codes**.
3. **Two uses, one mechanism**: login MFA (once per session) and step-up (re-verify before a high-risk
   action).
4. **An admin policy matrix** action → `require_otp`, extensible without a schema change.
5. **Requirement resolution** global → department → user, with: global-required cannot be personally
   disabled; global-optional means the user chooses; forced enrollment at onboarding.
6. **Per-user enrollment state** computed from the *current* policy, never a stored "pending" flag.
7. Optional MFA lives on the profile, next to the encryption key.
8. WebAuthn/passkeys are a noted fast-follow, not this build.
9. A lost authenticator must never lock a user out of their **encryption key** (§7.4).
10. New tables only; no new secrets; the schema change is declared in `docs/upgrade-matrix.json` in the
    same change, per `CLAUDE.md`.

---

## 3. The core: challenge → verify → receipt

Four verifiers, one interface, one receipt. Module: `app/core/second_factor.py` (pure where possible;
`db`/`redis` passed explicitly, like `otp_service`).

```
verify_second_factor(db, *, user, action: str, method: str, code: str, session_hash: str) -> Receipt
```

| `method` | What is checked | Where the state lives |
|---|---|---|
| `totp` | RFC 6238 against the sealed seed, ±1 step of drift, and the step is claimed with **one conditional write** — `UPDATE second_factor_enrollments SET last_used_step = :step, last_used_at = now() WHERE user_id = :u AND status = 'active' AND last_used_step < :step` — accepted only when the row count is 1. Two concurrent verifies of the same 30-second code (a login and a step-up, or two sessions) race that update and exactly one wins; a read-then-write would let both pass. | `second_factor_enrollments` (§7) |
| `email` | `otp_service.verify(purpose=f"sf:{action}", user_id, code)`; the code was issued by the challenge step to the user's own address | `otp_codes` / Redis (existing) |
| `recovery` | argon2 verify against the user's unconsumed recovery codes; the matching row is consumed with a conditional `UPDATE … WHERE consumed_at IS NULL` (single winner) | `second_factor_recovery_codes` (§7) |
| `password` | the account password (`verify_password`), **only** for `admin.*` actions and only for an admin who has no enrollment — §5.3 explains why this exists | `users.password_hash` (existing) |

**The receipt is itself an OTP-service code.** On success the core calls

```
otp_service.issue(db, purpose=f"stepup:{action}", user_id=user.id, destination=session_hash, ttl_minutes=5)
```

and returns the plaintext as the receipt. That gives the receipt every property §2 requires, without
new machinery: single active receipt per `(action, user)`, single-winner consumption, a short TTL,
invalidation on re-issue, Redis-primary with a durable fallback — and **session binding**, because
`destination` carries the hash of the session that earned it and the consumer compares it (§3.2).

### 3.1 The challenge step

`POST /auth/second-factor/challenge` `{action, method?}`:

- validates that `action` is in the catalog (§4) and that the second factor is *in effect* for this user
  (§5.3);
- for `email`: checks the method is allowed by policy and the user has an email, then
  `otp_service.issue(purpose=f"sf:{action}", destination=user.email, ttl=mfa_email_code_ttl_minutes)`
  and sends it through **a new system email action** `second_factor_code` (§4.3) — the code reaches only
  the mailbox; the response never carries it;
- for `totp` / `recovery` / `password`: nothing to issue; the response just lists the methods available
  so the client can render the prompt.

Both `/challenge` **and** `/verify` are rate-limited on the existing auth bucket (`rate_limit_api_auth`)
keyed by `(client_ip, user_id)` — the bucket the login throttle uses, which fails closed from Redis to
the DB — in addition to the OTP service's own 3-strike rule.

### 3.2 Consuming a receipt

```
require_step_up(action)  — decorator, stacks under @require_endpoint_permission
```

reads `X-Second-Factor` from the request, resolves whether the action requires a second factor for this
user right now (§5.3 × §4.1), and if so calls
`otp_service.verify(purpose=f"stepup:{action}", user_id, code=receipt)`. It accepts only when
`result.ok` **and** `result.destination == hash_session_token(this session)`. A missing or bad receipt
returns

```
403 {"error": "second_factor_required", "action": "<key>", "methods": ["totp", "recovery", ...]}
```

which the API client turns into the step-up modal and a retry (§8.3). A receipt is consumed on first use,
so it covers exactly one call. When the action is not required for this user the decorator is a no-op —
the route behaves exactly as today — **except for `admin.*` actions, which are never a no-op** (§5.3).

Login is the same protocol with a different receipt: the "action" is `login` and the thing unlocked is
the session itself (§6).

---

## 4. The action catalog and the policy matrix

### 4.1 `SECOND_FACTOR_ACTIONS` (code) → `second_factor_actions` (table)

A new pure module `app/core/second_factor_actions.py`, shaped like `email_actions._ACTION_META`:

| key | route(s) it guards today | default `require_otp` |
|---|---|---|
| `login` | `POST /auth/login` | on (a second factor that is not asked for at login is not a second factor) |
| `account.change_password` | `PATCH /users/me` with `new_password` (already demands `current_password`) | on |
| `account.change_email` | `PATCH /users/me` when the request changes `email` (the direct change the handler performs whenever `email_change_requires_verification` is off — its default), **and** `POST /users/me/request-email-change` (the verified path; this is a *different* purpose from the code sent to the new address) | on |
| `account.second_factor` | enroll / disable / regenerate recovery codes (§7) | on |
| `account.encryption_key.replace` | the proof-bound private-key replacement in `app/api/ecc_router.py` | on |
| `vault.delete` | `POST /vaults/{vault_id}/delete` | on |
| `vault.change_password` | `PUT /vaults/{vault_id}/password` | off |
| `vault.rotate_key` | `POST /vaults/{vault_id}/rotate-key` | off |
| `share.create` | `POST /shares` | off |
| `public_link.create` | `POST /note-links`, and `POST /public-links` once the secure-send design (`docs/design/secure-send-and-receivers.md`) ships | on |
| `receiver.create` | `POST /receivers` (the upload-links surface in the same design) — listed here so the two catalogs match | on |
| `temp_credential.create` | `POST /auth/temp-credentials` | off |
| `admin.user.manage` | **every mutating `USER_MANAGE` route**: `POST /users`, `POST /invites`, `PATCH /users/{user_id}`, `POST /users/{user_id}/send-reset-link`, `POST /users/{user_id}/delete`, `POST /users/{user_id}/terminate-sessions`, and in `app/api/user_management_api.py` (prefix `/api/user-management`) `PUT …/users/{user_id}` (sets role / active), `POST …/users/{user_id}/toggle-locked`, `POST …/users/{user_id}/toggle-active`, `PATCH …/users/{user_id}/role`; plus the new `POST /users/{user_id}/second-factor/reset` (§7.5) | on |
| `admin.settings.write` | `PUT /settings` — the single save endpoint for **every** Settings tab, including the MFA policy itself, so a stolen *enrolled* admin session cannot switch the second factor off (the un-enrolled-admin case is §5.3) | on |

`POST /users` and `POST /invites` are in the `admin.user.manage` row on purpose: both mint an account
with a chosen role, and an account-minting route left outside the matrix turns any admin session into a
factory for factor-less admins (§5.3 closes the other half of that chain).

`login` is special only in that its receipt is the session (§6); it is in the catalog so the matrix
shows it and so `require_otp=false` on it means "second factor is enrolled but only used for step-up"
(a legitimate configuration for a deployment behind an SSO proxy that already does login MFA).

`admin.settings.write` defaulting on means every save on every Settings tab asks for a code. Q3 offers
the alternative of scoping that row to the security-relevant keys.

Seeding mirrors `seed_email_actions`: one row per key, `require_otp` from the catalog default on first
creation only, metadata refreshed from code, an admin's toggles never overwritten. **Extensibility is
adding a tuple to the catalog and a decorator to the route** — no migration, no UI change (the matrix
renders from `GET /second-factor/actions`).

### 4.2 Two contract checks

Mirroring `validate_endpoint_permission_contract` in `app/core/endpoint_permissions.py`: every
`require_step_up(key)` adds `key` to a `GUARDED_STEP_UP_ACTIONS` set, and startup fails unless that set
equals the catalog keys. A catalog entry with no guarded route is a matrix row that does nothing; a
guard with no catalog entry is a route no admin can configure. Both are refused at boot.

That check cannot see a route that is simply **not decorated**, so a second, test-time check
enumerates the routes: every route decorated `@require_endpoint_permission("USER_MANAGE")` whose method
is not `GET` must also carry `require_step_up("admin.user.manage")`, and the test fails on the first
one that does not. A future account-minting route cannot ship unguarded.

### 4.3 The email action

`email_actions.ACTION_CATALOG` gains a **system** entry `second_factor_code` with a default template that
carries `{{action.code}}` and `{{action.expires}}`; the existing required-token fail-safe then guarantees
an admin edit can never ship a code email without the code. It is `system` because when the policy
allows the email method the vault must be able to send it; when the policy does not allow the email
method (§5.1) the action is simply never triggered.

---

## 5. Policy and requirement resolution

### 5.1 The admin policy (in the global settings blob)

| key | values | default | notes |
|---|---|---|---|
| `mfa_mode` | `optional` / `required` | `optional` | `required` = every account must enroll; cannot be personally disabled |
| `mfa_required_group_ids` | list of group ids | `[]` | department tier |
| `mfa_allowed_methods` | non-empty subset of `["totp", "email"]` | `["totp"]` | `recovery` is always allowed once enrolled — it is the safety net, not a method an admin can remove; `password` is not a policy choice (§5.3) |
| `mfa_email_code_ttl_minutes` | 1..60 | 5 | same bounds and validation shape as `email_change_otp_ttl_minutes` |
| `mfa_sftp_policy` | `allow` / `temp_credential_only` | `allow` | §5.5 |

Validation is split the way the account policy's is: a new pure `app/core/second_factor_policy.py`
checks shape and bounds and takes the DB-derived facts as arguments; the `PUT /settings` handler
supplies those facts and calls the existing DB-bound `_validate_group_id_list` for
`mfa_required_group_ids`, exactly as it does for the two existing group lists.

Save-time guards, following `validate_account_policy`'s "DB-derived facts as arguments" pattern:

- `mfa_allowed_methods == ["email"]` is **refused** if any active admin has no email address (the same
  lockout reasoning as the `login_identifier="email"` guard), and refused outright unless SMTP is
  configured (`smtp_configured`, the same fact `email_change_requires_verification` demands). Every
  allowed method must be **enrollable** — which is why §7.2 defines an email enrollment and not only a
  TOTP one; without it, `["email"]` under `mfa_mode=required` would be a permanent lockout, and under
  `optional` no user could ever be in effect.
- `mfa_mode="required"` is allowed even when no admin is enrolled: it does not lock anyone out — it
  forces enrollment at the next login (§5.4). The save response carries a warning listing admins who are
  not yet enrolled, so the admin who flips it knows they will be walked through enrollment themselves.

`GET /auth/policy` (the pre-auth allowlist) gains **nothing** — the login screen learns that a second
factor is needed from the login response (§6), not from policy.

### 5.2 Per-user state — computed, never stored

There is no `users.mfa_pending` column and no per-user "required" flag. The only persisted facts are:

- policy (above), and
- whether the user has an **active enrollment** row (§7.1 — `status='active'`; a row still in the
  enrollment wizard is `unconfirmed` and does not count).

The effective state is a pure function:

```
effective_second_factor(mode, required_group_ids, user_group_ids, has_active_enrollment)
  -> {"required": bool, "source": "global" | "department" | None,
      "state": "setup" | "pending" | "not_setup"}
```

- `required` = `mode == "required"` **or** any of the user's groups is in `required_group_ids`.
- `state` = `setup` if enrolled; else `pending` if required; else `not_setup`.

Because `pending` is derived, an admin dropping the requirement makes every un-enrolled user
`not_setup` on the next read, with no stale flag anywhere and nothing to backfill. A user in a required
department who is moved out of it stops being `pending` the moment the membership row goes — the same
live re-evaluation `stamp_share_scope` already does for department audiences.

The user tier of the resolution is the user's **own** choice (enroll or not, when optional). An
admin-set per-user requirement — a `mfa_required_user_ids` list validated like the group list and
folded into `required` with `source: "user"` — is a small addition to the same function and is Q10
rather than a silent decision.

### 5.3 "In effect", and the admin rule

The second factor is **in effect** for a user when `required` is true **or** the user has an active
enrollment. Only then does login demand it and do the matrix rows bite. A user for whom it is not in
effect is untouched by any of this — their login and every route behave exactly as today.

The consequence to state plainly: an admin who turns `require_otp` on for `vault.delete` while
`mfa_mode` is `optional` has protected only the users who chose to enroll. The matrix UI says so next to
every row (§8.4). Whether ordinary users should get a password re-prompt instead of nothing is Q4.

For **`admin.*` actions the decorator is never a no-op.** The chain it closes: with the default
`mfa_mode=optional`, a stolen *enrolled* admin session could otherwise call `POST /users` (or
`POST /invites`, or the user-management `PUT`) to mint a fresh admin with a chosen password; that
account has no enrollment and is not required, so it is not in effect; the attacker logs in as it with
no factor and calls `PUT /settings` — which the matrix claims to guard — as a no-op. So:

- an admin **with** an enrollment satisfies an `admin.*` step-up with any enrolled method, as anyone
  does;
- an admin **without** one must present the account password through the same challenge/verify
  protocol (`method: "password"`, §3) — a re-authentication, not a second factor, but it is the
  strongest thing a stolen bearer token does not carry, and it means a freshly minted admin cannot act
  on the matrix without knowing its own password (which the attacker chose — so this raises the bar
  from "any bearer" to "the password the attacker set", which is honest to state);
- and the matrix rows for `admin.user.manage` and `admin.settings.write` are **on** by default and
  cover every account-minting route (§4.1), so the chain cannot start without a step-up.

The stronger alternative — treating `mfa_mode=optional` as `required` for `role=admin`, so every admin
is `pending` until enrolled and a freshly minted admin hits forced enrollment at first login (§5.4) —
closes the chain completely and is the recommended answer to Q4.

### 5.4 Forced enrollment

For a user whose state is `pending`, `POST /auth/login` with the correct password returns the same
pre-authenticated response as MFA (§6.1) but with `enrollment_required: true`. The pre-auth token can
reach only the enrollment endpoints (§7.2) and `POST /auth/second-factor/cancel`; the session is created
only once enrollment completes and the first code is verified. This covers onboarding (invitation
acceptance, self-signup and admin-created accounts all end at first login), an existing user when policy
tightens, and a user whose enrollment an admin reset.

### 5.5 SFTP

SFTP authenticates with the account password or an SSH key (`SFTPServer.check_auth_password` /
`check_auth_publickey`) and has no interactive second step; `paramiko` does support
keyboard-interactive, but building an SFTP second factor is not this document. What this document does is
refuse to let SFTP silently become the single-factor back door:

- `mfa_sftp_policy="allow"` (default): unchanged — SFTP stays password/key. **With this default a
  password-only attacker still reads and writes every Standard vault over SFTP**, and `/features` must
  say so (§8.5).
- `mfa_sftp_policy="temp_credential_only"`: an account for which the second factor is in effect may
  reach SFTP **only through a temporary credential**, reusing the exact mechanism
  `_user_requires_temp_cred_for_sftp` already implements per group; minting that credential is a
  `temp_credential.create` step-up if the matrix says so.

Q6 asks whether the default should be the stricter one; §8.5 says what each answer means for the
advertised flag.

---

## 6. Login

### 6.1 The two-step login — no session until the second step

`POST /auth/login`, unchanged up to and including `authenticate_user`. Then:

- **Temporary credentials** (`temp_*`) never enter this path. A temporary credential is a scoped
  delegation of an account, its own gate (validity window, one-time/multi-use, optional per-vault
  passcode), not an account login; the second factor belongs to the account holder's own sessions.
- If the second factor is **not in effect** (§5.3): today's response, byte-for-byte, session row and
  all.
- Otherwise **no `ActiveSession` row is created yet.** A `pending_logins` row is inserted instead
  (§7.1: id, user, client ip, attempts, 5-minute expiry) and the response is `200` with

  ```
  {"access_token": null, "second_factor_required": true, "enrollment_required": <bool>,
   "methods": ["totp", "recovery"] | ["email"] | ...,
   "pre_auth_token": "<jwt>"}
  ```

  The pre-auth token is a JWT with `sub`, **`stage: "second_factor"`**, `pre_auth: <pending_logins.id>`
  and a 5-minute `exp` — and **no `session_token`**. That absence is the confinement: `get_current_user`,
  the `/ws/monitor` handshake and `POST /api/logout` each already refuse a token with no session
  (§1.4), so nothing that exists today can be reached with it, including the live monitor feed that a
  session-backed pre-auth token would have opened. The only routes that accept it use a dedicated
  dependency, `get_pre_auth_principal`: verify the signature, require `stage`, load the
  `pending_logins` row by `pre_auth`, and require it unconsumed and unexpired. Audit records
  `login_password_ok` (a new action), not `login_success`; the `login_alert` optional email and the
  monitor broadcast fire only after the second step.

### 6.2 The second step

`POST /auth/second-factor/verify` `{method, code}` with the pre-auth token:

- runs `verify_second_factor(action="login", ...)` (§3);
- on success **consumes the `pending_logins` row** with a conditional `UPDATE … WHERE consumed_at IS
  NULL` (single winner), creates the session through `_create_session`, mints the full JWT with
  `session_token`, `amr: ["pwd", "<method>"]`, `mfa_at: <epoch>` and the normal `session_timeout`
  expiry; records `login_success`; fires the login broadcast and `login_alert`;
- on failure: the OTP service's 3-strike rule applies to email codes; for TOTP, recovery and password
  the `pending_logins.attempts` column is incremented **in the database** and the row is invalidated at
  5 — durable, so the lockout survives a Redis outage, unlike a Redis-only counter would. The user
  starts again from the password. Combined with the auth-bucket rate limit on `/verify` (§3.1), online
  TOTP guessing is bounded by two independent gates.

`POST /auth/second-factor/cancel` consumes the pending row without a session, so an abandoned login is
closed cleanly rather than left to expire.

Using a **recovery** code at login succeeds, then does three things: audits `second_factor_recovery_used`,
raises an in-app notification through `_notify_users` ("a recovery code was used to sign in from
<ip>"), and sets a flag in the response that makes the client open the profile modal recommending
re-enrollment. When the last recovery code is consumed the profile status turns red.

### 6.3 Mid-session policy changes

The requirement is evaluated at login. A session minted before an admin flips `mfa_mode` to `required`
keeps working until its JWT expires (`session_timeout`); there is no absolute session lifetime in the
shipped tree, so that window is bounded only by expiry and re-login. The stricter alternative —
`get_current_user` comparing `amr` against the live requirement and answering
`401 {"detail": "second_factor_required"}` — is Q5, and the shipped state is why it matters.

---

## 7. Enrollment, recovery codes, data model

### 7.1 Tables (new, additive — `create_all` builds them; no ALTER)

```
second_factor_enrollments
  id UUID PK · user_id UUID FK users CASCADE UNIQUE · method VARCHAR(16) ('totp' | 'email')
  secret_enc TEXT NULL (encrypt_secret of the base32 seed; NULL for 'email')
  status VARCHAR(16) ('unconfirmed' | 'active')
  last_used_step BIGINT NOT NULL DEFAULT 0 · created_at · confirmed_at · last_used_at

second_factor_recovery_codes
  id UUID PK · user_id UUID FK users CASCADE (index) · code_hash VARCHAR(255) (argon2)
  consumed_at · created_at

second_factor_actions
  key VARCHAR(64) PK · require_otp BOOLEAN NOT NULL · updated_at

pending_logins
  id UUID PK · user_id UUID FK users CASCADE (index) · client_ip VARCHAR(45)
  enrollment_required BOOLEAN · attempts INTEGER NOT NULL DEFAULT 0
  expires_at · consumed_at · created_at
```

The enrollment status is `unconfirmed`, not `pending`, so the word `pending` means exactly one thing in
this design (the derived state of §5.2). `UNIQUE(user_id)` on enrollments means one active method per
user for now; WebAuthn (§10) will relax it to `UNIQUE(user_id, method)`, which is a new constraint on a
table that will then already exist — that ALTER is the fast-follow's problem and is noted there so it is
not a surprise. `pending_logins` rows are swept after expiry. The declaration in
`docs/upgrade-matrix.json`: reversible (dropping the tables loses enrollments, nothing else), no backup
required, condition: "users enrolled in a second factor will be asked to enroll again after a downgrade".

**Why `otp_codes` is reused for email codes and receipts but not for TOTP.** A TOTP proof is not issued
by the server, so there is nothing to store per code; what must be stored is the seed and the
replay counter, which is the enrollment row.

### 7.2 Enrollment protocol

All of these run under `require_step_up("account.second_factor")`. The very first enrollment of an
un-enrolled user is exempt from that gate — there is nothing yet to verify with — and instead requires
the account password to be re-entered in the request body.

**TOTP**

1. `POST /users/me/second-factor/totp/enroll` → server mints a 20-byte seed (`secrets.token_bytes`),
   stores it sealed with `status='unconfirmed'` (replacing any prior *unconfirmed* row; an *active* row
   is never replaced here — that is "disable, then enroll"), returns the
   `otpauth://totp/<brand>:<username>?secret=…&issuer=<brand>&algorithm=SHA1&digits=6&period=30`
   URI and the base32 seed for manual entry. The issuer is the effective brand `app_name`.
2. The client renders the **QR code locally**. `tests/test_static_selfhosted_assets.py` guards against
   CDN references, so the encoder is either a vendored QR library under `static/vendor/` or a
   server-rendered SVG from a small PyPI dependency (`qrcode`, no Pillow) at
   `GET /users/me/second-factor/totp/qr.svg` — **Q1**.
3. `POST /users/me/second-factor/totp/confirm` `{code}` → verifies against the unconfirmed seed; on
   success generates **10 recovery codes** (10 characters from a 32-symbol alphabet, ~50 bits each,
   grouped `xxxxx-xxxxx`), stores their argon2 hashes, and returns the plaintext codes **once**,
   together with the enrollment still marked `unconfirmed`.
4. `POST /users/me/second-factor/recovery/acknowledge` → flips the enrollment to `active`. Until this
   call the user is not enrolled: the recovery codes are mandatory not by a checkbox the UI could skip
   but by the state machine. An abandoned enrollment is swept after 24 h.
5. Enrolling revokes the user's **other** sessions with `_revoke_sessions` — the helper the lock,
   terminate-sessions and password-reset paths use — on the principle that a change to how the account
   authenticates should not leave older sessions standing. (This design assumes the same will hold for
   a self-service password change; the shipped tree does not do it yet, §1.4.)

**Email** (only when `email` is in `mfa_allowed_methods`; makes that method enrollable, §5.1)

1. `POST /users/me/second-factor/email/enroll` → refuses if the account has no email; issues
   `otp_service.issue(purpose="sf:enroll_email", destination=user.email)` and sends it via
   `second_factor_code`; creates the `unconfirmed` row with `method='email'`, `secret_enc NULL`.
2. `POST /users/me/second-factor/email/confirm` `{code}` → verifies; then recovery codes and
   `acknowledge` exactly as for TOTP (steps 3–5). An email enrollment is invalidated automatically if
   the account's email is later removed (the `PATCH /users/me` clear path), which returns the user to
   `pending`/`not_setup` by the computed rule.

Disable (`DELETE /users/me/second-factor`) is refused with `409` when the second factor is required for
this user (§5.2), otherwise deletes the enrollment and every recovery code under the
`account.second_factor` step-up. Regenerate (`POST /users/me/second-factor/recovery/regenerate`)
invalidates all previous codes and returns ten new ones, once, under the same step-up.

### 7.3 Replay and drift

TOTP acceptance requires `|step − now_step| ≤ 1` and then the conditional `UPDATE … WHERE
last_used_step < :step` of §3 to report one row. This is RFC 6238 §5.2's "must not accept the same OTP
twice" made concrete and race-free, and it is what makes the 30-second code *action-bound* in practice:
one code, one verification, one receipt, one action — even when two verifications race.

### 7.4 The encryption key is not behind the second factor

The zero-knowledge private key is an opaque passphrase-encrypted envelope
(`docs/design/vault-private-key-envelope-v1.md`); the passphrase, not the session, opens it. The second
factor gates **sessions**. So a lost authenticator plus lost recovery codes loses the *session*, never
the key: an admin resets the enrollment (§7.5), the user logs in with password only, enrolls again, and
the key envelope is untouched. Nothing in this design wraps, derives from, or stores anything near the
ZK material, and nothing should — a second factor that could be reset by an admin must not be a
component of a key the server is supposed to be unable to reconstruct.

### 7.5 Admin reset

`POST /users/{user_id}/second-factor/reset` — `USER_MANAGE`, interactive admin, `admin.user.manage`
step-up. Deletes the enrollment and recovery codes, revokes the user's sessions, audits
`second_factor_admin_reset`, notifies the user. If the account is `pending`/`required` they enroll at
next login (§5.4). An admin cannot reset their **own** enrollment through this route while
`mfa_mode="required"` and they are the only enrolled admin — Q7 asks whether that guard is wanted at
all, since the alternative recovery path is `scripts/` access to the host.

---

## 8. Frontend

### 8.1 Login screen

`#login-form` submits as today. On `second_factor_required` the form is swapped for a second card: a
code input, a method switch when more than one is allowed, and "Use a recovery code". The input is
`inputmode="numeric"` / `autocomplete="one-time-code"` for TOTP; for the email method it depends on
Q11 — the OTP service's code is 12 hexadecimal characters today, which a numeric keyboard cannot type,
so either `otp_service.issue` grows a digits variant (six digits, which with the 3-strike rule is a
1-in-333 000 guess per issued code) or the email prompt uses a text input. On `enrollment_required` the
card is the enrollment wizard (§8.2) in-place, gated by the pre-auth token. Errors are the server's
`detail`, verbatim, never the reason category (the code-vs-locked distinction stays inside the audit
log).

### 8.2 Profile: "Two-factor authentication", beside "Encryption key"

A new `profile-dropdown-item` opening `#second-factor-modal`, built exactly like
`refreshEncryptionKeyStatus`: status first (`setup` / `pending` / `not_setup` from
`GET /users/me/second-factor`, plus the source of the requirement — "required by your organisation",
"required for the Engineering department", "optional"), then the actions the state permits (enroll;
regenerate recovery codes; disable, disabled with an explanation when required). The wizard: QR + manual
key → confirm code → recovery codes with copy/download and an explicit "I have saved these" that calls
`acknowledge`. The recovery-code download is a plain text file named after the brand and username; the
page never keeps the codes after the modal closes.

### 8.3 The step-up modal

`apiRequest` gains one branch: a `403` whose body is `second_factor_required` opens a generic modal for
`action`, runs the challenge (for `email`) and `verify`, stores the receipt, and **retries the original
request once** with `X-Second-Factor`. A second `403` is surfaced as an error. The modal names the
action in plain words ("Confirm deleting the vault *Finance 2025*") — the catalog's `name` — so a user
is never asked for a code without knowing what it will authorize. For an un-enrolled admin on an
`admin.*` action the modal asks for the account password (§5.3) and says why.

### 8.4 Settings → Accounts & Access → "Second factor"

Mode, departments (the same chip picker `sftp_require_temp_cred_groups` uses), allowed methods, email
code TTL, SFTP policy, and the **action matrix**: one row per catalog entry with its name, description,
the routes it guards, a switch, and the plain sentence "applies to users who have a second factor set up
or are required to; administrators are always asked" (§5.3). Saving is itself an
`admin.settings.write` step-up.

The Users page shows the computed state per user as a chip (`Set up` / `Pending` / `Not set up`) and a
**Reset second factor** action.

### 8.5 The `/features` flag — derived, and honest about SFTP

`authentication.2fa_enabled` becomes **derived**, and it is `true` only when both hold: the login path
of §6 is shipped and enforcing, **and** SFTP is covered — `mfa_sftp_policy != "allow"` or SFTP is
disabled (`enable_sftp` false). With the proposed default (`allow`) the flag therefore stays `false`,
and a new `authentication.2fa_scope: ["web"]` says what is actually enforced, so a deployment never
advertises a second factor that a password-only SFTP login walks around. `enable_2fa` is kept as an
accepted-but-ignored field for one release with a deprecation note in its description (it is part of
the `BRAND_*` public contract, which `CLAUDE.md` forbids removing without a deprecation path), then
removed. Until §6 ships, nothing changes and the flag stays `false`.

---

## 9. Testing (the load-bearing cases)

- **Action binding.** A receipt earned for `login` presented on `POST /vaults/{id}/delete` → 403; a
  TOTP code accepted for login, replayed within the same step for a step-up → refused; two concurrent
  verifies of one TOTP code → exactly one receipt; an email code issued under `sf:vault.delete`
  verified under `sf:login` → `not_found`.
- **Single use.** Two concurrent presentations of one receipt: exactly one succeeds (drives the OTP
  service's single-winner path, which its own tests already cover; this pins the receipt use).
- **Session binding.** A receipt earned in session A presented in session B for the same user → 403.
- **Pre-auth token confinement.** A `stage: second_factor` token on `GET /vaults` → 401; on
  `/ws/monitor` → the socket is closed with 1008; on `POST /api/logout` → 401; on
  `/auth/second-factor/verify` → allowed; after `cancel`, on `/verify` → 401.
- **Admin chain.** Enrolled admin mints an admin via `POST /users` without a receipt → 403; with one,
  the new admin's `PUT /settings` without a password receipt → 403.
- **Contract.** A catalog key without a guarded route fails boot; a guard without a catalog key fails
  boot; a mutating `USER_MANAGE` route without `require_step_up("admin.user.manage")` fails the
  route-enumeration test.
- **Computed state.** User in a required department: `pending`; remove the membership: `not_setup` on
  the next read with no write in between (assert on the DB row count).
- **Forced enrollment.** `mfa_mode=required`, fresh account: login yields `enrollment_required`; the
  enrollment endpoints work under the pre-auth token; `GET /vaults` does not, until `acknowledge`.
  `mfa_mode=required` with `mfa_allowed_methods=["email"]`: a fresh user with an email can complete
  login.
- **Lockout durability.** Five wrong TOTP codes with Redis stopped → the sixth is refused.
- **Recovery.** Each code works once; using one at login audits + notifies; the tenth consumption flips
  the profile status; regenerate invalidates the old set.
- **Encryption key untouched.** Enroll, reset by admin, re-login: the `UserKeyPair` row and the
  passphrase-envelope round-trip are byte-identical before and after.
- **Honesty.** `GET /features` reports `2fa_enabled: false` until the login refusal test above passes
  **and** `mfa_sftp_policy` is not `allow`; `2fa_scope` lists exactly the enforced surfaces; the
  assertions live in the same test file so one cannot be green without the other.
- **Policy guards.** `mfa_allowed_methods=["email"]` with an email-less admin → 400; an empty method
  set → 400; `mfa_mode=required` save returns the un-enrolled-admin warning.

---

## 10. Non-goals

- **WebAuthn / passkeys.** The fast-follow. The catalog, the challenge/verify protocol and the
  enrollment table's `method` column are shaped to take a `webauthn` method (a challenge that carries
  the credential-request options, a verify that takes the assertion); the `UNIQUE(user_id)` relaxation
  is noted in §7.1. Not built here.
- **An SFTP interactive second factor.** §5.5 gives the admin a lever; it does not add
  keyboard-interactive to `paramiko`.
- **SMS / push.** No carrier integration, no vendor app.
- **Remembered devices / "don't ask again on this browser".** Every new session asks. A trusted-device
  cookie is a separate design with its own threat model.
- **Second factor on temporary credentials.** They have their own gates (validity, one-time, passcode).
- **Binding the second factor into zero-knowledge key derivation.** Explicitly rejected in §7.4.
- **A grace period after a step-up.** A receipt covers one call. Batching (for example deleting three
  vaults) asks three times; if that proves too noisy the fix is a bounded multi-use receipt, decided
  later with evidence.
- **Revoking other sessions on a self-service password change.** Assumed, not built here (§1.4, §7.2).

---

## 11. Open questions (decisions to make before building)

1. **QR rendering**: vendor a small JS encoder under `static/vendor/` (client-side, no new Python
   dependency) or add `qrcode` to `requirements.txt` and serve an SVG (server-side, one more supply-chain
   pin)? Recommendation: server-side SVG — the seed already crosses the wire in the enroll response, and
   one reviewed Python dependency is easier to keep pinned than a JS bundle.
2. **Is the `email` method wanted at all?** It is phishable and only as strong as the mailbox.
   Recommendation: ship it, default *off* (`mfa_allowed_methods: ["totp"]`), for deployments whose
   users cannot install an authenticator.
3. **Catalog defaults**: the `on`/`off` column in §4.1 is a proposal. In particular: should
   `share.create` and `temp_credential.create` default on; and should `admin.settings.write` gate every
   `PUT /settings` (proposed) or only the security-relevant keys (MFA policy, account policy, the
   sharing switches)?
4. **Un-enrolled users and the matrix** (§5.3): for ordinary users, do nothing (proposed) or fall back
   to a password re-prompt? For administrators, keep the password re-prompt (proposed here) or treat
   `mfa_mode=optional` as `required` for `role=admin` (recommended — it closes the account-minting
   chain completely)?
5. **Mid-session tightening** (§6.3): let existing sessions run out, or refuse them until they
   re-authenticate with the second factor?
6. **SFTP default** (§5.5): `allow` (proposed, no behaviour change — and `/features` then reports
   `2fa_scope: ["web"]` rather than `2fa_enabled: true`) or `temp_credential_only`?
7. **Last-enrolled-admin guard** (§7.5): keep it, or accept that host access is the recovery path?
8. **Response shape for the two-step login**: `200` with `access_token: null` (proposed, keeps every
   existing client's error handling intact) or a dedicated status?
9. **Recovery-code count and format**: ten codes of ~50 bits each (proposed); some deployments prefer
   eight or sixteen.
10. **Per-user admin requirement** (§5.2): is an admin-set `mfa_required_user_ids` wanted, or is the
    user tier purely the user's own choice?
11. **Email code format** (§8.1): a six-digit numeric variant of the OTP service's code (typeable,
    weaker per code, bounded by the 3-strike rule and the rate limit), or keep the 12-hex-character code
    with a text input?
