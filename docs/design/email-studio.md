# Design: Email Studio (sending profiles, HTML templates, image resources)

Status: implemented · Scope: `app/api/email_studio_router.py`, `app/core/email_actions.py`,
`app/core/email_sanitize.py`, `app/core/email_send.py`, `app/core/otp_service.py`,
`app/core/password_reset.py`, `app/core/models.py`, `app/api/api_server.py`, Settings → Email +
Settings → Accounts & Access UI · Audience: self-hosters + admins

Email Studio replaces the vault's single global SMTP form with a small workbench for outbound mail:
multiple **sending profiles**, reusable **HTML templates** with a live editor, a private
admin-only **image resource folder**, per-recipient **personalization tokens**, and a manual
**send** flow. The whole authoring surface is admin-only and defense-in-depth on the HTML that goes
out.

On top of that workbench the vault drives its **automated emails** — the messages the vault itself
sends in response to an event (email-change verification, password reset, an account invitation, and
five optional courtesy notices). Each automated email is an **action** bound to a template an admin
can edit; the security-sensitive ones (the OTP code, the reset link) are backed by dedicated
single-use, expiring, peppered-at-rest token machinery (§7–§9).

---

## 1. Motivation

The vault could store exactly one SMTP configuration and had no way to compose a real email. An
operator who wanted to send a branded HTML message — a welcome note, an announcement — had nowhere to
do it, and there was no safe path for embedding an image. Email Studio adds that, while treating the
HTML body as untrusted input at every hop, because a template is rich text an admin authors and the
server ultimately turns into mail sent to real inboxes.

## 2. Data model (new tables only)

Three new tables, created by `init_db()`'s `create_all()` (which only ever *adds* missing tables — it
never ALTERs an existing one), so a deployed vault migrates cleanly on the next start:

- **`email_profiles`** — a named SMTP sender identity: `smtp_server`, `smtp_port`, `smtp_username`,
  `smtp_password` (write-only — never returned by any GET; blank on update keeps the stored value),
  `from_email`, `from_name`, and an `is_default` flag. A partial unique index enforces **at most one
  default**; deleting the default auto-promotes another profile.
- **`email_templates`** — `name`, `description`, an optional `profile_id` (FK, `SET NULL` so deleting
  a profile doesn't delete templates), `subject`, and `body_html` (the server-sanitized authoritative
  HTML).
- **`email_resources`** — a private image, stored as **bytes in the DB** (`LargeBinary`) with its
  `filename`, sniffed `content_type`, `byte_size`, and `sha256`. The row's UUID **is** the only handle
  a template ever holds.

Storing resource bytes in the DB is deliberate: there is no filesystem path to leak, and the image is
served only through an admin-gated endpoint.

## 3. The sanitization pipeline (the security core)

`app/core/email_sanitize.py` is built on **nh3** (the Rust *ammonia* HTML sanitizer). HTML is treated
as untrusted at three points:

1. **On save** — `POST/PUT /email/templates` runs the body through the nh3 allowlist and stores the
   result. Independently, a **hostile-content check** runs on the *raw* submission: a `<script>`,
   an `on*=` handler, a `javascript:`/`vbscript:`/`data:text/html` URL, or an `<iframe>`/`<object>`/
   `<embed>`/`srcdoc` triggers a `MALICIOUS_EMAIL_CONTENT` security event tied to the admin's
   identity **and a 400** — it is not silently stripped. Benign-but-unsupported tags (`<style>`,
   `<meta>`, `<form>`, `<svg>`) are silently dropped by the allowlist, not alerted.
2. **On preview** — `POST /email/templates/preview` sanitizes + personalizes for the editor's render
   pane. It never raises a security event (it runs live as the admin types) — it just shows the
   sanitized result, which visibly strips anything unsafe.
3. **Before send** — every recipient's message is personalized and then **re-sanitized**, and a
   tamper check re-runs the hostile-content scan on the stored body. So even a body altered directly
   in the database on a running host cannot put script into an outgoing email; a tamper hit raises the
   security event and refuses the send.

The allowlist keeps a small formatting vocabulary (paragraphs, `strong`/`em`, `h1`–`h4`, lists,
links, tables, `blockquote`, `code`, `img`). Links are forced to `http`/`https`/`mailto` with
`rel="noopener noreferrer"`. An `img` may carry only `data-resource-id`/`alt`/`width`/`height` — **no
`src`** survives sanitization, so a template can never reference an external URL.

### Personalization tokens

`{{user.username}}`, `{{user.email}}`, `{{user.display_name}}`, `{{current_date}}`,
`{{current_time}}`, `{{current_datetime}}`, and `{{vault.name}}` are substituted per recipient. Values
are HTML-escaped (including attribute-quote escaping) and the substitution runs *before* the final
re-sanitize, so a recipient's own field can never introduce markup. The **subject** substitution
additionally strips CR/LF, closing the header-injection vector. Automated emails add
**action-context tokens** (`{{action.code}}` for the OTP, `{{action.link}}` for the reset/invite link)
that the sending flow supplies per event; these slot into the same escape-then-re-sanitize table (the
full grouped set is served by `GET /email/dynamic-actions`). An unknown `{{…}}` is left as literal,
inert text and flagged as a non-blocking warning.

## 4. Images: referenced by UUID, resolved at the edges

A template body only ever contains `<img data-resource-id="UUID">` — the byte location appears
nowhere in stored templates or in sent mail. The reference is resolved differently per surface:

- **Editor preview**: the resolved image is inlined as a `data:<type>;base64,…` URI. The render pane
  is a `sandbox=""` (opaque-origin, no-credentials) iframe, so it can't authenticate to the admin-only
  byte route; inlining lets it display the image without a URL. To bound memory, the preview caps the
  total bytes it will inline per request and is rate-limited — a template can otherwise reference many
  large images and a scripted loop could exhaust the worker.
- **Send**: each referenced image becomes an inline `cid:` part (`multipart/related`); the message
  carries the bytes, never a link back to the vault.
- A dangling/deleted/unknown reference is dropped (the `<img>` is removed) at both surfaces — a path is
  never emitted.

Uploads accept raster images only (`png`/`jpeg`/`gif`/`webp`), and the **content type is decided by
sniffing the magic bytes, never trusting the client**. SVG is rejected (it is an XML/script vector).
Bytes are served with `X-Content-Type-Options: nosniff` and `Content-Disposition: inline`, so a
polyglot (e.g. a script-bearing GIF) can't be re-interpreted as HTML by a browser. There are per-image
size and per-folder count caps.

## 5. Endpoints (all admin-gated, prefix `/email`)

All routes require an **interactive admin** (the same surface as `PUT /settings`; a temp-credential
minted by an admin cannot manage them). The bulk live in `email_studio_router.py` to keep them out of
`api_server.py`.

- Profiles: `GET/POST /profiles`, `PUT/DELETE /profiles/{id}`, `POST /profiles/test` (send a one-off
  test through a saved-or-unsaved profile body; save-independent).
- Templates: `GET/POST /templates`, `GET/PUT/DELETE /templates/{id}`, `POST /templates/preview`,
  `POST /templates/{id}/send` (recipients = vault user ids + free-form addresses; per-recipient
  render; inline images; dedup + a combined recipient cap; before-send re-sanitize + tamper check;
  rate-limited).
- Resources: `GET /resources` (metadata only), `POST /resources` (upload), `GET /resources/{id}`
  (admin-gated bytes, for the picker thumbnails), `DELETE /resources/{id}`.
- Actions: `GET /email/actions`, `PUT /email/actions/{key}` (bind a template / toggle an optional
  notice — enabling requires a bound template, 400 otherwise), `GET /email/default-templates` (the
  code defaults for Load From), `POST /email/actions/{key}/test` (styled send-test; resolves a picked
  user's address server-side; `[Test]`-marked).

The public, non-admin automated-email surfaces live in `api_server.py`: `POST /auth/forgot-password`
and `GET`/`POST /reset/{token}` (rate-limited, gated, enumeration-safe — §9), the admin
`POST /users/{id}/send-reset-link` (`USER_MANAGE`), and the email-change verify/confirm endpoints (now
on the OTP service — §8).

`_send_email`/`_smtp_configured` in `api_server.py` read the **default profile** (with a legacy blob
fallback) so the vault's automated mail keeps sending.

## 6. Frontend

Settings → Email is two stacked sections plus modals: a **sending-profile card grid** (edit/create in
a modal with server|port and username|password on single rows and Send-test + Save side by side), and
a **template card grid** feeding a full-width **inline editor** (name, description, profile select,
subject; a formatting toolbar; a **Code / Render / Split** view toggle). The Render pane is the
sandboxed preview iframe. All DOM is built with `createElement`/`textContent`; the sandboxed iframe's
`srcdoc` is the only HTML sink in the UI. A client-side check blocks obvious script markup before Save,
but it is a UX affordance — the server sanitizer is authoritative.

## 7. Automated email actions

`app/core/email_actions.py` turns the manual workbench into the vault's outbound automation. It
defines a fixed **action catalog** (`ACTION_CATALOG`) — one entry per automated email — in two
categories:

- **System** (`email_change`, `password_reset`, `account_invite`): the email *is* the mechanism for a
  flow the user asked for, so it is always on and cannot be switched off. Its built-in body carries a
  required dynamic token (`{{action.code}}` or `{{action.link}}`).
- **Optional** (`account_welcome`, `login_alert`, `share_created`, `vault_member_added`,
  `temp_credential_issued`): courtesy notices. Each is **off by default** and an admin turns it on
  per action — but only once a template is bound (§7.2).

**Seeded defaults.** `DEFAULT_TEMPLATES` holds a real, polished HTML body for every action, written to
survive the nh3 allowlist unchanged. On boot `seed_default_templates()` creates any missing default
row (keyed by a nullable, partial-unique `EmailTemplate.default_key`) and **pre-binds** each action to
it if the action is not already bound — so a fresh install has working, editable copy for all eight
emails, and re-seeding is idempotent and race-safe (a savepoint tolerates a concurrent boot). A
default row cannot be deleted (`DELETE /email/templates/{id}` refuses it) and its `default_key` cannot
be reassigned, so the restore path below always has an anchor. `GET /email/default-templates` exposes
the code defaults so the editor can offer **Load From** — restore an action's subject+body to its
built-in default (or copy any of the admin's own templates as a starting point) without touching the
stored row until the admin saves.

### 7.1 The central send helper

Everything sends through `send_action_email(db, key, *, recipient, action_context, force,
subject_prefix, footer_html, raise_errors)`. It resolves the action, renders the bound template with
the per-recipient tokens plus the action-specific `action_context` (e.g. `{{action.code}}`,
`{{action.link}}`), re-sanitizes, and hands off to the SMTP layer. Two gates keep an automated email
from going out when it shouldn't:

1. an **optional action that is not enabled** returns without sending (`force` bypasses this only for
   the admin send-test path), and
2. **defense in depth** — an optional action whose template is unexpectedly missing also returns
   without sending, so a half-configured state can never emit a blank email.

For system security actions a **fail-safe** restores the built-in body if a customized template has
dropped the required `{{action.code}}`/`{{action.link}}`, so an admin edit can never ship a reset mail
with no reset link.

Call sites in `api_server.py` fire the optional triggers through thin `_fire_action_email` /
`_fire_action_email_bulk` helpers: they do a cheap enabled-check on the request path, then fan the
actual render+send out to a **daemon thread with its own DB session**, so a slow or failing SMTP
server never blocks or breaks the user-facing operation. `temp_credential_issued` deliberately notifies
the owner **without** putting the plaintext credential in the email; `share_created` links to the
recipient's in-app **Shared** view, never to a raw claim token.

### 7.2 The admin controls (Settings → Email)

Each action renders as a row with a template picker and a clear on/off switch. The switch is
**disabled until a template is bound** (picking "none" unbinds it and forces the notice off); enabling
an optional action with no template is also refused **server-side** (400), so the UI affordance is
backed by a real invariant. The **send-test** control is a styled in-app modal (not a browser prompt):
an admin searches users by username/email and picks one — the destination address is resolved
**server-side** from the user id — or types a free-form address. Test messages carry a `[Test]` subject
prefix and a footer marker so a real recipient can tell a test apart from the genuine article.

## 8. The OTP service (`app/core/otp_service.py`)

A generalized one-time-code service backs the email-change verification (and is available to any future
code-based flow). A code is bound to a **(purpose, user, destination)** triple, so a code minted to
confirm one address can never verify a different purpose, user, or address.

- **Storage: Redis-primary, DB-fallback.** `issue()` writes the code to Redis with a TTL and also
  persists a durable `otp_codes` row; `verify()` consults both. A Redis-issued code lost to a restart
  still verifies from the DB, and a re-issue while Redis is down cannot be shadowed by a stale key: each
  record carries an `issued_at` generation stamp and the **newer store wins in both directions**.
- **At rest** the code is a peppered HMAC-SHA256 (constant-time compare, pepper-length guarded) — never
  the plaintext. Consume is **single-winner**: the Redis delete-count / a conditional DB
  `UPDATE … WHERE consumed_at IS NULL` guarantees a code can be redeemed at most once even under
  concurrent verifies.
- **Limits.** Wrong codes are counted; after **3** consecutive wrong tries the code is invalidated, on
  top of the outer per-endpoint rate limit. TTL is configurable
  (`email_change_otp_ttl_minutes`, default **5**, bounded 1–60). All time math is UTC.

## 9. Password reset (`app/core/password_reset.py`)

A password reset is a **single-use, expiring token** emailed as a link, minted through the same token
discipline as invitations (`secrets.token_urlsafe(32)`, an indexed prefix, a peppered HMAC at rest with
a reset-specific pepper domain, constant-time compare) in a `password_reset_tokens` table.

- **Two ways to start, both owner-bound.** A **public self-service** flow (`POST /auth/forgot-password`)
  is **gated off by default** (`password_reset_enabled`) and, when on, is enumeration-safe: it always
  returns `202`, and the mint+send is backgrounded so a resolved identifier can't be told from an
  unknown one by timing. An **admin** flow (`POST /users/{id}/send-reset-link`,
  `USER_MANAGE`, interactive-admin only) is always available. No other actor can trigger a reset for an
  account.
- **Redeeming** (`GET`/`POST /reset/{token}`) is rate-limited fail-closed per IP, validates the token
  strictly (generic `404` for anything unusable — expired, consumed, unknown), enforces the password
  policy, then **atomically claims** the token (`UPDATE … WHERE consumed_at IS NULL`) and, on success,
  changes the password and **revokes all of the user's existing sessions**, committed durably. TTL is
  configurable (`password_reset_ttl_minutes`, default **5**, bounded 1–60).
- The raw reset token is scrubbed from the access log (both the `/reset/{token}` path and the
  `?reset=` landing query are masked, at the uvicorn access-log filter and the in-app sink), so a
  web-scoped log-pull can't read it back.
- The emailed link's base URL prefers the operator-configured public host (`ALLOWED_HOSTS`, via
  `email_actions.public_base_url` / `vault_url`) over the request's own `Host` header, so a spoofed
  `Host` can't poison the tokened link for a deployment that has set `ALLOWED_HOSTS`. **An
  internet-facing vault that enables public self-service reset should set `ALLOWED_HOSTS`** — that both
  pins the link host and turns on `TrustedHostMiddleware`; with it unset the link falls back to the
  request host (unchanged default behaviour, matching the invite and share links). The account
  invitation link uses the same helper.

The three security knobs (`email_change_otp_ttl_minutes`, `password_reset_enabled`,
`password_reset_ttl_minutes`) live in the one account-policy blob and are surfaced in **Settings →
Accounts & Access**; `PUT /settings` validates type and bounds server-side.

## 10. Non-goals (this iteration)

- **No inline `style`/`class`** on template HTML (no arbitrary CSS). A documented follow-up.
- **No scheduling / bulk campaign management.** The manual **send** flow is an admin-initiated action;
  automated emails fire only in response to their event.
- **No email delivery of the temp-credential secret or share claim token** — those notices point the
  recipient into the app; the secret is never in the mail.
