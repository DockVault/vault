# Design: Email Studio (sending profiles, HTML templates, image resources)

Status: implemented · Scope: `app/api/email_studio_router.py`, `app/core/email_sanitize.py`,
`app/core/email_send.py`, `app/core/models.py`, Settings → Email UI · Audience: self-hosters + admins

Email Studio replaces the vault's single global SMTP form with a small workbench for outbound mail:
multiple **sending profiles**, reusable **HTML templates** with a live editor, a private
admin-only **image resource folder**, per-recipient **personalization tokens**, and a manual
**send** flow. The whole surface is admin-only and defense-in-depth on the HTML that goes out.

Nothing here changes how the vault sends its *system* mail (the email-change verification): that path
keeps working through the migrated **Default** profile.

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
additionally strips CR/LF, closing the header-injection vector. `{{otp}}` and other future tokens slot
into the same table; an unknown `{{…}}` is left as literal, inert text and flagged as a non-blocking
warning.

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

`_send_email`/`_smtp_configured` in `api_server.py` read the **default profile** (with a legacy blob
fallback) so the vault's own email-change verification keeps sending.

## 6. Frontend

Settings → Email is two stacked sections plus modals: a **sending-profile card grid** (edit/create in
a modal with server|port and username|password on single rows and Send-test + Save side by side), and
a **template card grid** feeding a full-width **inline editor** (name, description, profile select,
subject; a formatting toolbar; a **Code / Render / Split** view toggle). The Render pane is the
sandboxed preview iframe. All DOM is built with `createElement`/`textContent`; the sandboxed iframe's
`srcdoc` is the only HTML sink in the UI. A client-side check blocks obvious script markup before Save,
but it is a UX affordance — the server sanitizer is authoritative.

## 7. Non-goals (this iteration)

- **No inline `style`/`class`** on template HTML (no arbitrary CSS). A documented follow-up.
- **No binding of templates to system flows** (invite / reset / email-change). System verification
  keeps using the migrated Default profile; wiring templates into those flows is later work.
- **No scheduling / bulk campaign management.** Send is a manual, admin-initiated action.
- **No OTP token yet** — the `{{token}}` framework is in place; the OTP value is future work.
