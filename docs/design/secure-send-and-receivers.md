# Design: secure send (public file links) and receivers (upload links)

Status: **proposed — design only, nothing in this document is implemented** · Scope:
`app/core/models.py` (`Share*`, `NoteLink*`, `Vault`, `File`, `ChunkedUploadSession`),
`app/core/note_link_policy.py`, `app/core/sharing_policy.py`, `app/api/api_server.py` (the share,
note-link, vault-create, vault-settings and upload routes), `static/note-link.html` +
`static/js/note-link.js`, the Shared page and the Share modal in `static/index.html` / `static/js/app.js`,
Settings → Sharing · Audience: self-hosters + admins + whoever builds it

External file exchange in two directions, both built on primitives that already exist:

- **Outbound — "secure send".** The anonymous public-link engine today carries *text only*: a
  `NoteLink` is a frozen `title_snapshot`/`body_snapshot` of a note, redeemed at `/l/{token}`. This
  document extends that engine to **files and folders**, keeps its tags, tighten-only policy, kill
  switch, revoke and admin oversight, and folds the result into the existing **Shared** page rather
  than adding one.
- **Inbound — "receivers".** A new **Upload links** page where a user creates a *receiver*: a
  throwaway Standard vault with a random name, fronted by a public upload link. Two kinds: **Standard**
  (direct upload, encrypted at rest by the server as every Standard-vault file is) and **Confidential**
  (a symmetric password envelope applied in the uploader's browser before the bytes leave it; the owner
  types the same password to read). The second kind is deliberately labelled *confidential /
  pseudo-protected* and **never "zero-knowledge"** — §4.3 says exactly what it is and is not.

Inbound is treated as what it is: a **data-exfiltration-IN surface** on the deployment. Size caps,
retention, a scanning hook and an admin master gate are must-haves, not options (§5).

Where this document says "step-up", it means the receipt mechanism of
`docs/design/login-mfa-and-step-up-otp.md` §3; the two catalogs are kept in agreement (§2.2, §3.1).

---

## 1. What exists

### 1.1 Internal sharing (identity-checked, never anonymous)

`Share` / `ShareTag` / `ShareClaim` in `app/core/models.py`; `POST /shares` (`create_share`) refuses a
temporary session, a disabled feature (`sharing_policy.sharing_enabled`, strict `is True`), a
zero-knowledge vault, a password-protected vault/folder/file, an inactive tag, and a creator the tag's
live allowlist (`sharing_policy.user_can_create_with_tag`) does not admit; it snapshots the tag's
limits onto the row, mints a bearer link token stored only as a SHA-256, and shows it once. Redemption
is `POST /shares/claim` by a **logged-in** user; access is granted per request at the vault chokepoint —
`PermissionService.stamp_share_scope` (`app/core/authorization.py`) stamps a *visible* and a
*downloadable* subtree, re-evaluated live so revocation, expiry and a department change bite on the
next request. Revoke is whole-share or per-claimant. The UI is the **Shared** section
(`#shared-section`: tabs *Shared with me* / *Shared by me*, cards from `_sharedCard` /
`_sharedByMeCard`) and the **Share** modal (`#create-share-modal`: tag → audience → recipients →
view-only → limits → once-shown link). `vaultShareable()` hides Share on ZK and password-protected
vaults.

### 1.2 Public note links (anonymous, text only)

`NoteLinkTag` is an admin **floor**: `min_token_len`, `default_ttl_hours`/`max_ttl_hours`,
`require_secret` (`none`/`pin`/`password` + PIN/password strength), `max_uses_cap`, tile
`border_color`/`icon`, and the same create-allowlist fields as `ShareTag`.
`note_link_policy.resolve_link_policy(tag, overrides)` is a **pure** merge that lets the owner only
*tighten* (longer token, stronger secret, shorter expiry, fewer uses) and raises `PolicyViolation` on
any loosening; the resolved policy is **frozen onto the link row** so a later tag edit or delete
(`tag_id` is `SET NULL`) never changes an existing link. `POST /note-links` enforces the master switch
(`public_note_links_enabled`, default `False`), the allowlist, a per-user active-link cap
(`public_note_link_user_cap`, default 50), allocates a base62 token, and audits. The anonymous page is
`GET /l/{token}` → `static/note-link.html` (`no-store`, `X-Robots-Tag: noindex, nofollow`) with
`static/js/note-link.js` (`textContent` only, no inline handlers under `script-src 'self'`).
`POST /note-links/{token}/redeem` applies **two** fail-closed rate limits (per `(ip, token)` at 10/min
and per IP at 600/min — the enumeration bound), a per-link wrong-secret lockout (5 → 15 min), the
**kill switch** (feature off ⇒ every minted link 404s), a uniform 404 for missing/revoked/expired/
exhausted, and an atomic `UPDATE … WHERE` consume of one use. Owners revoke/delete; admins list
(`/admin/note-links`, never the body), revoke one, or `revoke-all`. Owner tiles render in the Notes
section's *Shared* tab (`_noteLinkCard`), coloured by the tag.

Everything above is reusable as-is. What does not exist is any way to attach a **file** to that path.

### 1.3 The vault primitive

`Vault` has `type` (`standard` / `zero_knowledge`), an optional `password_hash`, `size_limit` (the sum of
`VaultStorageGrant` rows — the owner **and any managers** each fund from their own account budget,
enforced by `_enforce_vault_size` at `POST /vaults`), `expire_files_after_days` + `expire_files_unit`
(which `calculate_file_expiration` turns into `File.expires_at`, swept by
`VaultService.cleanup_expired_files`), and membership through `vault_members` (`read` / `write` /
`delete` / `manage` per user — there is **no** member-level "view but not download" flag — managed at
`POST|DELETE /vaults/{vault_id}/permissions/...`) plus `vault_group_access`. Creation goes through
`_resolve_vault_type_for_create` (the deployment's allowed types, the ZK opt-in and cap, the force-ZK
department rule). The owner can later rewrite `size_limit` and `expire_files_after_days` through
`PATCH /vaults/{vault_id}/settings`. A receiver is exactly this object with a wrapper around it (§3.1) —
and that last route is one of the things the wrapper has to constrain.

### 1.4 Uploads

Two authenticated paths: multipart `POST /vaults/{vault_id}/files`, and the resumable session
(`POST /vaults/{vault_id}/uploads` → `PUT …/chunks/{i}` → `POST …/complete`) backed by
`ChunkedUploadSession`. Its staged chunks are **sealed on disk** by `app/core/upload_chunk_crypto.py`
(a per-session key; no plaintext chunk is ever at rest), and `/complete` streams them
`open_staged_chunk` → `ctx.write_chunk` straight into the at-rest blob through
`VaultService.upload_file_streaming` → `finalize_streaming_upload` — **no assembled plaintext file ever
exists.** New sessions are capped at **25 per principal** (`_session_principal`, which for an
interactive user is "sessions with no `temp_credential_id`"), so a scoped credential cannot lock its
owner out of uploading elsewhere. Deployment policy is `app/core/upload_policy.py`
(`allowed_file_types`, `max_file_size` clamped to `MAX_FILE_SIZE_MB`), `would_exceed_deployment_storage`,
and the concurrency gate `app/core/transfer_admission.py` (`MAX_CONCURRENT_TRANSFERS`, a queue, `503`
+ `Retry-After`). Every one of these takes a `User` principal; none has an anonymous caller today.

### 1.5 Browser crypto

`static/js/ecc_crypto.js` ships two password envelopes. `encryptPrivateKey` / `decryptPrivateKey` are
the **legacy** pair (no AAD; kept byte-for-byte for a pinned vector). The current one is
`encryptPrivateKeyV1` / `decryptPrivateKeyV1`: the AAD-bound grammar of
`docs/design/vault-private-key-envelope-v1.md` — PBKDF2-SHA256 at 600 000 iterations
(`PBKDF2_ITERATIONS`, 32-byte salt) deriving an AES-256-GCM key. The KDF helper behind both
(`_deriveKeyFromPassword`) is private to the module, so the receiver page gets a new public entry point
rather than reaching into it. Beside those there is a memory-bounded streaming content writer for
zero-knowledge uploads (`encryptBlobV2`, measured in `docs/resource-budgets.md`: the renderer holds a
bounded working set, the ciphertext accumulates as Blob parts) with a matching streaming reader on the
download side. The receiver envelope (§4.1) is the v1 envelope grammar and that content writer
composed, with a different key source.

### 1.6 What does not exist

- No anonymous **upload** path of any kind.
- No scanning hook: `grep -ri "clamav\|antivirus\|scan_hook" app/` finds nothing — and, per §1.4,
  no plaintext file a scanner could be pointed at.
- No per-file retention edit endpoint (retention is a vault policy applied at upload).
- No per-user "everything I have exposed" view — internal shares live on the Shared page, note links on
  the Notes page.
- No `MALICIOUS_UPLOAD` security event; `SecurityEventType` (`app/services/security_monitor.py`) ends
  at `MALICIOUS_EMAIL_CONTENT`.

---

## 2. Outbound: public links for files and folders

### 2.1 Which tags govern a public file link

Two tag families exist and they encode different things. `ShareTag` is about **who inside the
deployment** may claim (audiences, recipient caps, view-only) — it presumes an identity. `NoteLinkTag`
is about **how hard an anonymous link is to reach and how long it lives** (token length floor, secret
requirement, TTL ceiling, uses cap). A public file link is anonymous, so it is governed by the
**note-link tag family**, which this document generalises to *public-link tags* while keeping the table
(`note_link_tags`), the routes (`/note-link-tags`) and the seeded catalog (*Open* / *Restricted* /
*Confidential*) unchanged.

One column is added: `allowed_targets JSON NOT NULL DEFAULT '["note"]'` — the target kinds a link
under this tag may expose (`note`, `file`, `folder`). **On upgrade every existing tag gets
`["note"]`**, so no deployment wakes up with a tag that silently permits file exposure; an admin opts a
tag into files explicitly. Per `CLAUDE.md` this is an `ADD COLUMN IF NOT EXISTS` in the boot DDL list
*plus* a backfill *plus* `SET NOT NULL`, declared in `docs/upgrade-matrix.json` (reversible: a downgrade
ignores the column). The alternative — a separate `public_link_tags` table with no ALTER — is Q1.

### 2.2 Data model

```
public_links                                    (files and folders; notes stay in note_public_links)
  id UUID PK · owner_id FK users CASCADE · tag_id FK note_link_tags SET NULL
  token VARCHAR(64) UNIQUE (base62, like NoteLink) · token_len
  vault_id FK vaults CASCADE · target_type ('file' | 'folder')
  target_file_id FK files CASCADE · target_folder_id FK folders CASCADE
  secret_kind ('none' | 'pin' | 'password') · password_hash (argon2)
  expires_at NULL=never · max_uses NULL=unlimited · use_count · download_count · bytes_served BIGINT
  revoked BOOL · created_at · last_used_at
```

The FKs cascade from the **target**: deleting the file (or the folder, or the vault) deletes the link,
so a public link can never outlive what it points at. `use_count` counts successful redemptions (the
thing `max_uses` caps); `download_count` / `bytes_served` are for the owner's card and the admin's
oversight.

Creation (`POST /public-links`) runs under `require_step_up("public_link.create")` — the same catalog
row that guards `POST /note-links` in the MFA design — and mirrors `create_share` and
`create_note_link`:

- `public_file_links_enabled` (new master switch, default `False`, validated like
  `public_note_links_enabled`) must be `True`;
- Standard vaults only; a password-protected vault, folder or file is refused; a temporary session is
  refused;
- the creator must hold READ on the vault (`can_access_vault`) — and, for a *file* or *folder*, the
  target must be in the vault (the same existence checks `create_share` does);
- the tag must be active, list the target kind in `allowed_targets`, and admit the creator
  (`user_can_create_with_tag`, live);
- `resolve_link_policy` (reused unchanged — it is pure and reads a tag through `_tag_attr`) merges the
  floor with the owner's tightening; a `PolicyViolation` is a 400;
- the per-user cap is shared with note links: `public_note_link_user_cap` counts active note links
  **and** public file links together (one budget for "how many anonymous exposures may one user hold
  open"); the key keeps its name for compatibility and the UI label generalises (Q2);
- audit `public_link_create` with `target_type`, `tag`, `secret_kind`, `token_len`, `has_expiry`,
  `max_uses`.

### 2.3 Redemption and download

`GET /p/{token}` serves `static/public-link.html` — a sibling of `note-link.html` with the same
headers and the same `textContent`-only discipline — and `static/js/public-link.js`.

`POST /public-links/{token}/redeem` `{secret?}` is `redeem_note_link` with the body swapped: the two
rate limits, the secret prompt/lockout, the kill switch (`public_file_links_enabled` off ⇒ 404 for
every minted link), the uniform 404, the atomic consume. What it returns differs: not content, but a
**download grant** — a short-lived, single-use bearer bound to `(link, client ip)`, minted with
`secrets.token_urlsafe(32)` and stored hashed in Redis for 60 s. It is deliberately not an
`otp_codes` record (that store is single-active per user, and an anonymous grant has no user), and it
is **fail-closed**: if Redis is unavailable `/redeem` answers `503` and mints nothing — a grant that
cannot be stored is never handed out, and the download endpoint refuses any grant it cannot find. For a
*file* link the response is `{kind: "file", name, size, grant}`; for a *folder* link it is
`{kind: "folder", entries: [{id, name, size, is_folder}], grant}` — one level, names read from the
Standard vault's in-memory-decrypted `File.name` / `Folder.name` (the same plaintext the internal
share card shows), no recursion in v1 (Q3).

`GET /public-links/{token}/download/{file_id}` with the grant in an `X-Download-Grant` header — never a
query parameter, which proxies and browser history record — streams the file. The grant is consumed on
first use (single winner, like the OTP service), the `file_id` must lie inside the link's target
(`app/core/id_scope.id_in_scope` with the folder ancestry — the same membership check
`require_scope` uses for temp credentials and share claims), and the response is built with
`BoundedDownload` / `verified_stream` (`app/services/download_stream.py`) under a
`transfer_admission` slot, exactly as the authenticated download is. `Content-Disposition` goes
through the existing filename hardening. One redemption = one use = one grant = one download; a
folder link therefore counts one use per file fetched (Q3 again). The IP binding is only as good as the
deployment's trusted-proxy configuration (`ClientIPMiddleware`), which the public page's documentation
must say.

**No `User` is ever synthesised for the anonymous caller.** The path bypasses `get_vault` (which
requires a principal) and instead re-validates, on every request and in this order: master switch on;
link active (not revoked / expired / exhausted); vault active, Standard, not password-protected; target
still present and still inside the link's subtree; **neither the target file nor any ancestor folder
has acquired a `password_hash` since the link was minted** (creation refuses those, and a password
added later must bite on the next request just as it would for a share recipient); the **owner's**
account active and not locked and the owner **still holds READ** on the vault (a live check — an owner
removed from a shared vault takes their public links with them, the way `stamp_share_scope` re-checks
a department audience). Any failure is the uniform 404.

### 2.4 Revoke, kill switch, oversight

Owner: `POST /public-links/{id}/revoke`, `DELETE /public-links/{id}`. Admin: `GET /admin/public-links`
(owner, vault, target kind, tag, status, counts — never a token or a URL, mirroring
`_notelink_admin_dict`), `POST /admin/public-links/{id}/revoke`, `POST /admin/public-links/revoke-all`.
The master switch is the kill switch for the whole anonymous read path, as it is for notes.

### 2.5 UX: fold into the Shared page, not a new page

**Shared by me** becomes the one place a user sees everything they have exposed. Its list merges three
sources — `GET /shares`, `GET /public-links`, and `GET /note-links` — into one card grid with a filter
bar: **kind** (Internal / Public), **status** (Active / Expired / Revoked / Exhausted), **tag**. Internal
cards keep today's look (`_sharedByMeCard`). Public cards take the tag's `border_color` / `icon` exactly
as `_noteLinkCard` does, plus a **Public** pill and the counters (`use_count`/`max_uses`,
`download_count`, `last_used_at`), and a *Copy link* action for an active link (the URL is not secret
in the way an internal claim token is — it *is* the exposure, and the owner already holds it). Notes
keeps its *Shared* tab as a shortcut into the same data (Q4).

**Shared with me** is unchanged: an anonymous recipient is not a user.

**The Share modal** (`#create-share-modal`) gains a first choice:

- *Share with people in this deployment* — the modal exactly as today.
- *Create a public link (anyone with the link)* — shown only when `public_file_links_enabled` and
  `GET /public-link-policy` (the file/folder twin of `/note-link-policy`: enabled flag, cap, remaining,
  and the tags the user may create with that list this target kind) returns at least one tag. The
  branch shows the tag select with its floor summarised in words ("expires within 7 days · password
  required · one download"), the tighten controls (expiry ≤ ceiling, uses ≤ cap, secret ≥ floor), then
  the once-shown `/p/<token>` URL with *Copy*.

Neither branch appears on a ZK or password-protected vault (`vaultShareable()` already hides Share
there).

---

## 3. Inbound: receivers ("Upload links")

### 3.1 A receiver is a vault plus a wrapper — and the wrapper constrains the vault

Creating a receiver (`POST /receivers`, under `require_step_up("receiver.create")`, a row the MFA
design's catalog carries for that purpose) creates a **Standard vault** through
`vault_service.create_vault` with a random name (`recv-<12 base62 chars>`; the owner-facing label lives
on the receiver row — Q5), `type='standard'` (a receiver is never a ZK vault — §4.4), `size_limit` = the
receiver's total cap, funded by **a single owner grant** written with `_write_vault_grant` (a normal
vault may carry manager grants too; a receiver never does), so the **owner pays for the space** — the
first anti-exhaustion control — and `expire_files_after_days` = the receiver's retention. Because it is
an ordinary vault:

- the owner browses, previews, downloads, moves and deletes its files in the ordinary vault view;
- the owner grants **other users** access through the ordinary Permissions tab (`vault_members`) —
  **read only**: on a receiver vault the permissions route refuses `write`, `delete` and `manage`
  grants, so a colleague can see and download what arrived but cannot alter the receiver or its
  contents. `vault_members` has no "view but not download" flag; the v1 answer to *view-only* is the
  internal share engine (a whole-vault share of the receiver vault with `view_only`, identity-checked,
  revocable), and Q13 asks whether a member-level flag is wanted instead;
- `cleanup_expired_files` retires uploads at the retention boundary with no new sweeper;
- deleting the receiver deletes the vault — `POST /vaults/{id}/delete` semantics: **the owner, or an
  admin who is a member of the vault** (that route's `get_vault` READ gate has no admin bypass), with a
  `vault.delete` step-up if that matrix row is on; admin oversight deletes through `/admin/receivers`
  (§3.4), never through the vault route.

Because an ordinary vault's owner can otherwise rewrite the policy the wrapper froze, three routes are
**constrained on a vault that has a `receivers` row**: `PATCH /vaults/{vault_id}/settings` refuses
`expire_files_after_days` / `expire_files_unit` and clamps `size_limit` to the receiver's frozen
`max_total_bytes` (the receiver's own `PATCH` is the way to change either, and it re-runs the
tighten-only resolution); `POST /vaults/{vault_id}/permissions` refuses non-read grants as above; and
the storage-grant helpers refuse a second contributor. Retention is additionally made **authoritative
from the receiver row**: `finalize_streaming_upload` on a receiver session computes `File.expires_at`
from `receivers.retention_days`, not from the vault column, so even a hand-edited vault row cannot
extend an upload's life past the tag ceiling.

The wrapper:

```
receivers
  id UUID PK · owner_id FK users CASCADE · vault_id FK vaults CASCADE UNIQUE
  tag_id FK receiver_tags SET NULL · label VARCHAR(120)
  kind ('standard' | 'confidential')
  token VARCHAR(64) UNIQUE · token_len
  secret_kind · password_hash                      -- an optional LINK secret (PIN/password) to reach the page
  envelope JSON NULL                                -- confidential only: {v, kdf, iterations, salt, verifier}  (§4.1)
  expires_at · max_uploads NULL=unlimited · upload_count
  max_file_bytes · max_total_bytes · retention_days
  paused BOOL · revoked BOOL · created_at · last_upload_at

receiver_tags                                     -- the receiver twin of note_link_tags
  name · description · is_active · border_color · icon
  min_token_len · default_ttl_hours · max_ttl_hours
  require_secret · min_pin_len · password_min_len · password_require_alnum      (the LINK secret floor)
  kind_floor ('standard' | 'confidential')          -- 'confidential' FORCES the browser envelope
  max_uploads_cap · max_file_bytes_cap · max_total_bytes_cap
  retention_max_days · retention_default_days
  allowed_department_ids · allowed_user_ids · blocked_user_ids · auto_enroll_new_users   (create-allowlist)

receiver_upload_sessions                          -- binds an anonymous session to its receiver
  session_id UUID PK FK chunked_upload_sessions CASCADE · receiver_id FK receivers CASCADE
  secret_hash VARCHAR(64) · client_ip · created_at
```

Seeded defaults (only on a fresh deployment, mirroring `should_seed_default_note_link_tags`): **Drop
box** (standard, 7-day link, 100 MB per file, 30-day retention, auto-enroll) and **Confidential inbox**
(`kind_floor='confidential'`, password floor on the link, 24-hour link, 7-day retention, *not*
auto-enrolled — an admin allowlists who may open one).

A pure `receiver_policy.resolve_receiver_policy(tag, overrides)` mirrors `resolve_link_policy`:
tighten-only on every axis, and the resolved values are frozen onto the row.

### 3.2 The anonymous upload path

`GET /u/{token}` → `static/upload-link.html` + `static/js/upload-link.js` (same conventions as the
note-link page). Then:

1. `POST /receivers/{token}/redeem` `{secret?}` — the note-link redeem shape: the two rate limits, the
   link-secret prompt and lockout, the kill switch (`public_receivers_enabled`), the uniform 404 for
   missing / revoked / paused / expired / full. On success it returns the receiver's **public
   configuration** — `kind`, `max_file_bytes`, `allowed_extensions`, `uploads_remaining`,
   `expires_at`, and for `confidential` the envelope parameters `{v, kdf, iterations, salt, verifier}`
   (§4.1) — and an **upload token**: a JWT minted by `create_access_token` with
   `{"receiver": id, "stage": "receiver_upload"}` and a 1-hour `exp`. It carries no `session_token`, so
   `get_current_user`, the `/ws/monitor` handshake and `POST /api/logout` all refuse it (each already
   treats a session-less token as a forgery). The receiver routes use their own dependency,
   `get_receiver_principal`, which verifies the stage and **re-loads the receiver row live on every
   request** — revoke, pause, expiry, the master switch and the owner's account state all bite
   mid-upload. **No route accepts the envelope password**; there is no server-side envelope check and
   therefore no online oracle beyond the link-secret lockout.
2. `POST /receivers/{token}/uploads` `{filename, total_size, sha256, envelope?}` opens a
   `ChunkedUploadSession` with `user_id = owner_id`, `vault_id = receiver.vault_id`,
   `temp_credential_id = NULL`, and a `receiver_upload_sessions` row whose per-session secret is
   returned once and required on every later call — the same principal-binding lesson the
   `temp_credential_id` column records: a session must belong to the thing that opened it, and two
   uploaders on one receiver must not be able to touch each other's sessions. Two consequences of
   reusing the owner's `user_id` have to be handled explicitly:
   - **the owner's 25-session cap.** `_session_principal` for an interactive user selects sessions with
     no `temp_credential_id`, which receiver sessions as described would match — twenty-five half-open
     anonymous sessions would then stop the owner from starting any upload in any vault, the exact
     scope escape that predicate was written to fix. The predicate therefore gains
     `AND NOT EXISTS (SELECT 1 FROM receiver_upload_sessions WHERE session_id = id)` (no ALTER: the
     binding table is the marker), and receiver sessions get **their own caps**: per receiver
     (`max_open_sessions`, default 10) and per client IP (default 5), counted at open;
   - **`total_size` and the name.** `total_size` is bounded by
     `min(receiver.max_file_bytes, upload_policy.effective_max_file_bytes(...))` and by the vault's
     remaining `size_limit`; the extension by `upload_policy.file_type_allowed` (deployment policy) and
     the receiver's own allowlist; the filename by `sanitize_filename`.
3. `PUT /receivers/{token}/uploads/{sid}/chunks/{i}` — `seal_stream_to_file` (sealed staging, bounded
   memory, unchanged).
4. `POST /receivers/{token}/uploads/{sid}/complete` — under a `transfer_admission` slot: the sha256
   check, the **scan hook** (§5.3), then `finalize_streaming_upload` with `replace_same_name=False` and
   the final name decided **server-side**: an anonymous uploader is never told a name is taken (a 409
   would be a filename-existence oracle and a way to pre-claim names against other uploaders), so a
   clash is resolved by suffixing (`name (2).ext`) at finalize. Then the atomic `upload_count`
   increment under `WHERE upload_count < max_uploads AND NOT revoked AND NOT paused AND expires_at >
   now` (the note-link consume pattern — a race past the cap loses), the owner notification
   (`_notify_users([owner], "receiver_upload", …)` with **no filename in the body**, for the sealed-name
   reason `create_share` records) and the optional email action `receiver_upload_received`
   (`OPTIONAL`, off by default, in `ACTION_CATALOG`).

**There is no read path for the anonymous caller.** No listing, no download, no "your upload is here"
URL, no name-collision answer. A receiver is write-only from the outside; the only way to see what
landed is to be the owner or a member of the vault. That property is what makes hosting a receiver on
an organisation's domain tolerable: it cannot be used to *serve* anything.

### 3.3 Owner surface: the Upload links page

A new nav entry beside Shared (`#receivers-section`). Cards: label, kind badge (*Standard* / a
lock-marked *Confidential*), tag colour, `upload_count`/`max_uploads`, bytes used / cap, expiry,
status (Active / Paused / Expired / Full / Revoked), last upload; actions: *Copy link*, *Open* (the
vault view), *Pause* / *Resume*, *Revoke*, *Delete* (deletes the vault and everything in it, confirmed
in red), *Share with a colleague* (deep-links to the vault's Permissions tab, read-only grants). The
create dialog asks for: label, tag (floor summarised), kind (only the kinds the tag floor and the
deployment allow — a `confidential` floor shows no choice), link expiry, max uploads, max file size,
total space (reserved from the owner's budget now, so the dialog shows "you have N GB free"),
retention, an optional link PIN/password, and — for confidential — the **envelope password** (§4.1)
with the tag's password strength floor applied; the browser derives the verifier locally and the
password itself is never sent.

### 3.4 Admin surface

Settings → Sharing gains two cards and one editor:

- **Public file links** — `public_file_links_enabled` (default off); the per-user cap (shared with
  notes, relabelled); the note-link tag editor gains the `allowed_targets` checkboxes.
- **Upload links** — `public_receivers_enabled` (default off); `receiver_allowed_kinds` (subset of
  `standard`, `confidential`; default both; a deployment that wants scannable uploads only removes
  `confidential` — §5.3); `receiver_max_file_mb` (clamped to `MAX_FILE_SIZE_MB` the way `max_file_size`
  is); `receiver_max_total_gb`; `receiver_max_retention_days`; the scanner switches (§5.3).
- **Receiver tags** — the note-link tag editor cloned for `receiver_tags`.
- **Oversight** — `GET /admin/receivers` (owner, label, kind, tag, counts, status; never a token),
  `POST /admin/receivers/{id}/revoke`, `POST /admin/receivers/revoke-all`,
  `DELETE /admin/receivers/{id}` (the admin path to delete a receiver and its vault); and the
  public-links list from §2.4. Every switch and cap is validated in `_validate_settings_payload` with
  the same bool/int/bounds discipline as the note-link keys.

---

## 4. Confidential receivers: the password envelope, honestly described

### 4.1 What it is

At receiver creation the owner chooses an **envelope password** (strength floor from the tag). **The
password never leaves a browser.** The owner's page derives `KEK = PBKDF2-SHA256(password, salt,
600 000)` with a receiver-level random 32-byte `salt`, and stores beside it a **client-checkable
verifier** — `AES-256-GCM(KEK, nonce, "dockvault-receiver-verify-v1", AAD = (receiver_id, v))` — in
`receivers.envelope = {v: 1, kdf: "PBKDF2-SHA256", iterations: 600000, salt, verifier}`. The server
holds the salt and an opaque ciphertext it cannot check without deriving the key, which it cannot do.
`/redeem` returns those parameters; the upload page derives `KEK` locally and decrypts the verifier, so
a mistyped password is caught *before* an upload without any server round-trip. The password reaches an
uploader out of band (the owner tells them).

Per upload, in the uploader's browser:

1. `KEK` as above (one PBKDF2 per upload, from the receiver-level `salt`);
2. `DEK` ← 32 random bytes; `wrapped_dek` ← AES-256-GCM(`KEK`, `DEK`) with AAD binding
   `(receiver_id, format version)` — the same shape as the v1 private-key envelope, through a new public
   entry point in `ecc_crypto.js` rather than the legacy pair (§1.5);
3. the content is encrypted under `DEK` with the **streaming chunked content format the ZK upload
   writer already produces** (`encryptBlobV2`), so the browser never holds the whole file (the measured
   property in `docs/resource-budgets.md`);
4. the session is opened with `envelope = {v: 1, wrapped_dek}` (salt and iterations are the
   receiver's), which `finalize_streaming_upload` stores in `File.encryption_metadata`
   (`{"receiver_envelope": …}`) — a new algorithm **label** is added in
   `app/core/key_wrap_algorithms.py` for this wrap kind, per the rule that a wrap must declare what it
   is.

The server then stores the ciphertext through the **ordinary Standard pipeline** — AES-GCM at rest over
the browser's AES-GCM — so nothing about `vault.type` changes and every Standard-vault invariant
(name sealing, checksum sealing, terminal, quota) holds unchanged. The plaintext checksum the server
records is the checksum of the *ciphertext it received*, which is what the download path verifies.

Reading: the owner (or a member) opens the file in the vault view; the card shows a *Confidential*
badge; download prompts for the envelope password (kept in page memory for that receiver only, never
persisted), derives `KEK` from the receiver's `salt`, unwraps `DEK`, and stream-decrypts through the ZK
content **reader** into the download sink. A wrong password fails at the `wrapped_dek` tag before a
byte of content is touched.

### 4.2 Why a password and not the owner's public key

A symmetric envelope was asked for, and it has a real merit: the owner can hand read access to a
colleague by telling them the password, without that colleague needing an encryption key or a ZK
unlock. But the honest alternative must be on the table. The owner already has a P-384 public key
(`UserKeyPair`), and the browser already wraps AES keys to such a key with ECDH + HKDF + AES-GCM (the
ZK member wrap). An uploader **does not need an identity key to encrypt to the owner** — only the
owner's public key, which the upload page could fetch. That construction is genuinely one-way: no
shared secret with uploaders, no offline password attack, and the owner opens it with their own
passphrase-protected private key. It costs the owner an enrolled encryption key and a ZK-style unlock
on read, and colleagues would need to be added as ZK-style key recipients. **Q6 asks which one ships
first.** This document designs the symmetric envelope because it is the simpler construction and the
one requested, and records that the asymmetric one is the stronger.

### 4.3 The label, and what must be said next to it

*Confidential / pseudo-protected.* Concretely, in the UI copy and in the docs:

- **Confidentiality against the server and its operator:** yes — without the password the stored bytes
  are opaque; the server holds only a salt and a verifier it cannot check.
- **Confidentiality against other uploaders:** no — everyone who can upload holds the password, and
  the password is the key.
- **Sender authenticity:** none — anyone with the link (and the password) can upload; nothing binds an
  upload to a person. The owner must not treat a confidential upload as *from* anyone.
- **Offline attack:** the stored envelopes can be attacked with a password guesser at 600 000 PBKDF2
  iterations per guess — and so can the **verifier**, by anyone who has redeemed the link, without
  uploading anything. The link itself is therefore sensitive, a weak password is a weak envelope, and
  the tag's strength floor is the only defence; it is the admin's to set.
- **No online oracle:** no server route ever sees or checks the envelope password.
- **Visible to the server:** the file **name**, **size**, MIME type as declared, upload time and the
  uploader's IP. Sealing the name too (a `zk2:`-style browser seal, as ZK vaults do) is Q7.
- **Not scannable:** the server sees ciphertext. §5.3.
- **Not zero-knowledge.** No word in the product may say "zero-knowledge", "end-to-end" or "E2E" about
  this kind. The name is *Confidential*.

### 4.4 Why a receiver is never a zero-knowledge vault

A ZK vault's DEK is wrapped to member identity keys and every file's name is browser-sealed; an
anonymous uploader has no identity key, so a ZK vault has no way to hand them a DEK without the owner
first publishing something an uploader could use — which is the asymmetric design of §4.2, not a ZK
vault. Making a receiver `type='zero_knowledge'` would also drag it out of SFTP, out of server-side
previews and out of the scan hook while delivering none of ZK's guarantees. So: Standard vault, plus
an envelope, plus an honest label.

---

## 5. Inbound as a data-exfiltration-IN surface

### 5.1 Threats and the control for each

| Threat | Control | Where |
|---|---|---|
| Storage exhaustion | the owner's account budget funds the receiver vault (`VaultStorageGrant`, one owner grant); `size_limit` per receiver; `would_exceed_deployment_storage`; `receiver_max_total_gb` | vault create, `/complete` |
| Flooding one receiver | `max_uploads` consumed atomically; per-`(ip, token)` and per-IP rate limits; per-receiver and per-IP open-session caps; `transfer_admission` | `/redeem`, every upload route |
| Starving the owner's own uploads | receiver sessions excluded from the owner's 25-session cap (§3.2) | session open |
| Token enumeration | base62 tokens with the tag floor (`min_token_len` ≥ 6, secure tiers 20+) and the per-IP 600/min bound, as for note links | `/redeem` |
| Oversized or forbidden files | `total_size` ≤ `min(receiver, deployment)`; `allowed_file_types` (deployment) ∩ receiver allowlist; `sanitize_filename` | session open |
| Filename oracle / name squatting | no 409 to an anonymous caller; server-side suffixing | `/complete` |
| Malware | the scan hook (§5.3); `confidential` uploads are unscannable and can be forbidden deployment-wide | `/complete` |
| Using the deployment to serve content | no anonymous read path, ever (§3.2) | by construction |
| Owner escaping the frozen policy | the vault-settings, permissions and storage-grant routes are constrained on receiver vaults; retention authoritative from the receiver row (§3.1) | those routes, `/complete` |
| Stale exposure | link expiry; `paused`; revoke; the master kill switch; retention sweeps the files themselves | `/redeem`, `cleanup_expired_files` |
| Cross-session interference | per-session secret + `receiver_upload_sessions` binding; no overwrite | upload routes |
| Owner de-provisioned | `get_receiver_principal` re-checks the owner is active and not locked on every call | every anonymous route |

### 5.2 Retention

`retention_days` on the receiver is written to the vault as `expire_files_after_days` (unit `days`)
for the ordinary vault UI to display, and — authoritatively — used by `finalize_streaming_upload` on a
receiver session to compute `File.expires_at` (§3.1), so the existing sweep deletes each upload at the
boundary the tag allowed and nothing the owner can do to the vault row changes that. Per-file
retention — extending one upload's life or shortening it — has no endpoint today; v1 offers the owner
*move to another vault* (the existing move/copy engine) as the "keep this one" affordance, and Q8 asks
whether a per-file expiry edit is wanted in scope.

### 5.3 The scan hook — a stream, never a file

There is no plaintext file to scan and there must not be one: staged chunks are sealed on disk
precisely so that no plaintext sits on the volume mid-upload, and writing one out for a scanner would
reintroduce that exposure for the worst possible content (anonymous input). So the hook is defined as a
**stream**. A new module `app/core/inbound_scan.py` with one interface:

```
scan(chunks: Iterable[bytes], *, name: str, size: int) -> ScanVerdict   # 'clean' | 'infected' | 'error'
```

`/complete` feeds it `open_staged_chunk(...)` for each staged chunk — the same generator that feeds
the at-rest writer — **before** anything is handed to `upload_file_streaming`, so the scanner sees the
plaintext once, in memory-bounded pieces, and the blob is written only on `clean`. Backends: `off`
(default — the hook runs and returns `clean`); `stream_command` — an operator-configured executable
that reads the file on **stdin** (`INBOUND_SCAN_COMMAND`, e.g. a `clamdscan -` or `clamscan -`
invocation; the daemon's socket `INSTREAM` protocol is the same shape and a natural second backend),
with a timeout, mapping the exit status. Config: `INBOUND_SCAN_COMMAND` + `INBOUND_SCAN_TIMEOUT_SECONDS`
in `app/core/config.py` — which by the sync rule means `.env.example` and `dockvault.py`'s setup flow
in the same change — and two settings-blob keys, `inbound_scan_enabled` and `inbound_scan_fail_closed`.
The cost is one extra decrypt pass over the staged chunks per upload, which is the honest price of not
having a plaintext file.

Outcomes: `infected` → the upload is refused (`422`, the session and its staged chunks removed, an
audit row `receiver_upload_rejected` with the backend's short verdict and **no filename**, and a
**new** `SecurityEventType.MALICIOUS_UPLOAD` security event — modelled on `MALICIOUS_EMAIL_CONTENT` —
raised on the owner's receiver, never on the anonymous uploader, who has no identity); `error` →
refused when `inbound_scan_fail_closed`, else stored and the owner's notification says *unscanned*.
`confidential` uploads are never scanned (ciphertext); with `inbound_scan_enabled` on, the admin UI
shows the warning next to `receiver_allowed_kinds`, and Q9 asks whether enabling the scanner should
*require* dropping `confidential`. Q10 asks whether the command backend ships in v1 at all.

The hook is also the right place for an authenticated upload later; nothing in it is receiver-specific
beyond where it is called from.

### 5.4 Fail-closed tag-policy inheritance (the rules, in the order they are evaluated)

1. **Master switch off ⇒ nothing.** Not creatable, not redeemable, existing links and receivers 404
   (kill switch), exactly as `public_note_links_enabled` behaves today. Both switches default `False`
   and use the strict `is True` read.
2. **Deployment caps clamp tag caps clamp user requests.** `receiver_max_file_mb` ≤
   `MAX_FILE_SIZE_MB`; a tag's `max_file_bytes_cap` ≤ the deployment cap; a receiver's
   `max_file_bytes` ≤ the tag cap. The `effective_max_file_bytes` shape, applied three times.
3. **A tag must be active and admit the creator** (`user_can_create_with_tag`, live, blocklist wins,
   no admin bypass) and, for public links, list the target kind in `allowed_targets`.
4. **Tighten-only.** `resolve_link_policy` / `resolve_receiver_policy` raise on any loosening; a
   `confidential` `kind_floor` cannot be lowered to `standard` by the creator.
5. **Frozen on the row — and the row wins.** A later tag edit never loosens an existing link or
   receiver; a deleted tag `SET NULL`s and the row's own policy governs; and the vault routes an owner
   could use to loosen a receiver from underneath are constrained (§3.1), with retention computed from
   the receiver row at finalize.
6. **Upgrade adds nothing.** Existing note-link tags get `allowed_targets=["note"]`; no receiver tag
   exists until seeded on a fresh deployment or created by an admin.
7. **Kind withdrawn ⇒ paused, not converted.** Removing `confidential` from `receiver_allowed_kinds`
   pauses existing confidential receivers (they 404 on redeem) rather than silently accepting plaintext
   into a vault whose owner expected envelopes.

---

## 6. Testing (the load-bearing cases)

- Public link: created only under a tag with the target kind allowed; a note-only tag → 400; without a
  `public_link.create` receipt when that matrix row is on → 403; kill switch → 404 on redeem of a
  minted link; revoke → 404; deleting the file deletes the link (row count); the grant is single-use
  and IP-bound and travels in a header; Redis stopped → `/redeem` 503 and no grant; a `file_id` outside
  a folder link's subtree → 404; a password added to the file or an ancestor folder after minting →
  404; owner loses READ on the vault → 404; the download bytes equal the authenticated download's
  bytes.
- Shared page: one grid renders internal + public + note cards with the kind filter narrowing each
  way; the public card shows the tag colour.
- Receiver: creation reserves the owner's budget (a second receiver beyond the budget → 400) and needs
  a `receiver.create` receipt when that row is on; the anonymous session cannot be advanced with
  another session's secret; **25 open anonymous sessions on a receiver do not 429 the owner's own
  uploads**, and the 11th on one receiver is refused; `max_uploads` is exact under concurrent
  completes; a paused/revoked/expired receiver 404s mid-upload (re-check on `/complete`); the
  anonymous token is refused by every `get_current_user` route, by `/ws/monitor` and by
  `POST /api/logout`; no GET on a receiver ever returns file bytes or a listing; two uploads of the
  same name both land, suffixed, with no 409; the owner's `PATCH /vaults/{id}/settings` on a receiver
  vault cannot raise expiry above the tag ceiling and cannot grow `size_limit` past the frozen cap; a
  non-read member grant on a receiver vault → 400; `File.expires_at` matches the receiver row even after
  the vault column is hand-edited.
- Confidential: no route accepts the envelope password (a request body carrying one is ignored, and a
  grep over the routes pins it); the stored bytes do not contain the plaintext; the server-side
  download returns the envelope ciphertext; the verifier decrypts under the right password and fails
  under a wrong one, in the browser; a wrong password fails at the wrap, not mid-content; the owner's
  round trip is byte-identical to the uploader's file; the word *zero-knowledge* appears nowhere in the
  receiver UI strings (a static assertion over `static/`).
- Scan hook: `infected` → 422 + no row + no blob + a `MALICIOUS_UPLOAD` event; `error` + fail-closed
  → 422; `error` + fail-open → stored + *unscanned* notification; a confidential upload never invokes
  the command; **no plaintext file exists under `storage/` at any point of a receiver upload** (mirror
  the sealed-staging tests).

---

## 7. Non-goals

- **Anonymous read of a receiver.** Never.
- **A zero-knowledge receiver.** §4.4. The asymmetric envelope (§4.2) is the honest upgrade path and is
  Q6, not this build.
- **A plaintext scan spool.** §5.3 — the hook streams or it does not exist.
- **Recursive folder links / zip streaming.** v1 lists one level and serves one file per grant.
- **Server-side unpacking** of archives (and therefore zip-bomb inspection) — the scan hook sees the
  file as uploaded.
- **Email to uploaders.** An uploader has no identity; the owner is notified, the uploader is not.
- **Per-uploader identity or quotas.** Everything is per receiver and per IP.
- **Previews on the public page.** A public link downloads.
- **Changing what a note-link tag means for notes.** `allowed_targets` only adds kinds.
- **Scanning confidential uploads.** Impossible by construction; the admin may forbid the kind.
- **A member-level view-only flag on `vault_members`.** Q13; v1 uses the share engine for that.

---

## 8. Open questions (decisions to make before building)

1. **Tag table**: add `allowed_targets` to `note_link_tags` (one tag family for every anonymous
   link — proposed) or a separate `public_link_tags` table (no ALTER, two catalogs to maintain)?
2. **Shared cap**: should `public_note_link_user_cap` count file links too (proposed) or should file
   links get their own cap?
3. **Folder links**: one use per file fetched (proposed — the cap means "N downloads"), or one use
   per redemption regardless of how many files are fetched?
4. **Notes → Shared tab**: keep it as a shortcut into the merged Shared page (proposed) or remove it
   once public links live on Shared?
5. **Receiver vault naming**: `recv-<random>` with a separate owner label (proposed) or let the owner
   name the vault and randomise only the token?
6. **Which envelope first**: the symmetric password envelope as specified (this document), or the
   asymmetric encrypt-to-owner-key construction (§4.2), which is stronger but requires an enrolled
   encryption key?
7. **Seal the uploaded filename** in the confidential envelope too (the server then sees only a
   placeholder, as for ZK files) — or accept a visible name in v1 (proposed, simpler)?
8. **Per-file retention edit** (§5.2): in scope, or "move to another vault" is enough for v1?
9. **Scanner vs confidential**: should enabling the scanner force `receiver_allowed_kinds` to drop
   `confidential`, or only warn (proposed)?
10. **Scan backend**: ship the stdin-stream command backend in v1 (proposed), or ship `off` only with
    the streaming hook interface and leave the backend to a follow-up? (A file-path backend is not on
    the table — §5.3.)
11. **One password per receiver or one per upload** (§4.1): a receiver-level password the owner sets
    and shares (proposed — one thing to remember, one verifier), or a password each uploader chooses
    and must communicate to the owner separately?
12. **Verifier or no verifier** (§4.1): store the client-checkable verifier so a typo is caught before
    upload (proposed, at the cost of an offline guessing target for anyone who redeemed the link), or
    store nothing and let a wrong password surface only at the owner's unwrap?
13. **View-only colleagues** (§3.1): reuse the internal share engine with `view_only` (proposed) or add
    a member-level "read without download" flag to `vault_members`?
