# At-Rest Cleartext Surface Hardening — plan

> **Status:** authored, not started. Nothing claimed yet.
> **Source:** an external at-rest security review of `DockVault/vault` at **v0.16.1 (`499fd3c`)**,
> dated 2026-08-25 — 15 findings (1 Critical, 4 High, 6 Medium, 4 Low) plus a note on a separate
> control-plane component. Each finding here was **re-verified against v0.16.1 source** before being
> written down; where the review's claim did not hold, this plan says so.
> **Branch:** `security/cleartext-surface-plan` (this plan) → each phase is its **own** branch cut
> from a freshly-fetched `main`, shipped as its **own PR** so GitHub CI (fast-tests + the real-Docker
> integration lane, both run on every PR) exercises it.

---

## 0. How to work this plan

- **One finding-group per PR.** Phases are sized so each is a self-contained, reviewable PR. The
  order in §5 is by *risk-reduced-per-unit-of-effort*, not by severity.
- **The iron rule for every schema/crypto change — read-old / write-new.** Existing deployments hold
  data in the *old* shape. A change may add a new column/format and write it going forward, but it
  must **keep reading the old shape** and **must never NULL or rewrite existing rows in place**. The
  frozen crypto fixtures (`tests/crypto_reference_vectors.py`, the `v0.10.0` `standard-0x10` and
  `standard-fernet-chunk-stream` fixtures) must stay green. A change that cannot satisfy this is
  *forward-only* and must be flagged loudly.
- **A schema change declares itself** in the *same* PR: model (`app/core/models.py`) **and** the boot
  DDL list (`app/api/api_server.py`, `ALTER TABLE … ADD COLUMN IF NOT EXISTS` around line 15450+)
  **and** a `docs/upgrade-matrix.json` entry (the release gate refuses an undeclared version).
- **Config stays in sync:** a new/changed field in `app/core/config.py` needs the matching
  `.env.example` line **and** the `dockvault.py` setup prompt in the same PR.
- **Tests, then tests again.** Every phase ships: unit tests proving the new behaviour, a
  **non-vacuous** live/throwaway-Docker test proving the exposure is actually closed (assert the
  canary is *absent* after the fix and *present* at HEAD), **and** a backward-compat/regression test
  proving already-stored data still reads. Run the offline lane locally *without* `--maxfail`
  (`python -m pytest -m "unit and not docker" -q`) before pushing — CI's `--maxfail=1` only reveals
  one failure per run.
- **Throwaway containers only.** Every live test uses a **unique `VAULT_VOLUME_PREFIX`** (e.g.
  `clrtxt<n>`) so it never touches an existing deployment's volumes. **Never** run `reset` /
  `docker compose down -v` / any prune against a set you did not create in that test.
- **Public-repo hygiene:** no internal identifiers, no cross-repo paths, no AI-attribution trailers
  in vault source or commit messages. Leak-review each diff before pushing.

---

## 1. Executive summary

The review is **accurate and well-grounded**. The content-encryption core, token discipline, and
logging hygiene are sound (verified independently — see §4). Every finding sits at a *boundary*:
where a secret leaves `.env`, where plaintext waits to be encrypted, or where a column was never
brought into the scheme that covers its neighbours.

Crucially for sequencing: **almost none of the fixes touch the file-content crypto format**, so almost
none can make already-stored file blobs undecryptable. The genuinely dangerous ones — the handful
that change how bytes are keyed/derived/stored, or that could silently corrupt in-flight or make a
whole class of names/records unreadable — are called out explicitly in Tier C and are gated behind
owner decisions.

**The single highest-value change is not even in the security report's top severity: it is the
`dockvault.py` restore bug (Part 2).** Restore currently *merges over* live volumes without stopping
the stack, so a "restore to an earlier state" neither replaces the data nor takes effect on the
running server — which is exactly the "I restored and saw the same files" behaviour the owner hit.
That is a data-integrity/trust defect and should land first.

### Risk-vs-effort tiering (the "deep vs easy" question)

| Tier | Meaning | Findings |
|------|---------|----------|
| **A — Easy & safe** | No crypto-format or schema change (or a trivial additive one). Contained, low breakage risk. Hours each. | C1-now, H4, H1-min, H2-interim, H3-interim, L2, M5-cheap, M3-relabel, M1-doc, L4, L1, **DV-RESTORE**, **DV-STORAGE**, **DV-UX** |
| **B — Medium** | Additive schema/behaviour change needing a careful read-old fallback + migration. 1–2 days each. | L3, M5-full, M6, H2-real, C1-proper, H1-full, M3-encrypt |
| **C — Deep / high-risk** | Changes how bytes are keyed/derived/stored, or is cross-cutting enough that a bug breaks a whole class of data. Careful, multi-day, owner-gated. | **M4** (integrity format), **M2** (vault-name sealing incl. ZK), **H3-real** (streaming SFTP encrypt) |

**"One change in crypto can break everything" — the specific traps this plan guards against:**
- **M4**: apply a keyed verifier to an *old* row and every pre-fix file fails its download integrity
  check → undownloadable. Old rows MUST keep the plain-SHA path.
- **M2**: if the transparent-decrypt listener for Standard vault names is buggy, `vault.name` reads
  back NULL and **every SFTP top-level directory silently renames to `vault_<uuid>`**, breaking client
  scripts and name-based path resolution.
- **H2-real / H3-real**: a per-session staging key that is *not* deterministically re-derivable (or a
  sequential-AEAD stream fed SFTP's random-offset writes) **silently corrupts in-flight uploads**.
- **M3-encrypt**: encrypting note titles without widening `title` to `Text` first **truncates
  ciphertext** at the DB layer → corrupt notes.
- **M6**: run the session-token boot migration *after* the code starts hashing-on-read and **every
  live session is logged out**; ship fail-closed revocation before the migration and regular users
  drop too.

---

## 2. Verified surface map (what actually holds cleartext)

Confirmed against v0.16.1. "Sealed" = encrypted with a key not co-located at rest.

| Surface | Holds | State | Finding |
|---|---|---|---|
| `storage/<vault>/files/` | file content blobs | **Sealed** (AES-256-GCM, per-file HKDF subkeys, per-chunk AAD, `0x20` terminal) | — |
| `storage/_uploads/<sid>/` | buffered resumable chunks | Cleartext (Standard vaults) | **H2** |
| `storage/.sftp_tmp/up_*` | in-flight SFTP uploads | Cleartext | **H3** |
| `vault_pg_data` (Postgres) | users, vaults, notes, audit, wrapped keys, sessions, checksums | **Mixed** | **M1–M6** |
| `keys/ssh_host_rsa_key` | SFTP host private key (RSA-2048, unencrypted) | Cleartext | **L1** |
| `certs/key.pem` | TLS private key (unencrypted) | Cleartext (0600) | **L1** |
| `logs/combined.log` | request lines, IPs, UUIDs | No secrets (verified clean) | **L2** |
| `backups/dockvault-*/` | master key + full DB + all blobs + host key | Cleartext bundle | **H1** |
| `.env` / `.env.enc` | all deployment secrets | Sealable (host-only) | C1 |
| `docker containers/<id>/config.v2.json` | all deployment secrets | **Cleartext** (survives lock + stop) | **C1** |
| `redis /data` | hashed sessions, rate limits | tmpfs — RAM only | — |

---

## 3. What held up (verified sound — do not touch)

Independently confirmed against v0.16.1, so we know the baseline the fixes build on:
- **File content at rest** — AES-256-GCM chunk stream, per-file HKDF subkeys, per-chunk AAD binding
  vault+file+write-id+position, the `0x20` terminal record closing the truncation gap. Canary never
  appears in the blob.
- **Filename encryption (Standard)** — `enc_name`/`enc_mime` sealed via `encrypt_object_field` with a
  per-vault HMAC blind index for exact-match lookup; plaintext columns NULL. This is the exact
  machinery M2/M3/M5 reuse.
- **Token hygiene** — log-pull, invitations, resets, OTPs, email-change codes all store peppered
  HMAC-SHA256 with a public prefix. M6 (sessions) is the lone outlier.
- **Container hardening** — non-root, `cap_drop: ALL`, `no-new-privileges`, read-only root fs; Redis
  `/data` on tmpfs.

---

## Part 1 — At-rest cleartext findings

Format per finding: **verdict** (verified? any report correction) · **fix** · **depth/risk** ·
**deps** · **tests** · **owner decision** (if any).

### C1 — Every `.env` secret written to host disk in cleartext by Docker · Critical
- **Verified.** All three app services use `env_file: ../.env` (`deploy/docker-compose.secure.yml`
  114/204/299); `DATABASE_URL` is assembled inline from `${VAULT_DB_PASSWORD}` (118/208/303). Docker
  persists every container-env value verbatim into `/var/lib/docker/containers/<id>/config.v2.json`
  (root-readable) for the container's whole lifetime. `dockvault.py lock()` (2086) only removes the
  host `.env`; `stop(--lock)` runs `compose stop` (2200) which **stops but does not remove** the
  container, so the secrets survive. `status`/`_print_status` prints `LOCKED` from `_is_locked()`
  alone — never checks whether a container still holds the env. In the Docker default ("legacy")
  mode, `startup_security.load_legacy_credentials` reads the 5 secrets straight from `os.getenv`.
- **Fix — two tiers.**
  - **Now (Tier A):** make `lock()` and `stop(--lock)` run `docker compose down` (**never `-v`** —
    volumes + data survive) so the container and its `config.v2.json` are removed with the secrets;
    make `_print_status` warn when a container is still present while `_is_locked()` is true.
  - **Proper (Tier B):** move the 5 secrets to compose top-level `secrets:` (file mounts under
    `/run/secrets`) and teach `startup_security.load_legacy_credentials` to read `<NAME>_FILE` first,
    else fall back to `os.getenv(NAME)`. Postgres supports `POSTGRES_PASSWORD_FILE` natively.
- **Depth/risk — contained.** No stored-ciphertext/schema change → zero risk to existing blobs. Real
  risks: `down` drops the compose bridge network + is slower to restart; the `_FILE` change **must**
  be read-old/write-new (prefer the file only when `<NAME>_FILE` is set, else keep `os.getenv`) or
  every existing `.env` install fails to boot; `DATABASE_URL` is assembled from a secret so it needs
  `DATABASE_URL_FILE` (or in-app URL assembly from a DB-password file) and must still honour a
  directly-set `DATABASE_URL`; Redis `--requirepass ${REDIS_PASSWORD}` is on the command line (also
  in `config.v2.json` + `/proc/<pid>/cmdline`) and `redis:8-alpine` has no `REQUIREPASS_FILE` — a
  botched change starts Redis with **no auth**, so split that into its own follow-up.
- **Deps:** the `dockvault.py` lifecycle + `_guard_db_secret` (a wrong DB-password source vs the
  password baked into an existing `vault_pg_data` locks the app out of Postgres); the config-sync
  rule. Independent of the crypto findings.
- **Tests:** unit — `load_legacy_credentials` prefers `<NAME>_FILE`, falls back to env, sanitized
  error on unreadable file; `stop(--lock)`/`lock()` invoke `down` and never pass `-v` (mock
  subprocess); `_print_status` warns when a container is present + locked. Live (throwaway) — after
  `stop --lock` (now `down`), `docker inspect vault` is gone / no `config.v2.json` holds
  `ENCRYPTION_KEY`; with secret files, `docker inspect` env shows none of the secrets; **data
  regression** — bring the stack up on a pre-existing `vault_storage`+`vault_pg_data` via the
  secret-file path and prove previously-uploaded files still decrypt and existing users still log in.
- **Owner decision:** threat boundary — a root-on-host attacker reads `/proc/<pid>/environ` of the
  live process regardless, so secret-files help *at rest after the container is removed*, not against
  live-host-root. Confirm whether C1 is "Critical" or a hardening improvement. Which strategy to
  standardize (Docker secret files vs extend the existing encrypted-credential mode). Should `down`
  be the default `stop` for everyone (changes restart semantics) or gated behind `--lock`/a prompt?

### H1 — Backup bundles are self-decrypting archives · High
- **Verified, with corrections.** `_do_backup` (3096) copies the live `.env` verbatim as plaintext
  `env` (3128) beside the pg/storage/keys tars; the co-located `ENCRYPTION_KEY` makes every blob
  plaintext, and the `keys` tar carries the SFTP host key (couples L1). `update` auto-creates a
  bundle (3596) and **nothing prunes** them. **Corrections to the report:** the bundle dir is `0700`
  and `env` is `0600` (not world-readable); `backups/` is in both `.gitignore` and `.dockerignore`
  (never committed, never in the image). The report's claim that "the coupling fingerprint works over
  the sealed form" is **false** — `compute_coupling_fingerprint` (1223) hashes the *plaintext*
  `ENCRYPTION_KEY`+`VAULT_DB_PASSWORD`, so restore can only verify coupling **after** unlocking.
- **Fix — two tiers.**
  - **Minimum (Tier A):** retention pruning (keep newest N `dockvault-<prefix>-*` dirs, only that
    prefix, never arbitrary dirs); warn/refuse when the backup root is under the repo tree; make
    `update`'s auto-backup seal when the deployment is already locked. (The dedicated backup location
    is Part 2 / DV-STORAGE.)
  - **Full (Tier B):** store `env.enc` instead of `env`, reusing the existing `env_lock_seal`
    envelope so the bundle carries a passphrase/recovery-key-wrapped DEK; `_do_restore` must
    `env_lock_open` first, then verify coupling on the recovered env, then install. Restore must
    accept **both** old plaintext-`env` and new `env.enc` bundles.
- **Depth/risk — contained code, but a DR *product* change.** No effect on live at-rest crypto.
  **Critical DR hazard:** sealing makes restore **require** the passphrase/recovery-key — an operator
  with the bundle but not the passphrase is locked out; a lost passphrase = unrecoverable bundle. The
  plaintext bundle was previously the DR escape hatch. Sealing `.env` alone still leaves the pg dump
  and SSH host key plaintext inside the tars — fully protecting the bundle means encrypting the whole
  bundle (larger, couples L1). Existing `tests/test_dockvault_tool.py` asserts a plaintext `0600`
  `env`, so sealing must be opt-in or those tests updated.
- **Deps:** L1, the `env_lock` feature, the coupling machinery, `update`'s non-interactive auto-backup
  (where does it get a passphrase?), and the Part-2 backup UX.
- **Tests:** sealed round-trip (backup with passphrase → `env.enc` + non-secret coupling stamp, no
  cleartext secret; restore unseals, coupling verifies, `.env` byte-identical); wrong-passphrase
  restore writes no volumes; recovery-key restore works; **backward-compat** — a new restore still
  restores an old plaintext bundle; retention keeps only newest N of the matching prefix and never
  touches foreign dirs; non-interactive `update` auto-backup never blocks on a passphrase.
- **Owner decision:** sealed default (lost passphrase = unrecoverable) vs opt-in `backup --lock`?
  Where does `update`'s non-interactive auto-backup get its passphrase? Seal `.env` only, or the
  whole bundle? Ship the minimum tier now regardless — it removes the DR downside.

### H2 — Resumable uploads stage plaintext chunks on the storage volume · High
- **Verified.** Standard-vault chunks stream verbatim to `<storage>/_uploads/<sid>/chunk_*`
  (`api_server.py` upload path) and are encrypted only at `/complete`. Abandoned sessions persist to
  `chunk_session_ttl_hours` (default **24h**). The genuinely-failed finalize branches (`except
  HTTPException`, `except ValueError`, `except Exception`) set `status='failed'` but do **not**
  `rmtree(sdir)` — only success + `DuplicateNameError` clean up immediately (the `PermissionDenied`
  /403 path retains on purpose). ZK vaults stage client-ciphertext (unaffected).
- **Fix — two tiers.** Interim (Tier A): drop the default TTL to 2–4h (+ `.env.example` + `dockvault`
  per config-sync); add `rmtree(sdir)` to the three genuinely-failed branches (**not** the 403 path).
  Real (Tier B): stage-encrypt each Standard chunk on arrival with a **deterministically re-derivable**
  per-session key (HKDF over the deployment root key with `info=session_id`), decrypt-on-read at
  assembly; branch on `is_zk` to leave ZK chunks verbatim. Final stored blob format unchanged.
- **Depth/risk — contained.** Staging is transient → no migration of stored data. **Traps:** the
  staging key MUST be re-derivable across a container restart (a random per-process key destroys an
  in-flight resume); `upload_chunk` doesn't currently compute `is_zk` — mis-branching double-encrypts
  a ZK chunk into an undecryptable blob (store an `is_zk` flag on the session at init); the interim
  `rmtree` must not fire on the 403 path.
- **Deps:** M4 (the `/complete` checksum re-hashes plaintext — decrypt-on-read must reproduce
  byte-identical plaintext); the per-chunk resume hash sidecars; the sweep/TTL machinery.
- **Tests:** staging key deterministic across a fresh process; stage-encrypt→decrypt round-trips;
  `/complete` checksum equals SHA-256 of the original plaintext; ZK chunks staged byte-identical;
  live — mid-transfer, grep the chunk files for a canary and assert it is **absent** (positive
  control: present at HEAD); abandoned session pruned after TTL+sweep; forced finalize failure removes
  the dir; 403 finalize **retains** the dir (regression guard); resume-across-restart still completes.
- **Owner decision:** lower the default TTL (breaks "multi-day resume")? staging-key derivation +
  accept that a root-key rotation invalidates in-flight staged chunks.

### H3 — SFTP uploads buffer the client's plaintext to the storage volume · High
- **Verified.** Every SFTP `put` buffers cleartext to `<storage>/.sftp_tmp/up_*`
  (`sftp_server.py:86`, write path 852–871) and encrypts only at handle close. The sweep runs **only
  at process startup** (1612), so a crash/OOM/dropped-connection leaves plaintext on the persisted
  volume until restart. SFTP refuses ZK vaults entirely (479–483) → server-side codec always applies.
- **Fix — two tiers.** Interim (Tier A): move `.sftp_tmp` onto container **tmpfs** (RAM) — a `/tmp`
  tmpfs already exists on all services — so a crash cannot leave plaintext on persistent disk.
  Real (Tier B): stream-encrypt as bytes arrive; mint the file id + `StreamingUploadContext` at
  `open()`.
- **Depth/risk — contained, but the interim has an OOM footgun and the real fix a corruption
  footgun.** No crypto-format/DB change. **tmpfs interim:** `max_file_size_mb` defaults to **10 GB** —
  buffering that into RAM OOM-kills the container; the interim is viable **only** with a low effective
  SFTP ceiling and a tmpfs `size=` cap. **Streaming real fix:** `GcmChunkStreamCodecV2` is strictly
  **sequential** (monotonic AAD index) whereas SFTP `write(offset)` is random-access — a client that
  writes out-of-order/sparse would corrupt the stream, so the buffer-then-encrypt path must remain as
  a fallback (detect/require sequential offsets). Must preserve the atomic-overwrite/no-orphan
  guarantee (don't destroy the replaced file on a late rejection).
- **Deps:** the shared close-time size/quota/plan re-checks; the atomic same-name replacement logic.
- **Tests:** crash-simulation (partial write, drop handle, assert buffer swept / on tmpfs); size
  bound still rejects over-ceiling; live SFTP `put` round-trip byte-identical; overwrite-on-clash
  atomic; rejected upload leaves no orphan and does not destroy the replaced file; out-of-order write
  rejected or falls back (never silent GCM corruption); no plaintext under `/app/storage` after an
  interrupted transfer.
- **Owner decision:** a low default SFTP ceiling (needed for tmpfs) vs tmpfs as documented opt-in?
  Can SFTP require sequential writes, or must the buffer fallback stay?

### H4 — `ADMIN_PASSWORD` kept in cleartext for the life of the deployment · High
- **Verified, with a correction.** `_seed_admin_user` (15199) is one-shot (no-ops on blank password
  or existing admin), yet the password stays in `.env`→container env→`config.v2.json` forever. The
  config guard already treats a whitespace-only value as blank (config.py 378–389), and
  `dockvault.admin_password_problem` returns None for blank. **Correction:** the report's "`setup`
  rewrites it on every re-run" is **wrong** — the reuse path does not rewrite `ADMIN_PASSWORD`; only
  a fresh install or new volume-set writes it. The app runs read-only root fs and `.env` is host-side,
  so **only `dockvault.py` (host) can blank it**.
- **Fix — contained, no schema.** (1) App: on a successful seed (and on the already-exists no-op),
  write a marker to the existing `SystemSetting` KV table (a new *row*, not a new column → no DDL, no
  upgrade-matrix). (2) `dockvault.py`: after the setup health check passes, blank `ADMIN_PASSWORD` via
  the existing `_set_env_key(...,'ADMIN_PASSWORD','')`, on both the fresh and reuse paths.
- **Depth/risk — contained.** Blanking does not delete the seeded (hashed) admin user → no lockout.
  **Trap:** an *unconditional* blank-after-health would destroy the only copy of the password if
  seeding silently failed (the seed is wrapped in a broad `except`) → gate the blank on the positive
  marker. Document that changing the admin password must go through the app UI (the seed never
  re-ran anyway). No crypto/data impact.
- **Deps:** the seed path, `SystemSetting`, the `dockvault` setup+reuse flows. Note the *other*
  secrets in the same `.env` can't be blanked (needed every boot) — this only retires one now-dead
  secret; the `.env` trust boundary itself is C1.
- **Tests:** unit — seed writes the marker, is idempotent across two boots, blank password skips
  seeding and passes the guard; `dockvault` rewrites `ADMIN_PASSWORD` to empty after health while
  preserving other keys + perms. Live — fresh setup → log in with the shown password → assert host
  `.env` `ADMIN_PASSWORD` empty → restart → still boots → admin still logs in; existing deployment
  carrying a cleartext value → blanked → admin still logs in, no re-seed.
- **Owner decision:** marker-gated blank (recommended) vs unconditional vs a manual "clear admin
  password" action. Blank on the reuse path too (recommended, covers existing installs)?

### M1 — Postgres volume unencrypted; everything hangs off one key · Medium (architectural)
- **Verified.** No DB-volume encryption; every server-side at-rest key derives via HKDF from the
  single `settings.encryption_key`. ZK vault *content* is the genuine exception (server holds no key).
- **Fix — split.** *This plan:* make host full-disk-encryption a **loud documented prerequisite**
  (deploy docs + README) and add a `dockvault.py setup` check/warning. *Deferred to its own
  owner-gated epic:* a second operator-held key / KEK-DEK envelope for per-tenant separation.
- **Depth/risk:** docs + setup-warning break nothing. The per-tenant-key work is **crypto-format,
  high-risk** (re-keying HKDF-derived data can make existing blobs/names undecryptable) — never bundle
  it here.
- **Tests:** the setup warning fires when the mount isn't detected encrypted; docs-presence check.
- **Owner decision:** confirm M1 = docs + setup-warning in this plan, per-tenant-key deferred.

### M2 — Vault names/descriptions are plaintext — including for ZK vaults · Medium
- **Verified, with a correction.** `Vault.name`/`description` (models.py 566/567) are plaintext with
  no `enc_*` columns; `submitCreateVault` sends the name raw for both types; `encryptName` is never
  called for a vault's own name. The name flows into `audit_logs.details.vault_name`, notifications,
  share invites, email templates (`{{vault.name}}`), and every list/get response. The `ZKShareInvite`
  docstring falsely claims the name "stays client-sealed". **Correction:** the report's "flows into
  SFTP directory listings" is **inaccurate for ZK vaults** — SFTP skips non-standard vaults entirely
  (479–483, 591–592); it only ever lists Standard vault names (plaintext by design).
- **Fix — cross-cutting, split into 3 PRs.** (1) Schema: add `enc_name`/`enc_description` (Text,
  nullable) to `Vault` + boot DDL + `ALTER COLUMN … DROP NOT NULL` on `name` (two-statement rule) +
  upgrade-matrix; add a `Vault` load/refresh transparent-decrypt listener mirroring the Folder one so
  Standard reads keep using `vault.name`; seal Standard names server-side via `encrypt_object_field`.
  (2) ZK: seal name/description **client-side** in the browser create/rename under the vault DEK
  (`encryptName(name, dek, vaultId, 'name', epoch, vaultId)` — no new crypto), store the `zk*:`-marked
  blob (server leaves the columns NULL), and decrypt at every frontend read site. (3) Scrub plaintext
  `vault_name` from `audit_logs.details`; fix the two false docstrings.
- **Depth/risk — schema-migration, and the highest cross-cutting blast radius here.** File content
  untouched. **Trap:** a buggy/omitted Standard-vault decrypt listener makes `vault.name` read NULL →
  SFTP `_vault_display_name` falls back to `vault_<uuid>`, **silently renaming every SFTP top-level
  directory** and breaking name-based path resolution. Existing ZK vaults hold plaintext names the
  server can't re-seal (no DEK) → a **client-side backfill** on next owner unlock, forward-only; never
  blindly NULL them. For ZK, server-side surfaces (notifications, audit, email templates) can no
  longer render the name — omit / use id / render client-side.
- **Deps:** the folder-name transparent-decrypt infra + `encrypt_object_field`, SFTP display
  (Standard-only), the create path's ZK wrap material, rename, audit, every UI/notification/share
  read site.
- **Tests:** Standard — DB row shows `enc_name` + NULL `name`, but list/get/SFTP still show the
  plaintext name; ZK — DB NULL, API returns the blob, browser decrypts, `audit_logs.details` has no
  plaintext name, SFTP still doesn't list it; legacy plaintext vault left untouched (read-old); rename
  re-seals; SFTP path resolution by decrypted name still works (regression).
- **Owner decision:** backfill existing ZK vault names on next unlock, or accept them as a documented
  forward-only gap? Encrypt Standard names too (marginal — server holds the key) or ZK-only? How do
  server-side notifications/audit render a ZK vault name (omit/placeholder/client-side)? Retro-scrub
  existing `audit_logs.details.vault_name`?

### M3 — Notes stored entirely in plaintext · Medium
- **Verified (intentional per the model docstring).** `Note.title`/`body` are plaintext; the send-note
  snapshot copy and public `NoteLink` snapshots duplicate sender content into more plaintext rows.
  **Correction:** the "hidden" UI affordance is already honestly labelled a "local privacy toggle",
  not encryption — so the report's relabel ask is largely already satisfied.
- **Fix — two options.** Cheap (Tier B, security-appropriate): encrypt `title`/`body` at rest via
  `encrypt_object_field` keyed on `(owner_id, note_id)`, with a decrypt-with-plaintext-fallback
  read-old; widen `title` from `String(255)` to `Text` first. Honest (out of scope): client-seal under
  the user's ECC key — costs server-side send/links; a separate epic.
- **Depth/risk — schema-migration.** **Trap:** encrypting without widening `title` to `Text`
  **truncates ciphertext** → corruption; forward-only per row without a read-old fallback; send-note +
  `NoteLink` snapshots must re-encrypt under their own row's `(owner_id, note_id)`.
- **Deps:** `encrypt_object_field`; the send-note flow; `NoteLink` snapshots; the notification
  pipeline (carries note title). Not the ZK path.
- **Tests:** round-trip keyed on `(owner_id,note_id)`; read-old returns legacy plaintext; a 255-char
  multibyte title survives (proves the `Text` widening); live — create note, read raw DB, assert bytes
  ≠ plaintext; send-note recipient copy decrypts; public link redeem works; legacy note still reads.
- **Owner decision:** is note-at-rest encryption in scope for this plan or a deferred product call?
  Encrypt `Notification`/`NoteLink` snapshots in the same change or leave inconsistent?

### M4 — `checksum_sha256` is a plaintext-content hash, stored beside the ciphertext · Medium
- **Verified, and the exposure is *broader* than the report stated.** For Standard vaults the checksum
  is SHA-256 of the **plaintext** (`StreamingUploadContext` hashes raw bytes before the codec). That
  makes the DB column a confirmation oracle **and** a cross-tenant identical-file fingerprint. **Newly
  found:** the same plaintext hash is also emitted to clients as the download **HTTP ETag**
  (`api_server.py:13416`) and used for If-Range resume, so the oracle is reachable by any *authorized
  downloader*, not just a raw-volume reader. ZK is genuinely unaffected (hash is over ciphertext).
- **Fix — keyed integrity.** Store `content_mac = HMAC-SHA256(k, plaintext)`, `k` HKDF-derived from
  the deployment root **per-file** (mirror `_gcm_stream_subkey`; per-file also kills the
  same-deployment identical-file fingerprint). Add a **new** `content_mac` column (leave
  `checksum_sha256` for legacy rows); `finalize_streaming_upload` writes it for new Standard rows and
  **stops** writing plaintext-SHA there; `verified_stream`/`BoundedDownload`/`_reader_for` carry a
  mode+key and compute HMAC for keyed rows / plain-SHA for legacy+ZK; the ETag emits `content_mac`
  (opaque) for keyed rows; upgrade-matrix entry.
- **Depth/risk — CRYPTO-FORMAT, the sharpest "breaks everything" trap.** **Apply a keyed verifier to
  an old (plain-SHA) row and every pre-fix Standard file becomes undownloadable** — legacy rows
  (`content_mac IS NULL`) MUST route through the plain-SHA path; the frozen `v0.10.0` fixtures must
  stay green; **no backfill** of old rows (can't recompute a keyed MAC without re-reading plaintext).
  The `verified_stream` fail-closed "no recorded checksum" branch must get the keyed value for keyed
  rows. If `checksum_sha256` stays NOT NULL, new rows still need a value there — writing plaintext-SHA
  keeps the oracle, so relax it to nullable (extra `ALTER COLUMN DROP NOT NULL`) or add a discriminator.
- **Deps:** the whole download/verify path incl. ETag/If-Range; all three upload writers (web
  streaming, chunked, SFTP); conceptually the `0x20` terminal (which already gives authenticated
  anti-tamper, so M4's remaining job is oracle-removal). Not the ZK envelope.
- **Tests:** unit — per-`(vault,file)` key determinism; identical plaintext → different `content_mac`
  (fingerprint gone); HMAC ≠ plain SHA. Live — new Standard file: stored value ≠ `sha256(plaintext)`,
  download succeeds byte-identical; corrupt the governing column → download fails mid-stream; **legacy
  row** (plain-SHA) still downloads+verifies and still fails on corruption; frozen fixtures still
  download; ZK unchanged; ETag present + If-Range works. Update `tests/test_api_share_downloads.py`'s
  `_corrupt_checksum` (targets the governing column) — it *will* break otherwise.
- **Owner decision:** `checksum_sha256` NOT NULL → nullable + `content_mac`, vs a `checksum_kind`
  discriminator? Per-file key (recommended) vs the report's per-deployment key? Confirm no downstream
  consumer treats the ETag as a plaintext SHA. Priority — the `0x20` terminal already gives
  authenticated integrity, so M4 is purely an oracle/fingerprint + ETag-leak fix; confirm it warrants
  a crypto-format change now vs deferral.

### M5 — In-flight upload filenames plaintext, survive failed sessions · Medium
- **Verified, with a correction.** `chunked_upload_sessions.filename`/`mime_type` hold the cleartext
  Standard-vault name; only the success path deletes the row. **Correction:** the report's "up to full
  TTL" is inaccurate for the two `status='failed'` paths (the 5-min periodic sweep prunes them
  regardless of age); it *is* accurate for the `HTTPException`/`PermissionDenied` paths that leave the
  row `active`, and for the whole normal in-flight window.
- **Fix — two options.** Full (Tier B): seal on init — write `enc_name`/`enc_mime` (columns already
  exist) via `encrypt_object_field(vault_id, session.id, …)`, leave the plaintext columns NULL, and
  make `_session_payload` decrypt for the owner (guarded by `is_zk_sealed_name`), keeping `name_bi`
  for resume matching. Cheap (Tier A): NULL `filename`/`mime_type` on the persisting failure/active
  paths.
- **Depth/risk — contained.** Reuses existing `enc_name`/`enc_mime` columns → no new column. **Trap:**
  resume matching keys on plaintext `filename` — if NULLed, match on the already-stored `name_bi`;
  keep `_session_payload` backward-compatible (decrypt `enc_name` if present, else fall back to
  plaintext for old in-flight rows).
- **Deps:** the ZK upload path (shares the columns/marker), `encrypt_object_field`, the resume-match
  logic, the sweep/prune backstop.
- **Tests:** init → row has `enc_name` populated + `filename` NULL; owner-facing resume listing shows
  the decrypted name; force each failure path → no cleartext name remains; backward-compat old-shape
  row still shows + resumes; live — kill a resumable upload mid-transfer, assert no plaintext name in
  the DB, completed upload's file name still decrypts.
- **Owner decision:** full seal-on-init vs cheap clear-on-failure (the cheap one still exposes
  plaintext for the whole normal in-flight window)? Ever DROP the redundant plaintext columns (a later
  schema hop)?

### M6 — Session tokens stored unhashed in Postgres; revocation fails open on unknown session · Medium
- **Verified (both halves).** `active_sessions.session_token` stores the **raw** 43-char token while
  Redis stores SHA-256 hashes — the one bearer secret not hashed at rest. Separately, the regular-user
  durable revocation check (`api_server.py:1319-1329`) reads `revoked_session is not None and
  revoked_session[0]`, so a JWT carrying a session token **not in the table** passes (fail-open) —
  whereas the temp path fails closed.
- **Fix — one interdependent PR.** Store `hash_session_token(token)` in the column and hash the
  incoming token at every DB lookup (keep the raw token in the client JWT and as the in-process SFTP
  key); convert the pubsub payload + the SFTP `active_transports` keying together (or SFTP force-close
  breaks); flip the regular revocation guard to reject a **missing** row; add a one-time boot
  migration rehashing legacy rows.
- **Depth/risk — contained (session table only; worst case = forced re-login, never lost files).**
  **Traps:** the boot rehash MUST run **before** the code hashes-on-read, or every live session's row
  stops matching; the pubsub↔`active_transports` keying must change **together**; ship fail-closed
  **after** the migration is confirmed. **Verified safe:** regular `ActiveSession` rows are never
  deleted (sweeper/terminate only flip `is_active`/`revoked`), so a regular JWT (30-min expiry) is
  guaranteed a row for its lifetime → fail-closed won't spuriously log out regular users post-migration.
- **Deps:** `auth_service.py` (writes), `api_server.py` (web+WS+logout+pubsub+migration),
  `sftp_server.py` (lookups + `active_transports`). No crypto-envelope coupling.
- **Tests:** `_create_session` stores a 64-char hash; lookups locate the row given the raw token;
  regular JWT with no row is **rejected** (fail-open regression guard); revoked row still 401s under a
  simulated Redis outage; migration — seed a raw-token row, run the migration, assert a JWT with the
  original raw token still authenticates (no forced re-login); live — SFTP login then admin
  lock/deactivate tears down the transport (proves keying stayed consistent).
- **Owner decision:** plain SHA-256 (matches Redis, simplest) vs peppered HMAC (matches the other
  bearer secrets, needs a pepper)? Rehash legacy rows at boot (zero forced re-logins, recommended) vs
  accept a one-time logout? Ship fail-closed in the same release?

### L1 — SFTP host key + TLS key are unencrypted private keys · Low
- **Verified.** Host key is `paramiko.RSAKey.generate(2048)` (`sftp_server.py:1605`), unencrypted;
  TLS key is unencrypted RSA-4096 (0600). Correctly permissioned; the real exposure is that the host
  key rides in the backup bundle (closed by H1).
- **Fix — contained.** Generate **Ed25519** host keys for **new** deployments (RSA fallback), make the
  load path type-detecting so existing RSA keys still load; add a `dockvault.py` "Rotate host key"
  action (warns clients see a changed host key).
- **Depth/risk:** new installs only touch nothing stored; the load path MUST accept a pre-existing RSA
  key or upgraded installs fail to start SFTP; rotation breaks pinned `known_hosts` (document, never
  automatic).
- **Tests:** generation → loadable Ed25519; load path accepts pre-existing RSA + Ed25519; live fresh
  deploy SFTP round-trip; simulate an existing RSA key file and confirm boot.
- **Owner decision:** Ed25519 new-only (recommended) vs rotate existing on upgrade (breaks pinned
  `known_hosts` fleet-wide)?

### L2 — Audit records retain IPs/UAs/vault names indefinitely by default · Low
- **Verified.** `AUDIT_LOG_RETENTION_DAYS=0` = keep forever (the cleanup machinery exists, only the
  default keeps it off); `vault_name` is written into `details` though `resource_id` already carries
  the vault; inconsistent with `SECURITY_ALERT_RETENTION_DAYS=90`.
- **Fix — contained.** Default 0→90 (+ `.env.example` + `dockvault` setup); drop `vault_name` from
  audit `details` (or add it to the redaction tuple); optional /24 IP truncation.
- **Depth/risk:** flipping to 90 makes the next cleanup **delete** rows older than 90d on installs that
  were keeping everything — a compliance-visible change; must be documented + operator-overridable
  (0 restores keep-forever). Dropping `vault_name` affects only new rows.
- **Tests:** cleanup deletes >N, keeps newer, 0 keeps all; `vault_name` no longer persisted; config-sync.
- **Owner decision:** is 90 acceptable for a compliance trail, or 365 / keep-forever + recommendation?
  IP truncation wanted (degrades incident response)?

### L3 — Deprecated `encrypted_password` column never purged · Low
- **Verified.** `temporary_credentials.encrypted_password` is deprecated (new rows write None) but two
  read sites still consult it and old ciphertext is never purged.
- **Fix — schema-migration (small).** Boot DDL `UPDATE … SET encrypted_password = NULL` then `ALTER
  TABLE … DROP COLUMN IF EXISTS`; remove the column from the model; base the two `has_password` reads
  on `password_shown` + the validity window; upgrade-matrix entry.
- **Depth/risk:** `DROP COLUMN` is forward-only (a downgrade still `SELECT`ing it fails); model + DDL +
  both reads + upgrade-matrix must land together.
- **Tests:** creating a temp cred doesn't touch the column; list/detail `has_password` consistent with
  `password_shown`; live — boot against a DB with a stale value → column gone + purge ran, endpoints
  still serve.
- **Owner decision:** confirm no external consumer reads that column; confirm intended `has_password`
  semantics now the password is never re-fetchable.

### L4 — Storage layout leaks structural metadata · Low
- **Verified.** Paths are all UUIDs (names leak nothing) but the tree reveals vault/file/folder counts,
  per-blob size (≈ plaintext + small overhead), and mtimes — the residual ZK metadata channel.
- **Fix — documentation only.** State it as an explicit ZK non-goal in the design docs + README
  security section; note host FDE (M1) as the at-rest-reader mitigation.
- **Owner decision:** does any product claim imply metadata-level ZK (making this a claims-correction)?
  Is size-bucketing/padding ever in scope, or a permanent declared non-goal?

---

## Part 2 — `dockvault.py` (the management tool)

The owner's questions: are the options well-implemented, are their names true to their actions, is
everything needed, and can an operator *blindly trust* it for crucial things like backups? Verified
against v0.16.1. Two of these — the restore correctness bug and the backup-location resolver — are the
practical heart of this whole plan.

### DV-RESTORE — Restore silently doesn't do what the operator expects (the reported bug)
This is the direct explanation for "I took a backup, deleted a file, uploaded another, ran `backup
--force` → Restore, and saw the same files, not the old ones." Three confirmed defects, one fix,
**ship together**:

1. **Restore MERGES, it doesn't REPLACE.** `untar_volume` (dockvault.py:1333) runs `cd /dest && tar
   xzf …` with **no step that empties `/dest` first**. So restore extracts *over* the live volume: a
   file uploaded *after* the backup stays (not in the archive → never removed); a file deleted after
   the backup comes back. For `vault_pg_data` it is worse than a merge — extracting the backup's
   database files over the current cluster's data directory mixes two point-in-time on-disk states of
   an interdependent file set (heap/WAL/control file) = physical corruption, not a clean rollback.
2. **Restore never stops the stack.** `_do_restore` (3170) has no `_stop_stack`/`_stop_db_only` call; it
   extracts under a **running** Postgres that holds `pg_data` open (buffer cache, WAL, open fds), then
   prints "Run Setup to start it". The server keeps serving from its cached state, so **the restored
   bytes have essentially no effect on what the app returns** — this is precisely why the owner saw no
   change. On the next restart Postgres may fail recovery or corrupt.
3. **The labels lie.** The `--force` message says it "replaces their contents" but the code merges and
   doesn't stop; the docstring says restore will "recreate the volumes" (it doesn't); the menu
   "Restore a bundle" carries no warning that it discards current data.

**Fix (contained, but must be correct together):** in `_do_restore`, after validation and before any
extraction — (a) `self._stop_stack()` (down, **no `-v`**, volumes survive); (b) **clear each target
volume** before extracting (`docker volume rm`+recreate for `pg` to guarantee a pristine data dir;
clear-in-place for storage/keys) — strictly on the **reconstructed** `names[role]`, never a
manifest-supplied name; (c) install the restored `.env`; (d) bring the stack back up and health-check.
Reword the menu / `--force` help / docstring / success line to state "this stops the stack and
REPLACES the current data with the backup (current data is discarded)", and add a strong confirmation
for an over-existing interactive restore (`--non-interactive --force` bypasses it).

- **Depth/risk — contained; data-safety-critical.** No crypto/format change. The safety hazard is
  clearing the **wrong** volume — mitigated by the existing prefix validation + role reconstruction
  (a crafted manifest cannot redirect the clear). A clear-then-failed-extract leaves an
  empty/absent volume → verify the archive exists (already done) before clearing; consider a temp-volume
  swap for atomicity. Stopping introduces expected downtime; bring the stack back up on the **restored**
  `.env` (order: stop → clear+extract → install restored `.env` → up → health).
- **Tests:** unit — restore issues a clear/rm for each reconstructed role volume **before** the untar,
  only on `names[role]`; calls `_stop_stack` before the first untar and starts+health-checks after;
  labels state "replaces/discards"; `--non-interactive --force` bypasses the confirm. **Live throwaway
  stack (unique prefix):** setup → create file A → backup → delete A, upload B → `backup --force`
  restore → restart → assert **only A** is present (B absent) via API listing, DB consistent (psql
  select succeeds, row counts match pre-change), vault-db starts cleanly (no recovery/`invalid page`
  errors). This is the non-vacuous proof that closes the reported bug.
- **Owner decision:** restore auto-restart + health-check, or stop-restore-then-leave-stopped with
  instructions? Atomic temp-volume swap or clear-then-extract? A typed-phrase confirm (like `reset`) or
  simple y/N for an over-existing restore?

### DV-STORAGE — Where backups live (the "Downloads folder" question)
- **Verified.** `_backup_root` (3086) returns `args.backup_dir or <repo_root>/backups`, where the root
  is the directory `dockvault.py` itself lives in. **So bundles land inside the clone tree** — and if
  the clone lives under Downloads, `<clone>/backups` *is* under Downloads. That is exactly the observed
  behaviour. There is no per-OS app-data resolver and no `DOCKVAULT_BACKUP_DIR`. Restore lists from
  that same single root, so once the default moves, old bundles would be orphaned.
- **Fix (contained, stdlib-only):** add `default_backup_dir()` with precedence: (1) `--backup-dir`;
  (2) `DOCKVAULT_BACKUP_DIR` env; (3) per-OS app-data under `DockVault/backups` — Windows
  `%LOCALAPPDATA%` (non-roaming: bundles are large + secret, must not sync); macOS `~/Library/
  Application Support`; Linux `$XDG_DATA_HOME` or `~/.local/share`; (4) writability-probed fallback to
  `~` then `~/Downloads`. Create `0700` on POSIX. Make restore **search a list of roots** (new default
  **and** legacy `<repo>/backups`, deduped, path-disambiguated) so old bundles stay discoverable; add a
  `backup --list` that prints "backups live here: `<path>`" + the enumerated bundles; print the
  destination **before** archiving. Never silently orphan legacy bundles — keep the legacy path a
  permanent search fallback and only *offer* migration (copy, verify, then optionally delete),
  never auto-move.
- **Depth/risk — low.** Changes only *where* new bundles go + *where* listing looks; no format/schema.
  The fallback chain must probe **writability** (not just existence) or an `update` auto-backup could
  fail at the worst moment. Dual-search must disambiguate duplicate basenames across roots by full path.
- **Tests:** unit (monkeypatch `os.name`/`sys.platform`/env) — correct path per platform, precedence
  order, fallback on `OSError`, `0700` on POSIX; listing helper finds bundles from **both** roots
  deduped; `--backup-dir` narrows to one; `--list` prints the resolved location without a running
  vault. Live — `backup` with no `--backup-dir` writes under the resolved app-data dir (not the clone)
  and restore finds it.
- **Owner decision:** confirm `%LOCALAPPDATA%` (recommended) vs `%APPDATA%` and the `DockVault/backups`
  subdir name; does `--backup-dir` win over `DOCKVAULT_BACKUP_DIR` (recommended: explicit flag wins)?

### DV-UX — Option naming, necessity, and trustworthiness audit
The tool is fast and explains itself, and several safety behaviours are genuinely good (backup refuses
an empty capture; restore validates the coupling fingerprint and reconstructs volume names rather than
trusting the manifest — a path-injection guard; `reset` requires typing the exact set name). The gaps
are about names matching actions and crucial actions being discoverable and honest:

- **`lock`/`stop` overstate sealing (couples C1/DV-RESTORE-labels).** `lock` says "plaintext .env
  removed" and `stop` keeps only "data volumes"; neither mentions that a stopped/running container
  still exposes every secret via `docker inspect`. Reword honestly; optionally make `stop --lock` run
  `compose down` (no `-v`) so lock actually removes the env-bearing container (gated, opt-in).
- **`stop --lock` is CLI-only and undiscoverable.** The interactive menu's Stop calls `stop(None)` so
  `--lock` is always false — a user who wants "stop and seal" has no menu path. Add an interactive
  "Also seal `.env` now?" prompt after a successful stop (guarded off under `--non-interactive`).
- **Menu is flat and dilutes everyday actions.** `lock`/`unlock`/`change-passphrase` are a niche
  `.env`-sealing workflow occupying 3 of the first 8 slots ahead of Backup; a new operator can't tell
  "lock" means an at-rest `.env` seal (not locking the vault UI). Move them behind an "Advanced /
  credential sealing" submenu; keep the CLI subcommands unchanged so scripts still work.
- **`reset` doesn't offer an inline backup.** It says "Back up first if unsure" but leaves it as manual
  homework at the moment data is about to be destroyed. Offer "Take a backup now?" (default No, skipped
  under `--confirm --non-interactive`). Optionally sharpen the label to "Reset — DESTROY data + start
  fresh".
- **`storage` label vs action.** The command key is `storage` but the label is "Limits …" and the one
  action sets *two* unrelated ceilings (disk + transfer concurrency) and can recreate the stack. Align
  the label ("Storage & transfer limits") and note it may recreate the stack — **don't** rename the CLI
  key (breaks scripts).
- **`backup` destination disclosed only after the fact / `update` auto-backup surprises.** Print the
  backup destination **before** archiving (couples DV-STORAGE); surface `update`'s auto-backup
  destination + a rough free-space check and list the planned multi-stage hops up front.

All DV-UX items are contained host-tool UX with no crypto/schema/data risk; the only rule is never add
an interactive prompt on a `--non-interactive` path (scripts would hang) and never rename a CLI
subcommand key.

---

## 5. Recommended PR sequence

Ordered by risk-reduced-per-effort and dependency; each row is one PR from a fresh `main`. Tier-C PRs
are gated on the owner decisions in §6.

| # | PR | Tier | Findings | Why here |
|---|----|------|----------|----------|
| 1 | **Restore correctness** | A | DV-RESTORE (merge+stop+labels) | Highest value: fixes a data-integrity/trust defect the owner already hit. Independent. |
| 2 | **Backup location** | A | DV-STORAGE + DV-UX backup/menu polish | Directly answers the "Downloads" question; makes backups trustworthy + discoverable. |
| 3 | **Container secret hygiene** | A | C1-now (lock/stop→down + status warn), H4, DV-UX lock/stop honesty + discoverability | The `.env`/container secret story, all host-tool + one app marker; no schema. |
| 4 | **At-rest quick wins** | A | H2-interim, H3-interim, L2, M5-cheap, M3-relabel | Batch of small, safe at-rest reductions. |
| 5 | **Docs & host keys** | A | M1-doc + L4-doc + FDE setup-warning, L1 (Ed25519 + rotation) | Documentation + new-install key upgrade; low risk. |
| 6 | **Small schema drop** | B | L3 (drop `encrypted_password`) | Self-declaring schema hop; good warm-up for the migration discipline. |
| 7 | **Session token hardening** | B | M6 (hash column + fail-closed + boot migration) | Contained, interdependent, well-understood; rows-never-deleted proven. |
| 8 | **Secret file mounts** | B | C1-proper (`<NAME>_FILE` + compose `secrets:`) | The real fix for C1; read-old/write-new; Redis split out if needed. |
| 9 | **Sealed backup bundle** | B | H1-full | Owner-decision-gated (DR tradeoff). H1-min already shipped in PR 2/3. |
| 10 | **In-flight name + notes** | B | M5-full, M3-encrypt | Additive column reuse + note `Text` widening. |
| 11 | **Encrypt chunks on arrival** | B | H2-real | Deterministic staging key; depends on M4 checksum semantics being settled. |
| 12 | **Keyed checksum** | C | M4 | Crypto-format; heaviest test burden; read-old mandatory. |
| 13 | **Vault name sealing** | C | M2 (split into 3 sub-PRs: schema+Standard, ZK browser, audit scrub) | Cross-cutting; SFTP-rename + ZK-backfill hazards. |
| 14 | **Streaming SFTP encrypt** | C | H3-real | Sequential-AEAD vs random-offset; keep buffer fallback. |

PRs 1–5 (all Tier A) can proceed immediately and independently. PRs 6–11 (Tier B) each need their
read-old fallback + migration + upgrade-matrix. PRs 9, 12, 13, 14 are gated on §6 decisions.

## 6. Owner decisions to resolve before the deep phases

Collected from the per-finding notes. The Tier-A PRs (1–5) need none of these.

1. **C1 threat boundary + strategy** — is C1 "Critical" or hardening (secret files don't stop
   live-host-root)? Docker secret files vs the existing encrypted-credential mode? Default `stop`→`down`
   for everyone or gated?
2. **H1 DR tradeoff** — sealed bundle by default (lost passphrase = unrecoverable) vs opt-in
   `backup --lock`? Where does `update`'s non-interactive auto-backup get a passphrase? Seal `.env`
   only or the whole bundle?
3. **H2** — lower the default chunk TTL (breaks multi-day resume)? staging-key derivation.
4. **H3** — low default SFTP ceiling (for tmpfs) vs tmpfs opt-in? Require sequential SFTP writes?
5. **M2** — backfill existing ZK vault names on unlock or accept a forward-only gap? How do server-side
   notifications/audit render a ZK vault name? Encrypt Standard names too or ZK-only?
6. **M3** — in scope for this plan or a deferred product call? Encrypt Notification/NoteLink snapshots
   too?
7. **M4** — `checksum_sha256` nullable + `content_mac` vs a discriminator column? Per-file vs
   per-deployment MAC key? Warrant a crypto-format change now vs deferral (the `0x20` terminal already
   gives anti-tamper integrity)?
8. **M6** — plain SHA-256 vs peppered HMAC? Rehash legacy rows at boot (recommended) vs one-time
   logout? Ship fail-closed in the same release?
9. **L2** — audit retention default (90 / 365 / keep-forever + recommendation)? IP truncation?
10. **DV-RESTORE** — auto-restart after restore or leave stopped? Atomic swap? Confirm style.
11. **DV-STORAGE** — `%LOCALAPPDATA%` + subdir name; flag-vs-env precedence.

## 7. Out of scope

The review also noted one item outside this repository entirely — in a separate deployment component
that is not part of `DockVault/vault`. It is tracked separately and is not addressed by this plan.

---

## 8. Provenance

- Findings verified against `DockVault/vault` at **v0.16.1 (`499fd3c`)**.
- Every finding above was cross-checked against the actual source; report inaccuracies are called out
  inline (H4 "setup rewrites on every re-run" — false; M2 SFTP-listing claim — inaccurate for ZK; M5
  "full TTL" — inaccurate for failed sessions; H1 mitigation-overstatement; M4 oracle is *broader*
  than reported — also the download ETag).
- CI: `fast-tests.yml` + `tests.yml` (offline lane → real-Docker integration) run on every PR.

