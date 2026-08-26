# Design: credential lock/unlock + deployment lifecycle commands

Status: implemented · Scope: `dockvault.py` (the host-side management tool) · Audience: self-hosters

This adds two related capabilities to `dockvault.py`:

1. **Credential lock/unlock** — seal the `.env` (which holds every deployment secret) into an
   encrypted `.env.enc` at rest, and open it back to `.env` to run. Two credentials can open it: an
   **unlock passphrase** and a **credential recovery key**.
2. **Lifecycle commands** — `start` / `stop` / `restart` / `status`, so operators stop reaching for
   raw `docker compose` and get health-gated, log-on-failure, data-safe controls.

The two are paired: `start`/`restart` are the natural place the unlock prompt lives.

---

## 1. Motivation and honest threat model

`.env` holds the crown jewels: `ENCRYPTION_KEY` (the Fernet at-rest master key — **lose it and every
stored file is unrecoverable**), `VAULT_DB_PASSWORD`, `REDIS_PASSWORD`, `JWT_SECRET_KEY`,
`ADMIN_PASSWORD`. Today it sits in plaintext at mode `600`. Security-conscious operators manually move
it off the host when the server is down and copy it back to restart. This feature makes that a clean,
less-error-prone `lock`/`unlock`.

**What locking protects (state it plainly to users):** the `.env` while the server is **off and
locked** — i.e. a stolen disk, a stolen backup, or a VM snapshot that happens to capture the box while
it was sealed. Also: `.env.enc` is safe to include in a backup bundle where plaintext `.env` would not
be. `backup --lock` uses exactly this envelope to seal a bundle's `env` into `env.enc` (opt-in): the
volume archives are already ciphertext at rest, so sealing the one file that holds `ENCRYPTION_KEY`
makes a stolen backup undecryptable. Restore detects `env.enc`, decrypts it in memory with the
passphrase or recovery key (a wrong credential aborts before the deployment is touched), and installs
the plaintext `.env` only onto the restored host.

**What it does NOT protect:**
- A **running** server. A running vault must hold the plaintext secrets in process memory, so the
  compose stack always runs on a plaintext `.env`. Root on the running box reads `/proc/<pid>/mem`, the
  container environment, or the decrypted files regardless.
- Anything, once the disk is stolen **while unlocked** (the common state for a 24/7 box).

The **real control for a running box is host full-disk encryption** (ideally FDE + TPM), which also
covers the data volumes, not just `.env`. The docs will say this. Locking is a focused convenience +
defense-in-depth for the at-rest/off state, not a substitute for FDE.

## 2. Non-goals (deliberately rejected, with reasons)

- **No unattended auto-unlock / Docker-restart auto-unlock.** For a box to self-decrypt after a bare
  reboot with no human, the unlock secret must live on that same box — so a disk thief has it too. This
  is the "secret zero" bootstrapping problem: unattended auto-unlock and resistance to a disk/host
  attacker are mutually exclusive. Operators who want unattended reboot recovery use host FDE+TPM at the
  OS layer; `dockvault.py` will not reinvent it. **Consequence: while `.env` is locked, the stack cannot
  auto-recover from a reboot — someone unlocks it first.** This is documented, not hidden.
- **No in-file second factor / "2FA code".** A factor stored beside the ciphertext is not a factor — the
  file-reading attacker gets both in one read. A TOTP code is ~20 bits, time-rolling, and designed for
  an online rate-limited check, not key derivation. Rejected.
- **No per-field encryption in the running `.env`.** Compose interpolates `${VAULT_DB_PASSWORD:?}` and
  the DB/Redis containers read those in the clear, so an encrypted-in-place `.env` cannot run under
  compose. (That model — `scripts/setup_master_password.py` — stays as a separate advanced bare-metal
  option; see §10.)
- **No home-rolled cipher.** We use vetted primitives only.

## 3. The `.env.enc` format — envelope encryption (one payload, key-wrapped)

"Two credentials can open one file" is *envelope encryption with key slots* (the LUKS / `age`
multi-recipient model), done correctly — NOT encrypting the values twice.

- Generate a random **Data Encryption Key (DEK)** = `Fernet.generate_key()` (32 random bytes,
  url-safe base64).
- Encrypt the whole `.env` **once**: `payload = Fernet(DEK).encrypt(env_bytes)`. Fernet is
  authenticated (AES-128-CBC + HMAC-SHA256), so tampering is detected.
- **Passphrase slot:** derive a Key-Encryption-Key from the passphrase with a memory-hard KDF and wrap
  the DEK: `wrapped_dek = Fernet(KEK).encrypt(DEK)` where `KEK = urlsafe_b64(scrypt(passphrase, salt))`.
- **Recovery key = the DEK itself**, shown once to the operator. To recover, `Fernet(recovery_key)
  .decrypt(payload)` directly. (The recovery key is literally the file's master key — that is what a
  recovery key *is*: a second credential that opens the file without the passphrase.)

On-disk layout — a small text header line + a JSON body, so the file is self-describing and a
mismatched/garbled file is detectably not a valid lock (never silently "corrupted"):

```
DOCKVAULT-ENV-LOCK v1
{
  "version": 1,
  "kdf": { "algo": "scrypt", "n": 32768, "r": 8, "p": 1, "salt": "<b64>" },
  "cipher": "fernet",
  "wrapped_dek": "<b64 Fernet(KEK).encrypt(DEK)>",
  "payload": "<b64 Fernet(DEK).encrypt(env_bytes)>",
  "created_at": "<ISO8601>",
  "hint": "<optional non-secret passphrase hint>"
}
```

Rotation for free: **change the passphrase = re-wrap the tiny DEK** (payload untouched, recovery key
unchanged). Invalidating a leaked recovery key = re-lock with a fresh DEK (a full re-encrypt of the
small `.env`, instant).

### KDF and dependency

- **KDF: `hashlib.scrypt`** (stdlib, memory-hard). Params `n=2**15, r=8, p=1` (tunable; recorded in the
  header so future changes stay decryptable). Fallback to `hashlib.pbkdf2_hmac('sha256', …, 600_000)` if
  scrypt is unavailable on the host's Python build.
- **AEAD: Fernet from the `cryptography` package.** dockvault.py is otherwise stdlib-only, and Python's
  stdlib has no cipher, so lock/unlock is the **one** command that needs a dependency. It is imported
  **lazily inside the lock/unlock handlers only** — every other command (setup, start/stop/restart/
  status, backup, …) stays stdlib-only and unaffected. If `cryptography` is absent, lock/unlock prints a
  one-line `pip install cryptography` instruction and exits non-zero; nothing else breaks. (Precedent:
  `scripts/setup_master_password.py` already requires `cryptography`.)

## 4. State machine and safety (verify-before-destroy)

Two files, two strict states, never a header-marked half-`.env`:

| State | `.env` | `.env.enc` |
|-------|--------|-----------|
| Unlocked (can run) | present (compose input) | present (sealed copy, kept) |
| Locked (sealed)    | **absent** | present |

- **`unlock`** materialises `.env` from `.env.enc`, keeping `.env.enc`. It **refuses to overwrite an
  existing `.env`** without `--force` (never clobber a plaintext you might be mid-edit on).
- **`lock`** re-encrypts the current `.env` and, only after proving the new ciphertext round-trips,
  deletes `.env`. Concretely:
  1. Read `.env` bytes.
  2. If `.env.enc` exists: unwrap the existing DEK with the passphrase (verifies the passphrase, keeps
     the recovery key stable); else generate a fresh DEK (first lock → show the recovery key once).
  3. Write `.env.enc` **atomically** (temp file in the same dir, `fsync`, `os.replace`), mode `600`.
  4. **Verify:** re-read `.env.enc`, decrypt with the in-memory DEK, assert byte-identical to step 1.
  5. Only then delete `.env`. A failure at any step leaves BOTH files intact and exits loud.
- All writes reuse the existing atomic-write + `600`/`icacls` helpers.
- A bad passphrase, a failed AEAD tag, or a format-version mismatch fails **loud** and never touches the
  counterpart file.

**Data-loss warning (shown at first `lock`):** the recovery key and passphrase are the only ways back
to `ENCRYPTION_KEY`. Lose both → every stored file is permanently unrecoverable. Save the recovery key
in a password manager; keep an off-host backup of `.env` or `.env.enc`.

## 5. Commands

### Credential lock (grouped under a `credentials` menu entry for the interactive tool)

| Command | Behaviour |
|---------|-----------|
| `lock` | Seal `.env` → `.env.enc`, delete `.env`. Prompts for the passphrase (first time: set + confirm, then **display the recovery key once**). Non-interactive: `--passphrase-file PATH` or `--passphrase-stdin`. `--hint TEXT` stores a non-secret hint. |
| `unlock` | `.env.enc` → `.env`. Prompts for the passphrase; `--recovery-key` (prompt) / `--recovery-key-file PATH` to use the recovery key instead. `--force` to overwrite an existing `.env`. |
| `unlock --show-recovery-key` | Unlock in memory and re-display the recovery key (for someone who has the passphrase but lost the key). |
| `change-passphrase` | Set a new unlock passphrase, authenticating with the CURRENT passphrase OR the recovery key. Re-wraps the same data key, so the recovery key is unchanged - this is how a forgotten passphrase is replaced. |

**Password input:** getpass by default; `--passphrase-file` / `--passphrase-stdin` for automation.
**Never** a bare `--passphrase VALUE` argument (leaks into shell history / `ps`). There is **no
top-level `recover` command** — recovery is a *mode* of `unlock` — to avoid confusion with data /
deployment recovery. The fallback string is always named the **credential recovery key**; help text
states verbatim: *"unlocks your `.env` if you forget the passphrase; it does not recover vault files or
deployments."*

**Recovery-key artifact:** a **string** (the Fernet key, 44 url-safe-base64 chars), shown once and
meant for a password manager. `lock --recovery-out PATH` optionally also writes it to a file for the
operator to move off-box, with a warning not to leave it on the host.

### Deployment lifecycle

| Command | Behaviour |
|---------|-----------|
| `start` | Preflight (`.env` present & parseable, volume set present, secret-bundle guard satisfied, ports free) → `up -d` → **wait for health** → per-container status. On failure, tail the failing service's logs and exit non-zero. If only `.env.enc` is present, **prompt to unlock inline** and continue (the server needs plaintext `.env` to run anyway). Never touches volumes. |
| `stop` | `compose stop` (preserves containers + volumes; not `down -v`). `--lock` (or an interactive prompt) offers to re-seal `.env` after stopping. |
| `restart` | `stop` → `start` with the same health gate. If the new start fails health, say so loudly; data is untouched. |
| `status` | Per-container running/health, published ports, image + digest, and whether `.env` is locked/unlocked. Read-only. |

**Friendly vs loud:** `start` / `restart` (and a `setup` re-run) prompt-unlock inline when locked;
every other command that needs `.env` and finds only `.env.enc` **fails loud** ("`.env` is locked; run
`python dockvault.py unlock` first") rather than silently exposing secrets.

Lifecycle commands reuse the existing internals: `_start_secure_stack`, `_stop_stack`,
`_wait_secure_healthy`, `_tail_logs`, `_run_dc`, `_load_env`, and honour the combined-vs-split
`COMPOSE_PROFILES`.

## 6. Failsafes summary

- Never `down -v`, never touch data volumes, from any lifecycle command.
- `lock` is verify-before-destroy; `unlock` refuses to clobber without `--force`; both are atomic.
- Missing/locked `.env` → clear, actionable error (point at `setup` or `unlock`).
- The existing secret-mismatch guardrail (a `.env` whose secrets don't match the persisted volume set)
  still fires on `start` — prevents the "wrong password after re-setup" footgun.
- Health-gated starts with a bounded timeout and a log dump on failure — no silent hang.
- Loud, non-zero exit on any crypto failure; the counterpart file is never left in a half state.

## 7. Testing

- **Crypto round-trip:** lock → unlock with passphrase → byte-identical `.env`; lock → unlock with the
  recovery key → byte-identical; wrong passphrase → loud failure, files intact; tampered `.env.enc`
  (flip a byte) → AEAD failure, refuses. `change-passphrase` keeps the recovery key working.
- **State machine:** `unlock` refuses to overwrite an existing `.env` without `--force`; `lock` leaves
  both files intact if the verify step is made to fail; atomic-write leaves no partial file on an
  interrupted write.
- **Lifecycle (real Docker, in the setup-matrix lane):** `start` brings the stack healthy; `status`
  reports it; `stop` stops without removing volumes; `restart` returns healthy; `start` on a locked
  `.env` prompts unlock then runs; a read-only command on a locked `.env` fails loud.
- **Dependency-absent:** with `cryptography` uninstalled, lock/unlock print the install hint and exit
  non-zero while `status`/`setup` still work (stdlib-only preserved).

## 8. Docs / sync

- `.env.example`: note that `.env` can be sealed with `python dockvault.py lock` and the exact at-rest
  threat coverage (off/locked only; FDE is the running-box control).
- README: a short "Sealing credentials at rest" section + the lifecycle commands.
- Per the repo rule, any new `.env`/config field stays in sync across `config.py` ⇄ `.env.example` ⇄
  `dockvault.py` (this feature adds no new app config field — it only wraps the existing `.env`).

## 9. What we are explicitly NOT building now (future, opt-in)

- An **automation slot** (a second wrapped-DEK whose KEK lives OFF the box: a key file on removable
  media, a TPM-sealed key, or a KMS-fetched key). This is the only sound way to do less-attended unlock,
  and it is opt-in, advanced, and documented per-source with its exact coverage. Deferred.
- **Shamir k-of-n** recovery for multi-admin escrow. Deferred.
- Rotatable, audit-logged, leak-detectable unlock — that is a KMS feature and only makes sense if the
  product grows a managed/cloud tier. Deferred.

## 10. Relationship to `scripts/setup_master_password.py`

That script is the *other* model — it encrypts individual secret fields in place (`ENCRYPTED_*`) and the
**app** decrypts them at boot via an OS keyring / prompt. It fits **bare-metal** (app runs on the host
with a keyring), not the compose container (no keyring/TTY). It is kept as an advanced option and should
be **renamed** to say what it does (e.g. `encrypt-dotenv` / `seal-credentials`). The lock/unlock feature
here is the compose-friendly, operator-facing default. The two are scoped so they are not competing
"which encryption?" choices: **lock/unlock = seal `.env` at rest when off; setup_master_password =
run bare-metal without plaintext secrets on disk.**
