# Security Policy

DockVault Vault is a self-hosted, encrypted file vault. We take the security of the
project — and of everyone who self-hosts it — seriously.

## Supported versions

| Release line | Security fixes |
|---|---|
| 0.33.x, the latest line | Yes |
| 0.32.x and earlier | No. Upgrade to the latest release. |

Each minor release line from 0.33 on (0.33.x, 0.34.x, ...) receives security fixes until six
months after the next minor release ships. When 0.34.0 ships, 0.33.x gets its own row here with
that date, so for a while two lines are supported: the latest and the one before it. 0.32.x and
earlier receive no more security fixes. (The README's "minimum supported version" is a different
thing: the oldest release `dockvault.py update` can upgrade from.)

Security fixes ship as patch releases. Once a newer line exists, a fix for an older line that is
still supported is released from that line's `release/X.Y` branch, in the same release window as
the fix for the latest line; [docs/guides/maintenance-releases.md](../docs/guides/maintenance-releases.md)
describes how. Every fixed vulnerability is published as an advisory, with a CVSS v4 score, in the
upgrade matrix (`docs/upgrade-matrix.json`), which marks each release that has a known advisory as
not secure. `dockvault.py update`, the in-app update notice and the upgrades page of the
documentation site read that matrix.

### Release images

Every release is published as `ghcr.io/dockvault/vault:vX.Y.Z`, which never changes. The newest
release of each line is also tagged `:vX.Y` (for example `:v0.33`), which moves to each new patch
release of that line. `:latest`, and GitHub's "latest release", name the highest version released,
so a patch release of an older line never moves them.

### Accepted residuals

Two ways round the rule that another administrator's credential change needs an independent
approver remain in 0.33.x, and each step of them is announced to every administrator or to the
account's user:

- someone who creates several administrator accounts and waits 14 days can approve their own
  changes through them;
- an administrator whose current password someone else set can still approve another
  administrator's credential change, so whoever set that password can approve through that
  account. 0.34.0 refuses such approvals.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public issue,
pull request, or discussion for a security report.

- Preferred: this repository's **Security** tab → **Report a vulnerability** (a private
  GitHub Security Advisory).
- Please include the affected version/commit, a description, and reproduction steps or
  a proof of concept.

What to expect:

- an acknowledgement within 5 business days;
- a first assessment within 10 business days: whether we can reproduce it, and its severity
  (CVSS v4);
- a fix within 30 days for Critical and High severity and within 90 days for Medium. Low
  findings are fixed in the next regular release, and in the supported previous line in the same
  release window.

We will keep you informed, coordinate disclosure with you, and credit you in the release notes
unless you ask us not to. Please allow us to release a fix before any public disclosure.

## Deploying securely

Use the hardened production path, not the local-trial default:

- `dockvault.py setup` + `deploy/docker-compose.secure.yml` — TLS-only, non-root, read-only
  container, the generated `.env` secrets file written at mode `600`, and the
  database/Redis never published to the host. (On rootless / user-namespace-remapped
  engines the TLS private key may be widened to `644` so the remapped container user can
  read it — the tool warns when it does this; keep such hosts single-tenant.) The old
  `./setup-secure.sh` / `.ps1` scripts still work — they are retired shims that launch it.
- Set your **own** strong secrets in `.env`; never reuse the placeholders in
  `.env.example`. The application refuses to boot with placeholder secrets in production.
- Always run behind TLS. Do not expose the plaintext HTTP listener to an untrusted
  network.

## Encryption at rest, and upgrading an existing deployment

The vault encrypts file **contents** at rest, and recent releases also seal sensitive
**metadata** in the database — note titles/bodies, file/folder names, and vault
names/descriptions — so they are not stored in the clear. What stays in the clear, and every
other place a deployment keeps personal data (the audit log, sessions, cache, logs, emails and
exports), with its retention and how it is erased, is listed in
[docs/data-inventory.md](../docs/data-inventory.md).

When you **upgrade an existing deployment**, the boot migrations seal the rows that were
written in the clear by an older version, in place. This is an important caveat for a
raw-volume threat model:

- **Postgres does not erase the old plaintext when a row is sealed in place.** An in-place
  update writes a new row version and keeps the old one as a *dead tuple* until `VACUUM`
  reclaims it, and records the change (including the old value) in the write-ahead log
  (`pg_wal`) regardless. So for a while after an upgrade, the raw data volume can still
  contain the pre-seal plaintext — recoverable only by someone who can read the raw
  Postgres files or a filesystem-level backup/snapshot, **not** through the application.
- **A fresh install never accumulates this residue** — it writes sealed from the first row.
- To actually retire the residue on an upgraded deployment, use **host full-disk
  encryption** (which protects the whole volume regardless), or **dump and restore onto a
  fresh volume** after upgrading (a new data directory + WAL that never held the plaintext).

If your threat model does not include an attacker obtaining the raw data volume (disk
image, filesystem backup, or storage snapshot), this residue is not reachable and no
action is needed.

## Zero-knowledge key changes need proof of the key

From 0.33.2, creating or sharing a zero-knowledge vault, rotating its key and setting its
name-index key each carry a proof, made in the person's browser over a one-time challenge and
the exact request, that they hold their own encryption key, the vault's current key and any key
the change puts in place. The server refuses a change without a proof (428) or with a wrong one
(403), and changes nothing when it refuses. Signing in as someone — as an administrator who reset
their password can, or anyone holding a stolen session — is therefore no longer enough to change
the key of a zero-knowledge vault they hold. The protocol is specified in
[docs/design/vault-zk-key-proof-v1.md](../docs/design/vault-zk-key-proof-v1.md).

- **`ZK_KEY_PROOF_ENFORCE`** (`.env` only, default `true`). Setting it to `false` accepts changes
  without a proof again, which reopens the problem the proof closes; use it only to postpone
  enforcement while older clients are updated. Each change then made without a proof is recorded
  in the audit log as `zk_key_proof_absent`, and the web container says at startup that it is off.
  An administrator cannot change it from the settings page. Rolling back below 0.33.2 has the same
  effect as `false`.
- **Clients.** The web app a server serves always matches it; reload browser tabs opened before
  an upgrade. A DockVault Desktop build whose built-in web app predates 0.33.2 cannot create or
  share a zero-knowledge vault, rotate its key or set its name-index key, and cannot remove a
  member from one (removal rotates the key first), until it is updated. Reading, uploading,
  downloading and syncing are unaffected, and nobody is signed out.
- **Reverse proxies** must pass the `X-ZK-Key-Proof` request header and the request body on
  unchanged: the proof is a MAC over the body's exact bytes.
- **The compatibility promise.** A request without a proof never half-applies: it gets a refusal
  with a plain `detail` and a `reason`, never a 401. Reads, uploads, downloads and sync never depend
  on proof material. A client recognises a server without key proofs by a 404 without a `reason`
  from the challenge route, and sends its request without one. A new version of the proof header
  is accepted by servers at least one minor release before any client sends it, and a new format of
  the stored material ships its reader at least one minor release before its writer.

What this does not cover:

- **A weak zero-knowledge passphrase.** Someone who can sign in as a person can download their
  passphrase-encrypted key and try to guess the passphrase offline; a guessed passphrase makes them
  that person. Use a long passphrase.
- **An account that has not set up its encryption key yet.** Whoever sets it up first owns it. If
  someone signs in as a person before that person has set up a key, a vault shared to that account
  afterwards is shared to them.
- **Keys changed before the upgrade.** A vault whose key someone else chose before 0.33.2 keeps that
  key. Check the audit log for entries made after an administrator changed a vault member's sign-in
  details: `zk_vault_rekeyed` and `zk_member_key_granted`, and `vault_created` for a zero-knowledge
  vault made by that member's account. Have a key holder rotate any vault with a change nobody
  recognises, and do not upload to a zero-knowledge vault its owner did not create. Setting a vault's
  name-index key is recorded, as `zk_index_key_wrapped`, only from 0.33.0; before that it left no
  entry.

## Update check (opt-in phone-home)

The optional update check (`UPDATE_CHECK_ENABLED=true`, **default off**) makes an outbound request
on a configurable interval (`UPDATE_CHECK_INTERVAL_MINUTES`, default 360; a shared cache bounds real
requests to that rate no matter how often the UI polls) to GitHub's public API (`api.github.com` /
`raw.githubusercontent.com`) to learn the latest published version, its upgrade matrix, the copy on
`main`, and the matrix of the newest release of each older line that the copy on `main` lists (at
most five, whether or not the line still gets security fixes); these are the same requests
whatever version an install runs. It sends **no** instance identifier, account data, version,
or other telemetry — only the request's egress IP reaches GitHub (inherent to any outbound HTTP).
It is fail-closed-silent (never blocks a request, never errors), the "update available" status is
admin-only, and it is suppressed on centrally managed deployments. Leave `UPDATE_CHECK_ENABLED`
at its default `false` to make no outbound calls at all; air-gapped installs are unaffected.

## Credentials and repository history

**Any credential value that appears anywhere in this repository's git history is a
non-production development fixture.** Such values have been removed from the current
tree, are treated as invalid, and have been rotated where they were ever used. They must
never be used to access any instance.

- Never copy a password, key, or token out of this repository — its working tree **or**
  its history — into a real deployment.
- Every install generates its own secrets (`dockvault.py setup` does this for you;
  `.env.example` ships only non-functional placeholders).

If you believe a credential found in this repository is, or ever was, valid against a
real instance, please report it through the private channel above so we can confirm it
has been rotated.
