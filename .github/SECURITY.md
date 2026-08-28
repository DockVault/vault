# Security Policy

DockVault Vault is a self-hosted, encrypted file vault. We take the security of the
project — and of everyone who self-hosts it — seriously.

## Supported versions

Security fixes are applied to the latest release on `main`. Self-hosters should track
the latest tagged release.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public issue,
pull request, or discussion for a security report.

- Preferred: this repository's **Security** tab → **Report a vulnerability** (a private
  GitHub Security Advisory).
- Please include the affected version/commit, a description, and reproduction steps or
  a proof of concept.

We will acknowledge the report, work on a fix, and coordinate disclosure. Please allow a
reasonable window to release a fix before any public disclosure.

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
names/descriptions — so they are not stored in the clear.

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

## Update check (opt-in phone-home)

The optional update check (`UPDATE_CHECK_ENABLED=true`, **default off**) makes an outbound request
on a configurable interval (`UPDATE_CHECK_INTERVAL_MINUTES`, default 360; a shared cache bounds real
requests to that rate no matter how often the UI polls) to GitHub's public API (`api.github.com` /
`raw.githubusercontent.com`) to learn the latest published version. It sends **no** instance identifier, account data, version,
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
