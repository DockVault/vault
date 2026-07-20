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

- `./setup-secure.sh` + `deploy/docker-compose.secure.yml` — TLS-only, non-root, read-only
  container, the generated `.env` secrets file written at mode `600`, and the
  database/Redis never published to the host. (On rootless / user-namespace-remapped
  engines the TLS private key may be widened to `644` so the remapped container user can
  read it — the installer warns when it does this; keep such hosts single-tenant.)
- Set your **own** strong secrets in `.env`; never reuse the placeholders in
  `.env.example`. The application refuses to boot with placeholder secrets in production.
- Always run behind TLS. Do not expose the plaintext HTTP listener to an untrusted
  network.

## Credentials and repository history

**Any credential value that appears anywhere in this repository's git history is a
non-production development fixture.** Such values have been removed from the current
tree, are treated as invalid, and have been rotated where they were ever used. They must
never be used to access any instance.

- Never copy a password, key, or token out of this repository — its working tree **or**
  its history — into a real deployment.
- Every install generates its own secrets (`./setup-secure.sh` does this for you;
  `.env.example` ships only non-functional placeholders).

If you believe a credential found in this repository is, or ever was, valid against a
real instance, please report it through the private channel above so we can confirm it
has been rotated.
