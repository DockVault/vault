# Supply-chain controls

This document separates controls enforced by this repository from controls that exist only in
GitHub repository settings. The hosted-settings audit below was performed read-only on
2026-07-24 against the public `DockVault/vault` repository. It does not treat a source file as
proof of a hosted setting.

## Enforced in source

- The Alpine Python runtime and the Postgres and Redis Compose sidecars use reviewed, immutable
  multi-architecture manifest-list digests. Their readable tags remain beside the digests so
  Dependabot can propose reviewed updates.
- `requirements.txt` is the human-edited direct production input.
  `requirements.lock` is generated on Python 3.14 with fully resolved versions and package
  hashes. CI removes the existing output before regenerating it, rejects byte drift, installs it
  with `--require-hashes`, runs `pip check`, and audits it without dependency resolution. The
  Dockerfile installs the same lock with hash enforcement.
- A release builds the already-tested commit into a local image before registry authentication.
  It generates an SPDX JSON SBOM and scans that exact local image before login. Only a passing
  image is pushed. Both release tags must resolve to one registry digest, and GitHub attestations
  bind build provenance and the SBOM to that digest. The digest comes from each successful push;
  both push responses and both immediate tag resolutions must agree before it can become an
  attestation subject. The live branch/tag refs are force-fetched and revalidated again
  immediately before registry authentication.
- Release OCI metadata includes the public source URL, semantic version, tested revision, and
  `AGPL-3.0-only` license identifier.
- Dependabot covers the production and test Python manifests, the Dockerfile, both Compose
  variants under `deploy/`, and GitHub Actions.

## Scanner and backport policy

The release gate fails for every unexcepted vulnerability at `high` or `critical` severity,
whether or not the feed advertises a fix. There is no blanket `only-fixed` bypass or global Grype
ignore file.

Python 3.14.6 predates three security fixes which are already merged on CPython's maintained
`3.14` branch. The image replaces `Lib/tarfile.py` and `Lib/html/parser.py` with their exact
versions from CPython commit `07efb08123ba9367a7107325adb9d5626dca1ca9`, which contains the
3.14 backports for `CVE-2026-11940`, `CVE-2026-11972`, and `CVE-2026-15308`. The Docker build
checks the vendored file and PSF-license hashes before copying them over the base standard
library, and removes pip after the locked dependency installation. The file origins and expected
hashes are recorded in `security/cpython-backports/README.md`.

The reviewed OpenVEX template therefore uses `vulnerable_code_not_present` for exactly those three
findings and the `pkg:generic/python@3.14.6` subcomponent. Before the local scan, the workflow
renders it for the tested source revision, the versioned image reference, and the local image
content ID. After push, it overwrites the release asset with the exact registry manifest digest.
Every statement contains both the immutable OCI digest PURL and versioned image reference; the
GitHub Release publishes that rendered VEX beside the SBOM. Any additional exception requires a
source-reviewed template change.
## Hosted settings evidence

| Control | Evidence on 2026-07-24 | Status |
| --- | --- | --- |
| Private vulnerability reporting | The public repository endpoint returned `enabled: true`. | Verified enabled |
| Main branch rules | The public ruleset endpoint returned one active default-branch ruleset. It prevents deletion and non-fast-forward updates. | Verified, limited |
| Required status checks | The public main ruleset contains no required-status-check rule. The classic branch-protection endpoint required authenticated API access, so no second layer could be proven. | Not proven; do not rely on it |
| Tag protection | The public ruleset inventory contains no tag-targeting ruleset, and the legacy tag-protection endpoint returned no configuration. | Not present in public evidence |
| CodeQL/default code scanning | No CodeQL workflow exists in source or in the public workflow inventory. The default-setup endpoint required authenticated API access. | Not proven |
| Secret scanning | The setting is not represented in source and its state was unavailable through the connected repository API. | Not proven |
| Secret-scanning push protection | The setting is not represented in source and its state was unavailable through the connected repository API. | Not proven |
| Dependabot alerts and security updates | Dependabot and dependency-graph workflows are active, but alert/security-update settings required authenticated API access. | Partially evidenced; setting not proven |

Before relying on GitHub as an enforcement boundary, a repository administrator must confirm the
unproven settings in **Settings → Code security** and add reviewed required-check and tag rules.
The release workflow remains fail-closed on its own test gates, but that does not substitute for
protecting `main` and release tags from unrelated writes.
