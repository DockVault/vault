#!/usr/bin/env python3
"""Read a running deployment's identity so a setup scenario can prove continuity.

Prints one canonical JSON line: health, the sorted vault ids, and the sorted usernames. Two runs
that print the same line describe the same deployment — which is the whole question the setup
matrix asks about re-running setup over existing data.

Deliberately talks to the deployed API rather than to Postgres: that is the surface a user would
notice losing, and it proves the app can still decrypt what the volume holds rather than merely
that rows survived.

The deployment serves HTTPS with the certificate setup generated, so this pins THAT certificate as
the only trust anchor (certs/cert.pem by default) rather than switching verification off. A
scenario that silently started serving a different certificate should fail here, not pass.

``--identity-only`` omits health from the printed line, for the one comparison where including
it would be wrong: a profile transition. Health describes the TOPOLOGY a deployment is running
under — combined serves SFTP from the web container, split from its own — so demanding a
byte-identical health payload across a combined/split change asserts that the topology did not
change, which is the opposite of what those scenarios do. Identity (vaults, users) is what has
to survive; the caller asserts health separately, on its own terms. Health is still READ in this
mode, so a deployment that cannot answer /health still fails here.

Usage:  deployment_state.py [--identity-only] <base-url> <admin-user> <admin-password> [cert-path]
Exits non-zero (with the reason on stderr) if the deployment cannot be read.
"""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

DEFAULT_CERT = os.path.join("certs", "cert.pem")


def build_context(cert_path):
    ctx = ssl.create_default_context(cafile=cert_path)
    # The generated certificate is self-signed for the server name, so it is its own issuer and
    # carries no CA basic-constraint. Trusting it as an anchor is the point; the hostname check
    # below still has to pass.
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


def call(base, path, ctx, payload=None, token=None):
    req = urllib.request.Request(base + path, method="POST" if payload is not None else "GET")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    body = json.dumps(payload).encode() if payload is not None else None
    with urllib.request.urlopen(req, body, timeout=30, context=ctx) as resp:
        return json.load(resp)


def main(argv):
    flags = [a for a in argv[1:] if a.startswith("--")]
    positional = [a for a in argv if not a.startswith("--")]
    identity_only = "--identity-only" in flags
    if set(flags) - {"--identity-only"} or not 4 <= len(positional) <= 5:
        print(__doc__, file=sys.stderr)
        return 2
    base, user, password = positional[1].rstrip("/"), positional[2], positional[3]
    cert_path = positional[4] if len(positional) == 5 else DEFAULT_CERT
    if not os.path.exists(cert_path):
        print(f"no certificate to trust at {cert_path}; setup should have written one",
              file=sys.stderr)
        return 1
    ctx = build_context(cert_path)
    try:
        health = call(base, "/health", ctx)
        token = call(base, "/auth/login", ctx, {"username": user, "password": password})["access_token"]
        vaults = sorted(v["id"] for v in call(base, "/vaults", ctx, token=token))
        users = sorted(u["username"] for u in call(base, "/users", ctx, token=token))
    except (urllib.error.URLError, urllib.error.HTTPError, ssl.SSLError, KeyError, ValueError) as exc:
        print(f"could not read the deployment at {base}: {exc}", file=sys.stderr)
        return 1
    # sort_keys so two runs are byte-comparable with plain diff
    state = {"vault_ids": vaults, "users": users}
    if not identity_only:
        state["health"] = health
    print(json.dumps(state, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
