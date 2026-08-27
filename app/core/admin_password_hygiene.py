"""Drop the first-admin bootstrap password once it has been spent.

ADMIN_PASSWORD is only ever needed once: to seed the FIRST admin (see app.core.admin_bootstrap,
which records an ``admin_bootstrap`` marker after that happens exactly once per deployment). Keeping
it afterwards -- in a plaintext .env, a mounted secret file, or the process environment -- is a
standing liability: anyone who can read the deployment's environment then holds the initial admin's
password.

Once the admin is bootstrapped, drop the spent password:
  * remove a writable mounted ``ADMIN_PASSWORD_FILE`` (the secret leaves the mount -- this is the
    persistent, on-disk copy, and the one that matters);
  * drop ADMIN_PASSWORD / ADMIN_PASSWORD_FILE from THIS process's ``os.environ`` (defense in depth --
    application code and any later-spawned child process no longer see it; this does not rewrite the
    kernel's /proc/self/environ snapshot, fixed at exec, nor the already-loaded ``settings`` copy,
    which stays resident in process memory for its lifetime -- the persistent on-disk source is the
    copy that matters and the one this removes); and
  * warn about a source this process cannot remove (a plaintext .env value, or a read-only mount) so
    the operator removes it.

Importing this module is inert. It never raises -- credential hygiene must never break boot.

Re-provisioning trade-off: a deployment later reset to a FRESH database (no admin, marker gone) must
re-supply ADMIN_PASSWORD to bootstrap a new admin. Re-supplying a bootstrap secret for a fresh
deployment is the correct posture, and the management tool re-writes it as part of a reset.
"""
import os

# bootstrap_admin() statuses that mean an admin now exists and the marker is set, so the bootstrap
# password is spent. "no-password"/"error" mean no admin was seeded this boot -- a later boot may
# still need the password, so those are left untouched.
_BOOTSTRAPPED = frozenset({"seeded", "already-bootstrapped", "marked-existing"})


def scrub_bootstrap_password_source(bootstrap_status, *, environ=None):
    """Drop a spent ADMIN_PASSWORD after the admin is bootstrapped.

    Returns a short status string (for logs and tests):
      ``kept-not-bootstrapped`` - no admin was bootstrapped this boot; the password is left in place.
      ``absent``                - nothing to drop (no ADMIN_PASSWORD / ADMIN_PASSWORD_FILE set).
      ``file-removed``          - a mounted ADMIN_PASSWORD_FILE was removed and the env cleared.
      ``warned``                - the source could not be removed (plaintext .env / read-only mount);
                                  the env value was cleared and the operator was warned to remove it.
      ``cleared-env-only``      - only the process environment carried it (e.g. a file already gone).
    Never raises.
    """
    env = environ if environ is not None else os.environ
    if bootstrap_status not in _BOOTSTRAPPED:
        return "kept-not-bootstrapped"

    file_path = env.get("ADMIN_PASSWORD_FILE")
    had_value = bool((env.get("ADMIN_PASSWORD") or "").strip())
    if not had_value and not file_path:
        return "absent"

    removed_file = False
    if file_path:
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
                removed_file = True
        except OSError as exc:
            # A read-only mount (e.g. a Kubernetes secret) or a permission error. Never echo the
            # file's CONTENTS; the path/error is safe.
            print(f"⚠ ADMIN_PASSWORD file could not be removed ({exc}); remove it manually -- "
                  "the admin is already bootstrapped and it is no longer needed")

    # Defense in depth: drop the spent value from THIS process's environment.
    env.pop("ADMIN_PASSWORD", None)
    env.pop("ADMIN_PASSWORD_FILE", None)

    if removed_file:
        print("[OK] Dropped the spent bootstrap password: removed its mounted ADMIN_PASSWORD file "
              "(the admin is already bootstrapped)")
        return "file-removed"
    if had_value:
        print("⚠ ADMIN_PASSWORD is still configured but the admin is already bootstrapped; it is "
              "no longer needed. Remove it from your .env / secret file so a plaintext admin password "
              "is not retained.")
        return "warned"
    return "cleared-env-only"
