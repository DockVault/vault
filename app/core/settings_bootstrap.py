"""What a FRESH deployment's settings start as — decided here, applied by the API's startup.

Split out for the same reason ``admin_bootstrap`` is: the decision is side-effect-free and therefore
testable, while the database work stays in the caller. Importing the API module pulls in the whole
runtime bootstrap and exits when no secrets are configured, so logic that lives there cannot be
covered by a unit test at all.

THE POINT OF SEEDING RATHER THAN CHANGING DEFAULTS
--------------------------------------------------
Each feature below ships OFF in code, and stays off. Turning them on by changing the code default —
``.get(key, False)`` to ``.get(key, True)`` — would switch them on for every EXISTING deployment that
had merely never saved the key. Someone's server would begin accepting anonymous uploads because they
ran an upgrade.

It would also be invisible to the check meant to police it: a settings-blob diff across an upgrade
would show nothing, because nothing in the blob would have changed. The behaviour would have moved
and the data would not.

So the defaults stay off and a brand-new deployment gets the keys WRITTEN instead. "Brand-new" is not
inferred: the admin bootstrap reports ``seeded`` only when it has just created the first admin on an
empty database.
"""

from __future__ import annotations

# The status ``admin_bootstrap.bootstrap_admin`` returns when, and only when, it created the first
# admin on an empty database. Anything else — already-bootstrapped, marked-existing, no-password,
# error — is a deployment that existed before this run.
FRESH_BOOTSTRAP_STATUS = "seeded"

FRESH_INSTALL_SETTINGS = {
    "temp_passcodes_enabled": True,      # issuing temporary vault passcodes
    "public_receivers_enabled": True,    # upload links (drop vaults)
    "public_file_links_enabled": True,   # public links may target files and folders, not notes alone
}


def should_seed_settings(bootstrap_status) -> bool:
    """Only a deployment that did not exist before this run."""
    return bootstrap_status == FRESH_BOOTSTRAP_STATUS


def settings_to_add(blob) -> dict:
    """The fresh-install keys this blob does not already carry.

    A key that is present is never returned, whatever its value: an operator who explicitly turned a
    feature off, or pre-seeded a blob, keeps their choice. Empty dict means there is nothing to write,
    which the caller treats as "do not touch the row at all".
    """
    existing = blob or {}
    return {k: v for k, v in FRESH_INSTALL_SETTINGS.items() if k not in existing}
