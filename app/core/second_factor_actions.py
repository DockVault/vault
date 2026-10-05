"""The second-factor action catalog: the stable set of high-risk actions an admin can gate behind a
step-up, shaped like email_actions' metadata. Seeded into `second_factor_actions` at boot (one row per
key); code owns the keys + the defaults, the admin owns the per-row toggles.

Each action carries TWO independent admin toggles (the owner's model, a deliberate divergence from the
design spec's single `require_otp`): `require_otp` (present the OTP second factor) and `require_password`
(re-enter the account password). An admin can set neither / one / both per action.

Extensibility = add a tuple here and (in the step-up phase) a `require_step_up(key)` decorator to the
route. Routes that do not exist yet (an upload-links `receiver.create`, the secure-send `/public-links`
half) are deliberately NOT listed until they ship, so the boot contract that pairs each catalog key with
a guarded route stays satisfiable.
"""

# (key, human name, default require_otp). require_password defaults False for every action. Owner's model
# (B): a fresh deploy forces MFA on NO ONE. require_otp ships ON only where it cannot lock anyone out —
# `login` (an enrolled account presents its factor at sign-in; an un-enrolled one is unaffected) and
# `account.second_factor` (managing your OWN two-factor, whose first enrollment is exempt so an un-enrolled
# user still reaches it). EVERY other action — including admin management — ships OFF; an admin opts each
# one in from the matrix, and turning require_otp on then requires everyone (the admin included) to enroll
# before that action. Because admin management defaults OFF, a fresh admin is never locked out; and because
# changing the MFA config is itself gated by `account.second_factor`, an admin who wants to lock actions
# down enrolls first (via the exempt path) and so always keeps an OTP to reach the matrix and undo it.
SECOND_FACTOR_ACTIONS = [
    ("login",                          "Log in",                                   True),
    ("account.change_password",        "Change your account password",             False),
    ("account.change_email",           "Change your account email",                False),
    ("account.second_factor",          "Manage two-factor / recovery codes",       True),
    ("account.encryption_key.replace", "Replace your account encryption key",       False),
    ("vault.delete",                   "Delete a vault",                            False),
    ("vault.change_password",          "Change a vault password",                   False),
    ("vault.rotate_key",               "Rotate a vault key",                        False),
    ("share.create",                   "Create an internal share",                 False),
    ("public_link.create",             "Create a public link (note or file)",      False),
    ("receiver.create",                "Create an upload link (receiver)",         False),
    ("temp_credential.create",         "Mint a temporary credential",              False),
    ("admin.user.manage",             "Manage users (create / edit / delete / invite)", False),
    ("admin.settings.write",           "Change organization settings",             False),
]

# Fast lookups.
ACTION_KEYS = [k for (k, _n, _o) in SECOND_FACTOR_ACTIONS]
ACTION_META = {k: {"name": n, "default_require_otp": o} for (k, n, o) in SECOND_FACTOR_ACTIONS}

# The admin-plane actions, kept only as a CLASSIFICATION (e.g. to group/label the admin rows in the
# matrix UI). Under the owner's model B these carry NO special "never a no-op" rule — you cannot force
# an admin to own an OTP device, so an admin who has enabled nothing is not gated. `resolve_action_
# requirement` accepts `is_admin_action` but does not act on it; forcing must never be reintroduced here.
ADMIN_ALWAYS_ENFORCED = {"admin.user.manage", "admin.settings.write"}


def is_admin_action(key: str) -> bool:
    return key in ADMIN_ALWAYS_ENFORCED


# Step-ups whose requirement is fixed in code rather than chosen in the admin's matrix: key -> (human name,
# policy), the policy one of second_factor_policy.FIXED_POLICIES. They are kept OUT of SECOND_FACTOR_ACTIONS,
# and so out of the seeded rows and the matrix's toggles, which could otherwise switch them off (every
# catalogued action but signing in and managing your own second factor ships off). The step-up routes accept
# them, with the usual receipt and 403 shape, so the web app's step-up prompt and retry work unchanged. A
# route guards one with app.core.fixed_step_up.guard(key), called inside its body, and the boot contract
# refuses to start while one is guarded by no route.
OWNER_KEY_RESET = "vault.owner_key_reset"
FIXED_STEP_UP_ACTIONS: dict = {
    # A zero-knowledge vault owner's key reset (app/api/ecc_router.py, rekey_vault): whenever the owner has a
    # second factor enrolled, the reset needs it; an account without one is not asked.
    OWNER_KEY_RESET: ("Reset a zero-knowledge vault's key as its owner", "factor_when_enrolled"),
    # How long records are kept (app/api/managed_settings_router.py): the password every time, plus any second
    # factor the account has enrolled, so an install with one administrator and no second factor can still
    # manage it.
    "admin.retention.write": ("Change how long records are kept", "password_always"),
    # What the audit log records of personal data (app/api/recording_levels_router.py): the same policy, since
    # the levels decide what is kept about every user.
    "admin.audit_privacy.write": ("Change what the audit log records", "password_always"),
}

# The steps of compliance access (app/api/compliance_router.py), each under the compliance policy: the password
# and a TOTP or recovery code, every time, whatever the matrix says. An email code never counts (an
# administrator can change the address it goes to), and an account with no TOTP enrollment enrolls first.
COMPLIANCE_STEP_UPS: dict = {
    "compliance.grant.propose": "Propose an auditor grant",
    "compliance.grant.approve": "Approve or turn down an auditor grant",
    "compliance.grant.reconfirm": "Reconfirm your auditor right",
    "compliance.case.request": "Request a compliance case",
    "compliance.case.approve": "Approve, turn down or extend a compliance case",
    "compliance.case.export": "Export files from a compliance case",
    "compliance.hold.place": "Place a legal hold",
    "compliance.hold.decide": "Confirm or release a legal hold",
}
FIXED_STEP_UP_ACTIONS.update({key: (name, "compliance") for key, name in COMPLIANCE_STEP_UPS.items()})


def fixed_policy(key: str):
    """The policy of a fixed step-up, or None for any other key."""
    entry = FIXED_STEP_UP_ACTIONS.get(key)
    return entry[1] if entry else None


def is_step_up_action(key: str) -> bool:
    """A key the step-up routes accept: a catalogued action or a fixed one."""
    return key in ACTION_KEYS or key in FIXED_STEP_UP_ACTIONS
