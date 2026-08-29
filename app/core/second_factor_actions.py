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
    ("public_link.create",             "Create a public note link",                False),
    ("temp_credential.create",         "Mint a temporary credential",              False),
    ("admin.user.manage",             "Manage users (create / edit / delete / invite)", False),
    ("admin.settings.write",           "Change organization settings",             False),
]

# Fast lookups.
ACTION_KEYS = [k for (k, _n, _o) in SECOND_FACTOR_ACTIONS]
ACTION_META = {k: {"name": n, "default_require_otp": o} for (k, n, o) in SECOND_FACTOR_ACTIONS}

# Actions that are NEVER a no-op even when the second factor is not "in effect" for the caller: an
# admin-management or settings-write route must always demand a re-authentication, so a freshly minted
# (factor-less) admin session cannot act on the matrix. See spec 5.3.
ADMIN_ALWAYS_ENFORCED = {"admin.user.manage", "admin.settings.write"}


def is_admin_action(key: str) -> bool:
    return key in ADMIN_ALWAYS_ENFORCED
