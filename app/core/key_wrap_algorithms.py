"""The vocabulary of key-wrapping algorithm labels, and the only place that owns it.

`VaultMemberKey.wrapping_algorithm` looks like metadata. It is not. It is the **only**
discriminator between two completely different kinds of row that share one table:

  * a *direct DEK* wrap  — the vault's data key, wrapped to one member, keyed by DEK epoch;
  * a *team private* wrap — the team keypair's private half, wrapped to one member, keyed by
    the entirely separate TEAM epoch.

The two live on different version axes, so mixing them up does not merely mislabel a row: it
applies one axis's floor to the other axis's rows. That is why every query that touches this
table pairs the label with a `key_version`, and why the stale-key prune's `db.delete()` filters
on it. A row the filters do not match is not "uncategorised" — it is invisible to revocation.

**Why a set per kind rather than a constant.** The v2 envelope work introduces a second
generation of labels for the same two kinds. A writer that emits a new label while the server
still compares against one string does not fail loudly; it fails in six quiet ways, and the
worst of them is silent: `_team_rotation_owed` stops seeing a deactivated member, so the
server stops *requiring* the team-keypair rotation that actually revokes them, and a cheap
DEK-only rotation is accepted instead. The removed member's retained team private key unwraps
the new DEK. Revocation reports success and does nothing.

So the widening has to land **before** any writer exists, not alongside it. This module is
that widening: membership tests, not equality tests, over a vocabulary declared once.

**The canonical constants are what we WRITE; the sets are what we ACCEPT.** New rows keep
using generation 1 until a v2 writer ships. Turning that on is a one-line change here, and it
cannot be done in one place and forgotten in another, because there is only one place.

**Registering a label into the prune is a claim about epochs, not just a name.** The stale-key
prune compares `key_version` against a floor chosen per kind. Adding a label to one of these sets
therefore asserts that rows carrying it sit on that kind's epoch axis and may be *deleted* by that
kind's floor. That is a stronger statement than "this reader should accept it", and it is why the
v2 labels are declared here rather than being invented at the call site: a future generation that
changes the versioning scheme must revisit these sets before it ships a writer, not after.

**On the model's column default.** `VaultMemberKey.wrapping_algorithm` defaults to
`'ECDH-AES-256-GCM'`. That default is not hypothetical — rows written before the labels became
explicit carry it, which is why `get_vault_keys`' direct read path deliberately applies no
algorithm filter. It is a direct-DEK wrap, and it is registered as one; leaving it unrecognised
would make the prune's unclassified count non-zero forever on any deployment old enough to have
one, which is a tripwire nobody would keep listening to.

The risk that motivated leaving it unrecognised — an omitted field quietly becoming a
*confidently misclassified* row — is real, but a permanently-firing alarm is the wrong instrument
against it. Omission is guarded where it happens instead: a test asserts every construction of a
`VaultMemberKey` passes the field explicitly.
"""

# --- generation 1: shipped, and what every current row carries -------------------------------
DIRECT_DEK_ALGO_V1 = 'ECDH-P384-AES-KW'
TEAMPRIV_ALGO_V1 = 'ECDH-P384-AES-GCM-TEAMPRIV'

# Rows predating the explicit labels carry the model's column default. They are direct-DEK
# wraps in direct vaults -- the read path at `get_vault_keys` skips the algorithm filter
# precisely so it does not exclude them. Classifying them is what keeps the prune's
# unclassified tripwire silent on an ordinary old deployment.
DIRECT_DEK_ALGO_LEGACY = 'ECDH-AES-256-GCM'

# --- generation 2: reserved by the v2 envelope grammar, not yet written by anything -----------
# Declared here ahead of the writer on purpose. The queries below must already accept these on
# the day the first one appears, because the failure mode of a late widening is silent.
DIRECT_DEK_ALGO_V2 = 'ECDH-P384-AES-GCM-DIRECT-V2'
TEAMPRIV_ALGO_V2 = 'ECDH-P384-AES-GCM-TEAMPRIV-V2'

# --- what we accept --------------------------------------------------------------------------
DIRECT_DEK_ALGOS = frozenset({DIRECT_DEK_ALGO_LEGACY, DIRECT_DEK_ALGO_V1, DIRECT_DEK_ALGO_V2})
TEAMPRIV_ALGOS = frozenset({TEAMPRIV_ALGO_V1, TEAMPRIV_ALGO_V2})
ALL_KNOWN_ALGOS = DIRECT_DEK_ALGOS | TEAMPRIV_ALGOS

# The two kinds must never share a label; if they did, one filter would match the other's rows
# and the prune would apply the wrong epoch floor to them.
assert not (DIRECT_DEK_ALGOS & TEAMPRIV_ALGOS), "a label cannot name both kinds of wrap"

# --- what we write ----------------------------------------------------------------------------
DIRECT_DEK_ALGO = DIRECT_DEK_ALGO_V1
TEAMPRIV_ALGO = TEAMPRIV_ALGO_V1


def is_direct_dek(label) -> bool:
    """True if `label` names a direct-DEK wrap of any generation."""
    return label in DIRECT_DEK_ALGOS


def is_teampriv(label) -> bool:
    """True if `label` names a team-private wrap of any generation."""
    return label in TEAMPRIV_ALGOS


def classify(label):
    """Return `'direct'`, `'teampriv'`, or `None` for a label this build does not know.

    `None` is a real answer, not an error: a row written by a newer build is exactly the case
    this module exists to keep visible. Callers must decide what to do about it rather than
    letting it fall through a filter unnoticed.
    """
    if label in DIRECT_DEK_ALGOS:
        return 'direct'
    if label in TEAMPRIV_ALGOS:
        return 'teampriv'
    return None
