"""Which sink a decrypted download is written to, and who got to decide.

Two modes, and the difference is what reaches the disk before the object has authenticated:

* ``buffered`` — the page accumulates decrypted records and hands the browser one finished file.
  Nothing appears in Downloads until the whole object verifies. Costs about one copy of the file,
  so a file larger than the tab can hold fails.
* ``streaming`` — the page writes records into an open download as they arrive. Memory stays flat,
  so size stops being a limit, but a failed transfer can leave a partial file that neither the page
  nor the server can remove. A page cannot delete anything from Downloads; there is no API for it.

The organisation decides, or delegates. A user preference may choose only within what the
organisation allows and can never widen it — which is the direction that matters, because the
restrictive value is the one a tenant sets deliberately.

Pure and dependency-free on purpose: the precedence rule is the part worth testing exhaustively,
and it should be testable without a database, a request, or a running deployment.
"""
from __future__ import annotations

#: What the page does with decrypted bytes.
BUFFERED = "buffered"
STREAMING = "streaming"

#: What an organisation may set. ``USER_CHOICE`` delegates to the per-user preference.
USER_CHOICE = "user_choice"

ORG_POLICIES = frozenset({BUFFERED, STREAMING, USER_CHOICE})
USER_PREFERENCES = frozenset({BUFFERED, STREAMING})

#: Chosen so the shipped defaults reproduce today's behaviour exactly: the organisation delegates,
#: the user has expressed nothing, and the result is the buffered path that already ships. Nobody
#: gets bytes on disk early until somebody asks for it.
DEFAULT_ORG_POLICY = USER_CHOICE
DEFAULT_USER_PREFERENCE = BUFFERED


def resolve_download_sink(org_policy, user_preference, *, secure_context: bool = True) -> str:
    """The mode a download should actually use.

    ``secure_context`` is not a preference. A service worker cannot be registered outside a secure
    context, so streaming is unavailable over plain HTTP on a LAN address however the policy reads.
    Reporting ``streaming`` there would promise something the browser will refuse, so it resolves to
    ``buffered`` and the caller does not have to special-case it.

    Unrecognised values fall back to the default rather than raising. This is read on a request
    path, and a settings row written by an older or newer build must not make downloads fail; the
    write path validates, which is where a bad value should be refused.
    """
    # `in` on a frozenset raises for an unhashable value, so a settings row holding a list or a
    # dict would crash the download rather than fall back -- which is the opposite of what this
    # function promises. The type check comes first for that reason, not for tidiness.
    org = (org_policy if isinstance(org_policy, str) and org_policy in ORG_POLICIES
           else DEFAULT_ORG_POLICY)

    if org == USER_CHOICE:
        chosen = (user_preference
                  if isinstance(user_preference, str) and user_preference in USER_PREFERENCES
                  else DEFAULT_USER_PREFERENCE)
    else:
        # The organisation named a mode. A user preference is not consulted at all -- not
        # preferred, not merged, not used as a tie-break -- because "may only narrow" is easy to
        # write as a comparison and easy to get backwards.
        chosen = org

    if chosen == STREAMING and not secure_context:
        return BUFFERED
    return chosen


def describe_download_sink(org_policy, user_preference, *, secure_context: bool = True) -> dict:
    """The resolved mode plus why, for a client that has to explain itself to a person.

    ``reason`` distinguishes the three ways ``buffered`` can happen, which look identical from the
    outside and mean very different things: the organisation required it, the user chose it, or the
    browser cannot do anything else here.
    """
    resolved = resolve_download_sink(org_policy, user_preference, secure_context=secure_context)
    org = (org_policy if isinstance(org_policy, str) and org_policy in ORG_POLICIES
           else DEFAULT_ORG_POLICY)

    if resolved == BUFFERED and org != BUFFERED and not secure_context:
        reason = "insecure_context"
    elif org != USER_CHOICE:
        reason = "organisation"
    else:
        reason = "user"

    return {
        "sink": resolved,
        "reason": reason,
        "org_policy": org,
        "user_may_choose": org == USER_CHOICE,
    }
