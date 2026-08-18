"""Reading values out of the shipped application source, for tests that assert on call sites.

Some of what the version-2 wraps depend on cannot be checked any other way. The three write sites
are dead while the writer is gated off, so no test can execute them, and a wrong argument there
produces a wrap that is perfectly well formed and opens for nobody -- surfacing only for whoever
enables the writer first.

Asserting on source text is a blunt instrument and it was used bluntly: the first version of these
checks asked whether the call CONTAINED `"dekEpoch: 1"`, which is also true of `dekEpoch: 10`. Every
correct value in these transcripts is a prefix of a plausible wrong one -- `userId` of
`userIdOfSharer`, `uid` of `uidBeingRemoved`, `payload.id` of `payload.idOfSomething` -- so seven
wrong values passed while four harmless refactors failed. A test shaped that way is shaped by the
mistakes someone imagined rather than by the values that are correct.

Reading to the delimiter fixes both directions, and lives here so the direct and team wrap tests
cannot drift apart in what they consider an assertion.
"""

from __future__ import annotations

import re
from pathlib import Path

APP_JS = Path(__file__).resolve().parents[1] / "static" / "js" / "app.js"


def call_text(source: str, fn: str, after: int = 0) -> tuple[str, int]:
    """The text of one `await <fn>(...)` CALL, and the offset it started at.

    Anchored on the call rather than the bare name: matching the name alone finds the function's own
    declaration first, and asserting against a signature proves nothing about any caller.
    """
    i = source.index("await " + fn, after)
    return source[i:source.index(";", i)], i


def positional_arg(call: str, index: int) -> str:
    """The `index`-th positional argument of a call, whitespace-normalised.

    The transcript literal is only half of what a wrap site decides. The other half is the public
    key it seals to, which is a positional argument -- and reading only the literal leaves the
    argument that determines WHO CAN DECRYPT unasserted. Sealing a team private key to the team's
    own public key instead of the member's produces a perfectly well-formed wrap that no member's
    key will ever open, and it is one token away from correct.

    Splits on top-level commas so a nested call or object in an earlier argument does not shift the
    count.
    """
    open_paren = call.index("(")
    depth = 0
    args, current = [], []
    for ch in call[open_paren + 1:]:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(current))
            current = []
            continue
        current.append(ch)
    args.append("".join(current))
    if index >= len(args):
        raise AssertionError(
            f"the call has {len(args)} arguments, not {index + 1}: {' '.join(call.split())}")
    return " ".join(args[index].split())


def bound_value(call: str, field: str) -> str:
    """The exact value bound to `field` in a transcript literal, whitespace-normalised.

    Handles the two ways a property is written -- `{ vaultId: x }` and the shorthand `{ vaultId }`,
    which binds the local of the same name and is a real binding, not an absent one -- and tolerates
    a redundant outer parenthesis, since failing on that would make this a test of formatting.
    """
    # Scoped to the LAST object literal in the call -- the transcript -- rather than the first
    # occurrence anywhere in it. An earlier argument containing a same-named property would
    # otherwise mask the value that is actually bound.
    brace = call.rfind("{")
    scope = call[brace:] if brace != -1 else call
    marker = field + ":"
    if marker not in scope:
        if re.search(r"[{,]\s*" + re.escape(field) + r"\s*[,}]", scope):
            return field
        raise AssertionError(
            f"{field} is not bound at this call site at all: {' '.join(call.split())}")
    i = scope.index(marker) + len(marker)
    end = min(
        (pos for pos in (scope.find(",", i), scope.find("}", i)) if pos != -1),
        default=len(scope),
    )
    value = " ".join(scope[i:end].split())
    # An inline comment is the same value written differently, exactly as a redundant
    # paren is, so it is normalised away rather than treated as a difference.
    value = re.sub(r"/\*.*?\*/", " ", value)
    value = " ".join(value.split())
    while value.startswith("(") and value.endswith(")"):
        value = value[1:-1].strip()
    return value
