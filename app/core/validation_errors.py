"""What a 422 tells the caller: where its input was wrong and why, never the input itself.

The framework's default 422 repeats every rejected value back to the sender ("input"), along with a
"ctx" that can hold the validator's own exception. For a sign-in that echoes a password typed into
the username field; for a large body it serializes the whole body a second time, on the event loop.
This keeps each error's type, location and message and drops everything else, and it bounds how many
errors are returned and how long a location part or a message may be (a location can name a key the
sender chose).
"""
from typing import Any, Dict, List, Sequence

MAX_ERRORS = 20
MAX_LOC_PART = 128
MAX_MESSAGE = 500


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def public_validation_errors(errors: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The errors a 422 may return: [{"type", "loc", "msg"}], at most MAX_ERRORS of them."""
    out = []
    for err in errors[:MAX_ERRORS]:
        loc = []
        for part in err.get("loc") or ():
            if isinstance(part, int) and not isinstance(part, bool):
                loc.append(part)
            else:
                loc.append(_clip(str(part), MAX_LOC_PART))
        out.append({"type": _clip(str(err.get("type") or ""), MAX_LOC_PART),
                    "loc": loc,
                    "msg": _clip(str(err.get("msg") or ""), MAX_MESSAGE)})
    return out
