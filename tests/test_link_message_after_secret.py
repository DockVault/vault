"""A file link's or note link's message is shown only to someone who has its PIN or password, offline.

The owner's message is part of what the link opens. On a link with a PIN or password, every answer given
before the right one (the prompt, a wrong one, a lockout) is a refusal that names what to enter and nothing
else; the message comes in the answer that follows the right PIN or password. The live and browser tests
(test_api_link_message_after_secret.py, test_ui_link_message_after_secret.py) prove it on a running stack.
"""
import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SOURCE = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8")


def _function(name):
    return next(n for n in ast.walk(ast.parse(SOURCE))
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)


def _secret_block(route):
    """The `if link.secret_kind != "none":` block of the redeem route: what is answered before the secret."""
    blocks = [n for n in ast.walk(_function(route)) if isinstance(n, ast.If)
              and ast.unparse(n.test) == "link.secret_kind != 'none'"]
    assert len(blocks) == 1, route
    return blocks[0]


@pytest.mark.parametrize("route", ["redeem_public_link", "redeem_note_link"])
def test_every_answer_before_the_secret_is_a_refusal_without_the_message(route):
    block = _secret_block(route)
    assert not [n for n in ast.walk(block) if isinstance(n, ast.Return)], f"{route} answers inside the secret check"
    raised = [n for n in ast.walk(block) if isinstance(n, ast.Raise)]
    assert len(raised) >= 3, route
    for r in raised:
        assert "message" not in ast.unparse(r), f"{route}: {ast.unparse(r)}"
    details = [ast.unparse(k) for n in ast.walk(block) if isinstance(n, ast.keyword) and n.arg == "detail"
               and isinstance(n.value, ast.Dict) for k in n.value.keys]
    assert sorted(set(details)) == ["'error'", "'secret_kind'"], details


@pytest.mark.parametrize("route", ["redeem_public_link", "redeem_note_link"])
def test_the_message_is_answered_only_after_the_secret_block(route):
    fn = _function(route)
    block = _secret_block(route)
    late = [n for n in ast.walk(fn) if isinstance(n, ast.Dict)
            and any(isinstance(k, ast.Constant) and k.value == "message" for k in n.keys)]
    assert late, route
    for d in late:
        # A peek of a link with no secret answers the message too; it sits after the secret block as well.
        assert d.lineno > block.end_lineno, f"{route}: a message at line {d.lineno} is before the secret check"
