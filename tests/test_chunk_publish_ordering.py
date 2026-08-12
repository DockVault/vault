"""The chunk and its digest are published while the session row is locked.

A chunk is renamed into place and its digest is written next to it -- two filesystem operations. Two
requests at one index can finish them interleaved (rename A, rename B, digest B, digest A) and leave
one request's bytes under the other's digest, which is the value a resuming client compares its own
copy against. Doing both under the per-session `SELECT ... FOR UPDATE` that already serializes the
counter update closes that, because the only writers that can collide are other requests in the same
session.

This is a structural check rather than a behavioural one, deliberately and with a reason. The window
is a few microseconds between two local filesystem calls; six concurrent same-index uploads at three
different timings did not hit it against a build with the publish moved back outside the lock, so a
test claiming to cover it behaviourally would be claiming more than it does. What this can do is
fail if the publish is ever moved back out, which is the realistic way the property gets lost.

It reads the source rather than importing it -- `app.api.api_server` builds the application at
import and is not loadable in an offline lane.
"""

import ast
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit

HANDLER = "upload_chunk"
SOURCE = Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py"


def _handler_body():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == HANDLER:
            return node
    pytest.fail(f"{HANDLER} not found in {SOURCE.name} -- this test is anchored to the wrong name")


def _line_of(node, predicate):
    """First line inside `node` whose expression tree satisfies `predicate`."""
    for child in ast.walk(node):
        if predicate(child):
            return child.lineno
    return None


def _is_call_to(node, attr):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == attr)


def test_the_chunk_is_published_while_the_session_row_is_locked():
    handler = _handler_body()

    lock_line = _line_of(handler, lambda n: _is_call_to(n, "with_for_update"))
    publish_line = _line_of(
        handler,
        lambda n: (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and n.func.attr == "replace"
                   and isinstance(n.func.value, ast.Name) and n.func.value.id == "os"))
    commit_line = _line_of(handler, lambda n: _is_call_to(n, "commit"))

    assert lock_line is not None, "the session row is no longer locked in this handler"
    assert publish_line is not None, "no os.replace -- the chunk is published some other way now"
    assert commit_line is not None, "the handler no longer commits, so there is no lock to be under"

    assert lock_line < publish_line < commit_line, (
        f"the chunk is published at line {publish_line}, outside the session lock "
        f"(acquired at {lock_line}, released by the commit at {commit_line}). Two requests at one "
        "index can then leave one request's bytes under the other's digest.")


def test_the_digest_is_written_in_the_same_locked_region():
    """Writing the chunk under the lock and its digest after it would rebuild the same gap."""
    handler = _handler_body()

    lock_line = _line_of(handler, lambda n: _is_call_to(n, "with_for_update"))
    digest_line = _line_of(handler, lambda n: _is_call_to(n, "write_text"))
    commit_line = _line_of(handler, lambda n: _is_call_to(n, "commit"))

    assert digest_line is not None, "the chunk digest is no longer written by this handler"
    assert lock_line < digest_line < commit_line, (
        f"the digest is written at line {digest_line}, outside the session lock "
        f"(acquired at {lock_line}, released by the commit at {commit_line})")
