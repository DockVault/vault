"""Every step that finishes stored bytes inside an async handler is handed to app/core/off_loop.py, offline.

Blocking work in an async handler holds every other request until it ends. Each step listed here reads,
encrypts, writes or syncs a whole file, or removes one, so it runs off the event loop instead: handed to
off_loop.run_to_end, or, when it uses the request's database session, to off_loop.run_to_end_on_session with
that session, which rolls the session back when the step fails. A step called in the handler itself runs on
the loop again; a step that uses the session and is handed to run_to_end keeps a failed step's row locks while
the request handles the error. Only the slowest of these (a resumable upload's completion, a copy to another
vault) shows on a running stack, where tests/test_upload_completion_answers_others_live.py measures them, so
this reads the source for all of them.
"""
import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
API = "app/api/api_server.py"
CHUNKS = "app/core/upload_chunk_crypto.py"

PLAIN, ON_SESSION = "run_to_end", "run_to_end_on_session"

# (file, the async function, the step as it is written there, what it is handed to)
STEPS = [
    (API, "upload_brand_asset", "_write_image", PLAIN),
    (API, "receiver_complete_upload", "_assemble", ON_SESSION),
    (API, "receiver_complete_upload", "_record", ON_SESSION),
    (API, "receiver_complete_upload", "vault_service._remove_blobs", ON_SESSION),
    (API, "_complete_chunked_upload", "_assemble", ON_SESSION),
    (API, "_complete_chunked_upload", "_record", ON_SESSION),
    (API, "_complete_chunked_upload", "vault_service._remove_blobs", ON_SESSION),
    (API, "upload_file", "vault_service.upload_file_streaming", ON_SESSION),
    (API, "upload_file", "ctx.write_chunk", PLAIN),
    (API, "upload_file", "ctx.sync_written", PLAIN),
    (API, "upload_file", "vault_service.finalize_streaming_upload", ON_SESSION),
    (API, "copy_file_endpoint", "vault_service.copy_file", ON_SESSION),
    (API, "move_file_endpoint", "vault_service.move_file", ON_SESSION),
    (API, "copy_folder_endpoint", "vault_service.copy_folder", ON_SESSION),
    (CHUNKS, "seal_stream_to_file", "durable_write.sync_file", PLAIN),
]


def _async_function(source, name):
    found = [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.AsyncFunctionDef) and n.name == name]
    assert len(found) == 1, f"expected one async function {name}, found {len(found)}"
    return found[0]


def _on_the_loop(node):
    """The nodes of ``node`` that run on the event loop: all of it but the synchronous functions defined in it,
    which run where they are handed (an async function defined in it runs on the loop, and is kept)."""
    out = []
    stack = list(ast.iter_child_nodes(node))
    while stack:
        child = stack.pop()
        if isinstance(child, (ast.FunctionDef, ast.Lambda)):
            continue
        out.append(child)
        stack.extend(ast.iter_child_nodes(child))
    return out


def _off_loop_calls(node, helper):
    return [c for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
            and c.func.attr == helper and isinstance(c.func.value, ast.Name) and c.func.value.id == "off_loop"]


def handed(node, step, helper):
    """The calls in ``node`` that hand ``step`` to off_loop's ``helper`` (with the session ``db`` first, for
    run_to_end_on_session)."""
    out = []
    for call in _off_loop_calls(node, helper):
        if helper == ON_SESSION:
            if len(call.args) > 1 and ast.unparse(call.args[0]) == "db" and ast.unparse(call.args[1]) == step:
                out.append(call)
        elif call.args and ast.unparse(call.args[0]) == step:
            out.append(call)
    return out


def called_on_the_loop(node, step):
    return [c for c in _on_the_loop(node) if isinstance(c, ast.Call) and ast.unparse(c.func) == step]


@pytest.mark.parametrize("path, function, step, helper", STEPS,
                         ids=[f"{function}:{step}" for _, function, step, _h in STEPS])
def test_each_step_is_handed_off_the_loop_and_never_run_on_it(path, function, step, helper):
    node = _async_function((ROOT / path).read_text(encoding="utf-8"), function)
    assert handed(node, step, helper), f"{function}: {step} is not handed to off_loop.{helper}"
    other = PLAIN if helper == ON_SESSION else ON_SESSION
    assert not [c for c in _off_loop_calls(node, other) if step in map(ast.unparse, c.args[:2])], (
        f"{function}: {step} is handed to off_loop.{other}, not off_loop.{helper}")
    assert not called_on_the_loop(node, step), f"{function}: {step} is called on the event loop"


def test_the_reading_finds_a_step_run_on_the_loop_or_handed_to_the_wrong_helper():
    source = (
        "async def h(db, vault_service):\n"
        "    def _record():\n"
        "        return vault_service.finalize_streaming_upload(1)\n"
        "    async def _cleanup():\n"
        "        vault_service._remove_blobs([1])\n"
        "    vault_service.copy_file(1)\n"
        "    await off_loop.run_to_end(vault_service.move_file, 1)\n"
        "    await off_loop.run_to_end_on_session(db, _record)\n"
        "    await off_loop.run_to_end_on_session(other, vault_service.copy_folder)\n")
    node = _async_function(source, "h")
    assert called_on_the_loop(node, "vault_service.copy_file")
    assert called_on_the_loop(node, "vault_service._remove_blobs"), "an async function defined inside runs on the loop"
    assert not called_on_the_loop(node, "vault_service.finalize_streaming_upload"), "a handed function runs off it"
    assert handed(node, "_record", ON_SESSION)
    assert handed(node, "vault_service.move_file", PLAIN) and not handed(node, "vault_service.move_file", ON_SESSION)
    assert not handed(node, "vault_service.copy_folder", ON_SESSION), "handed with another session than the request's"
