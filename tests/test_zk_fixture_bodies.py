"""No test fabricates a zero-knowledge upload body the server would refuse.

A zero-knowledge upload declares an attempt token, and the server refuses such a session a first
chunk shorter than 28 bytes -- the smallest real body is a 12-byte nonce plus a 16-byte tag. Test
helpers fabricate bodies, and a short one surfaces as a 409 on the first chunk deep inside a test
about something else. Worse, the API suite stops at its first failure, so ONE short caller hides
every other: that is how a dozen call sites went unnoticed behind the one that sorted first.

The helpers refuse a short body at run time, but those tests need a running stack. This is the
half that needs nothing: every call site that passes a LITERAL body is read from the source and
measured here, in the offline lane.

WHAT THE SCAN BELOW DOES NOT PROVE. For a request body that declares an attempt token, the syntax
tree is read for a call to ``require_zk_first_chunk`` in the enclosing function, placed before the
statement that declares the token. That shows the guard EXISTS and runs FIRST. It does not show
that the guard's argument is the body that then goes out: ``require_zk_first_chunk(b"x" * 64)``
beside a helper that PUTs a short body passes this scan (shown by making exactly that change).
Following the value through the function would cost more than it protects. What covers the gap is
the run-time assertion in the helpers, where the argument IS the body being sent, and the server's
own 409 in the integration lane.
"""
import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

TESTS = Path(__file__).resolve().parent
MIN_FIRST_CHUNK = 28

#: helper -> index of its `content` positional argument
HELPERS = {
    "zk_chunked_upload": 3,     # (client, vault_id, name, content, dek, ...)
    "_zk_chunked_upload": 2,    # (client, vid, content, ...)
    "_zk_pw_upload": 3,         # (client, vid, name, content, dek, pw)
    "_upload_named": 4,         # (admin, vid, name, dek, content, epoch, ...)
}


def _literal_bytes(node):
    """The bytes a literal expression denotes, or None when it is not a literal we can measure."""
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        for data, times in ((node.left, node.right), (node.right, node.left)):
            base = _literal_bytes(data)
            if base is not None and isinstance(times, ast.Constant) and isinstance(times.value, int):
                return base * times.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal_bytes(node.left), _literal_bytes(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _call_sites():
    for path in sorted(TESTS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name not in HELPERS:
                continue
            index = HELPERS[name]
            arg = node.args[index] if len(node.args) > index else next(
                (kw.value for kw in node.keywords if kw.arg == "content"), None)
            if arg is not None:
                yield path.name, node.lineno, name, arg


def test_the_scan_sees_the_call_sites_it_is_meant_to_measure():
    # Guard against vacuity: a rename of a helper, or a change to its signature, would otherwise
    # leave the check below passing on nothing.
    sites = list(_call_sites())
    measured = [s for s in sites if _literal_bytes(s[3]) is not None]
    assert len(sites) >= 30, f"only {len(sites)} zero-knowledge upload call sites were found"
    assert len(measured) >= 20, f"only {len(measured)} of them pass a measurable literal body"
    assert {s[2] for s in sites} == set(HELPERS), "a zero-knowledge upload helper is no longer called"
    assert _literal_bytes(ast.parse('b"ab" * 3 + b"c"', mode="eval").body) == b"abababc"


def test_no_call_site_fabricates_a_first_chunk_the_server_would_refuse():
    short = [f"{file}:{line} {helper}(... {len(_literal_bytes(arg))} bytes ...)"
             for file, line, helper, arg in _call_sites()
             if _literal_bytes(arg) is not None and len(_literal_bytes(arg)) < MIN_FIRST_CHUNK]
    assert not short, (
        f"a zero-knowledge upload's first chunk must be at least {MIN_FIRST_CHUNK} bytes (a 12-byte "
        "nonce + a 16-byte tag is the smallest real body; the server refuses a shorter one for a "
        "session that declared an attempt token):\n  " + "\n  ".join(short))


GUARD = "require_zk_first_chunk"

#: Files where the string "blob_id" appears in some form OTHER than building an upload's request
#: body, each with the reason no first chunk is ever sent from there. Anything not listed here and
#: not a declaration (below) fails the scan, so a new form cannot slip past unexamined.
OTHER_MENTIONS = {
    "test_ui_e2e.py": "reads back the init the BROWSER sent; the page seals the bytes itself",
    "test_upload_object_id.py": "a Standard upload carrying the field is refused at init: no chunk",
    "test_upload_session_principal.py": "a Standard upload carrying the field is refused at init: no chunk",
    "test_zk_fixture_bodies.py": "this module",
}


def _is_blob_id(node) -> bool:
    return isinstance(node, ast.Constant) and node.value == "blob_id"


def _declarations(tree):
    """Every place a request body is given a "blob_id": a dict literal's key, or body["blob_id"] = ..."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if _is_blob_id(key):
                    yield key
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store) and _is_blob_id(node.slice):
            yield node.slice


def _calls(func, name):
    return [n for n in ast.walk(func) if isinstance(n, ast.Call)
            and (getattr(n.func, "id", None) == name or getattr(n.func, "attr", None) == name)]


def _scan():
    sites, unguarded, stray = [], [], []
    for path in sorted(TESTS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        declared = list(_declarations(tree))
        for key in declared:
            where = f"{path.name}:{key.lineno}"
            sites.append(where)
            func = key
            while func is not None and not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func = parents.get(func)
            # The guard is a real CALL in the enclosing function's syntax tree, so a commented-out
            # call, or the name left behind in a docstring, does not count.
            guards = _calls(func, GUARD) if func is not None else []
            if not guards:
                unguarded.append(f"{where} declares an attempt token with no {GUARD}() call")
                continue
            # ...and it runs BEFORE the statement that makes the declaration -- the request that
            # opens the session, or the line that puts the token into its body. (A function may
            # well post other things first, such as creating the vault it uploads into.)
            stmt = key
            while not isinstance(stmt, ast.stmt):
                stmt = parents[stmt]
            if min(g.lineno for g in guards) >= stmt.lineno:
                unguarded.append(f"{where}: {GUARD}() runs only after the token is declared")
        mentions = sum(1 for n in ast.walk(tree) if _is_blob_id(n))
        if mentions > len(declared) and path.name not in OTHER_MENTIONS:
            stray.append(f"{path.name}: \"blob_id\" appears in a form this scan does not understand")
    return sites, unguarded, stray


def test_every_site_that_declares_an_attempt_token_holds_its_first_chunk_to_the_bar():
    # Driven off the DECLARATIONS, not off a list of helper names: a fifth helper, a session opened
    # directly in a test, or a computed body is invisible to a scan that only knows four names. Here
    # every request body that is given a "blob_id" must sit in a function that really CALLS the
    # guard, before it opens the session -- or the scan fails naming file:line.
    # (mutation: comment the guard call out -> red; add a "blob_id" init with no guard -> red.)
    sites, unguarded, stray = _scan()
    assert len(sites) >= 7, f"only {len(sites)} declarations found; the scan has gone blind: {sites}"
    assert not unguarded, "\n  ".join(["a first chunk is not held to the server's bar:"] + unguarded)
    assert not stray, "\n  ".join(stray)
    conftest = ast.parse((TESTS / "conftest.py").read_text(encoding="utf-8"))
    bar = [n for n in ast.walk(conftest) if isinstance(n, ast.Assign)
           and getattr(n.targets[0], "id", None) == "ZK_MIN_FIRST_CHUNK"]
    assert len(bar) == 1 and bar[0].value.value == MIN_FIRST_CHUNK
