"""Every conftest helper a test imports must be called with arguments it accepts.

Written after calling `skip_if_container_absent()` with no arguments when it takes two. The whole
file errored at setup, so twenty-two tests never ran, and it could only surface in CI: locally the
fixtures skip before reaching the call, so the mistake is invisible until a run with a live
deployment. Twenty minutes to learn something a parser answers instantly.

Static on purpose -- it reads the syntax tree rather than importing anything, so it costs nothing
and cannot be defeated by a module that is expensive or side-effecting to import. It is also
deliberately narrow: it reports a call that CANNOT work, never one that merely looks unusual. A
guard that cries wolf gets marked xfail and stops guarding.
"""
import ast
import io
import pathlib

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
CONFTEST = TESTS / "conftest.py"


def _signatures(tree):
    """Positional arity of every top-level function: (minimum, maximum or None for *args)."""
    out = {}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        args = node.args
        positional = args.posonlyargs + args.args
        required = len(positional) - len(args.defaults)
        out[node.name] = (max(0, required), None if args.vararg else len(positional))
    return out


def _imported_from_conftest(tree):
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "conftest":
            for alias in node.names:
                names[alias.asname or alias.name] = alias.name
    return names


def _calls(tree, watched):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in watched:
            continue
        if any(isinstance(a, ast.Starred) for a in node.args):
            continue      # unpacking hides the count; not something to guess about
        yield node


@pytest.mark.unit
def test_no_test_calls_a_conftest_helper_with_the_wrong_number_of_arguments():
    signatures = _signatures(ast.parse(io.open(CONFTEST, encoding="utf-8").read()))
    assert signatures, "no helpers parsed out of conftest, so this check would pass vacuously"

    problems = []
    checked = 0
    for path in sorted(TESTS.glob("test_*.py")):
        tree = ast.parse(io.open(path, encoding="utf-8").read())
        imported = _imported_from_conftest(tree)
        watched = {local: real for local, real in imported.items() if real in signatures}
        for call in _calls(tree, watched):
            low, high = signatures[watched[call.func.id]]
            given = len(call.args)
            # Keywords can only satisfy named parameters, so they raise the floor a positional
            # call must clear; counting them as satisfying anything is what keeps this quiet
            # about the many legitimate keyword-only styles in this suite.
            supplied = given + len(call.keywords)
            checked += 1
            if supplied < low:
                problems.append(
                    f"{path.name}:{call.lineno} calls {call.func.id}() with {supplied} "
                    f"argument(s); it requires at least {low}")
            elif high is not None and given > high:
                problems.append(
                    f"{path.name}:{call.lineno} calls {call.func.id}() with {given} positional "
                    f"argument(s); it accepts at most {high}")

    assert checked, "no calls to conftest helpers were found, so this check proved nothing"
    assert not problems, (
        "these calls cannot succeed, and each one fails at setup rather than as an assertion -- "
        "so the tests around them do not run at all:\n  " + "\n  ".join(problems))


@pytest.mark.unit
def test_the_check_can_actually_see_a_wrong_call():
    """A control. Without it, a bug in the walk above turns the check into a silent pass."""
    conftest = ast.parse("def needs_two(a, b):\n    pass\n"
                         "def takes_any(*rest):\n    pass\n"
                         "def one_optional(a, b=1):\n    pass\n")
    signatures = _signatures(conftest)
    assert signatures == {"needs_two": (2, 2), "takes_any": (0, None), "one_optional": (1, 2)}

    caller = ast.parse("from conftest import needs_two, takes_any, one_optional\n"
                       "needs_two()\n"            # too few: the mistake this exists for
                       "needs_two(1, 2)\n"        # fine
                       "takes_any(1, 2, 3)\n"     # fine, *args
                       "one_optional(1)\n"        # fine, default fills the second
                       "one_optional(1, 2, 3)\n")  # too many
    watched = {n: n for n in _imported_from_conftest(caller)}
    verdicts = []
    for call in _calls(caller, watched):
        low, high = signatures[call.func.id]
        given = len(call.args)
        verdicts.append(given < low or (high is not None and given > high))
    assert verdicts == [True, False, False, False, True], verdicts
