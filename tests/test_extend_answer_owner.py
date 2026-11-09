"""Who gets the full answer to an extension, offline (app/api/api_server.py).

An administrator may extend an item someone else made; the answer then says only what was extended until,
not the item's own details. Whether the answer is the maker's is decided in each extend route by comparing
the item's maker with the person asking, with ==. A route that decided it any other way (always the maker,
or a comparison that is never equal) would hand an administrator the maker's view, or the maker less than
theirs.
"""
import ast
import functools
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SOURCE = Path(__file__).resolve().parent.parent / "app" / "api" / "api_server.py"

# Each extend route and the attribute that names the item's maker.
ROUTES = {
    "extend_share": ("share", "creator_id"),
    "extend_public_link": ("link", "owner_id"),
    "extend_note_link": ("link", "owner_id"),
    "extend_receiver": ("r", "owner_id"),
}


def _functions(tree):
    return {node.name: node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _attr(node):
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id, node.attr
    return None


def _problems(source: str):
    """What is wrong with the by_owner decision in each extend route; empty when every route is right."""
    functions = _functions(ast.parse(source))
    problems = []
    for name, maker in ROUTES.items():
        fn = functions.get(name)
        if fn is None:
            problems.append(f"{name}: not found")
            continue
        assigns = [node for node in ast.walk(fn) if isinstance(node, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == "by_owner" for t in node.targets)]
        if len(assigns) != 1:
            problems.append(f"{name}: {len(assigns)} assignments to by_owner")
            continue
        value = assigns[0].value
        if not (isinstance(value, ast.Compare) and len(value.ops) == 1 and isinstance(value.ops[0], ast.Eq)):
            problems.append(f"{name}: by_owner is not one == comparison ({ast.unparse(value)})")
            continue
        sides = {_attr(value.left), _attr(value.comparators[0])}
        if sides != {maker, ("current_user", "id")}:
            problems.append(f"{name}: by_owner compares {ast.unparse(value)}")
            continue
        # And the decision is what the answer is built with.
        passed = [kw for node in ast.walk(fn) if isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Name) and node.func.id == "_extend_answer"
                  for kw in node.keywords if kw.arg == "by_owner"]
        if len(passed) != 1 or not (isinstance(passed[0].value, ast.Name) and passed[0].value.id == "by_owner"):
            problems.append(f"{name}: _extend_answer is not given by_owner=by_owner")
    return problems


@functools.lru_cache(maxsize=1)
def _routes_source() -> str:
    """The four routes' own source, cut from the module (parsed once)."""
    source = SOURCE.read_text(encoding="utf-8")
    functions = _functions(ast.parse(source))
    return "\n\n".join(ast.get_source_segment(source, functions[name]) for name in ROUTES if name in functions)


def test_each_extend_route_decides_the_makers_answer_by_comparing_the_maker_with_the_asker():
    assert _problems(SOURCE.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize("route", sorted(ROUTES))
@pytest.mark.parametrize("decision", ["True", "{a}.{b} != current_user.id", "{a}.{b} is not None"])
def test_the_check_refuses_a_route_that_decides_it_another_way(route, decision):
    # The control: the routes with one route's decision changed are refused, so the check above is not vacuous.
    source = _routes_source()
    assert _problems(source) == []
    a, b = ROUTES[route]
    original = f"by_owner = {a}.{b} == current_user.id"
    fn = _functions(ast.parse(source))[route]
    lines = source.splitlines()
    hits = [i for i in range(fn.lineno - 1, fn.end_lineno) if lines[i].strip() == original]
    assert len(hits) == 1, (route, hits)
    indent = lines[hits[0]][: len(lines[hits[0]]) - len(lines[hits[0]].lstrip())]
    lines[hits[0]] = indent + "by_owner = " + decision.format(a=a, b=b)
    problems = _problems("\n".join(lines))
    assert problems and all(p.startswith(route + ":") for p in problems), problems
