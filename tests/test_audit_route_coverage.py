"""Every route that changes something writes an audit row, or is listed here with the reason it does not.

The scan reads app/ as source (no app import). A route is a function decorated with a POST, PUT, PATCH or
DELETE route. It records itself when its body calls an AuditLogger method (a log_... method, or build_row
for a row committed with the route's own change), or a function that does (followed to any depth): one of
the same module called by name, or one of another app module called through that module
(``from app.core import setting_changes`` ... ``setting_changes.request(...)``). A route that records
nothing must be in NOT_RECORDED with a reason, so a new route cannot quietly join them.

What it cannot see: which path writes. A route that records only its failures (or only one of two
branches) counts as recording; those are covered by the live tests of the rows themselves.
"""
import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"
MUTATING = {"post", "put", "patch", "delete"}

# (file, "METHOD path") -> why the route writes no audit row.
NOT_RECORDED = {
    ("app/api/activity_search_router.py", "POST /activity/events/search"):
        "a read of the Events list, posted so what was typed stays out of the request line",
    ("app/api/activity_search_router.py", "POST /activity/summary/search"):
        "a read of the summary band, posted so what was typed stays out of the request line",
    ("app/api/activity_search_router.py", "POST /activity/export"):
        "the export, posted so what was typed stays out of the request line; its handler records it",
    ("app/api/api_server.py", "POST /auth/second-factor/cancel"):
        "abandons a pending sign-in; no session was made",
    ("app/api/api_server.py", "POST /auth/second-factor/challenge"):
        "only lists the methods a step-up accepts; the step-up itself is recorded when it fails",
    ("app/api/api_server.py", "POST /users/me/second-factor/totp/enroll"):
        "an unconfirmed enrollment; the second factor is recorded when it is switched on",
    ("app/api/api_server.py", "POST /users/me/second-factor/totp/confirm"):
        "an unconfirmed enrollment; the second factor is recorded when it is switched on",
    ("app/api/api_server.py", "PUT /users/me/preferences"):
        "the person's own display preferences (skin, sort order)",
    ("app/api/settings_catalogue_router.py", "POST /settings/catalogue/seen"):
        "the person's own display preference: the release they last opened Settings at, for its New marks",
    ("app/api/api_server.py", "PUT /note-links/{link_id}/token-copy"):
        "stores the owner's sealed copy of a link address they already made; the link is recorded",
    ("app/api/api_server.py", "PUT /public-links/{link_id}/token-copy"):
        "stores the owner's sealed copy of a link address they already made; the link is recorded",
    ("app/api/api_server.py", "PUT /receivers/{token}/upload-session/{session_id}/chunks/{chunk_index}"):
        "one chunk of an upload; the upload is recorded when it opens and when it completes",
    ("app/api/api_server.py", "POST /vaults/{vault_id}/uploads"):
        "opens a resumable upload; the file is recorded when the upload completes, or its cancellation",
    ("app/api/api_server.py", "PUT /vaults/{vault_id}/uploads/{session_id}/chunks/{chunk_index}"):
        "one chunk of a resumable upload; the file is recorded when the upload completes",
    ("app/api/api_server.py", "POST /notifications/{notification_id}/read"):
        "the person's own notification state",
    ("app/api/api_server.py", "POST /notifications/read-all"):
        "the person's own notification state",
    ("app/api/api_server.py", "DELETE /notifications/{notification_id}"):
        "the person's own notification state",
    ("app/api/api_server.py", "POST /activity/saved-searches"):
        "the person's own saved searches on the Activity page",
    ("app/api/api_server.py", "PATCH /activity/saved-searches/{search_id}"):
        "the person's own saved searches on the Activity page",
    ("app/api/api_server.py", "DELETE /activity/saved-searches/{search_id}"):
        "the person's own saved searches on the Activity page",
    ("app/api/api_server.py", "POST /activity/saved-searches/{search_id}/default"):
        "the person's own saved searches on the Activity page",
    ("app/api/api_server.py", "DELETE /activity/saved-searches/{search_id}/default"):
        "the person's own saved searches on the Activity page",
    ("app/api/api_server.py", "PUT /vaults/{vault_id}/favorite"):
        "the person's own favourites",
    ("app/api/api_server.py", "DELETE /vaults/{vault_id}/favorite"):
        "the person's own favourites",
    ("app/api/ecc_router.py", "POST /decompress-point"):
        "a calculation; nothing is stored",
    ("app/api/ecc_router.py", "POST /keys/register/challenge"):
        "issues a one-time challenge; registering the key is recorded",
    ("app/api/ecc_router.py", "POST /keys/private/challenge"):
        "issues a one-time challenge; the key change is recorded, and so is a refused proof",
    ("app/api/ecc_router.py", "POST /vaults/{vault_id}/key-proof/challenge"):
        "issues a one-time challenge; the key change it is for is recorded by its own route",
    ("app/api/email_studio_router.py", "POST /templates/preview"):
        "renders a preview; nothing is stored or sent",
}


def _logger_methods():
    tree = ast.parse((APP / "services" / "audit_logger.py").read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AuditLogger")
    return {n.name for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and (n.name.startswith("log_") or n.name == "build_row")}


LOGGER_METHODS = _logger_methods()


def _names_used(fn):
    """Attribute names, called function names, and (module alias, function) pairs used inside fn."""
    attrs, calls, through = set(), set(), set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Attribute):
            attrs.add(node.attr)
            if isinstance(node.value, ast.Name):
                through.add((node.value.id, node.attr))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.add(node.func.id)
    return attrs, calls, through


def _app_module_aliases(tree):
    """{alias: module path relative to ROOT} for every app module the file imports as a module."""
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app"):
            for name in node.names:
                target = (ROOT / Path(*f"{node.module}.{name.name}".split("."))).with_suffix(".py")
                if target.is_file():
                    aliases[name.asname or name.name] = target.relative_to(ROOT).as_posix()
        elif isinstance(node, ast.Import):
            for name in node.names:
                target = (ROOT / Path(*name.name.split("."))).with_suffix(".py")
                if name.name.startswith("app.") and name.asname and target.is_file():
                    aliases[name.asname] = target.relative_to(ROOT).as_posix()
    return aliases


def _scan():
    routes, unrecorded = [], []
    modules = {}
    for path in sorted(APP.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        rel = path.relative_to(ROOT).as_posix()
        funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        modules[rel] = (funcs, {f.name: _names_used(f) for f in funcs}, _app_module_aliases(tree))
    writers = {(rel, name) for rel, (_f, used, _al) in modules.items()
               for name, (attrs, _c, _t) in used.items() if attrs & LOGGER_METHODS}
    while True:   # a function that calls a writer, by name in its module or through another module, writes
        more = set()
        for rel, (_funcs, used, aliases) in modules.items():
            for name, (_attrs, calls, through) in used.items():
                if (rel, name) in writers:
                    continue
                if any((rel, c) in writers for c in calls) or any(
                        (aliases[alias], fn) in writers for alias, fn in through if alias in aliases):
                    more.add((rel, name))
        if not more:
            break
        writers |= more
    for rel, (funcs, _used, _aliases) in modules.items():
        for fn in funcs:
            for dec in fn.decorator_list:
                if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                        and dec.func.attr in MUTATING and dec.args
                        and isinstance(dec.args[0], ast.Constant)):
                    key = (rel, f"{dec.func.attr.upper()} {dec.args[0].value}")
                    routes.append(key)
                    if (rel, fn.name) not in writers:
                        unrecorded.append(key)
    return routes, unrecorded


ROUTES, UNRECORDED = _scan()


def test_the_scan_sees_the_routes():
    # A scan that found nothing would pass everything below.
    assert len(ROUTES) > 150, len(ROUTES)
    assert ("app/api/api_server.py", "POST /auth/login") in ROUTES
    assert {"log_action", "log_vault_created", "build_row"} <= LOGGER_METHODS


def test_every_mutating_route_writes_an_audit_row_or_says_why_not():
    missing = sorted(set(UNRECORDED) - set(NOT_RECORDED))
    assert not missing, ("these routes change something and write no audit row; record the change, "
                         f"or list the route in NOT_RECORDED with the reason: {missing}")


def test_a_route_that_records_through_another_modules_function_is_seen_to_record():
    for route in (("app/api/managed_settings_router.py", "PUT /settings/managed/{key}"),
                  ("app/api/managed_settings_router.py", "POST /settings/managed/changes/{change_id}/cancel")):
        assert route in ROUTES and route not in UNRECORDED, route


def test_the_list_holds_only_routes_that_exist_and_record_nothing():
    stale = sorted(set(NOT_RECORDED) - set(UNRECORDED))
    assert not stale, f"these routes are gone or now record themselves; remove them from the list: {stale}"


def test_audit_rows_are_written_only_through_the_logger():
    # A row built directly skips the name redaction, the request's address, channel and route. A row
    # that must commit in the caller's own transaction comes from AuditLogger.build_row, which applies
    # them and leaves the commit to the caller.
    direct = []
    for path in sorted(APP.rglob("*.py")):
        if path.name == "audit_logger.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "AuditLog":
                direct.append(f"{path.relative_to(ROOT).as_posix()}:{node.lineno}")
    assert not direct, direct
