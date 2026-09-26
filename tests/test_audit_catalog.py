"""The audit action catalog stays complete: every action name the code can store is catalogued.

The scan reads app/ as source (no app import). An audit write is a call to AuditLogger.log_action or
log_custom_action, whose first argument is the action, or to a module's own `_audit...` helper that takes an
`action` parameter, checked at that parameter's position. A literal action must be in the catalog. A
non-literal one is either a wrapper passing its own `action` parameter through (its callers are checked
instead) or one of the few names built at run time, pinned below with every name it can produce.
"""
import ast
from pathlib import Path

import pytest

from app.core import audit_catalog as catalog

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"
METHODS = {"log_action": 0, "log_custom_action": 0}

# Wrappers that pass their own `action` parameter to the logger: the check moves to their callers.
PASS_THROUGH = {
    ("app/api/api_server.py", "_audit_access_change"),
    ("app/api/api_server.py", "_audit_device"),
    ("app/api/api_server.py", "_audit_note_link_tag"),
    ("app/api/api_server.py", "_audit_receiver_tag"),
    ("app/api/api_server.py", "_audit_share_tag"),
    ("app/api/ecc_router.py", "_audit_zk"),
    ("app/api/email_studio_router.py", "_audit"),
    ("app/core/temp_scope.py", "_audit_scope_denial"),
    ("app/services/audit_logger.py", "log_custom_action"),
    ("app/services/audit_logger.py", "log_error"),
    ("app/api/api_server.py", "_audit_change"),
    ("app/sftp/sftp_server.py", "_audit"),
}

# Names built at run time: (file, enclosing function, source of the expression) -> every name it yields.
COMPUTED = {
    ("app/api/api_server.py", "_handle_retired_secret_reuse",
     "'device_secret_reuse_' + ('revoke' if hard else 'suspend')"): ("device_secret_reuse_revoke",
                                                                    "device_secret_reuse_suspend"),
    ("app/api/api_server.py", "pause_receiver",
     "'receiver_pause' if want else 'receiver_resume'"): ("receiver_pause", "receiver_resume"),
}


def _action_param_index(fn):
    names = [a.arg for a in fn.args.args]
    if names and names[0] in ("self", "cls"):
        names = names[1:]
    return names.index("action") if "action" in names else None


def _scan():
    literal, dynamic = [], []
    for path in sorted(APP.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        rel = path.relative_to(ROOT).as_posix()
        helpers = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("_audit"):
                idx = _action_param_index(node)
                if idx is not None:
                    helpers[node.name] = idx
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

        def enclosing(node):
            while node in parents:
                node = parents[node]
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return node.name
            return "<module>"

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in METHODS:
                idx = METHODS[f.attr]
            elif isinstance(f, ast.Name) and f.id in helpers:
                idx = helpers[f.id]
            else:
                continue
            arg = next((k.value for k in node.keywords if k.arg == "action"), None)
            if arg is None and len(node.args) > idx:
                arg = node.args[idx]
            if arg is None:
                continue
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                literal.append((rel, node.lineno, arg.value))
            else:
                dynamic.append((rel, enclosing(node), ast.unparse(arg)))
    return literal, dynamic


LITERAL, DYNAMIC = _scan()


def test_the_scan_sees_the_audit_writes():
    # A scan that found nothing would pass everything below.
    assert len(LITERAL) > 150, len(LITERAL)
    assert {"login_success", "file_download", "note_link_create", "zk_vault_rekeyed"} <= {n for _, _, n in LITERAL}


def test_every_literal_action_is_catalogued():
    missing = sorted({(name, f"{f}:{line}") for f, line, name in LITERAL if catalog.lookup(name) is None})
    assert not missing, f"add these to app/core/audit_catalog.py with a category and a label: {missing}"


def test_every_non_literal_action_is_a_known_wrapper_or_pinned():
    unknown = []
    for f, fn, src in DYNAMIC:
        if src == "action" and (f, fn) in PASS_THROUGH:
            continue
        if (f, fn, src) in COMPUTED:
            continue
        unknown.append((f, fn, src))
    assert not unknown, ("an action name is built at run time here; pin it in COMPUTED with every name it "
                         f"can produce, and catalogue those names: {unknown}")


def test_the_pins_still_match_the_code():
    # A pin whose site is gone would silently stop covering anything.
    seen = set(DYNAMIC)
    stale = [k for k in COMPUTED if k not in seen]
    stale += [w for w in PASS_THROUGH if (w[0], w[1], "action") not in seen]
    assert not stale, f"these pinned sites no longer exist; remove the pins: {stale}"


@pytest.mark.parametrize("names", list(COMPUTED.values()))
def test_every_computed_name_is_catalogued(names):
    assert all(catalog.lookup(n) for n in names), names


def test_each_stored_name_belongs_to_exactly_one_entry():
    seen = {}
    for a in catalog.ACTIONS:
        for n in (a.name,) + a.aliases:
            assert n not in seen, f"{n!r} is in both {seen[n]!r} and {a.name!r}"
            seen[n] = a.name


def test_entries_use_known_categories_and_severities():
    keys = {k for k, _ in catalog.CATEGORIES}
    for a in catalog.ACTIONS:
        assert a.category in keys, a
        assert a.severity in catalog.SEVERITIES, a
        assert a.label and a.label[0].isupper() and not a.label.endswith("."), a


def test_a_category_filter_includes_every_spelling():
    files = catalog.stored_names(["files"])
    assert "file_upload" in files and "file_uploaded" in files
    assert "login_success" not in files
    assert catalog.label_for("USER_UPDATED") == catalog.label_for("user_updated")
    assert catalog.label_for("written_by_an_old_release") == catalog.LEGACY_LABEL
