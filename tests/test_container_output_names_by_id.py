"""The application's own lines in the container output name accounts by id, offline (docs/data-inventory.md, Logs).

What the web and SFTP processes print reaches `docker logs`, and through Log access the log file too, so a line says
what happened and to which account by its id: never a username, an email address, a display name, a provider's
subject for the person, or a name typed at sign-in. The audit log and the Activity page are where names belong.

The check reads every module the container runs (app/, run_combined.py, docker-entrypoint.py) and finds each call
that writes to the output: print, a write to sys.stdout or sys.stderr, logging.*, a logger's debug, info, warning,
error, exception, critical or log, and the vault's own writers (safe_event, log_failure, log_send_failure, _say).
A call fails it when its arguments, the parts of an f-string among them, read

- an attribute named display_name, subject or sub, or one whose name ends in username or email (user.username,
  settings.admin_username, cfg.from_email), directly, through getattr, or as a mapping's key (claims["sub"],
  info.get("email"));
- a variable whose name ends in username or email (actor_username, new_email).

A module's ``if __name__ == "__main__":`` block is left out: it runs only when someone runs the module by hand, and
prints to that person's terminal, not to the container output.

The check is a floor, not a proof: a name carried under another name (``who = user.username``, then ``print(who)``)
passes it. The text of an error is another matter (tests/test_error_logs_keep_no_text.py).
"""
import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]

# The modules the container runs besides the app package (the Dockerfile's ENTRYPOINT and CMD).
_ROOT_MODULES = ("run_combined.py", "docker-entrypoint.py")

_NAMED_ATTRIBUTES = frozenset({"display_name", "subject", "sub"})
_NAME_ENDINGS = ("username", "usernames", "email", "emails")

_LOGGER_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"})
_OWN_WRITERS = frozenset({"safe_event", "log_failure", "log_send_failure", "_say"})

# (file, the function the call is in, what it reads): a line that must keep reading it, with the reason.
_ALLOWED: dict = {}


def _modules():
    for path in sorted((ROOT / "app").rglob("*.py")):
        yield path
    for name in _ROOT_MODULES:
        yield ROOT / name


def _is_main_block(node) -> bool:
    test = getattr(node, "test", None)
    return (isinstance(node, ast.If) and isinstance(test, ast.Compare) and isinstance(test.left, ast.Name)
            and test.left.id == "__name__" and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value == "__main__")


def _names_logger(node) -> bool:
    """Whether the receiver of a call reads like a logger: a name or attribute with "log" in it on the way down
    (logger, log, _log, self.logger), or logging.getLogger(...) itself."""
    while isinstance(node, ast.Attribute):
        if "log" in node.attr.lower():
            return True
        node = node.value
    if isinstance(node, ast.Name):
        return "log" in node.id.lower()
    if isinstance(node, ast.Call):
        func = node.func
        return isinstance(func, ast.Attribute) and func.attr == "getLogger"
    return False


def _writes_output(func) -> bool:
    if isinstance(func, ast.Name):
        return func.id == "print" or func.id in _OWN_WRITERS
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr in _OWN_WRITERS:
        return True
    receiver = func.value
    if isinstance(receiver, ast.Name) and receiver.id == "logging":
        return True
    if func.attr == "write" and isinstance(receiver, ast.Attribute) and receiver.attr in ("stdout", "stderr") \
            and isinstance(receiver.value, ast.Name) and receiver.value.id == "sys":
        return True
    return func.attr in _LOGGER_METHODS and _names_logger(receiver)


def _is_named(name: str) -> bool:
    return name in _NAMED_ATTRIBUTES or name.lower().endswith(_NAME_ENDINGS)


def _reads(expression) -> list:
    """What of a person ``expression`` reads, as the text of each read."""
    called = {id(n.func) for n in ast.walk(expression) if isinstance(n, ast.Call)}
    found = []
    for node in ast.walk(expression):
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load) and id(node) not in called:
            if _is_named(node.attr):
                found.append(ast.unparse(node))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and id(node) not in called:
            if node.id.lower().endswith(_NAME_ENDINGS):
                found.append(node.id)
        elif isinstance(node, ast.Subscript):
            key = node.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and _is_named(key.value):
                found.append(ast.unparse(node))
        elif isinstance(node, ast.Call) and node.args:
            key = node.args[1] if (isinstance(node.func, ast.Name) and node.func.id == "getattr"
                                    and len(node.args) > 1) else (
                node.args[0] if isinstance(node.func, ast.Attribute) and node.func.attr == "get" else None)
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and _is_named(key.value):
                found.append(ast.unparse(node))
    return found


class _Finder(ast.NodeVisitor):
    def __init__(self):
        self.where = []
        self.calls = 0
        self.found = []         # (line, function, what it reads)

    def visit_If(self, node):
        if _is_main_block(node):
            for child in node.orelse:
                self.visit(child)
            return
        self.generic_visit(node)

    def _function(self, node):
        self.where.append(node.name)
        self.generic_visit(node)
        self.where.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _function

    def visit_Call(self, node):
        if _writes_output(node.func):
            self.calls += 1
            for argument in list(node.args) + [keyword.value for keyword in node.keywords]:
                for read in _reads(argument):
                    self.found.append((node.lineno, ".".join(self.where) or "<module>", read))
        self.generic_visit(node)


def _find(source: str) -> _Finder:
    finder = _Finder()
    finder.visit(ast.parse(source))
    return finder


def test_no_line_of_the_container_output_reads_a_name_an_address_or_a_subject():
    offending = []
    for path in _modules():
        relative = path.relative_to(ROOT).as_posix()
        for line, function, read in _find(path.read_text(encoding="utf-8")).found:
            if (relative, function, read) not in _ALLOWED:
                offending.append(f"{relative}:{line} ({function}) writes {read} to the output")
    assert not offending, ("name the account by its id, or drop the name:\n" + "\n".join(offending))


def test_the_inventory_says_what_the_lines_name_and_what_still_can_name_a_value():
    text = (ROOT / "docs" / "data-inventory.md").read_text(encoding="utf-8")
    logs = " ".join(text.split("\n## Logs", 1)[1].split("\n## ", 1)[0].split())
    assert "Those lines name an account by its id" in logs
    assert "the database driver's text for a broken uniqueness rule names the value that broke it" in logs


def test_every_allowed_line_still_reads_what_it_is_allowed():
    seen = set()
    for path in _modules():
        relative = path.relative_to(ROOT).as_posix()
        seen.update((relative, function, read) for _line, function, read in _find(path.read_text("utf-8")).found)
    stale = sorted(set(_ALLOWED) - seen)
    assert not stale, f"an allowance no line needs any more: {stale}"


def test_the_check_reads_the_modules_the_container_runs():
    paths = {path.relative_to(ROOT).as_posix() for path in _modules()}
    for expected in ("app/api/api_server.py", "app/sftp/sftp_server.py", "app/api/sso_router.py",
                     "app/services/oidc_client.py", "app/services/webauthn_service.py", "app/core/admin_bootstrap.py",
                     "run_combined.py", "docker-entrypoint.py"):
        assert expected in paths, expected
        assert (ROOT / expected).is_file(), expected
    writes = sum(_find(path.read_text(encoding="utf-8")).calls for path in _modules())
    assert writes > 300, f"only {writes} writes to the output were found: the check is not reading the code"


CONTROL = '''
import logging, re, sys
logger = logging.getLogger(__name__)
log = logging.getLogger("x")

def shapes(user, claims, info, actor_username, new_email, settings, row, account_id):
    print(f"Session invalidated for user {user.username}")
    print("Bootstrapped " + settings.admin_username)
    logger.info("linked %s", claims["sub"])
    log.warning("address %s", info.get("email"))
    logging.error("x %s", getattr(user, "email", None))
    sys.stderr.write(f"by {actor_username}\\n")
    logging.getLogger("y").info(f"to {new_email}")
    self_logger = log
    self_logger.critical("%s", row.display_name)
    _say(f"subject {claims.subject}")
    safe_event("auth.x", user=user.email)

def fine(user, account_id, text):
    print(f"Session invalidated for user {user.id}")
    logger.info("account %s", account_id)
    print(re.sub("a", "b", text))
    print(mask_email(text))
    audit_logger.log_login_failure(user.username)

if __name__ == "__main__":
    print(user.email)
'''


def test_the_check_finds_each_shape_it_looks_for_and_nothing_else():
    finder = _find(CONTROL)
    found = sorted(read for _line, _function, read in finder.found)
    assert found == sorted([
        "user.username", "settings.admin_username", "claims['sub']", "info.get('email')",
        "getattr(user, 'email', None)", "actor_username", "new_email", "row.display_name", "claims.subject",
        "user.email",
    ]), found
    assert {function for _line, function, _read in finder.found} == {"shapes"}
