"""A file's or a folder's own password is under the vault password's attempt limit.

The vault password has a failure-only, fail-closed attempt counter per vault and account; a file's or a folder's
own password was checked with none, so it could be guessed without bound. Each now has the same limit and window,
counted per file or folder and account: only a wrong password counts, and at the limit every attempt is refused
before any password is read, the right one included, until the window ends. The web routes answer that refusal
with 429, as for a vault password. SFTP never takes a file password (it refuses a password-protected file), so it
has nothing to guess.

These run VaultService's own checks with stand-ins for the database rows, the permission check and the counter's
store. tests/test_vault_attempt_throttle.py covers the counter itself; the live counterpart is
tests/test_file_password_limit_live.py.
"""
import ast
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import file_expiry, rate_limit_settings, vault_attempt_throttle  # noqa: E402
from app.core.models import File, Folder, RoleEnum, Vault  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.services import vault_service as VS  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
LIMIT, ADMIN_LIMIT, WINDOW = 3, 5, 60
RIGHT = "the-right-one"
HASH = hash_password(RIGHT)


class _Counter:
    """The counter's store: wrong attempts per key, and the window ending on demand."""

    def __init__(self):
        self.counts = {}
        self.asked = []
        self.burned = []

    def over_limit(self, key, limit, window):
        self.asked.append((key, limit, window))
        return self.counts.get(key, 0) >= limit

    def burn(self, key, window):
        self.burned.append((key, window))
        self.counts[key] = self.counts.get(key, 0) + 1

    def window_ends(self):
        self.counts.clear()


class _Rows:
    """The database: one row per model."""

    def __init__(self, rows):
        self.rows, self._model = rows, None

    def query(self, model):
        self._model = model
        return self

    def filter(self, *a, **k):
        return self

    def first(self):
        return self.rows.get(self._model)


@pytest.fixture
def counter(monkeypatch):
    c = _Counter()
    monkeypatch.setattr(vault_attempt_throttle, "over_limit", c.over_limit)
    monkeypatch.setattr(vault_attempt_throttle, "burn", c.burn)
    monkeypatch.setattr(file_expiry, "is_expired", lambda f, now=None: False)
    values = {"rate_limit_vault_attempts": LIMIT, "rate_limit_vault_attempts_admin": ADMIN_LIMIT,
              "rate_limit_vault_window_seconds": WINDOW}
    monkeypatch.setattr(rate_limit_settings, "effective", lambda key: values[key])
    return c


def _service(item):
    svc = VS.VaultService.__new__(VS.VaultService)
    vault = SimpleNamespace(id=item.vault_id)
    svc.db = _Rows({File: item, Folder: item, Vault: vault})
    svc.permission_service = SimpleNamespace(require_vault_permission=lambda *a, **k: None)
    return svc


def _item():
    return SimpleNamespace(id=uuid.uuid4(), vault_id=uuid.uuid4(), password_hash=HASH, expires_at=None)


def _person(role=RoleEnum.USER):
    return SimpleNamespace(id=uuid.uuid4(), role=role)


def _open(kind, svc, item, user, password):
    if kind == "file":
        return svc._resolve_download(item.id, user, password, False)[0]
    return svc.get_folder(item.id, user, password)


@pytest.mark.parametrize("kind", ["file", "folder"])
def test_wrong_passwords_reach_the_limit_and_then_even_the_right_one_is_refused_until_the_window_ends(counter,
                                                                                                         kind):
    item, user = _item(), _person()
    svc = _service(item)
    for _ in range(LIMIT):
        with pytest.raises(VS.InvalidPasswordError):
            _open(kind, svc, item, user, "a-guess")
    for attempt in (RIGHT, "a-guess", None):
        with pytest.raises(VS.RateLimitExceededError):
            _open(kind, svc, item, user, attempt)
    key = f"rate_limit:{kind}:{item.id}:{user.id}"
    assert counter.counts == {key: LIMIT}, "only the wrong passwords count; a refused attempt does not"
    assert counter.asked[-1] == (key, LIMIT, WINDOW), "the vault password's limit and window"
    # Each wrong password is counted over the vault password's window (a shorter one would let guesses spaced
    # just past it go on without end).
    assert counter.burned == [(key, WINDOW)] * LIMIT, counter.burned
    counter.window_ends()
    assert _open(kind, svc, item, user, RIGHT) is item


@pytest.mark.parametrize("kind", ["file", "folder"])
def test_the_count_is_per_item_and_account_and_a_right_password_counts_nothing(counter, kind):
    item, other_item, user, other_user = _item(), _item(), _person(), _person()
    svc = _service(item)
    for _ in range(LIMIT - 1):
        with pytest.raises(VS.InvalidPasswordError):
            _open(kind, svc, item, user, "a-guess")
    for _ in range(3):
        assert _open(kind, svc, item, user, RIGHT) is item
    with pytest.raises(VS.InvalidPasswordError):
        _open(kind, svc, item, user, "a-guess")
    with pytest.raises(VS.RateLimitExceededError):
        _open(kind, svc, item, user, RIGHT)
    # Another account, and another file or folder, have counts of their own.
    assert _open(kind, svc, item, other_user, RIGHT) is item
    assert _open(kind, _service(other_item), other_item, user, RIGHT) is other_item


def test_an_administrator_has_the_administrators_vault_limit(counter):
    item, admin = _item(), _person(RoleEnum.ADMIN)
    svc = _service(item)
    for _ in range(ADMIN_LIMIT):
        with pytest.raises(VS.InvalidPasswordError):
            _open("file", svc, item, admin, "a-guess")
    with pytest.raises(VS.RateLimitExceededError):
        _open("file", svc, item, admin, RIGHT)


def _password_checks():
    """Every call in api_server that asks for a vault password (get_vault(require_password=True)) or passes a file
    password on, with the try blocks whose body holds it, innermost first, within its own function: (name, tries)."""
    tree = ast.parse((ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8"))
    found = []

    def checks(n):
        return isinstance(n, ast.Call) and (
            (getattr(n.func, "attr", None) == "get_vault" and any(
                k.arg == "require_password" and isinstance(k.value, ast.Constant) and k.value.value is True
                for k in n.keywords))
            or any(k.arg in ("file_password", "source_file_password") for k in n.keywords))

    def visit(node, name, tries):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            name, tries = getattr(node, "name", name), []     # a nested function's tries are its own
        if checks(node):
            found.append((name, list(reversed(tries))))
        for field, value in ast.iter_fields(node):
            for child in value if isinstance(value, list) else [value]:
                if isinstance(child, ast.AST):
                    inner = tries + [node] if isinstance(node, ast.Try) and field == "body" else tries
                    visit(child, name, inner)

    visit(tree, None, [])
    return found


def _catches(handler, names):
    if handler.type is None:
        return True
    types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(ast.unparse(t).split(".")[-1] in names for t in types)


_LIMIT = {"RateLimitExceededError", "FileServiceError", "Exception", "BaseException"}
_HTTP = {"HTTPException", "Exception", "BaseException"}


def test_every_route_that_checks_a_password_answers_the_limit_with_429():
    """The vault password's limit, and a file's, are refused with 429 wherever a password is checked. From the call
    out, the first handler that would catch the limit is a clause that answers 429 (the catch-alls after it would
    make it 500, or the rendered preview's 404), or there is none and the application-wide FileServiceError handler
    answers 429 (copy and move). No try further out turns that 429 into anything else."""
    checks = _password_checks()
    names = {name for name, _ in checks}
    assert {"_serve_file", "preview_render_file", "get_file_info", "delete_file", "rename_file", "delete_vault",
            "change_vault_password", "upload_file", "create_folder", "delete_folder"} <= names, names
    assert len(checks) >= 23, len(checks)
    for name, tries in checks:
        caught = next(((i, h) for i, t in enumerate(tries) for h in t.handlers if _catches(h, _LIMIT)), None)
        if caught is None:
            continue
        at, handler = caught
        body = ast.unparse(handler)
        assert ast.unparse(handler.type) == "RateLimitExceededError", (name, ast.unparse(handler.type))
        assert "HTTP_429_TOO_MANY_REQUESTS" in body and "raise HTTPException" in body, (name, body)
        for outer in tries[at + 1:]:
            http = next((h for h in outer.handlers if _catches(h, _HTTP)), None)
            if http is not None:
                assert ast.unparse(http.body[0]) == "raise" and len(http.body) == 1, (name, ast.unparse(http))
                break
