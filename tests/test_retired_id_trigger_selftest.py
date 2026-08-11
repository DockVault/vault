"""The startup check that refuses to serve without the retired-id triggers.

Offline: it takes a database handle and asks one question, so a stub answers it.

This exists because the migration runner it sits at the end of reports failure by PRINTING. That is
the right call for a column addition -- one that will not apply is usually one that already exists.
It is the wrong call for these triggers, because the failure is silent in the direction that
matters: with no trigger nothing is ever recorded, every "has this id been spent" check keeps
answering no, and the deployment is quietly back to the liveness-only guard with nothing in the
logs anyone reads to say so. A client could then re-claim the id of a deleted object and read a
blob that outlived its row.

So the check is a hard stop, and this is what pins it as one. Without these tests the whole
mechanism could be reduced to a warning by a one-word edit and every other test would stay green --
they all run against a database where the triggers did land.
"""

import importlib.util
from pathlib import Path
import tempfile

import pytest


pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
ALL_THREE = ["trg_files_retire", "trg_folders_retire", "trg_vaults_retire"]


def _verifier():
    """Load just this function, without importing the API module, which wants a live config.

    The function's source is sliced out and imported as a module of its own. Slicing rather than
    duplicating matters: a copy in the test file would keep passing after the real one changed,
    which is the failure mode this whole file exists to prevent.
    """
    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    start = source.index("def _verify_retired_object_id_triggers(")
    end = source.index("\ndef ", start + 1)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "_retired_id_selftest_extract.py"
        path.write_text(source[start:end], encoding="utf-8")
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module._verify_retired_object_id_triggers


class _Db:
    """The one call the verifier makes, and a way to make it answer wrongly."""

    RELATION = {"trg_files_retire": "files", "trg_folders_retire": "folders",
                "trg_vaults_retire": "vaults"}

    def __init__(self, present=None, raises=None, rows=None):
        self._present = present if present is not None else []
        self._raises = raises
        self._rows = rows

    def execute(self, *_args, **_kwargs):
        if self._raises:
            raise self._raises
        rows = self._rows if self._rows is not None else [
            (name, self.RELATION[name], "O") for name in self._present]
        return type("R", (), {"fetchall": lambda _self: rows})()


def test_all_three_triggers_present_is_the_only_way_through():
    _verifier()(_Db(present=ALL_THREE))


@pytest.mark.parametrize("missing", ALL_THREE)
def test_any_missing_trigger_stops_startup(missing):
    """Each one individually, because each covers a different family of object id.

    Parameterised rather than tested as a set: a check that only looked for one of the three would
    pass a set-based test that removed all three, and folder ids in particular are easy to think of
    as unimportant -- they are not, because deleting a folder never removes its directory.
    """
    present = [t for t in ALL_THREE if t != missing]
    with pytest.raises(RuntimeError) as caught:
        _verifier()(_Db(present=present))
    assert missing in str(caught.value)
    for other in present:
        assert other not in str(caught.value), "the message names a trigger that is present"


def test_a_disabled_trigger_does_not_count_as_present():
    """`ALTER TABLE ... DISABLE TRIGGER` leaves the row in pg_trigger.

    A name-only lookup passed while nothing was being recorded -- demonstrated on a live database
    during review. The trigger is there, the check is happy, and every deletion frees its id.
    """
    rows = [("trg_files_retire", "files", "D"),
            ("trg_folders_retire", "folders", "O"),
            ("trg_vaults_retire", "vaults", "O")]
    with pytest.raises(RuntimeError) as caught:
        _verifier()(_Db(rows=rows))
    assert "trg_files_retire" in str(caught.value)


def test_a_trigger_on_the_wrong_table_does_not_count():
    """pg_trigger names are not unique across the database.

    A same-named trigger on any unrelated table satisfied the original lookup. The check has to
    say which relation it expects, or it is asserting that a name exists somewhere.
    """
    rows = [("trg_files_retire", "some_other_table", "O"),
            ("trg_folders_retire", "folders", "O"),
            ("trg_vaults_retire", "vaults", "O")]
    with pytest.raises(RuntimeError) as caught:
        _verifier()(_Db(rows=rows))
    assert "trg_files_retire" in str(caught.value)


def test_a_replica_only_trigger_is_still_accepted():
    """`ENABLE ALWAYS` reports 'A', and that is the state this deployment wants.

    Pinned so a future tightening of the check does not reject the very configuration the
    migration deliberately sets.
    """
    rows = [(n, r, "A") for n, r in _Db.RELATION.items()]
    _verifier()(_Db(rows=rows))


def test_a_database_that_cannot_answer_is_not_a_pass():
    """Fail closed. A query that errors says nothing about whether the triggers exist, and
    treating "I could not check" as "it is fine" is how the check becomes decoration."""
    with pytest.raises(RuntimeError) as caught:
        _verifier()(_Db(raises=OSError("connection reset")))
    assert "connection reset" in str(caught.value)


def test_the_failure_escapes_the_migration_routine():
    """The property the whole file exists for, and the one it did not check.

    The call used to be the last line INSIDE `_run_lightweight_migrations`'s own
    `try: ... except Exception: print(...)`. So it raised, the routine swallowed it, printed a
    warning in the same format it uses for a skipped column addition, and the application served
    without the triggers -- which is precisely the outcome this check exists to prevent. Every
    other test in this file passed throughout.

    Checked structurally: the call must not sit inside any `try` whose handler does not re-raise.
    """
    import ast

    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and getattr(n.func, "id", "") == "_verify_retired_object_id_triggers"]
    assert calls, "nothing calls the verifier"

    for call in calls:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            if not (node.lineno <= call.lineno <= (node.end_lineno or 0)):
                continue
            # An enclosing try is only acceptable if every handler that could catch a RuntimeError
            # re-raises it.
            for handler in node.handlers:
                catches_everything = handler.type is None or (
                    getattr(handler.type, "id", "") in ("Exception", "BaseException", "RuntimeError"))
                if not catches_everything:
                    continue
                reraises = any(isinstance(b, ast.Raise) for b in ast.walk(handler))
                assert reraises, (
                    f"the verifier call on line {call.lineno} is inside a try at line "
                    f"{node.lineno} whose handler swallows the failure -- a deployment missing "
                    "the triggers would print a warning and serve anyway")


def test_the_check_is_actually_wired_into_startup():
    """The function can be perfect and never called.

    Asserted against the source because the call sits inside the migration routine, which needs a
    live database to run -- and the failure this guards against is somebody deleting one line.
    """
    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    # A whole LINE that is exactly the call. Substring presence is not enough and that is not
    # hypothetical -- a mutation replacing the call with `pass  # _verify_...(db)` passed this
    # test, because the commented-out text still contains the string it was looking for.
    called = [ln for ln in source.splitlines()
              if ln.strip().startswith("_verify_retired_object_id_triggers(")
              and ln.strip().endswith(")")]
    assert called, (
        "the trigger self-test is defined but nothing calls it (a commented-out or disabled call "
        "does not count)")
    # Deliberately NOT asserting that the call appears after the DDL text. That comparison looks
    # like an ordering check and is not one: the DDL string lives in a list literal far above the
    # block that executes it, so moving the call to run BEFORE the statements are applied left the
    # assertion true. The AST test above is what actually constrains placement.
