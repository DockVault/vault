"""The legal hold's kept tables and triggers, offline (app/core/kept_tables.py).

What a hold keeps is kept by the database: the kept tables are built from the live ones and aligned at every
start, the trigger functions are generated from the live tables' columns, and the start refuses to serve unless
every trigger is there, on its table, of its kind, ENABLE ALWAYS, calling the function made for the columns the
table has now. These check the generated SQL, the alignment, the start's check against a catalog with each fault
in turn, its wiring into the start, the reason and actor the deleting code gives, and the kept models (their
names open as the live rows' do). test_kept_tables_live.py runs the triggers on Postgres.
"""
import ast
import tempfile
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import kept_tables as kt  # noqa: E402
from app.core import models as m  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent

FILES = [("id", "uuid", True), ("name", "character varying(255)", False), ("vault_id", "uuid", True),
         ("folder_id", "uuid", False), ("size_bytes", "bigint", True), ("storage_path", "character varying(512)", True),
         ("encryption_metadata", "json", False), ("enc_name", "text", False)]
FOLDERS = [("id", "uuid", True), ("name", "character varying(255)", False), ("enc_name", "text", False),
           ("vault_id", "uuid", True), ("parent_folder_id", "uuid", False), ("name_key_version", "integer", False)]


class _Rows:
    def __init__(self, rows):
        self._rows = list(rows)

    def fetchall(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class _Catalog:
    """A session answering kept_tables' catalog reads from dicts, as Postgres would."""

    def __init__(self, live=None, kept=None, triggers=None, functions=None, keyed=("held_files", "held_folders")):
        self.keyed = set(keyed)       # the kept tables that have their primary key
        self.columns = {"files": list(FILES), "folders": list(FOLDERS)}
        self.columns.update(live or {})
        self.columns.update(kept if kept is not None else {
            "held_files": [(n, k, False) for n, k, _ in self.columns["files"]] +
                          [(n, k, False) for n, k in kt.EXTRA_COLUMNS],
            "held_folders": [(n, k, False) for n, k, _ in self.columns["folders"]] +
                            [(n, k, False) for n, k in kt.EXTRA_COLUMNS]})
        self.triggers = triggers if triggers is not None else _healthy_triggers()
        self.functions = functions if functions is not None else kt.function_bodies(
            {"files": [c[0] for c in FILES], "folders": [c[0] for c in FOLDERS]})
        self.executed = []

    def execute(self, statement, params=None):
        sql = str(statement)
        self.executed.append(sql)
        if "FROM pg_attribute" in sql:
            return _Rows(self.columns.get(params["t"], []))
        if "FROM pg_trigger" in sql:
            return _Rows(row for name, row in self.triggers.items() if name in params["names"])
        if "FROM pg_proc" in sql:
            return _Rows((n, b) for n, b in self.functions.items() if n in params["names"])
        if "FROM pg_constraint" in sql:
            return _Rows([(1,)] if params["t"] in self.keyed else [])
        return _Rows([])


# How Postgres prints the rename triggers' WHEN clause (pg_get_triggerdef): casts to text, more parentheses.
PRINTED_WHEN = ("(((old.name)::text IS DISTINCT FROM (new.name)::text) OR "
                "(old.enc_name IS DISTINCT FROM new.enc_name))")


def _definition(t, when=None):
    columns = f"UPDATE OF {', '.join(t.columns)} " if t.columns else ""
    clause = f"FOR EACH ROW WHEN {when or PRINTED_WHEN} " if t.when else ""
    return f"CREATE TRIGGER {t.name} AFTER {columns}ON public.{t.table} {clause}EXECUTE FUNCTION {t.function}()"


def _healthy_triggers():
    return {t.name: (t.name, t.table, "A", t.tgtype, t.function, t.old_table, _definition(t)) for t in kt.TRIGGERS}


def _with(name, **change):
    rows = _healthy_triggers()
    fields = ["name", "table", "enabled", "tgtype", "function", "old_table", "definition"]
    row = dict(zip(fields, rows[name]))
    row.update(change)
    rows[name] = tuple(row[f] for f in fields)
    return rows


# --------------------------------------------------------------------------- the generated SQL

def test_the_keep_function_copies_every_live_column_in_order_for_held_vaults_only():
    body = kt.keep_function_body("files", "held_files", [c[0] for c in FILES])
    target = ", ".join(f'"{c[0]}"' for c in FILES)
    source = ", ".join(f'd."{c[0]}"' for c in FILES)
    assert f"INSERT INTO held_files ({target}, kept_at, kept_reason, kept_by)" in body
    # The deleting statement's time, which comes after the vault lock it waits for: not its transaction's start.
    assert f"SELECT {source}, (statement_timestamp() AT TIME ZONE 'utc'), why, left(who, 64)" in body
    assert "FROM deleted d" in body
    assert ("WHERE EXISTS (SELECT 1 FROM legal_hold_vaults h WHERE h.vault_id = d.vault_id "
            "AND h.released_at IS NULL)") in body
    assert f"-- columns: {kt.signature([c[0] for c in FILES])}" in body


def test_the_reason_is_one_the_code_gives_else_deleted_and_the_actor_comes_from_its_setting():
    body = kt.keep_function_body("folders", "held_folders", ["id", "vault_id"])
    assert "why text := current_setting('dockvault.delete_reason', true);" in body
    assert "who text := NULLIF(current_setting('dockvault.actor', true), '');" in body
    assert "IF why IS NULL OR why NOT IN ('replaced', 'expired', 'moved', 'duplicate') THEN" in body
    assert "why := 'deleted';" in body
    assert kt.REASONS == ("deleted", "replaced", "expired", "moved", "duplicate")


def test_a_new_column_changes_the_signature():
    assert kt.signature(["id", "a"]) != kt.signature(["id", "a", "b"])
    assert kt.signature(["id", "a"]) != kt.signature(["a", "id"])


def test_the_rename_functions_keep_the_old_sealed_name_of_a_held_vaults_object():
    bodies = kt.function_bodies({"files": ["id"], "folders": ["id"]})
    for kind, name in (("file", "dv_keep_file_name"), ("folder", "dv_keep_folder_name")):
        body = bodies[name]
        assert ("IF EXISTS (SELECT 1 FROM legal_hold_vaults h WHERE h.vault_id = OLD.vault_id "
                "AND h.released_at IS NULL) THEN") in body
        assert f"VALUES (gen_random_uuid(), OLD.id, OLD.vault_id, '{kind}', OLD.name, OLD.enc_name, " in body
    assert "OLD.name_key_version" in bodies["dv_keep_folder_name"]
    assert "(OLD.encryption_metadata ->> 'key_version')::integer" in bodies["dv_keep_file_name"]


def test_the_vault_trigger_refuses_a_held_vault_or_one_with_kept_rows_and_lets_others_go():
    body = kt.VAULT_FUNCTION_BODY
    assert "SELECT 1 FROM legal_hold_vaults h WHERE h.vault_id = OLD.id AND h.released_at IS NULL" in body
    assert "SELECT 1 FROM held_files k WHERE k.vault_id = OLD.id" in body
    assert "SELECT 1 FROM held_folders k WHERE k.vault_id = OLD.id" in body
    assert "RAISE EXCEPTION" in body and f"HINT = '{kt.HOLD_HINT}'" in body
    assert body.rstrip().endswith("RETURN OLD;\nEND")


def test_each_trigger_is_made_enable_always_and_of_its_kind():
    ddl = {t.name: t.ddl() for t in kt.TRIGGERS}
    for t in kt.TRIGGERS:
        assert ddl[t.name][1] == f"ALTER TABLE {t.table} ENABLE ALWAYS TRIGGER {t.name}"
        assert ddl[t.name][0].startswith(f"CREATE OR REPLACE TRIGGER {t.name} ")
        assert ddl[t.name][0].endswith(f"EXECUTE FUNCTION {t.function}()")
    assert ("AFTER DELETE ON files REFERENCING OLD TABLE AS deleted FOR EACH STATEMENT"
            in ddl["trg_files_keep"][0])
    assert ("AFTER DELETE ON folders REFERENCING OLD TABLE AS deleted FOR EACH STATEMENT"
            in ddl["trg_folders_keep"][0])
    assert "BEFORE DELETE ON vaults FOR EACH ROW" in ddl["trg_vaults_hold"][0]
    assert ("AFTER UPDATE OF name, enc_name ON files FOR EACH ROW WHEN (OLD.name IS DISTINCT FROM NEW.name "
            "OR OLD.enc_name IS DISTINCT FROM NEW.enc_name)") in ddl["trg_files_keep_name"][0]
    for table in ("files", "folders", "vaults"):
        assert f"BEFORE TRUNCATE ON {table} FOR EACH STATEMENT" in ddl[f"trg_{table}_hold_truncate"][0]
    assert {t.table for t in kt.TRIGGERS} == {"files", "folders", "vaults"}


# --------------------------------------------------------------------------- the alignment

def test_the_alignment_adds_what_is_missing_changes_types_and_drops_not_null_but_on_id():
    live = [("id", "uuid", True), ("a", "text", True), ("b", "character varying(64)", False),
            ("c", "integer", False)]
    kept = [("id", "uuid", True), ("a", "text", True), ("b", "character varying(32)", False),
            ("kept_at", "timestamp without time zone", False)]
    out = kt.alignment(live, kept)
    assert 'ALTER TABLE {table} ADD COLUMN "c" integer' in out
    assert 'ALTER TABLE {table} ALTER COLUMN "b" TYPE character varying(64) USING "b"::character varying(64)' in out
    assert 'ALTER TABLE {table} ALTER COLUMN "a" DROP NOT NULL' in out
    assert not any('"id" DROP NOT NULL' in s for s in out)
    for name, kind in kt.EXTRA_COLUMNS[1:]:
        assert f'ALTER TABLE {{table}} ADD COLUMN "{name}" {kind}' in out
    assert not any('ADD COLUMN "kept_at"' in s for s in out)


def test_an_aligned_table_needs_nothing():
    live = [("id", "uuid", True), ("a", "text", False)]
    kept = [("id", "uuid", True), ("a", "text", False)] + [(n, k, False) for n, k in kt.EXTRA_COLUMNS]
    assert kt.alignment(live, kept) == []


def test_install_builds_missing_kept_tables_like_the_live_ones_then_the_functions_then_the_triggers():
    db = _Catalog(kept={"held_files": [], "held_folders": []})
    kt.install(db)
    sql = db.executed
    creates = [s for s in sql if s.startswith("CREATE TABLE")]
    assert creates == ["CREATE TABLE IF NOT EXISTS held_files (LIKE files)",
                       "CREATE TABLE IF NOT EXISTS held_folders (LIKE folders)"]
    first_function = min(i for i, s in enumerate(sql) if s.startswith("CREATE OR REPLACE FUNCTION"))
    first_trigger = min(i for i, s in enumerate(sql) if s.startswith("CREATE OR REPLACE TRIGGER"))
    assert first_function < first_trigger
    for name, body in kt.function_bodies({"files": [c[0] for c in FILES],
                                          "folders": [c[0] for c in FOLDERS]}).items():
        assert kt.function_ddl(name, body) in sql
    for t in kt.TRIGGERS:
        for statement in t.ddl():
            assert statement in sql
    assert "CREATE INDEX IF NOT EXISTS idx_held_files_storage_path ON held_files (storage_path)" in sql


def test_install_gives_a_kept_table_its_primary_key_once():
    db = _Catalog(keyed=("held_folders",))
    kt.install(db)
    assert db.executed.count("ALTER TABLE held_files ADD PRIMARY KEY (id)") == 1
    assert "ALTER TABLE held_folders ADD PRIMARY KEY (id)" not in db.executed


def test_install_refuses_without_the_live_table():
    db = _Catalog(live={"files": []})
    with pytest.raises(RuntimeError):
        kt.install(db)


# --------------------------------------------------------------------------- the start's check

def test_a_healthy_catalog_has_no_problems():
    assert kt.problems(_Catalog()) == []


@pytest.mark.parametrize("trigger", [t.name for t in kt.TRIGGERS])
def test_a_missing_trigger_is_a_problem(trigger):
    rows = _healthy_triggers()
    del rows[trigger]
    assert any(trigger in p and "missing" in p for p in kt.problems(_Catalog(triggers=rows)))


@pytest.mark.parametrize("state", ["O", "D", "R"])
@pytest.mark.parametrize("trigger", ["trg_files_keep", "trg_folders_keep", "trg_vaults_hold", "trg_files_keep_name"])
def test_a_trigger_that_is_not_enable_always_is_a_problem(trigger, state):
    problems = kt.problems(_Catalog(triggers=_with(trigger, enabled=state)))
    assert any(trigger in p and "ENABLE ALWAYS" in p for p in problems)


@pytest.mark.parametrize("change, words", [
    ({"table": "vaults"}, "is on vaults"),
    ({"function": "dv_noop"}, "calls dv_noop"),
    ({"tgtype": 9}, "wrong time"),
    ({"old_table": None}, "does not read the deleted rows"),
])
def test_a_trigger_on_the_wrong_table_calling_another_function_or_of_the_wrong_kind_is_a_problem(change, words):
    problems = kt.problems(_Catalog(triggers=_with("trg_files_keep", **change)))
    assert any("trg_files_keep" in p and words in p for p in problems), problems


@pytest.mark.parametrize("when", ["(false)", "((old.name)::text IS DISTINCT FROM (new.name)::text)",
                                  "(((old.name)::text IS DISTINCT FROM (new.name)::text) AND "
                                  "(old.enc_name IS DISTINCT FROM new.enc_name))",
                                  "((((old.name)::text IS DISTINCT FROM (new.name)::text) OR "
                                  "(old.enc_name IS DISTINCT FROM new.enc_name)) AND false)", None])
def test_a_rename_trigger_whose_when_clause_is_not_the_one_install_writes_is_a_problem(when):
    """Same table, kind, columns and function, ENABLE ALWAYS: only the WHEN clause differs (or is gone), and a
    rename would then keep no old name."""
    trigger = next(t for t in kt.TRIGGERS if t.name == "trg_files_keep_name")
    definition = _definition(trigger, when) if when else _definition(trigger).replace(f"WHEN {PRINTED_WHEN} ", "")
    found = kt.problems(_Catalog(triggers=_with("trg_files_keep_name", definition=definition)))
    assert any("trg_files_keep_name" in p and "WHEN clause" in p for p in found), found


def test_the_when_clause_install_writes_and_the_one_postgres_prints_compare_equal():
    for trigger in (t for t in kt.TRIGGERS if t.when):
        assert kt.when_text(PRINTED_WHEN) == kt.when_text(trigger.when)
        assert kt._when_of(_definition(trigger)) == PRINTED_WHEN
    assert kt.when_text("(false)") != kt.when_text(kt.TRIGGERS[3].when)
    assert kt._when_of("CREATE TRIGGER x AFTER DELETE ON public.files EXECUTE FUNCTION f()") is None


def test_a_rename_trigger_on_other_columns_is_a_problem():
    rows = _with("trg_folders_keep_name", definition="CREATE TRIGGER trg_folders_keep_name AFTER UPDATE OF name "
                 "ON public.folders FOR EACH ROW EXECUTE FUNCTION dv_keep_folder_name()")
    assert any("trg_folders_keep_name" in p and "name, enc_name" in p for p in kt.problems(_Catalog(triggers=rows)))


def test_a_kept_table_missing_a_live_column_or_of_another_type_is_a_problem():
    kept = _Catalog().columns
    short = {"held_files": [c for c in kept["held_files"] if c[0] != "storage_path"],
             "held_folders": kept["held_folders"]}
    assert any("held_files.storage_path" in p for p in kt.problems(_Catalog(kept=short)))
    other = {"held_files": [(n, "text" if n == "size_bytes" else k, nn) for n, k, nn in kept["held_files"]],
             "held_folders": kept["held_folders"]}
    assert any("held_files.size_bytes" in p for p in kt.problems(_Catalog(kept=other)))
    no_extra = {"held_files": [c for c in kept["held_files"] if c[0] != "kept_reason"],
                "held_folders": kept["held_folders"]}
    assert any("held_files.kept_reason" in p for p in kt.problems(_Catalog(kept=no_extra)))
    gone = {"held_files": kept["held_files"], "held_folders": []}
    assert any("held_folders is missing" in p for p in kt.problems(_Catalog(kept=gone)))


def test_a_function_not_made_for_the_columns_the_table_has_now_is_a_problem():
    # files gained a column after the functions were generated (a later statement, a manual change).
    later = FILES + [("added_later", "text", False)]
    kept = _Catalog().columns
    kept_now = {"held_files": kept["held_files"] + [("added_later", "text", False)],
                "held_folders": kept["held_folders"]}
    problems = kt.problems(_Catalog(live={"files": later}, kept=kept_now))
    assert problems == ["the function dv_keep_files is missing, or was not made for the columns its table has now"]


@pytest.mark.parametrize("function", ["dv_keep_files", "dv_keep_folders", "dv_keep_file_name",
                                      "dv_keep_folder_name", "dv_hold_vault_delete", "dv_hold_no_truncate"])
def test_a_missing_or_changed_function_is_a_problem(function):
    healthy = _Catalog().functions
    gone = {n: b for n, b in healthy.items() if n != function}
    assert any(function in p for p in kt.problems(_Catalog(functions=gone)))
    changed = dict(healthy, **{function: "\nBEGIN\n    RETURN NULL;\nEND\n"})
    assert any(function in p for p in kt.problems(_Catalog(functions=changed)))


def test_verify_stops_the_start_with_the_problems_or_when_the_database_cannot_answer():
    kt.verify(_Catalog())
    rows = _healthy_triggers()
    del rows["trg_vaults_hold"]
    with pytest.raises(RuntimeError, match="trg_vaults_hold"):
        kt.verify(_Catalog(triggers=rows))

    class _Broken:
        def execute(self, *_a, **_k):
            raise ConnectionError("gone")

    with pytest.raises(RuntimeError, match="Could not check the legal hold triggers"):
        kt.verify(_Broken())


# --------------------------------------------------------------------------- wired into the start

def _api_source():
    return (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")


def test_the_start_calls_the_check_on_a_line_of_its_own_outside_any_try_that_swallows_it():
    source = _api_source()
    lines = [ln.strip() for ln in source.splitlines()]
    assert lines.count("_kept_tables.verify(_db)") == 1
    tree = ast.parse(source)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "verify" and getattr(n.func.value, "id", "") == "_kept_tables"]
    assert len(calls) == 1
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and node.lineno <= calls[0].lineno <= (node.end_lineno or 0):
            for handler in node.handlers:
                broad = handler.type is None or getattr(handler.type, "id", "") in (
                    "Exception", "BaseException", "RuntimeError")
                assert not broad or any(isinstance(b, ast.Raise) for b in ast.walk(handler)), node.lineno


def test_the_start_installs_after_every_column_statement_and_checks_after_installing():
    source = _api_source()
    body = source.split("\ndef _run_lightweight_migrations(", 1)[1].split("\ndef ", 1)[0]
    assert body.index("for stmt in statements:") < body.index("kept_tables.install(db)") \
        < body.index("_kept_tables.verify(_db)")
    # In the same function as the retired-id check, after it.
    assert body.index("_verify_retired_object_id_triggers(_db)") < body.index("_kept_tables.verify(_db)")


# --------------------------------------------------------------------------- what the deleting code says

class _Bound:
    def __init__(self, dialect):
        self.dialect = type("D", (), {"name": dialect})()


class _Session:
    def __init__(self, dialect):
        self.bind, self.calls = _Bound(dialect), []

    def get_bind(self):
        return self.bind

    def execute(self, statement, params=None):
        self.calls.append((str(statement), params))


def test_mark_deletes_sets_the_reason_and_actor_for_the_transaction_on_postgres():
    db = _Session("postgresql")
    uid = uuid.uuid4()
    kt.mark_deletes(db, "replaced", type("U", (), {"id": uid})())
    sql, params = db.calls[0]
    assert sql == ("SELECT set_config('dockvault.delete_reason', :why, true), "
                   "set_config('dockvault.actor', :who, true)")
    assert params == {"why": "replaced", "who": str(uid)}
    kt.mark_deletes(db, "expired")
    assert db.calls[1][1] == {"why": "expired", "who": "system"}


def test_mark_deletes_refuses_a_reason_the_kept_rows_do_not_know_and_does_nothing_elsewhere():
    with pytest.raises(ValueError):
        kt.mark_deletes(_Session("postgresql"), "purged")
    db = _Session("sqlite")
    kt.mark_deletes(db, "deleted")
    assert db.calls == []

    class _NoBind:
        def get_bind(self):
            raise RuntimeError("no database")

    kt.mark_deletes(_NoBind(), "deleted")


def test_the_actor_is_an_accounts_id_in_one_form():
    uid = uuid.uuid4()
    assert kt.actor_text(None) == "system"
    assert kt.actor_text(uid) == kt.actor_text(str(uid).upper()) == kt.actor_text(type("U", (), {"id": uid})())
    assert kt.actor_text(uid) == str(uid)


# --------------------------------------------------------------------------- the kept models

def test_create_all_never_builds_the_kept_tables():
    assert "held_files" not in m.Base.metadata.tables and "held_folders" not in m.Base.metadata.tables
    assert set(m.KeptBase.metadata.tables) == {"held_files", "held_folders"}
    for model in (m.HeldFile, m.HeldFolder):
        assert not model.__table__.foreign_keys
        assert not [i for i in model.__table__.indexes if i.unique]


def test_the_kept_models_map_the_live_models_columns_and_the_kept_ones():
    for live, kept in ((m.File, m.HeldFile), (m.Folder, m.HeldFolder)):
        assert set(live.__table__.columns.keys()) <= set(kept.__table__.columns.keys())
        assert {n for n, _ in kt.EXTRA_COLUMNS} <= set(kept.__table__.columns.keys())


@pytest.fixture
def factory():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'kept.db'}")
        m.KeptBase.metadata.create_all(engine)
        m.Base.metadata.create_all(engine, tables=[m.Base.metadata.tables["held_name_history"]])
        make = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        made = []

        def session():
            made.append(make())
            return made[-1]

        yield session
        for s in made:
            s.close()
        engine.dispose()


def test_a_kept_files_name_mime_and_checksum_open_as_the_live_rows_do(factory):
    from app.core.security import encrypt_object_field
    vault_id, file_id = uuid.uuid4(), uuid.uuid4()
    db = factory()
    db.add(m.HeldFile(id=file_id, vault_id=vault_id, storage_path="x", size_bytes=3,
                      enc_name=encrypt_object_field(vault_id, file_id, "minutes.pdf", "name"),
                      enc_mime=encrypt_object_field(vault_id, file_id, "application/pdf", "mime"),
                      enc_checksum=encrypt_object_field(vault_id, file_id, "ab" * 32, "checksum")))
    folder_id = uuid.uuid4()
    db.add(m.HeldFolder(id=folder_id, vault_id=vault_id,
                        enc_name=encrypt_object_field(vault_id, folder_id, "Board", "name")))
    db.commit()
    db2 = factory()
    kept = db2.get(m.HeldFile, file_id)
    assert (kept.original_name, kept.name, kept.mime_type, kept.checksum_sha256) == \
        ("minutes.pdf", "minutes.pdf", "application/pdf", "ab" * 32)
    assert db2.get(m.HeldFolder, folder_id).name == "Board"


def test_a_kept_old_name_opens_with_the_renamed_objects_id(factory):
    from app.core.security import encrypt_object_field
    vault_id, object_id, row_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    db = factory()
    db.add(m.HeldNameHistory(id=row_id, object_id=object_id, vault_id=vault_id, kind="file",
                             enc_name=encrypt_object_field(vault_id, object_id, "before.txt", "name")))
    db.commit()
    assert factory().get(m.HeldNameHistory, row_id).name == "before.txt"
    # Sealed for another object, it does not open, and the load still succeeds.
    other = uuid.uuid4()
    db.add(m.HeldNameHistory(id=other, object_id=uuid.uuid4(), vault_id=vault_id, kind="file",
                             enc_name=encrypt_object_field(vault_id, object_id, "before.txt", "name")))
    db.commit()
    assert factory().get(m.HeldNameHistory, other).name is None


def test_the_inventory_names_the_kept_tables():
    text = (ROOT / "docs" / "data-inventory.md").read_text(encoding="utf-8")
    rows = [ln for ln in text.splitlines() if ln.startswith("| `")]
    first_cells = " ".join(ln.split("|")[1] for ln in rows)
    for table in m.KeptBase.metadata.tables:
        assert f"`{table}`" in first_cells, table
