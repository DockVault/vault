"""Keep what is deleted from a vault under a legal hold: the kept tables, the triggers that fill them, and the
start's check that they stand.

While a vault is under a legal hold (a row of ``legal_hold_vaults`` whose ``released_at`` is NULL), every file or
folder row deleted from it is copied, in the deleting transaction, into ``held_files`` or ``held_folders``, with
when, why and by whom it was deleted. The database does it, not the code at each delete site: a statement-level
AFTER DELETE trigger on ``files`` and one on ``folders`` read the deleted rows from their transition table. So a
row removed by any path is kept, those with no Python site to hook included: the cascades from
``files.folder_id`` and ``folders.parent_folder_id``, the ORM's delete-orphan cascades, a bulk delete, the
expiry sweep, a cross-vault move, a same-name replacement, the start's duplicate collapse, the SFTP server, and
any path written later. For the people using the vault the deletion is done: the row is gone from ``files``,
the vault's counters drop, links and shares on it go. The stored bytes stay on disk: every destruction of a
committed blob asks the kept table first (kept_rows, from VaultService._destroy_blobs).

The kept tables are built from the live ones (``CREATE TABLE held_files (LIKE files)``: every column, no
foreign key, no unique index), not from the models, because the start adds columns to ``files`` and
``folders`` that the models do not declare. At every start install() brings them in line: a column the live
table gained is added (nullable: older kept rows have no value for it), a type that changed is changed, and no
column but ``id`` refuses a NULL. The trigger functions are generated then with the explicit list of the live
columns, in one transaction with the triggers themselves, so there is never a moment without them.

The other triggers:
- ``vaults``, BEFORE DELETE, per row: refuses to delete a vault under a hold, or one whose kept rows still
  wait for their purge. Deleting a vault removes its directory, kept blobs and all.
- ``files`` and ``folders``, AFTER UPDATE OF name, enc_name, per row: a rename in a held vault keeps the old
  sealed name in ``held_name_history``. Audit rows carry no names, so it would otherwise be lost.
- ``files``, ``folders`` and ``vaults``, BEFORE TRUNCATE: refused while any hold stands or kept rows remain.

Every trigger is ENABLE ALWAYS, so it fires under ``session_replication_role = replica`` too (a logical
replication worker, ``pg_restore --disable-triggers``), and the start refuses to serve unless each one is there,
on its table, of its kind, enabled always and calling the function generated for the columns the table has now
(verify()).

The deleting code says why and as whom through two transaction-local settings (mark_deletes):
``dockvault.delete_reason`` (``deleted`` when unset; ``replaced``, ``expired``, ``moved``, ``duplicate``) and
``dockvault.actor`` (an account's id, or ``system``).
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Iterable, Optional

from sqlalchemy import text

# The live tables and the tables that keep their deleted rows.
KEPT = (("files", "held_files"), ("folders", "held_folders"))
# What a kept table has beyond the live table's columns.
EXTRA_COLUMNS = (("kept_at", "timestamp without time zone"),
                 ("kept_reason", "character varying(16)"),
                 ("kept_by", "character varying(64)"),
                 ("purge_after", "timestamp without time zone"))
REASONS = ("deleted", "replaced", "expired", "moved", "duplicate")
DEFAULT_REASON = "deleted"
REASON_SETTING = "dockvault.delete_reason"
ACTOR_SETTING = "dockvault.actor"
SYSTEM_ACTOR = "system"
# What a refusal under a hold says, as the error's hint, so the code that sees it can answer 409.
HOLD_HINT = "dockvault-legal-hold"

# pg_trigger.tgtype bits.
_ROW, _BEFORE, _DELETE, _UPDATE, _TRUNCATE = 1, 2, 8, 16, 32

# The live hold on a vault, as every trigger reads it.
_LIVE_HOLD = "SELECT 1 FROM legal_hold_vaults h WHERE h.vault_id = {vault} AND h.released_at IS NULL"


class Trigger:
    def __init__(self, name, table, function, tgtype, *, old_table=None, columns=None, when=None):
        self.name, self.table, self.function, self.tgtype = name, table, function, tgtype
        self.old_table, self.columns, self.when = old_table, columns, when

    def ddl(self) -> list:
        if self.tgtype == _DELETE:
            timing = f"AFTER DELETE ON {self.table} REFERENCING OLD TABLE AS {self.old_table} FOR EACH STATEMENT"
        elif self.tgtype == _ROW | _BEFORE | _DELETE:
            timing = f"BEFORE DELETE ON {self.table} FOR EACH ROW"
        elif self.tgtype == _ROW | _UPDATE:
            timing = (f"AFTER UPDATE OF {', '.join(self.columns)} ON {self.table} FOR EACH ROW "
                      f"WHEN ({self.when})")
        elif self.tgtype == _BEFORE | _TRUNCATE:
            timing = f"BEFORE TRUNCATE ON {self.table} FOR EACH STATEMENT"
        else:  # pragma: no cover -- every trigger above is one of these
            raise ValueError(self.tgtype)
        return [f"CREATE OR REPLACE TRIGGER {self.name} {timing} EXECUTE FUNCTION {self.function}()",
                # ENABLE ALWAYS, not the default ORIGIN: an ORIGIN trigger does not fire under
                # session_replication_role = replica, which a replication worker and a restore run as.
                f"ALTER TABLE {self.table} ENABLE ALWAYS TRIGGER {self.name}"]


_NAME_CHANGED = "OLD.name IS DISTINCT FROM NEW.name OR OLD.enc_name IS DISTINCT FROM NEW.enc_name"

TRIGGERS = (
    Trigger("trg_files_keep", "files", "dv_keep_files", _DELETE, old_table="deleted"),
    Trigger("trg_folders_keep", "folders", "dv_keep_folders", _DELETE, old_table="deleted"),
    Trigger("trg_vaults_hold", "vaults", "dv_hold_vault_delete", _ROW | _BEFORE | _DELETE),
    Trigger("trg_files_keep_name", "files", "dv_keep_file_name", _ROW | _UPDATE, columns=("name", "enc_name"),
            when=_NAME_CHANGED),
    Trigger("trg_folders_keep_name", "folders", "dv_keep_folder_name", _ROW | _UPDATE,
            columns=("name", "enc_name"), when=_NAME_CHANGED),
    Trigger("trg_files_hold_truncate", "files", "dv_hold_no_truncate", _BEFORE | _TRUNCATE),
    Trigger("trg_folders_hold_truncate", "folders", "dv_hold_no_truncate", _BEFORE | _TRUNCATE),
    Trigger("trg_vaults_hold_truncate", "vaults", "dv_hold_no_truncate", _BEFORE | _TRUNCATE),
)


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


# --------------------------------------------------------------------------- the generated functions

def keep_function_body(live: str, kept: str, columns: Iterable[str]) -> str:
    """The body of the function that copies the rows deleted from ``live`` into ``kept``: every column of
    ``columns`` (the live table's, in order), the time, the reason and the actor, for the rows of vaults under
    a hold."""
    columns = list(columns)
    target = ", ".join(_q(c) for c in columns)
    source = ", ".join("d." + _q(c) for c in columns)
    reasons = ", ".join(f"'{r}'" for r in REASONS if r != DEFAULT_REASON)
    return (
        "\nDECLARE\n"
        f"    why text := current_setting('{REASON_SETTING}', true);\n"
        f"    who text := NULLIF(current_setting('{ACTOR_SETTING}', true), '');\n"
        "BEGIN\n"
        f"    -- columns: {signature(columns)}\n"
        f"    IF why IS NULL OR why NOT IN ({reasons}) THEN\n"
        f"        why := '{DEFAULT_REASON}';\n"
        "    END IF;\n"
        f"    INSERT INTO {kept} ({target}, kept_at, kept_reason, kept_by)\n"
        f"    SELECT {source}, (now() AT TIME ZONE 'utc'), why, left(who, 64)\n"
        "    FROM deleted d\n"
        f"    WHERE EXISTS ({_LIVE_HOLD.format(vault='d.vault_id')});\n"
        "    RETURN NULL;\n"
        "END\n")


def signature(columns: Iterable[str]) -> str:
    """A short digest of a column list, written into the generated function so a reader can tell which
    columns it was made for."""
    return hashlib.sha256("\n".join(columns).encode("utf-8")).hexdigest()[:16]


def _name_function_body(kind: str) -> str:
    epoch = ("CASE WHEN (OLD.encryption_metadata ->> 'key_version') ~ '^[0-9]{1,9}$' "
             "THEN (OLD.encryption_metadata ->> 'key_version')::integer END" if kind == "file"
             else "OLD.name_key_version")
    return (
        "\nBEGIN\n"
        f"    IF EXISTS ({_LIVE_HOLD.format(vault='OLD.vault_id')}) THEN\n"
        "        INSERT INTO held_name_history (id, object_id, vault_id, kind, name, enc_name, name_key_version, "
        "renamed_at)\n"
        f"        VALUES (gen_random_uuid(), OLD.id, OLD.vault_id, '{kind}', OLD.name, OLD.enc_name, {epoch}, "
        "(now() AT TIME ZONE 'utc'));\n"
        "    END IF;\n"
        "    RETURN NULL;\n"
        "END\n")


VAULT_FUNCTION_BODY = (
    "\nBEGIN\n"
    f"    IF EXISTS ({_LIVE_HOLD.format(vault='OLD.id')})\n"
    "       OR EXISTS (SELECT 1 FROM held_files k WHERE k.vault_id = OLD.id)\n"
    "       OR EXISTS (SELECT 1 FROM held_folders k WHERE k.vault_id = OLD.id) THEN\n"
    "        RAISE EXCEPTION 'vault % is under a legal hold, or keeps files for one until they are purged: it "
    "cannot be deleted', OLD.id\n"
    f"            USING HINT = '{HOLD_HINT}';\n"
    "    END IF;\n"
    "    RETURN OLD;\n"
    "END\n")

TRUNCATE_FUNCTION_BODY = (
    "\nBEGIN\n"
    "    IF EXISTS (SELECT 1 FROM legal_hold_vaults h WHERE h.released_at IS NULL)\n"
    "       OR EXISTS (SELECT 1 FROM held_files) OR EXISTS (SELECT 1 FROM held_folders) THEN\n"
    "        RAISE EXCEPTION '% cannot be emptied while a legal hold stands or kept rows wait for their purge', "
    "TG_TABLE_NAME\n"
    f"            USING HINT = '{HOLD_HINT}';\n"
    "    END IF;\n"
    "    RETURN NULL;\n"
    "END\n")


def function_bodies(live_columns: dict) -> dict:
    """{function name: body} for every trigger function, ``live_columns`` being {live table: [columns]}."""
    bodies = {f"dv_keep_{live}": keep_function_body(live, kept, live_columns[live]) for live, kept in KEPT}
    bodies["dv_keep_file_name"] = _name_function_body("file")
    bodies["dv_keep_folder_name"] = _name_function_body("folder")
    bodies["dv_hold_vault_delete"] = VAULT_FUNCTION_BODY
    bodies["dv_hold_no_truncate"] = TRUNCATE_FUNCTION_BODY
    return bodies


def function_ddl(name: str, body: str) -> str:
    return f"CREATE OR REPLACE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $dv${body}$dv$"


# --------------------------------------------------------------------------- the catalog

_COLUMNS_SQL = (
    "SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull FROM pg_attribute a "
    "JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE c.relname = :t AND n.nspname = current_schema() AND a.attnum > 0 AND NOT a.attisdropped "
    "ORDER BY a.attnum")


def columns_of(db, table: str) -> list:
    """[(column, type, not null)] of ``table`` in this schema, in order; empty when there is no such table."""
    return [(r[0], r[1], bool(r[2])) for r in db.execute(text(_COLUMNS_SQL), {"t": table}).fetchall()]


def alignment(live: list, kept: list) -> list:
    """The statements that bring a kept table (``kept``: its columns as columns_of gives them) in line with its
    live table (``live``) and the extra columns: a missing column added, a changed type changed, and no NOT NULL
    but on ``id``. The table's name is put in by the caller (``{table}``)."""
    have = {name: (kind, not_null) for name, kind, not_null in kept}
    out = []
    for name, kind, _not_null in list(live) + [(n, k, False) for n, k in EXTRA_COLUMNS]:
        if name not in have:
            out.append(f"ALTER TABLE {{table}} ADD COLUMN {_q(name)} {kind}")
        elif have[name][0] != kind:
            out.append(f"ALTER TABLE {{table}} ALTER COLUMN {_q(name)} TYPE {kind} USING {_q(name)}::{kind}")
    for name, (_kind, not_null) in have.items():
        if not_null and name != "id":
            out.append(f"ALTER TABLE {{table}} ALTER COLUMN {_q(name)} DROP NOT NULL")
    return out


def _has_primary_key(db, table: str) -> bool:
    return db.execute(text(
        "SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid "
        "JOIN pg_namespace n ON n.oid = t.relnamespace "
        "WHERE t.relname = :t AND n.nspname = current_schema() AND c.contype = 'p'"), {"t": table}).first() is not None


def install(db) -> None:
    """Build or align the kept tables and (re)create every trigger, in ``db``'s transaction (the caller commits
    once, so the triggers are replaced atomically). Postgres only."""
    live_columns = {}
    for live, kept in KEPT:
        live_cols = columns_of(db, live)
        if not live_cols:
            raise RuntimeError(f"the table {live} does not exist")
        live_columns[live] = [c[0] for c in live_cols]
        if not columns_of(db, kept):
            # LIKE copies the columns and their NOT NULL constraints, and nothing else: no foreign key, no
            # unique index, no default.
            db.execute(text(f"CREATE TABLE IF NOT EXISTS {kept} (LIKE {live})"))
        for statement in alignment(live_cols, columns_of(db, kept)):
            db.execute(text(statement.format(table=kept)))
        if not _has_primary_key(db, kept):
            db.execute(text(f"ALTER TABLE {kept} ADD PRIMARY KEY (id)"))
        db.execute(text(f"CREATE INDEX IF NOT EXISTS idx_{kept}_vault ON {kept} (vault_id)"))
    db.execute(text("CREATE INDEX IF NOT EXISTS idx_held_files_storage_path ON held_files (storage_path)"))
    for name, body in function_bodies(live_columns).items():
        db.execute(text(function_ddl(name, body)))
    for trigger in TRIGGERS:
        for statement in trigger.ddl():
            db.execute(text(statement))


# --------------------------------------------------------------------------- the start's check

_TRIGGER_SQL = (
    "SELECT t.tgname, c.relname, t.tgenabled, t.tgtype, p.proname, t.tgoldtable, pg_get_triggerdef(t.oid) "
    "FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE t.tgname = ANY(:names) AND NOT t.tgisinternal AND n.nspname = current_schema()")
_FUNCTION_SQL = (
    "SELECT p.proname, p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
    "WHERE p.proname = ANY(:names) AND n.nspname = current_schema()")


def problems(db) -> list:
    """What is wrong with the kept tables and their triggers, in plain words; empty when nothing is."""
    found = []
    live_columns = {}
    for live, kept in KEPT:
        live_cols = columns_of(db, live)
        live_columns[live] = [c[0] for c in live_cols]
        kept_cols = {name: kind for name, kind, _ in columns_of(db, kept)}
        if not kept_cols:
            found.append(f"the table {kept} is missing")
            continue
        for name, kind, _ in live_cols:
            if kept_cols.get(name) != kind:
                found.append(f"{kept}.{name} is missing or not of the type of {live}.{name} ({kind})")
        for name, kind in EXTRA_COLUMNS:
            if kept_cols.get(name) != kind:
                found.append(f"{kept}.{name} is missing or not {kind}")
    rows = {r[0]: r for r in db.execute(text(_TRIGGER_SQL), {"names": [t.name for t in TRIGGERS]}).fetchall()}
    for trigger in TRIGGERS:
        row = rows.get(trigger.name)
        if row is None:
            found.append(f"the trigger {trigger.name} is missing")
            continue
        _name, relation, enabled, tgtype, function, old_table, definition = row
        if relation != trigger.table:
            found.append(f"the trigger {trigger.name} is on {relation}, not {trigger.table}")
        if enabled != "A":
            found.append(f"the trigger {trigger.name} is not ENABLE ALWAYS (it is {enabled!r})")
        if int(tgtype) != trigger.tgtype:
            found.append(f"the trigger {trigger.name} fires at the wrong time (type {tgtype})")
        if function != trigger.function:
            found.append(f"the trigger {trigger.name} calls {function}, not {trigger.function}")
        if (old_table or None) != trigger.old_table:
            found.append(f"the trigger {trigger.name} does not read the deleted rows as {trigger.old_table}")
        if trigger.columns and f"UPDATE OF {', '.join(trigger.columns)} " not in (definition or ""):
            found.append(f"the trigger {trigger.name} does not fire on a change of {', '.join(trigger.columns)}")
    if all(live_columns.values()):
        expected = function_bodies(live_columns)
        have = dict(db.execute(text(_FUNCTION_SQL), {"names": sorted(expected)}).fetchall())
        for name, body in expected.items():
            if have.get(name) != body:
                found.append(f"the function {name} is missing, or was not made for the columns its table has now")
    return found


def verify(db) -> None:
    """Refuse to serve without every kept table and trigger as install() makes them. A deployment that cannot
    keep what a legal hold must keep would be telling its operators it does, so this is a hard stop."""
    try:
        found = problems(db)
    except Exception as exc:  # noqa: BLE001 -- a database that cannot answer is not a pass
        raise RuntimeError("Could not check the legal hold triggers, so what a hold keeps cannot be trusted: "
                           f"{type(exc).__name__}: {exc}") from exc
    if found:
        raise RuntimeError("The legal hold tables or triggers are not as they must be: " + "; ".join(found)
                           + ". Files deleted from a vault under a legal hold would not be kept. Check the "
                           "migration output above for the step that failed.")


# --------------------------------------------------------------------------- what the deleting code says

def _dialect(db) -> Optional[str]:
    try:
        bind = db.get_bind()
    except Exception:  # noqa: BLE001 -- a stand-in session without a database
        return None
    return getattr(getattr(bind, "dialect", None), "name", None)


def actor_text(actor) -> str:
    """An account (or its id) as the kept row records who deleted it; ``system`` for none."""
    if actor is None:
        return SYSTEM_ACTOR
    value = getattr(actor, "id", actor)
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError):
        return str(value)[:64] or SYSTEM_ACTOR


def mark_deletes(db, reason: str, actor=None) -> None:
    """Say, for the rest of ``db``'s transaction, why its deletions happen and as whom: what a kept row
    records. Nothing on a database without the triggers."""
    if reason not in REASONS:
        raise ValueError(f"not a reason a kept row records: {reason!r}")
    if _dialect(db) != "postgresql":
        return
    db.execute(text(f"SELECT set_config('{REASON_SETTING}', :why, true), set_config('{ACTOR_SETTING}', :who, true)"),
               {"why": reason, "who": actor_text(actor)})


# --------------------------------------------------------------------------- reading what is kept

def _has_kept_tables(db) -> bool:
    """On a database other than Postgres (the tests' SQLite), whether the kept tables were made there."""
    try:
        from sqlalchemy import inspect
        return inspect(db.get_bind()).has_table("held_files")
    except Exception:  # noqa: BLE001
        return False


def _readable(db) -> bool:
    """Whether ``db`` can hold kept rows: Postgres always (a failing read there is raised, never taken for
    "nothing kept"); another database only when the kept tables were made in it; a stand-in session never."""
    dialect = _dialect(db)
    if dialect == "postgresql":
        return True
    return dialect is not None and _has_kept_tables(db)


def kept_rows(db, rel_paths: Iterable[str]) -> list:
    """[(id, vault_id, storage_path, kept_reason)] of the kept files stored at ``rel_paths``. On Postgres an
    error is raised to the caller, which then keeps every blob (VaultService._destroy_blobs)."""
    from app.core.models import HeldFile
    paths = sorted({str(p) for p in rel_paths if p})
    if not paths or not _readable(db):
        return []
    return [tuple(r) for r in db.query(HeldFile.id, HeldFile.vault_id, HeldFile.storage_path, HeldFile.kept_reason)
            .filter(HeldFile.storage_path.in_(paths)).all()]


def vault_keeps(db, vault_id) -> bool:
    """Whether a hold stands on ``vault_id``, or kept rows of it wait for their purge."""
    from app.core.models import HeldFile, HeldFolder, LegalHoldVault
    if not _readable(db):
        return False
    vid = uuid.UUID(str(vault_id))
    return any(q.first() is not None for q in (
        db.query(LegalHoldVault.vault_id).filter(LegalHoldVault.vault_id == vid,
                                                 LegalHoldVault.released_at.is_(None)),
        db.query(HeldFile.id).filter(HeldFile.vault_id == vid),
        db.query(HeldFolder.id).filter(HeldFolder.vault_id == vid)))
