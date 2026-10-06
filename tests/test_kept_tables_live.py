"""The legal hold's kept tables and triggers on a running stack's Postgres (app/core/kept_tables.py).

The database keeps what is deleted from a held vault, whatever deletes it: each deletion here is plain SQL, with
no application code in the way. The kept tables have every column of the live ones and no foreign key or unique
index; every trigger is there and ENABLE ALWAYS, so a session as a replication worker or a restore runs (role
replica) still keeps; a held vault, or one whose kept rows wait for their purge, cannot be deleted, and the tables
cannot be emptied with TRUNCATE; a rename keeps the old sealed name, which opens with the object's id; and the
start's check refuses a missing, disabled or stale trigger. test_kept_tables.py checks the same offline.
"""
import json
import subprocess
import uuid

import pytest

from _account_change_helpers import DB, in_api_container, psql
from conftest import unique

pytestmark = pytest.mark.integration


def _sql_error(sql: str) -> str:
    """Run ``sql`` expecting it to fail; returns the error (psql's standard error)."""
    r = subprocess.run(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-v", "ON_ERROR_STOP=1",
                        "-Atc", sql], capture_output=True, text=True, timeout=30)
    assert r.returncode != 0, f"it did not fail: {r.stdout}"
    return r.stderr


def _upload(client, vid, name, content, folder_id=None):
    r = client.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))],
                    params={"folder_id": folder_id} if folder_id else None)
    r.raise_for_status()
    return r.json()["files"][0]["id"]


def _folder(client, vid, name):
    r = client.post(f"/vaults/{vid}/folders", json={"name": name, "parent_folder_id": None})
    r.raise_for_status()
    return r.json()["folder"]["id"]


def _hold(admin_id, admin_name, vault_id):
    """A case and a hold standing on ``vault_id``, written straight into the database. Returns the case id."""
    case_id = str(uuid.uuid4())
    psql("INSERT INTO compliance_cases (id, status, purpose, legal_basis, justification_enc, owner_note_enc, "
         "auditor_id, auditor_username, requested_at, created_at, updated_at) VALUES "
         f"('{case_id}', 'hold_only', 'other', 'legal_obligation', 'cenc1:x', 'cenc1:x', '{admin_id}', "
         f"'{admin_name}', now(), now(), now())")
    psql(f"INSERT INTO legal_hold_vaults (case_id, vault_id, placed_by_username, placed_at) "
         f"VALUES ('{case_id}', '{vault_id}', '{admin_name}', now())")
    return case_id


def _forget(vault_id, case_id=None):
    """Release and purge what this test kept (straight in the database), so the vault can go."""
    psql(f"UPDATE legal_hold_vaults SET released_at = now() WHERE vault_id = '{vault_id}' AND released_at IS NULL")
    for table in ("held_files", "held_folders", "held_name_history"):
        psql(f"DELETE FROM {table} WHERE vault_id = '{vault_id}'")
    if case_id:
        psql(f"DELETE FROM compliance_cases WHERE id = '{case_id}'")


@pytest.fixture
def held(admin):
    """A vault of the session's administrator under a hold, with three files and a folder holding one."""
    me = admin.get("/users/me").json()
    vault = admin.create_vault(name=unique("held"))
    vid = vault["id"]
    files = [_upload(admin, vid, f"{unique('f')}.txt", f"content {i}".encode()) for i in range(3)]
    folder = _folder(admin, vid, unique("dir"))
    inner = _upload(admin, vid, f"{unique('in')}.txt", b"inner", folder_id=folder)
    case_id = _hold(me["id"], me["username"], vid)
    try:
        yield {"vault": vid, "files": files, "folder": folder, "inner": inner, "case": case_id, "me": me}
    finally:
        _forget(vid, case_id)
        admin.delete_vault(vid)


def _columns(table):
    return psql("SELECT column_name || ':' || data_type || ':' || coalesce(character_maximum_length::text, '') "
                "FROM information_schema.columns WHERE table_schema = current_schema() "
                f"AND table_name = '{table}' ORDER BY column_name").splitlines()


def test_the_kept_tables_have_every_column_of_the_live_ones_and_no_key_to_anything():
    for live, kept in (("files", "held_files"), ("folders", "held_folders")):
        have = set(_columns(kept))
        assert set(_columns(live)) <= have, set(_columns(live)) - have
        for extra in ("kept_at:timestamp without time zone:", "kept_reason:character varying:16",
                      "kept_by:character varying:64", "purge_after:timestamp without time zone:"):
            assert extra in have, extra
        assert psql(f"SELECT count(*) FROM pg_constraint WHERE conrelid = '{kept}'::regclass AND contype IN "
                    "('f', 'u')") == "0"
        assert psql(f"SELECT count(*) FROM pg_index WHERE indrelid = '{kept}'::regclass AND indisunique "
                    "AND NOT indisprimary") == "0"
        # Every column may be NULL but the id: a row deleted under an older column set is kept too.
        assert psql("SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_schema = "
                    f"current_schema() AND table_name = '{kept}' AND is_nullable = 'NO'") == "id"


def test_every_hold_trigger_is_there_and_enable_always():
    rows = dict(line.split("|", 1) for line in psql(
        "SELECT t.tgname, c.relname || ':' || t.tgenabled::text FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
        "WHERE NOT t.tgisinternal AND (t.tgname LIKE 'trg\\_%\\_keep%' OR t.tgname LIKE 'trg\\_%\\_hold%')"
    ).splitlines())
    assert rows == {"trg_files_keep": "files:A", "trg_folders_keep": "folders:A", "trg_vaults_hold": "vaults:A",
                    "trg_files_keep_name": "files:A", "trg_folders_keep_name": "folders:A",
                    "trg_files_hold_truncate": "files:A", "trg_folders_hold_truncate": "folders:A",
                    "trg_vaults_hold_truncate": "vaults:A"}


def _kept(file_id):
    return psql(f"SELECT kept_reason || '|' || coalesce(kept_by, '') || '|' || storage_path FROM held_files "
                f"WHERE id = '{file_id}'")


def test_a_plain_delete_of_a_held_vaults_file_is_kept_with_every_column(held):
    f = held["files"][0]
    before = psql(f"SELECT row_to_json(f)::text FROM files f WHERE id = '{f}'")
    psql(f"DELETE FROM files WHERE id = '{f}'")
    assert _kept(f).startswith("deleted||")
    after = json.loads(psql(f"SELECT row_to_json(k)::text FROM held_files k WHERE id = '{f}'"))
    for key, value in json.loads(before).items():
        assert after[key] == value, key


def test_the_reason_and_actor_the_deleting_code_sets_are_kept(held):
    f = held["files"][1]
    actor = held["me"]["id"]
    psql(f"BEGIN; SELECT set_config('dockvault.delete_reason', 'moved', true), "
         f"set_config('dockvault.actor', '{actor}', true); DELETE FROM files WHERE id = '{f}'; COMMIT;")
    assert _kept(f).startswith(f"moved|{actor}|")
    # An unknown reason is recorded as a deletion.
    g = held["files"][2]
    psql(f"BEGIN; SELECT set_config('dockvault.delete_reason', 'whatever', true); "
         f"DELETE FROM files WHERE id = '{g}'; COMMIT;")
    assert _kept(g).startswith("deleted|")


def test_a_folders_delete_keeps_it_and_the_files_its_cascade_takes(held):
    psql(f"DELETE FROM folders WHERE id = '{held['folder']}'")
    assert psql(f"SELECT count(*) FROM held_folders WHERE id = '{held['folder']}'") == "1"
    assert _kept(held["inner"]).startswith("deleted|")


def test_a_replication_worker_or_a_restore_still_keeps(held):
    f = held["files"][0]
    psql(f"SET session_replication_role = replica; DELETE FROM files WHERE id = '{f}'")
    assert _kept(f).startswith("deleted|")


def test_a_vault_that_is_not_held_keeps_nothing(admin):
    vault = admin.create_vault(name=unique("free"))
    f = _upload(admin, vault["id"], "x.txt", b"x")
    try:
        psql(f"DELETE FROM files WHERE id = '{f}'")
        assert _kept(f) == ""
    finally:
        admin.delete_vault(vault["id"])


def test_a_held_vault_or_one_with_kept_rows_cannot_be_deleted_even_bypassing_the_app(held):
    vid = held["vault"]
    assert "legal hold" in _sql_error(f"DELETE FROM vaults WHERE id = '{vid}'")
    psql(f"DELETE FROM files WHERE id = '{held['files'][0]}'")
    psql(f"UPDATE legal_hold_vaults SET released_at = now() WHERE vault_id = '{vid}'")
    assert "legal hold" in _sql_error(f"DELETE FROM vaults WHERE id = '{vid}'"), "its kept row waits for a purge"
    assert psql(f"SELECT count(*) FROM vaults WHERE id = '{vid}'") == "1"


def test_the_tables_cannot_be_emptied_while_a_hold_stands(held):
    for table in ("files", "folders", "vaults"):
        # Inside a transaction rolled back either way: a missing trigger must not cost the stack its data.
        error = _sql_error(f"BEGIN; TRUNCATE {table} CASCADE; ROLLBACK;")
        assert "cannot be emptied" in error, (table, error)


def test_a_rename_keeps_the_old_name_which_opens_with_the_objects_id(admin, held):
    f = held["files"][0]
    old = psql(f"SELECT enc_name FROM files WHERE id = '{f}'")
    r = admin.put(f"/vaults/{held['vault']}/files/{f}/rename", json={"new_name": "renamed.txt"})
    assert r.status_code == 200, r.text
    assert psql(f"SELECT enc_name FROM held_name_history WHERE object_id = '{f}'") == old
    out = in_api_container(
        "from app.core.database import get_db_context\n"
        "from app.core.models import HeldNameHistory\n"
        "import uuid\n"
        "with get_db_context() as db:\n"
        f"    row = db.query(HeldNameHistory).filter(HeldNameHistory.object_id == uuid.UUID('{f}')).one()\n"
        "    print('NAME=' + str(row.name) + '|' + row.kind)\n")
    name = [ln for ln in out.stdout.splitlines() if ln.startswith("NAME=")][0][5:]
    assert name.endswith("|file") and name.split("|")[0].endswith(".txt") and name.split("|")[0] != "renamed.txt"


_CHECK = """
from sqlalchemy import text
from app.core import kept_tables
from app.core.database import get_db_context
out = {}
for label, sql in CHANGES:
    with get_db_context() as db:
        db.execute(text("SET LOCAL lock_timeout = '5s'"))
        db.execute(text(sql))
        try:
            kept_tables.verify(db)
            out[label] = None
        except RuntimeError as exc:
            out[label] = str(exc)
        db.rollback()
with get_db_context() as db:
    kept_tables.verify(db)
print("OUT=" + __import__("json").dumps(out))
"""


def test_the_starts_check_refuses_a_missing_disabled_or_stale_trigger_each_in_a_rolled_back_change():
    changes = [("dropped", "DROP TRIGGER trg_files_keep ON files"),
               ("origin", "ALTER TABLE folders ENABLE TRIGGER trg_folders_keep"),
               ("disabled", "ALTER TABLE vaults DISABLE TRIGGER trg_vaults_hold"),
               ("noop", "CREATE OR REPLACE FUNCTION dv_keep_files() RETURNS trigger LANGUAGE plpgsql AS "
                        "$f$ BEGIN RETURN NULL; END $f$"),
               ("new column", "ALTER TABLE files ADD COLUMN probe_after_start text")]
    out = in_api_container("CHANGES = " + repr(changes) + "\n" + _CHECK)
    found = json.loads([ln for ln in out.stdout.splitlines() if ln.startswith("OUT=")][0][4:])
    assert "trg_files_keep is missing" in found["dropped"]
    assert "trg_folders_keep is not ENABLE ALWAYS" in found["origin"]
    assert "trg_vaults_hold is not ENABLE ALWAYS" in found["disabled"]
    assert "dv_keep_files" in found["noop"]
    assert "held_files.probe_after_start" in found["new column"] and "dv_keep_files" in found["new column"]


_START = """
from app.api import api_server as api
from app.core import kept_tables
from app.core.database import get_db_context
from sqlalchemy import text
real = kept_tables.install
def failing(db):
    raise RuntimeError("the install step failed")
with get_db_context() as db:
    db.execute(text("DROP TRIGGER trg_folders_keep ON folders"))
    db.commit()
kept_tables.install = failing
try:
    api._run_lightweight_migrations()
    print("START=served")
except RuntimeError as exc:
    print("START=" + str(exc).splitlines()[0])
finally:
    # The real start again: it installs the triggers and records its steps as applied.
    kept_tables.install = real
    api._run_lightweight_migrations()
"""


def test_a_start_whose_triggers_did_not_land_refuses_to_serve():
    out = in_api_container(_START)
    line = [ln for ln in out.stdout.splitlines() if ln.startswith("START=")][0]
    assert line.startswith("START=The legal hold tables or triggers are not as they must be")
    assert "trg_folders_keep is missing" in line
    assert psql("SELECT tgenabled FROM pg_trigger WHERE tgname = 'trg_folders_keep'") == "A", "restored"
