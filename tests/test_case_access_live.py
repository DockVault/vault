"""Reading a compliance case on a running stack (app/core/case_access.py and the reading routes in
app/api/compliance_router.py): an auditor whose case two administrators approved lists the vault, opens a file
(and a byte range of another, which adds no record), previews Markdown, searches names, and opens a file the hold
kept after its owner deleted it; every read is recorded under the case and the owner's page lists the files opened.
A view whose record cannot be written (a fault in the database) is refused with no byte of the file sent. Reading
changes nothing of the vault. Refusals (not the case's auditor, a temporary credential, a device's secret, access
ended, the right revoked) are each recorded. A password vault opens only with its password, and the
vault-password throttle is the auditor's for the vault across two cases. First views of one file made at once
write one row, and a limited session keeps its statement timeout in every transaction.

test_case_access.py and test_case_reading.py cover the rules offline.
"""
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest
import requests

from _account_change_helpers import DB, in_api_container, psql
from _auditor_helpers import forget_grants, grant_right, new_auditor_account, two_admins
from _owner_notice_helpers import approved_case, forget_cases, owner_with_vault
from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

MINUTES = b"The board met on Monday and decided nothing."
NOTES = b"# Findings\n\nNothing <script>alert(1)</script> here."
CLIP = bytes(range(256)) * 1200


def _upload(client, vid, name, content, folder_id=None, password=None):
    r = client.post(f"/vaults/{vid}/files", files=[("files", (name, content, "application/octet-stream"))],
                    params={"folder_id": folder_id} if folder_id else None,
                    headers={"X-Vault-Password": password} if password else None)
    r.raise_for_status()
    return r.json()["files"][0]["id"]


def _folder(client, vid, name):
    r = client.post(f"/vaults/{vid}/folders", json={"name": name, "parent_folder_id": None})
    r.raise_for_status()
    return r.json()["folder"]["id"]


@pytest.fixture
def world(admin):
    """ada and bob (independent administrators), uma (an auditor they granted), olga (who owns a vault with a folder
    and three files). The cases made are removed afterwards with what their holds kept."""
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        olga, olga_c, vid = owner_with_vault(admin)
        board = _folder(olga_c, vid, "Board")
        files = {"minutes": _upload(olga_c, vid, "minutes.txt", MINUTES, board),
                 "notes": _upload(olga_c, vid, "notes.md", NOTES),
                 "clip": _upload(olga_c, vid, "clip.bin", CLIP)}
        made, vaults = [], [vid]
        try:
            yield {"admins": admins, "admin": admin, "uma": (uma, uma_c, codes), "olga": (olga, olga_c, vid),
                   "board": board, "files": files, "cases": made, "vaults": vaults}
        finally:
            forget_cases(made, vaults)
            forget_grants(uma["id"])


def _case(world, vault_ids, **extra):
    case = approved_case(world["admins"], world["uma"], vault_ids, **extra)
    world["cases"].append(case["id"])
    return case


def _rows(action, case_id, status="success"):
    return int(psql(f"SELECT count(*) FROM audit_logs WHERE action = '{action}' AND status = '{status}' "
                    f"AND case_id = '{case_id}'"))


def _refusals(case_id):
    out = psql("SELECT string_agg(details->>'reason', ',' ORDER BY timestamp) FROM audit_logs "
               f"WHERE action = 'case_access_refused' AND case_id = '{case_id}'")
    return out.split(",") if out else []


def test_the_auditor_reads_the_case_and_every_read_is_recorded(world):
    _uma, uma_c, _codes = world["uma"]
    _olga, olga_c, vid = world["olga"]
    files = world["files"]
    case = _case(world, [vid])
    base = f"/compliance/cases/{case['id']}"

    vaults = uma_c.get(f"{base}/tree").json()["vaults"]
    assert [v["vault_id"] for v in vaults] == [vid] and vaults[0]["name"]
    root = uma_c.get(f"{base}/tree", params={"vault_id": vid}).json()
    assert {e["name"] for e in root["entries"]} == {"Board", "notes.md", "clip.bin"}
    inside = uma_c.get(f"{base}/tree", params={"vault_id": vid, "folder_id": world["board"]}).json()
    assert [e["name"] for e in inside["entries"]] == ["minutes.txt"]
    info = uma_c.get(f"{base}/files/{files['minutes']}").json()
    assert info["name"] == "minutes.txt" and not any("checksum" in k for k in info)

    r = uma_c.get(f"{base}/files/{files['minutes']}/content")
    assert r.status_code == 200 and r.content == MINUTES, r.text
    assert "no-store" in r.headers["Cache-Control"] and r.headers["Content-Disposition"].startswith("inline")
    r = uma_c.get(f"{base}/files/{files['clip']}/content", headers={"Range": "bytes=1000-1999"})
    assert r.status_code == 206 and r.content == CLIP[1000:2000]
    r = uma_c.get(f"{base}/files/{files['clip']}/content", headers={"Range": "bytes=2000-2999"})
    assert r.status_code == 206 and r.content == CLIP[2000:3000]
    r = uma_c.get(f"{base}/files/{files['notes']}/preview-render")
    assert r.status_code == 200 and "Findings" in r.json()["html"] and "<script>alert" not in r.json()["html"]
    r = uma_c.post(f"{base}/search", json={"q": "MIN"})
    assert [x["name"] for x in r.json()["results"]] == ["minutes.txt"]

    assert _rows("case_file_viewed", case["id"]) == 3, "one per file: the two byte ranges added one row"
    # The case's vaults, the vault's root and the Board folder; a file's metadata counts as a listing of its folder,
    # which was listed a moment before (once in ten minutes).
    assert _rows("case_folder_listed", case["id"]) == 3
    assert psql(f"SELECT (details->>'query_length') || '|' || (details->>'matches') FROM audit_logs "
                f"WHERE action = 'case_search' AND case_id = '{case['id']}'") == "3|1"
    assert psql(f"SELECT count(*) FROM audit_logs WHERE case_id = '{case['id']}' "
                "AND details::text ILIKE '%min%' AND action = 'case_search'") == "0", "the query is never recorded"

    # The owner deletes a file; the case's hold keeps it, and the case still opens it, as kept.
    assert olga_c.post(f"/vaults/{vid}/files/{files['minutes']}/delete").status_code == 200
    gone = uma_c.get(f"{base}/files/{files['minutes']}").json()
    assert gone["status"] == "deleted_kept"
    assert uma_c.get(f"{base}/files/{files['minutes']}/content").content == MINUTES

    page = olga_c.get("/me/compliance-access").json()
    opened = {o["file_id"] for c in page["cases"] for o in c["opened"]}
    assert {files["minutes"], files["clip"], files["notes"]} <= opened


_FAULT = """
CREATE OR REPLACE FUNCTION test_refuse_case_view() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'injected fault'; END $$ LANGUAGE plpgsql;
CREATE TRIGGER test_refuse_case_view BEFORE INSERT ON audit_logs
FOR EACH ROW WHEN (NEW.action = 'case_file_viewed') EXECUTE FUNCTION test_refuse_case_view();
"""


def test_a_view_whose_record_cannot_be_written_sends_no_byte(world):
    _uma, uma_c, _codes = world["uma"]
    _olga, _c, vid = world["olga"]
    case = _case(world, [vid])
    psql(_FAULT)
    try:
        r = uma_c.get(f"/compliance/cases/{case['id']}/files/{world['files']['minutes']}/content")
        assert r.status_code == 503 and MINUTES not in r.content, r.text
        assert r.json()["detail"]["reason"] == "record_failed"
    finally:
        psql("DROP TRIGGER IF EXISTS test_refuse_case_view ON audit_logs; "
             "DROP FUNCTION IF EXISTS test_refuse_case_view()")
    assert _rows("case_file_viewed", case["id"]) == 0
    assert _refusals(case["id"]) == ["record_failed"]
    r = uma_c.get(f"/compliance/cases/{case['id']}/files/{world['files']['minutes']}/content")
    assert r.status_code == 200 and r.content == MINUTES


def _snapshot(vid, fid):
    return psql(f"SELECT coalesce(last_accessed::text, '') || '|' || updated_at::text FROM vaults WHERE id = '{vid}'"), \
        psql(f"SELECT updated_at::text || '|' || coalesce(modified_by::text, '') FROM files WHERE id = '{fid}'"), \
        psql(f"SELECT count(*) FROM vault_views WHERE vault_id = '{vid}'")


def test_reading_for_a_case_changes_nothing_of_the_vault(world):
    _uma, uma_c, _codes = world["uma"]
    _olga, _c, vid = world["olga"]
    case = _case(world, [vid])
    before = _snapshot(vid, world["files"]["notes"])
    base = f"/compliance/cases/{case['id']}"
    uma_c.get(f"{base}/tree", params={"vault_id": vid})
    assert uma_c.get(f"{base}/files/{world['files']['notes']}/content").status_code == 200
    assert uma_c.get(f"{base}/files/{world['files']['clip']}/content", headers={"Range": "bytes=0-9"}).status_code == 206
    uma_c.post(f"{base}/search", json={"q": "n"})
    assert _snapshot(vid, world["files"]["notes"]) == before


def test_refusals_are_each_recorded(world):
    admin = world["admin"]
    uma, uma_c, _codes = world["uma"]
    _olga, olga_c, vid = world["olga"]
    case = _case(world, [vid])
    content = f"/compliance/cases/{case['id']}/files/{world['files']['notes']}/content"

    r = olga_c.get(content)
    assert r.status_code == 404 and r.json()["detail"]["reason"] == "not_your_case"

    tc = admin.post("/auth/temp-credentials", json={"note": unique("case-read")}).json()
    temp = ApiClient(BASE_URL)
    temp.login(tc["temp_username"], tc["credential"])
    r = temp.get(content)
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "temporary_credential"

    device = uma_c.post("/devices", json={"label": unique("sync")})
    assert device.status_code == 200, device.text
    r = ApiClient(BASE_URL).session.get(f"{BASE_URL}{content}",
                                        headers={"Authorization": f"Bearer {device.json()['secret']}"})
    assert r.status_code == 401 and NOTES not in r.content, "a device's secret is no session"

    psql("UPDATE compliance_cases SET access_ends_at = (now() AT TIME ZONE 'utc') - interval '1 second' "
         f"WHERE id = '{case['id']}'")
    r = uma_c.get(content)
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "access_ended"
    psql("UPDATE compliance_cases SET access_ends_at = (now() AT TIME ZONE 'utc') + interval '1 day' "
         f"WHERE id = '{case['id']}'")
    assert uma_c.get(content).status_code == 200

    ada, ada_c, _ = world["admins"]["ada"]
    assert ada_c.delete(f"/users/{uma['id']}/auditor", json={"reason": "Ended."}).status_code == 200
    r = uma_c.get(content)
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "auditor_not_live"

    assert _refusals(case["id"]) == ["not_your_case", "temporary_credential", "access_ended", "auditor_not_live"]



# Each first view's row waits in its INSERT while the test holds this advisory lock: every view of the burst is past
# its ten-minute check before any row commits, as when they truly arrive at once.
_HOLD_KEY = (7340, 21)
_HOLD = f"""
CREATE OR REPLACE FUNCTION test_hold_case_view() RETURNS trigger AS $$
BEGIN PERFORM pg_advisory_xact_lock_shared({_HOLD_KEY[0]}, {_HOLD_KEY[1]}); RETURN NEW; END $$ LANGUAGE plpgsql;
CREATE TRIGGER test_hold_case_view BEFORE INSERT ON audit_logs
FOR EACH ROW WHEN (NEW.action = 'case_file_viewed') EXECUTE FUNCTION test_hold_case_view();
"""


def _waiting_on_locks() -> int:
    return int(psql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                    "AND datname = current_database() AND pid <> pg_backend_pid()"))


def test_first_views_of_one_file_made_at_once_write_one_row(world):
    """Six first views of one file at once: the auditor's row is locked from the ten-minute check to the commit, so
    one view writes case_file_viewed and the five after it find that row; all six are answered."""
    _uma, uma_c, _codes = world["uma"]
    _olga, _c, vid = world["olga"]
    case = _case(world, [vid])
    url = f"{BASE_URL}/compliance/cases/{case['id']}/files/{world['files']['notes']}/content"
    headers = dict(uma_c.session.headers)
    psql(_HOLD)
    holder = subprocess.Popen(["docker", "exec", "-i", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-Atc",
                               f"SELECT pg_advisory_lock({_HOLD_KEY[0]}, {_HOLD_KEY[1]}); SELECT pg_sleep(120)"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def release():
        psql("SELECT count(pg_terminate_backend(pid)) FROM pg_locks WHERE locktype = 'advisory' AND granted "
             f"AND classid = {_HOLD_KEY[0]} AND objid = {_HOLD_KEY[1]} AND mode = 'ExclusiveLock' "
             "AND pid <> pg_backend_pid()")

    try:
        for _ in range(120):
            if psql("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted AND mode = 'ExclusiveLock' "
                    f"AND classid = {_HOLD_KEY[0]} AND objid = {_HOLD_KEY[1]}") == "1":
                break
            time.sleep(0.25)
        else:
            raise AssertionError("the hold was not taken")
        with ThreadPoolExecutor(max_workers=6) as pool:
            answers = [pool.submit(requests.get, url, headers=headers, timeout=60) for _ in range(6)]
            for _ in range(60):
                if _waiting_on_locks() >= 6:
                    break
                time.sleep(0.05)
            waiting = _waiting_on_locks()
            release()
            statuses = [a.result().status_code for a in answers]
    finally:
        release()
        holder.kill()
        holder.wait(timeout=30)
        psql("DROP TRIGGER IF EXISTS test_hold_case_view ON audit_logs; "
             "DROP FUNCTION IF EXISTS test_hold_case_view()")
    assert waiting >= 6, f"only {waiting} views reached the database's locks"
    assert statuses == [200] * 6, statuses
    assert _rows("case_file_viewed", case["id"]) == 1


_SHOW_LIMITS = """
from sqlalchemy import text
from app.api import compliance_router as cr
from app.core.database import SessionLocal
show = lambda s: s.execute(text('SHOW statement_timeout')).scalar()
s = SessionLocal()
cr.limit_statements(s)
seen = [show(s)]
s.commit()
seen.append(show(s))
s.rollback()
seen.append(show(s))
s.close()
t = SessionLocal()
seen.append(show(t))
t.close()
print(' '.join(seen))
"""


def test_the_statement_timeout_holds_in_every_transaction_of_a_limited_session():
    """On Postgres: a session limited by the compliance routes keeps the statement timeout after it commits or rolls
    back (a read commits its record and goes on reading); a session never limited has none of it."""
    out = in_api_container(_SHOW_LIMITS)
    limited_first, after_commit, after_rollback, plain = out.stdout.strip().splitlines()[-1].split()
    assert limited_first == after_commit == after_rollback == "5s"
    assert plain != "5s"


def _redis_del(pattern):
    import os
    redis = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
    subprocess.run(["docker", "exec", redis, "sh", "-c", f"redis-cli --scan --pattern '{pattern}' | xargs -r redis-cli del"],
                   capture_output=True, text=True, timeout=30)


@contextmanager
def _vault_attempts(limit):
    """The vault-password throttle's limit for accounts set to ``limit`` (an administrator's override, read by the
    throttle within five seconds); the stack's own value afterwards."""
    psql("INSERT INTO system_settings (key, value) VALUES ('global', '{}') ON CONFLICT (key) DO NOTHING")
    psql("UPDATE system_settings SET value = (coalesce(value::jsonb, '{}'::jsonb) || "
         f"'{{\"rate_limit_vault_attempts\": {int(limit)}}}'::jsonb)::json WHERE key = 'global'")
    time.sleep(6)
    try:
        yield
    finally:
        psql("UPDATE system_settings SET value = (value::jsonb - 'rate_limit_vault_attempts')::json "
             "WHERE key = 'global'")


def test_a_password_vault_opens_with_its_password_and_the_throttle_spans_cases(world):
    uma, uma_c, _codes = world["uma"]
    _olga, olga_c, _vid = world["olga"]
    pv = olga_c.create_vault(name=unique("locked"), password="Vault-Pass-2026!")["id"]
    world["vaults"].append(pv)
    fid = _upload(olga_c, pv, "salaries.csv", b"name,amount\n", password="Vault-Pass-2026!")
    first = _case(world, [pv])
    second = _case(world, [pv])
    _redis_del(f"rate_limit:vault:{pv}:*")
    try:
        content = f"/compliance/cases/{first['id']}/files/{fid}/content"
        r = uma_c.get(content)
        assert r.status_code == 403 and r.json()["detail"]["reason"] == "vault_locked"
        names = uma_c.get(f"/compliance/cases/{first['id']}/tree", params={"vault_id": pv}).json()["entries"]
        assert [e["name"] for e in names] == [None], "no names until the password is given"

        unlock = f"/compliance/cases/{first['id']}/vaults/{pv}/unlock"
        assert uma_c.post(unlock, json={"password": "wrong"}).status_code == 403
        r = uma_c.post(unlock, json={"password": "Vault-Pass-2026!"})
        assert r.status_code == 200, r.text
        receipt = r.json()["receipt"]
        r = uma_c.get(content, headers={"X-Case-Unlock": f"{pv}={receipt}"})
        assert r.status_code == 200 and r.content == b"name,amount\n"
        other = f"/compliance/cases/{second['id']}/files/{fid}/content"
        assert uma_c.get(other, headers={"X-Case-Unlock": f"{pv}={receipt}"}).status_code == 403, \
            "a receipt opens the vault in its own case only"
        assert psql(f"SELECT string_agg(status || ':' || coalesce(details->>'reason', ''), ',' ORDER BY timestamp) "
                    f"FROM audit_logs WHERE action = 'case_vault_unlocked' AND case_id = '{first['id']}'") == \
            "failure:wrong_password,success:"

        # Wrong passwords in the first case spend the budget the second case's unlock uses: with a limit of 3, the
        # wrong one above and two more are counted, the next is refused before its password is checked, and so is
        # the right password in the second case.
        with _vault_attempts(3):
            statuses = [uma_c.post(unlock, json={"password": "wrong"}).status_code for _ in range(3)]
            assert statuses == [403, 403, 429], statuses
            r = uma_c.post(f"/compliance/cases/{second['id']}/vaults/{pv}/unlock",
                           json={"password": "Vault-Pass-2026!"})
            assert r.status_code == 429, r.text
        assert psql(f"SELECT count(*) FROM audit_logs WHERE action = 'case_vault_unlocked' AND status = 'success' "
                    f"AND case_id = '{second['id']}'") == "0"
    finally:
        _redis_del(f"rate_limit:vault:{pv}:*")
