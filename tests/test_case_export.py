"""Exporting a compliance case's files (app/core/case_export.py, its routes in app/api/compliance_router.py), offline
on a real (SQLite) database with files stored as the vault stores them.

Preparing asks for a fresh code only once the export may be made (a refused one costs no code and is recorded);
the case must allow export and the deployment too. Fetching works once, by the auditor who prepared it, before it
expires; each owner is told before the first byte. The archive is a ZIP64 with the files under safe, unique paths,
the manifest (JSON and CSV), case.json without the justification, README.txt and SHA256SUMS, which `sha256sum -c`
accepts; the manifest's SHA-256 is the one the end of the export records. A stream stopped before its end, or never
started, records its abort once; an export stops when the case's access does; memory stays bounded with a file of
several GB. test_case_access_live.py fetches one on a stack.
"""
# ruff: noqa: F811 -- the fixtures of _case_access_helpers are imported by name and used as parameters
import csv
import gc
import hashlib
import inspect
import io
import json
import shutil
import subprocess
import tracemalloc
import uuid
import zipfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from _async_run import run_coroutine  # noqa: E402
from _case_access_helpers import (  # noqa: E402,F401 -- the fixtures are used by name
    ROOT, SESSION, TEXT, db, people, quiet, settings, storage)
from _case_access_helpers import case as _case  # noqa: E402
from _case_access_helpers import file as _file  # noqa: E402
from _case_access_helpers import folder as _folder  # noqa: E402
from _case_access_helpers import kept as _kept  # noqa: E402
from _case_access_helpers import receipt as _receipt  # noqa: E402
from _case_access_helpers import rows as _rows  # noqa: E402
from _case_access_helpers import vault as _vault  # noqa: E402
from _case_access_helpers import vaults as _vaults  # noqa: E402
from app.api import api_server as api  # noqa: E402
from app.api import compliance_router as cr  # noqa: E402
from app.core import auditor_rights as rights  # noqa: E402
from app.core import body_limit as bl  # noqa: E402
from app.core import case_access as ca  # noqa: E402
from app.core import case_export as ce  # noqa: E402
from app.core import case_rules as rules  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402
from app.core import models as m  # noqa: E402
from app.core import owner_access  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def session(monkeypatch):
    monkeypatch.setattr(api, "_current_session_hash", lambda request: SESSION)


@pytest.fixture
def codes(monkeypatch):
    """The compliance step-up passes (its own tests cover it); each time it is asked for is counted."""
    asked = []
    monkeypatch.setattr(cr, "STEP_UP_CASE_EXPORT", lambda db_, user, request: asked.append(user.username))
    return asked


def _request(**headers):
    return SimpleNamespace(headers={k.lower().replace("_", "-"): v for k, v in headers.items()})


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs), None
    except HTTPException as exc:
        return None, exc


def _prepare(db, people, case, files=None, every=False, unlock=None, who=None):
    body = cr.ExportRequest(file_ids=[f.id for f in files] if files else None, all=every)
    return cr.prepare_case_export(case.id, body, _request(), x_case_unlock=unlock, current_user=who or people.uma,
                                  db=db)


def _fetch(db, people, case, export_id, unlock=None, who=None):
    return cr.fetch_case_export(case.id, uuid.UUID(str(export_id)), _request(), x_case_unlock=unlock,
                                current_user=who or people.uma, db=db)


def _body(response) -> bytes:
    async def collect():
        out = b""
        async for piece in response.body_iterator:
            out += piece
        return out
    return run_coroutine(collect())


def _archive(data: bytes) -> zipfile.ZipFile:
    archive = zipfile.ZipFile(io.BytesIO(data))
    assert archive.testzip() is None
    return archive


def _export(db, people, case, files=None, **kw):
    """(the export's id, the archive's bytes, the response): prepared and fetched."""
    prepared = _prepare(db, people, case, files, **kw)
    resp = _fetch(db, people, case, prepared["export_id"], unlock=kw.get("unlock"))
    return prepared["export_id"], _body(resp), resp


def _manifest(archive):
    return json.loads(archive.read("manifest.json"))


def _refused(db):
    return [r.details.get("reason") for r in _rows(db, "case_access_refused", "failure")]


# --------------------------------------------------------------------------- preparing

def test_an_export_is_prepared_with_a_code_and_recorded(db, people, storage, codes):
    a = _file(db, storage, people.v1, name="a.txt", content=b"alpha")
    b = _file(db, storage, people.v1, name="b.txt", content=b"bravo!")
    case = _case(db, people, _vaults(people.v1), can_export=True)
    out = _prepare(db, people, case, [a, b])
    assert codes == ["uma"] and out["files"] == 2 and out["bytes"] == 11
    export = db.get(m.ComplianceExport, uuid.UUID(out["export_id"]))
    assert export.status == "ready" and export.file_ids == [str(a.id), str(b.id)] and export.fetched_at is None
    assert export.expires_at - export.created_at == timedelta(hours=24)
    (row,) = _rows(db, "case_export_started")
    assert row.case_id == case.id and row.details["export_id"] == out["export_id"]
    assert row.details["file_count"] == 2 and row.details["vault_ids"] == [str(people.v1.id)]
    assert storage.opened == [], "preparing reads no file"
    assert _rows(db, "case_file_viewed") == []


def test_every_file_of_the_case_is_chosen_with_all_and_never_one_outside_it(db, people, storage, codes):
    board = _folder(db, people.v1)
    inside = _file(db, storage, people.v1, name="minutes.txt", folder=board)
    _file(db, storage, people.v1, name="outside.txt")
    gone = _kept(db, _file(db, storage, people.v1, name="draft.txt", folder=board))
    own = _file(db, storage, people.v1, name="own.txt", folder=board)
    own.password_hash = "argon2-hash"
    _file(db, storage, people.v2, name="other.txt")
    db.commit()
    case = _case(db, people, [{"kind": "folder", "target_id": board.id}], can_export=True)
    out = _prepare(db, people, case, every=True)
    export = db.get(m.ComplianceExport, uuid.UUID(out["export_id"]))
    assert sorted(export.file_ids) == sorted([str(inside.id), str(gone.id)]), \
        "the case's folder, kept files with it; never a file with a password of its own outside the override"


def test_a_refused_export_costs_no_code_and_is_recorded(db, people, storage, codes, settings):
    f = _file(db, storage, people.v1)
    zk = _vault(db, people.olga, kind="zero_knowledge")
    zf = _file(db, storage, zk, name="sealed.bin")
    pv = _vault(db, people.olga, password="argon2-hash")
    pf = _file(db, storage, pv, name="salaries.csv")
    no_export = _case(db, people, _vaults(people.v1))
    _, err = _call(_prepare, db, people, no_export, [f])
    assert err.status_code == 403 and err.detail["reason"] == ce.CASE_NO_EXPORT
    case = _case(db, people, _vaults(people.v1, zk, pv), can_export=True)
    settings[cs.EXPORT] = cs.DISABLED
    _, err = _call(_prepare, db, people, case, [f])
    assert err.status_code == 403 and err.detail["reason"] == ce.EXPORT_OFF
    settings[cs.EXPORT] = cs.ALLOWED
    for item, reason in ((zf, ca.ZERO_KNOWLEDGE), (pf, ca.LOCKED)):
        _, err = _call(_prepare, db, people, case, [f, item])
        assert err.status_code == 403 and err.detail["reason"] == reason
    _, err = _call(_prepare, db, people, case, [f], who=people.mallory)
    assert err.status_code == 404 and err.detail["reason"] == ca.NOT_AUDITOR
    assert _refused(db) == [ce.CASE_NO_EXPORT, ce.EXPORT_OFF, ca.ZERO_KNOWLEDGE, ca.LOCKED, ca.NOT_AUDITOR]
    # Malformed: nothing chosen, both chosen, too many. Answered, not recorded.
    for body in (cr.ExportRequest(), cr.ExportRequest(file_ids=[f.id], all=True)):
        _, err = _call(cr.prepare_case_export, case.id, body, _request(), x_case_unlock=None,
                       current_user=people.uma, db=db)
        assert err.status_code == 422 and err.detail["reason"] == ce.NO_FILES
    with pytest.raises(ca.Refused) as many:
        ce.choose(db, case, file_ids=[uuid.uuid4() for _ in range(ce.MAX_FILES + 1)])
    assert many.value.reason == ce.TOO_MANY_FILES and many.value.status == 413 and not many.value.record
    assert codes == [] and _rows(db, "case_export_started") == []
    assert len(_refused(db)) == 5


def test_a_password_vault_exports_once_unlocked_and_the_override_marks_the_row(db, people, storage, codes, settings):
    pv = _vault(db, people.olga, password="argon2-hash")
    f = _file(db, storage, pv, name="salaries.csv", content=b"name,amount\n")
    case = _case(db, people, _vaults(pv), can_export=True)
    unlock = f"{pv.id}={_receipt(case, pv, people.uma)}"
    _, err = _call(_prepare, db, people, case, [f])
    assert err.detail["reason"] == ca.LOCKED
    _id, data, _resp = _export(db, people, case, [f], unlock=unlock)
    assert _archive(data).read(_manifest(_archive(data))["files"][0]["entry"]) == b"name,amount\n"
    assert "password_override" not in _rows(db, "case_export_started")[-1].details
    settings[cs.PASSWORD_VAULTS] = cs.OVERRIDE
    over = _case(db, people, _vaults(pv), can_export=True, password_override=True)
    _prepare(db, people, over, [f])
    assert _rows(db, "case_export_started")[-1].details["password_override"] is True


# --------------------------------------------------------------------------- fetching

def test_the_owners_are_told_in_the_fetchs_commit_before_the_first_byte(db, people, storage, codes):
    a = _file(db, storage, people.v1, name="a.txt")
    b = _file(db, storage, people.v1, name="b.txt")
    c = _file(db, storage, people.v2, name="c.txt")
    case = _case(db, people, _vaults(people.v1, people.v2), can_export=True)
    out = _prepare(db, people, case, [a, b, c])
    db.query(m.ComplianceNoticeOutbox).delete()
    db.commit()
    resp = _fetch(db, people, case, out["export_id"])
    assert storage.opened == [], "no byte read yet"
    told = {(o.user_id, o.kind, o.details["files"]) for o in db.query(m.ComplianceNoticeOutbox)}
    assert told == {(people.olga.id, "export", 2), (people.otto.id, "export", 1)}
    assert db.get(m.ComplianceExport, uuid.UUID(out["export_id"])).fetched_at is not None
    _body(resp)
    assert sorted(storage.opened) == sorted(str(x.id) for x in (a, b, c))


def test_the_archive_holds_the_files_the_manifest_the_case_the_readme_and_the_sums(db, people, storage, codes,
                                                                                  tmp_path):
    board = _folder(db, people.v1)
    a = _file(db, storage, people.v1, name="minutes.txt", content=b"the board met", folder=board)
    b = _file(db, storage, people.v1, name="=cmd|calc.txt", content=bytes(range(256)) * 9)
    gone = _kept(db, _file(db, storage, people.v1, name="draft.txt", content=b"kept"))
    case = _case(db, people, _vaults(people.v1), can_export=True)
    export_id, data, resp = _export(db, people, case, [a, b, gone])
    assert resp.headers["content-type"] == "application/zip" and resp.headers["cache-control"] == "no-store"
    assert resp.headers["content-disposition"].startswith('attachment; filename="case-')
    archive = _archive(data)
    names = archive.namelist()
    assert {"manifest.json", "manifest.csv", "case.json", "README.txt", "SHA256SUMS"} <= set(names)
    manifest = _manifest(archive)
    by_id = {r["file_id"]: r for r in manifest["files"]}
    assert archive.read(by_id[str(a.id)]["entry"]) == b"the board met"
    assert by_id[str(a.id)]["entry"] == f"files/{people.v1.id}/Board minutes/minutes.txt"
    assert by_id[str(a.id)]["path"] == "Board minutes" and by_id[str(a.id)]["name"] == "minutes.txt"
    assert archive.read(by_id[str(b.id)]["entry"]) == bytes(range(256)) * 9
    assert by_id[str(gone.id)]["status"] == ca.KEPT_DELETED and archive.read(by_id[str(gone.id)]["entry"]) == b"kept"
    for f in (a, b, gone):
        row = by_id[str(f.id)]
        assert row["sha256"] == hashlib.sha256(archive.read(row["entry"])).hexdigest() and row["integrity"] == "ok"
        assert row["uploaded_by"] == "olga" and row["size"] == len(archive.read(row["entry"]))
    assert manifest["case_number"] == case.number and manifest["export_id"] == export_id
    table = list(csv.DictReader(io.StringIO(archive.read("manifest.csv").decode())))
    assert {r["file_id"] for r in table} == {str(f.id) for f in (a, b, gone)}
    assert {r["name"] for r in table if r["file_id"] == str(b.id)} == {"'=cmd|calc.txt"}, "no formula"
    document = json.loads(archive.read("case.json"))
    assert document["case"]["number"] == case.number and document["case"]["auditor"] == "uma"
    assert document["case"]["approved_by"] == "bob" and document["export"]["id"] == export_id
    raw = archive.read("case.json").decode()
    for secret in (TEXT["justification"], TEXT["owner_note"], "criminal_offence", "special_category"):
        assert secret not in raw, secret
    sums = archive.read("SHA256SUMS").decode().splitlines()
    assert len(sums) == len(names) - 1
    for line in sums:
        digest, name = line.split("  ", 1)
        assert hashlib.sha256(archive.read(name)).hexdigest() == digest
    if shutil.which("sha256sum"):
        archive.extractall(tmp_path / "x")
        check = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=tmp_path / "x", capture_output=True,
                               text=True, timeout=60)
        assert check.returncode == 0 and check.stdout.count(": OK") == len(sums), check.stdout + check.stderr
    assert "sha256sum -c SHA256SUMS" in archive.read("README.txt").decode()


def test_the_manifests_hash_is_the_one_the_end_of_the_export_records(db, people, storage, codes):
    f = _file(db, storage, people.v1, content=b"evidence")
    case = _case(db, people, _vaults(people.v1), can_export=True)
    export_id, data, _resp = _export(db, people, case, [f])
    (row,) = _rows(db, "case_export_completed")
    digest = hashlib.sha256(_archive(data).read("manifest.json")).hexdigest()
    assert row.details["manifest_sha256"] == digest and row.case_id == case.id
    assert row.details["file_count"] == 1 and row.details["bytes"] == len(b"evidence")
    assert row.details["export_id"] == export_id and row.details["mismatched"] == 0
    export = db.get(m.ComplianceExport, uuid.UUID(export_id))
    db.refresh(export)
    assert export.status == "completed" and export.manifest_sha256 == digest
    assert _rows(db, "case_export_aborted", "failure") == []
    (mine,) = owner_access.page(db, people.olga)["cases"]
    assert mine["exports"] == 1


def test_an_export_is_fetched_once_by_its_maker_before_it_expires(db, people, storage, codes):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1), can_export=True)
    out = _prepare(db, people, case, [f])
    _, err = _call(_fetch, db, people, case, out["export_id"], who=people.mallory)
    assert err.status_code == 404 and err.detail["reason"] == ca.NOT_AUDITOR
    _, err = _call(_fetch, db, people, case, out["export_id"], who=people.bob)
    assert err.status_code == 404
    _, err = _call(_fetch, db, people, case, uuid.uuid4())
    assert err.status_code == 404 and err.detail["reason"] == ce.NO_SUCH_EXPORT
    _body(_fetch(db, people, case, out["export_id"]))
    _, err = _call(_fetch, db, people, case, out["export_id"])
    assert err.status_code == 410 and err.detail["reason"] == ce.FETCHED
    late = _prepare(db, people, case, [f])
    export = db.get(m.ComplianceExport, uuid.UUID(late["export_id"]))
    export.expires_at = ca.utcnow() - timedelta(seconds=1)
    db.commit()
    _, err = _call(_fetch, db, people, case, late["export_id"])
    assert err.status_code == 410 and err.detail["reason"] == ce.EXPIRED
    assert _refused(db) == [ca.NOT_AUDITOR, ca.NOT_AUDITOR, ce.NO_SUCH_EXPORT, ce.FETCHED, ce.EXPIRED]
    assert len(_rows(db, "case_export_completed")) == 1


def test_an_export_made_for_one_case_is_not_fetched_through_another(db, people, storage, codes):
    f = _file(db, storage, people.v1)
    first = _case(db, people, _vaults(people.v1), can_export=True)
    second = _case(db, people, _vaults(people.v1), can_export=True)
    out = _prepare(db, people, first, [f])
    _, err = _call(_fetch, db, people, second, out["export_id"])
    assert err.status_code == 404 and err.detail["reason"] == ce.NO_SUCH_EXPORT
    assert db.get(m.ComplianceExport, uuid.UUID(out["export_id"])).fetched_at is None


def test_the_fetch_checks_the_case_and_every_file_again_and_changes_nothing_when_refused(db, people, storage, codes,
                                                                                        settings):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1), can_export=True)
    out = _prepare(db, people, case, [f])
    settings[cs.EXPORT] = cs.DISABLED
    _, err = _call(_fetch, db, people, case, out["export_id"])
    assert err.status_code == 403 and err.detail["reason"] == ce.EXPORT_OFF
    settings[cs.EXPORT] = cs.ALLOWED
    case.access_ends_at = ca.utcnow() - timedelta(seconds=1)
    db.commit()
    _, err = _call(_fetch, db, people, case, out["export_id"])
    assert err.status_code == 403 and err.detail["reason"] == rules.ACCESS_ENDED
    export = db.get(m.ComplianceExport, uuid.UUID(out["export_id"]))
    assert export.fetched_at is None and db.query(m.ComplianceNoticeOutbox).filter(
        m.ComplianceNoticeOutbox.kind == "export").count() == 0


# --------------------------------------------------------------------------- names in the archive

HOSTILE = ["../escape.txt", "/etc/passwd", "C:\\Windows\\win.ini", "con.txt", "a\x00b\x1fc\u202e.txt", "x" * 1000,
           "dup.txt", "dup.txt", "DUP.TXT", "...", "trailing. ", "nul",
           # Equal ignoring case only once folded: the second sorts after the first.
           "SS.txt", "ß.txt"]


def test_hostile_names_become_safe_unique_entries_and_the_manifest_keeps_them(db, people, storage, codes):
    up = _folder(db, people.v1, None, "..")
    files = [_file(db, storage, people.v1, name=n, content=n.encode("utf-8", "replace")) for n in HOSTILE]
    files.append(_file(db, storage, people.v1, name="inside.txt", folder=up))
    case = _case(db, people, _vaults(people.v1), can_export=True)
    _id, data, _resp = _export(db, people, case, files)
    archive = _archive(data)
    entries = [r["entry"] for r in _manifest(archive)["files"]]
    assert len(entries) == len(files) and len({e.casefold() for e in entries}) == len(entries)
    for entry in entries:
        segments = entry.split("/")
        assert segments[:2] == ["files", str(people.v1.id)], entry
        for seg in segments[2:]:
            assert seg and seg not in (".", "..") and not set(seg) & set('<>:"|?*\\'), entry
            assert all(ord(ch) >= 32 and ch != "\u202e" for ch in seg), entry
            assert len(seg) <= ce.SEGMENT_MAX, entry
            assert seg.split(".")[0].strip().lower() not in {"con", "nul"}, entry
            assert seg == seg.strip() and not seg.endswith("."), entry
    assert {r["name"] for r in _manifest(archive)["files"]} >= {"../escape.txt", "/etc/passwd", "x" * 1000}
    for info in archive.infolist():
        assert not info.filename.startswith("/") and ".." not in info.filename.split("/")


# --------------------------------------------------------------------------- the stream's end

def _stream(db, people, case, files):
    """An ExportStream for ``files``, claimed (the owners told), on sessions of the test's database."""
    from sqlalchemy.orm import sessionmaker
    out = _prepare(db, people, case, files)
    case_, export, entries = ce.claim(db, case.id, out["export_id"], people.uma, session_hash=SESSION)
    make = sessionmaker(bind=db.get_bind(), autoflush=False)
    return ce.ExportStream(make, case_.id, export.id, people.uma.id, entries), out["export_id"]


def test_a_stream_stopped_before_its_end_records_its_abort_once(db, people, storage, codes):
    a = _file(db, storage, people.v1, name="a.txt", content=b"a" * 5000)
    b = _file(db, storage, people.v1, name="b.txt", content=b"b" * 5000)
    case = _case(db, people, _vaults(people.v1), can_export=True)
    parts, export_id = _stream(db, people, case, [a, b])
    next(parts)
    parts.close()
    parts.close()
    (row,) = _rows(db, "case_export_aborted", "failure")
    assert row.details["export_id"] == export_id and row.details["reason"] == "stopped"
    assert row.details["file_count"] == 0 and row.case_id == case.id
    assert _rows(db, "case_export_completed") == []
    export = db.get(m.ComplianceExport, uuid.UUID(export_id))
    db.refresh(export)
    assert export.status == "aborted"
    # Never started: closed, or dropped by a response that never read it.
    never, _ = _stream(db, people, case, [a])
    never.close()
    dropped, _ = _stream(db, people, case, [a])
    del dropped
    gc.collect()
    assert len(_rows(db, "case_export_aborted", "failure")) == 3
    # A new export starts again, and is recorded.
    _id, data, _resp = _export(db, people, case, [a, b])
    assert len(_rows(db, "case_export_completed")) == 1 and _archive(data)


def test_an_export_stops_when_the_cases_access_ends(db, people, storage, codes):
    a = _file(db, storage, people.v1, name="a.txt", content=b"first")
    b = _file(db, storage, people.v1, name="b.txt", content=b"second")
    case = _case(db, people, _vaults(people.v1), can_export=True)
    parts, export_id = _stream(db, people, case, [a, b])
    got = b""
    while len(storage.opened) < 1:
        got += next(parts)
    case.access_ends_at = ca.utcnow() - timedelta(seconds=1)
    db.commit()
    with pytest.raises(ce.Stopped):
        while True:
            got += next(parts)
    parts.close()
    assert storage.opened == [str(a.id)], "nothing of the second file was read"
    (row,) = _rows(db, "case_export_aborted", "failure")
    assert row.details["reason"] == rules.ACCESS_ENDED and row.details["file_count"] == 1
    assert b"second" not in got


def test_a_file_gone_since_the_fetch_is_listed_missing_and_one_kept_since_is_exported(db, people, storage, codes):
    a = _file(db, storage, people.v1, name="a.txt", content=b"alpha")
    b = _file(db, storage, people.v1, name="b.txt", content=b"bravo")
    c = _file(db, storage, people.v1, name="c.txt", content=b"charlie")
    case = _case(db, people, _vaults(people.v1), can_export=True)
    parts, _export_id = _stream(db, people, case, [a, b, c])
    db.delete(b)
    db.commit()
    _kept(db, c)
    (storage.root / a.storage_path).unlink()
    data = b"".join(parts)
    parts.close()
    manifest = _manifest(_archive(data))
    status = {r["file_id"]: (r["status"], r["entry"]) for r in manifest["files"]}
    assert status[str(b.id)] == (ce.MISSING, None)
    assert status[str(a.id)] == (ce.UNREADABLE, None), "its row is there, its stored content is not"
    assert status[str(c.id)][0] == ca.KEPT_DELETED and _archive(data).read(status[str(c.id)][1]) == b"charlie"
    (row,) = _rows(db, "case_export_completed")
    assert row.details["missing"] == 1 and row.details["unreadable"] == 1 and row.details["file_count"] == 1


def test_a_stored_file_that_does_not_match_its_checksum_is_exported_and_flagged(db, people, storage, codes):
    f = _file(db, storage, people.v1, content=b"what was stored")
    f.checksum_sha256 = hashlib.sha256(b"something else").hexdigest()
    db.commit()
    case = _case(db, people, _vaults(people.v1), can_export=True)
    _id, data, _resp = _export(db, people, case, [f])
    archive = _archive(data)
    (row,) = _manifest(archive)["files"]
    assert row["integrity"] == ce.MISMATCH and archive.read(row["entry"]) == b"what was stored"
    assert row["sha256"] == hashlib.sha256(b"what was stored").hexdigest()
    assert _rows(db, "case_export_completed")[0].details["mismatched"] == 1


class _Huge:
    """A stored file of ``size`` bytes, read a MiB at a time, never held whole."""

    def __init__(self, size):
        self.size = size
        self.checksum = "0" * 64

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def pieces(self):
        block = bytes(range(256)) * 4096
        left = self.size
        while left > 0:
            piece = block if left >= len(block) else block[:left]
            left -= len(piece)
            yield piece


def test_memory_stays_bounded_with_a_multi_gigabyte_file(db, people, storage, codes, monkeypatch):
    size = 4 * 1024 ** 3 + 512 * 1024 ** 2   # past what a zip without ZIP64 can hold
    f = _file(db, storage, people.v1, name="disk.img", content=b"x")
    case = _case(db, people, _vaults(people.v1), can_export=True)
    parts, _export_id = _stream(db, people, case, [f])
    monkeypatch.setattr(ce, "_open_stored", lambda factory, entry, now: _Huge(size))
    total, tail = 0, b""
    tracemalloc.start()
    try:
        for piece in parts:
            total += len(piece)
            tail = (tail + piece)[-4096:]
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        parts.close()
    assert total > size and peak < 32 * 1024 ** 2, peak
    assert b"PK\x06\x06" in tail and b"PK\x06\x07" in tail, "the archive ends with ZIP64 records"
    (row,) = _rows(db, "case_export_completed")
    assert row.details["bytes"] == size


# --------------------------------------------------------------------------- how it is made

def test_the_export_routes_are_plain_defs_with_a_statement_timeout_and_no_group_or_permission():
    for fn in (cr.prepare_case_export, cr.fetch_case_export):
        assert not inspect.iscoroutinefunction(fn)
        source = inspect.getsource(fn)
        assert "limit_statements(db)" in source
        for forbidden in ("require_endpoint_permission", "PermissionEnum", "require_permission", "require_vault_cap"):
            assert forbidden not in source, forbidden
    prepare = inspect.getsource(cr.prepare_case_export)
    assert prepare.index("chosen()") < prepare.index("STEP_UP_CASE_EXPORT") < prepare.rindex("chosen()"), \
        "checked before the code is asked for, and again after"


def test_the_export_requests_body_has_its_class():
    rule = bl.rule_for("POST", f"/compliance/cases/{uuid.uuid4()}/exports")
    assert rule.name == "case_export_request" and rule.limit == 512 * 1024 and rule.needs_session


def test_only_the_export_reads_a_stored_file_without_its_checksum_check():
    """BoundedDownload.pieces() skips the check a download enforces: the export alone uses it, and says in its
    manifest whether the bytes matched."""
    users = sorted(str(p.relative_to(ROOT)).replace("\\", "/") for p in (ROOT / "app").rglob("*.py")
                   if ".pieces()" in p.read_text(encoding="utf-8"))
    assert users == ["app/core/case_export.py"]


def test_the_export_is_the_only_new_reader_of_stored_files_for_a_case():
    source = Path(ce.__file__).read_text(encoding="utf-8")
    assert source.count("_open_stored_file(") == 1 and "ca._vault_service(db)._open_stored_file" in source


# --------------------------------------------------------------------------- what "every file" leaves out, and what
# the fetch checks again

def test_every_file_leaves_out_what_the_case_may_not_export_instead_of_refusing_it(db, people, storage, codes):
    """A zero-knowledge vault, a locked password vault, a file outside the time range and a kept file due for its
    purge are left out of "every file"; the rest is exported."""
    zk = _vault(db, people.olga, kind="zero_knowledge")
    _file(db, storage, zk, name="sealed.bin")
    pv = _vault(db, people.olga, password="argon2-hash")
    _file(db, storage, pv, name="salaries.csv")
    keep = _file(db, storage, people.v1, name="recent.txt")
    old = _file(db, storage, people.v1, name="old.txt")
    old.created_at = old.updated_at = ca.utcnow() - timedelta(days=400)
    due = _kept(db, _file(db, storage, people.v1, name="purged.txt"))
    due.purge_after = ca.utcnow() - timedelta(minutes=1)
    db.commit()
    case = _case(db, people, _vaults(people.v1, zk, pv), can_export=True,
                 files_from=ca.utcnow() - timedelta(days=30))
    out = _prepare(db, people, case, every=True)
    assert db.get(m.ComplianceExport, uuid.UUID(out["export_id"])).file_ids == [str(keep.id)]


def test_an_export_is_fetched_only_by_the_account_that_prepared_it(db, people, storage, codes):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1), can_export=True)
    out = _prepare(db, people, case, [f])
    export = db.get(m.ComplianceExport, uuid.UUID(out["export_id"]))
    export.created_by = people.mallory.id
    db.commit()
    _, err = _call(_fetch, db, people, case, out["export_id"])
    assert err.status_code == 404 and err.detail["reason"] == ce.NO_SUCH_EXPORT
    assert export.fetched_at is None


def test_a_fetched_export_is_refused_as_fetched_before_its_files_are_checked_again(db, people, storage, codes):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1), can_export=True)
    out = _prepare(db, people, case, [f])
    _body(_fetch(db, people, case, out["export_id"]))
    people.v1.password_hash = "argon2-hash"
    db.commit()
    _, err = _call(_fetch, db, people, case, out["export_id"])
    assert err.status_code == 410 and err.detail["reason"] == ce.FETCHED


def test_two_fetches_at_once_give_the_archive_once(db, people, storage, codes, monkeypatch):
    """The fetch marks the export fetched only where it is not yet: another fetch that read it unfetched a moment
    before and committed first leaves this one nothing."""
    from sqlalchemy.orm import sessionmaker
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1), can_export=True)
    out = _prepare(db, people, case, [f])
    real = ca.unlocked_vaults
    other = sessionmaker(bind=db.get_bind())()

    def meanwhile(*a, **k):
        other.query(m.ComplianceExport).filter(m.ComplianceExport.id == uuid.UUID(out["export_id"])).update(
            {"fetched_at": ca.utcnow()})
        other.commit()
        return real(*a, **k)
    monkeypatch.setattr(ca, "unlocked_vaults", meanwhile)
    with pytest.raises(ca.Refused) as refused:
        ce.claim(db, case.id, out["export_id"], people.uma, session_hash=SESSION)
    other.close()
    assert refused.value.reason == ce.FETCHED
    assert db.query(m.ComplianceNoticeOutbox).filter(m.ComplianceNoticeOutbox.kind == "export").count() == 0


def test_a_password_vault_must_be_unlocked_again_to_fetch_its_export(db, people, storage, codes):
    pv = _vault(db, people.olga, password="argon2-hash")
    f = _file(db, storage, pv, name="salaries.csv")
    case = _case(db, people, _vaults(pv), can_export=True)
    unlock = f"{pv.id}={_receipt(case, pv, people.uma)}"
    out = _prepare(db, people, case, [f], unlock=unlock)
    _, err = _call(_fetch, db, people, case, out["export_id"])
    assert err.status_code == 403 and err.detail["reason"] == ca.LOCKED
    assert db.get(m.ComplianceExport, uuid.UUID(out["export_id"])).fetched_at is None
    assert _rows(db, "case_export_completed") == []
    _body(_fetch(db, people, case, out["export_id"], unlock=unlock))
    assert len(_rows(db, "case_export_completed")) == 1


def test_an_export_stops_when_exports_are_turned_off(db, people, storage, codes, settings):
    a = _file(db, storage, people.v1, name="a.txt", content=b"first")
    b = _file(db, storage, people.v1, name="b.txt", content=b"second")
    case = _case(db, people, _vaults(people.v1), can_export=True)
    parts, _export_id = _stream(db, people, case, [a, b])
    next(parts)
    settings[cs.EXPORT] = cs.DISABLED
    with pytest.raises(ce.Stopped):
        while True:
            next(parts)
    parts.close()
    (row,) = _rows(db, "case_export_aborted", "failure")
    assert row.details["reason"] == ce.EXPORT_OFF and row.details["file_count"] == 1


def test_the_response_closes_its_stream_when_the_client_goes_away(db, people, storage, codes):
    """The route's body ends the export when its reader stops (a client gone): the abort is recorded at once, not
    when the response is collected."""
    a = _file(db, storage, people.v1, name="a.txt", content=b"a" * 5000)
    case = _case(db, people, _vaults(people.v1), can_export=True)
    out = _prepare(db, people, case, [a])
    resp = _fetch(db, people, case, out["export_id"])

    async def one_then_leave():
        body = resp.body_iterator
        piece = await body.__anext__()
        await body.aclose()
        return piece
    assert run_coroutine(one_then_leave())
    (row,) = _rows(db, "case_export_aborted", "failure")
    assert row.details["export_id"] == out["export_id"] and resp is not None


def _scope():
    return {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
            "method": "GET", "path": "/", "headers": []}


@pytest.mark.parametrize("how", ["disconnect_heard", "send_fails", "task_cancelled"])
def test_a_client_gone_mid_stream_records_the_abort_before_the_response_is_collected(db, people, storage, codes,
                                                                                    how):
    """However the server learns the client is gone (it hears the disconnect, sending fails, or it cancels the
    request's task), the response closes its body, so the export's abort is recorded at once."""
    import asyncio
    a = _file(db, storage, people.v1, name="a.txt", content=b"a" * 5000)
    b = _file(db, storage, people.v1, name="b.txt", content=b"b" * 5000)
    case = _case(db, people, _vaults(people.v1), can_export=True)
    out = _prepare(db, people, case, [a, b])
    resp = _fetch(db, people, case, out["export_id"])

    async def serve():
        gone = asyncio.Event()

        async def send(message):
            if message["type"] == "http.response.body" and message.get("body"):
                if how == "send_fails":
                    raise OSError("the client went away")
                gone.set()
                await asyncio.sleep(3600)          # the client stops reading; the server hears it leave

        async def receive():
            if how == "task_cancelled":
                await asyncio.sleep(3600)          # this server never says; it cancels the task instead
            await gone.wait()
            return {"type": "http.disconnect"}
        try:
            if how == "task_cancelled":
                # Cancelled as an anyio host cancels a request: every await inside stays cancelled.
                import anyio
                async with anyio.create_task_group() as group:
                    async def cancel_when_gone():
                        await gone.wait()
                        group.cancel_scope.cancel()
                    group.start_soon(cancel_when_gone)
                    await resp(_scope(), receive, send)
            else:
                await resp(_scope(), receive, send)
        except Exception:  # noqa: BLE001 -- however the response ended
            pass
        # Read as the response ends, before the loop closes (closing it would close the body too).
        db.expire_all()
        return len(_rows(db, "case_export_aborted", "failure"))
    assert run_coroutine(serve()) == 1, "recorded when the response ended, not when it was collected"
    (row,) = _rows(db, "case_export_aborted", "failure")
    assert row.details["export_id"] == out["export_id"] and row.case_id == case.id and resp is not None
    assert _rows(db, "case_export_completed") == []
