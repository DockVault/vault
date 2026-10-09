"""Reading a compliance case through its routes (app/api/compliance_router.py, "reading a case"), offline on a real
(SQLite) database with files stored as the vault stores them: the case's vaults and folders with kept items and
their status, a file's metadata, its content (a range adds no record; served to be shown, never run), the rendered
preview, unlocking a password vault (one throttle for the auditor and the vault, whatever the case), and searching
names (the query never recorded). Every refusal of the reading routes, recorded. test_case_access.py covers the
resolver; test_case_access_live.py runs the routes on a stack."""
# ruff: noqa: F811 -- the fixtures of _case_access_helpers are imported by name and used as parameters
import inspect
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from _async_run import run_coroutine  # noqa: E402
from _case_access_helpers import (  # noqa: E402,F401 -- the fixtures are used by name
    SESSION, TEXT, db, people, quiet, settings, storage)
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
from app.core import case_rules as rules  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402
from app.core import models as m  # noqa: E402
from app.core import vault_unlock_receipts as receipts  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def session(monkeypatch):
    monkeypatch.setattr(api, "_current_session_hash", lambda request: SESSION)


def _request(**headers):
    return SimpleNamespace(headers={k.lower().replace("_", "-"): v for k, v in headers.items()})


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs), None
    except HTTPException as exc:
        return None, exc


def _body(response) -> bytes:
    async def collect():
        out = b""
        async for piece in response.body_iterator:
            out += piece if isinstance(piece, bytes) else piece.encode()
        return out
    return run_coroutine(collect())


def _tree(db, people, case, vault=None, folder=None, unlock=None, who=None):
    return cr.case_tree(case.id, _request(), vault_id=vault.id if vault else None,
                        folder_id=folder.id if folder else None, offset=0, limit=500, x_case_unlock=unlock,
                        current_user=who or people.uma, db=db)


def _content(db, people, case, f, unlock=None, who=None, **headers):
    return cr.case_file_content(case.id, f.id, _request(**headers), x_case_unlock=unlock,
                                current_user=who or people.uma, db=db)


def _refused_rows(db):
    return [(r.details.get("reason"), r.case_id) for r in _rows(db, "case_access_refused", "failure")]


# --------------------------------------------------------------------------- the tree

def test_the_case_lists_its_vaults_with_their_names_and_how_each_opens(db, people, storage):
    pv = _vault(db, people.olga, password="argon2-hash")
    zk = _vault(db, people.olga, kind="zero_knowledge")
    case = _case(db, people, _vaults(people.v1, pv, zk))
    out = {v["vault_id"]: v for v in _tree(db, people, case)["vaults"]}
    assert out[str(people.v1.id)]["name"] == people.v1.name and not out[str(people.v1.id)]["locked"]
    assert out[str(pv.id)]["locked"] is True and out[str(pv.id)]["name"] == pv.name
    assert out[str(zk.id)]["zero_knowledge"] is True and out[str(zk.id)]["name"] == zk.name, \
        "a zero-knowledge vault's label is what its members see while it is locked"
    (row,) = _rows(db, "case_folder_listed")
    assert row.case_id == case.id and row.resource_type == "case"


def test_a_folder_lists_folders_and_files_live_and_kept_with_their_status(db, people, storage):
    board = _folder(db, people.v1)
    live = _file(db, storage, people.v1, name="minutes.txt", folder=board)
    gone = _kept(db, _file(db, storage, people.v1, name="draft.txt", folder=board))
    expired = _kept(db, _file(db, storage, people.v1, name="old.txt", folder=board), reason="expired")
    case = _case(db, people, _vaults(people.v1))
    root = _tree(db, people, case, people.v1)
    assert [(e["kind"], e["name"]) for e in root["entries"]] == [("folder", "Board minutes")]
    out = _tree(db, people, case, people.v1, board)
    by_name = {e["name"]: e for e in out["entries"]}
    assert by_name["minutes.txt"]["status"] == ca.LIVE and by_name["draft.txt"]["status"] == ca.KEPT_DELETED
    assert by_name["old.txt"]["status"] == ca.KEPT_EXPIRED
    assert {by_name["draft.txt"]["id"], by_name["old.txt"]["id"]} == {str(gone.id), str(expired.id)}
    assert out["path"] == [{"id": str(board.id), "name": "Board minutes"}]
    assert all("checksum" not in str(k) for e in out["entries"] for k in e), "never the stored checksum"
    assert by_name["minutes.txt"]["uploaded_by"] == "olga" and by_name["minutes.txt"]["size"] == live.size_bytes


def test_a_listing_is_recorded_once_per_folder_in_ten_minutes(db, people, storage):
    board = _folder(db, people.v1)
    case = _case(db, people, _vaults(people.v1))
    now = ca.utcnow()
    for at in (now, now + timedelta(minutes=9)):
        ca.tree(db, case, people.uma, people.v1.id, board.id, now=at)
    ca.tree(db, case, people.uma, people.v1.id, None, now=now)
    listed = _rows(db, "case_folder_listed")
    assert sorted(r.resource_id for r in listed) == sorted([str(board.id), str(people.v1.id)])
    ca.tree(db, case, people.uma, people.v1.id, board.id, now=now + timedelta(minutes=11))
    assert len(_rows(db, "case_folder_listed")) == 3


def test_a_folder_case_lists_only_the_way_to_its_folders_above_them(db, people, storage):
    top = _folder(db, people.v1, None, "Company")
    board = _folder(db, people.v1, top, "Board minutes")
    side = _folder(db, people.v1, top, "Holidays")
    _file(db, storage, people.v1, name="root.txt")
    _file(db, storage, people.v1, name="top.txt", folder=top)
    _file(db, storage, people.v1, name="minutes.txt", folder=board)
    case = _case(db, people, [{"kind": "folder", "target_id": board.id}])
    assert [e["name"] for e in _tree(db, people, case, people.v1)["entries"]] == ["Company"]
    above = _tree(db, people, case, people.v1, top)["entries"]
    assert [(e["name"], e["in_scope"]) for e in above] == [("Board minutes", True)], \
        "the way to the case's folder, without its siblings or the files above it"
    assert [e["name"] for e in _tree(db, people, case, people.v1, board)["entries"]] == ["minutes.txt"]
    _, err = _call(_tree, db, people, case, people.v1, side)
    assert err.status_code == 404 and err.detail["reason"] == ca.OUT_OF_SCOPE
    assert (ca.OUT_OF_SCOPE, case.id) in _refused_rows(db)


def test_a_zero_knowledge_vault_lists_its_structure_and_sizes_but_no_name(db, people, storage):
    zk = _vault(db, people.olga, kind="zero_knowledge")
    sub = _folder(db, zk, None, "sealed-folder-name")
    _file(db, storage, zk, name="sealed-file-name", folder=sub)
    case = _case(db, people, _vaults(zk))
    (folder_entry,) = _tree(db, people, case, zk)["entries"]
    assert folder_entry["name"] is None and folder_entry["id"] == str(sub.id)
    (entry,) = _tree(db, people, case, zk, sub)["entries"]
    assert entry["name"] is None and entry["mime_type"] is None and entry["size"] > 0 and entry["uploaded_at"]


def test_a_password_vault_lists_names_only_once_unlocked_and_under_the_override_marks_the_row(db, people, storage,
                                                                                               settings):
    pv = _vault(db, people.olga, password="argon2-hash")
    _file(db, storage, pv, name="salaries.xlsx")
    case = _case(db, people, _vaults(pv))
    (locked,) = _tree(db, people, case, pv)["entries"]
    assert locked["name"] is None
    good = f"{pv.id}={_receipt(case, pv, people.uma)}"
    (opened,) = cr.case_tree(case.id, _request(), vault_id=pv.id, folder_id=None, offset=0, limit=500,
                             x_case_unlock=good, current_user=people.uma, db=db)["entries"]
    assert opened["name"] == "salaries.xlsx"
    settings[cs.PASSWORD_VAULTS] = cs.OVERRIDE
    over = _case(db, people, _vaults(pv), password_override=True)
    (shown,) = _tree(db, people, over, pv)["entries"]
    assert shown["name"] == "salaries.xlsx"
    assert [r.details.get("password_override") for r in _rows(db, "case_folder_listed")
            if r.case_id == over.id] == [True]
    settings[cs.PASSWORD_VAULTS] = cs.REFUSE
    _, err = _call(_tree, db, people, case, pv)
    assert err.status_code == 403 and err.detail["reason"] == ca.PASSWORD_REFUSED


def test_the_time_range_hides_files_outside_it_from_the_listing(db, people, storage):
    _file(db, storage, people.v1, name="in.txt", created_at=datetime(2026, 3, 5), updated_at=datetime(2026, 3, 5))
    _file(db, storage, people.v1, name="out.txt", created_at=datetime(2026, 5, 5), updated_at=datetime(2026, 5, 5))
    case = _case(db, people, _vaults(people.v1), files_from=datetime(2026, 3, 1), files_to=datetime(2026, 3, 31))
    assert [e["name"] for e in _tree(db, people, case, people.v1)["entries"]] == ["in.txt"]


def test_a_large_folder_is_listed_a_page_at_a_time(db, people, storage):
    for i in range(5):
        _file(db, storage, people.v1, name=f"f{i}.txt")
    case = _case(db, people, _vaults(people.v1))
    page = ca.tree(db, case, people.uma, people.v1.id, None, offset=2, limit=2)
    assert page["total"] == 5 and len(page["entries"]) == 2 and page["more"] is True


# --------------------------------------------------------------------------- one file

def test_a_files_metadata_never_carries_its_stored_checksum(db, people, storage):
    board = _folder(db, people.v1)
    f = _file(db, storage, people.v1, folder=board)
    case = _case(db, people, _vaults(people.v1))
    out = cr.case_file_info(case.id, f.id, _request(), x_case_unlock=None, current_user=people.uma, db=db)
    assert out["name"] == "minutes.txt" and out["path"] == [{"id": str(board.id), "name": "Board minutes"}]
    assert f.checksum_sha256 not in str(out) and not any("checksum" in k for k in out)
    assert _rows(db, "case_folder_listed")[-1].resource_id == str(board.id)


# --------------------------------------------------------------------------- content

def test_content_is_sent_to_be_shown_with_no_store_and_never_run(db, people, storage):
    page = _file(db, storage, people.v1, name="page.html", content=b"<script>alert(1)</script>")
    page.mime_type = "text/html"
    db.commit()
    case = _case(db, people, _vaults(people.v1))
    resp = _content(db, people, case, page)
    assert _body(resp) == b"<script>alert(1)</script>"
    assert resp.headers["cache-control"] == "no-store" and resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["content-type"].startswith("text/plain"), "an HTML file is sent as text"
    assert resp.headers["content-security-policy"] == "default-src 'none'; sandbox"
    assert resp.headers["content-disposition"].startswith("inline;")
    assert len(_rows(db, "case_file_viewed")) == 1


def test_a_byte_range_is_answered_and_adds_no_record(db, people, storage):
    data = bytes(range(256)) * 40
    f = _file(db, storage, people.v1, name="clip.bin", content=data)
    case = _case(db, people, _vaults(people.v1))
    assert _body(_content(db, people, case, f)) == data
    resp = _content(db, people, case, f, range="bytes=100-199")
    assert resp.status_code == 206 and _body(resp) == data[100:200]
    assert resp.headers["content-range"] == f"bytes 100-199/{len(data)}"
    later = _content(db, people, case, f, range="bytes=5000-")
    assert _body(later) == data[5000:]
    assert len(_rows(db, "case_file_viewed")) == 1, "byte ranges add no rows"
    stale = _content(db, people, case, f, range="bytes=0-9", if_range='"not-the-tag"')
    assert stale.status_code == 200 and _body(stale) == data
    _, err = _call(_content, db, people, case, f, range=f"bytes={len(data) + 10}-")
    assert err.status_code == 416


def test_the_preview_renders_markdown_records_a_view_and_refuses_a_large_file_unrecorded(db, people, storage,
                                                                                       monkeypatch):
    md = _file(db, storage, people.v1, name="notes.md", content=b"# Heading\n\n<script>x</script>")
    case = _case(db, people, _vaults(people.v1))
    resp = cr.case_file_preview(case.id, md.id, _request(), kind=None, x_case_unlock=None,
                                current_user=people.uma, db=db)
    html = resp.body.decode()
    assert "Heading" in html and "<script>x" not in html
    assert _rows(db, "case_file_viewed")[-1].details.get("preview") is True
    monkeypatch.setattr(cr, "PREVIEW_MAX_BYTES", 3)
    big = _file(db, storage, people.v1, name="big.md", content=b"0123456789")
    _, err = _call(cr.case_file_preview, case.id, big.id, _request(), kind=None, x_case_unlock=None,
                   current_user=people.uma, db=db)
    assert err.status_code == 413 and _rows(db, "case_access_refused", "failure") == []
    assert len(_rows(db, "case_file_viewed")) == 1


# --------------------------------------------------------------------------- unlocking a password vault

@pytest.fixture
def attempts(monkeypatch):
    """The vault-password throttle, counted in memory by its bucket."""
    from app.core import rate_limit_settings, vault_attempt_throttle
    counts = {}
    monkeypatch.setattr(vault_attempt_throttle, "over_limit", lambda key, limit, window: counts.get(key, 0) >= limit)
    monkeypatch.setattr(vault_attempt_throttle, "burn", lambda key, window: counts.__setitem__(key, counts.get(key, 0) + 1))
    monkeypatch.setattr(rate_limit_settings, "effective", lambda key: 3 if "attempts" in key else 900)
    return counts


@pytest.fixture
def vault_password(monkeypatch):
    from app.core import security
    monkeypatch.setattr(security, "verify_password", lambda given, stored: given == "right-password")


def _unlock(db, people, case, vault, password, who=None):
    return cr.unlock_case_vault(case.id, vault.id, cr.CaseUnlock(password=password), _request(),
                                current_user=who or people.uma, db=db)


def test_the_right_password_gives_a_receipt_for_this_case_and_the_wrong_one_is_recorded(db, people, storage, attempts,
                                                                                       vault_password):
    pv = _vault(db, people.olga, password="argon2-hash")
    f = _file(db, storage, pv)
    case = _case(db, people, _vaults(pv))
    _, err = _call(_unlock, db, people, case, pv, "wrong")
    assert err.status_code == 403
    out = _unlock(db, people, case, pv, "right-password")
    assert receipts.verify(out["receipt"], purpose=receipts.PURPOSE_CASE, session_hash=SESSION, case_id=case.id,
                           vault_id=pv.id, user_id=people.uma.id, credential=receipts.credential_digest("argon2-hash"))
    assert _body(_content(db, people, case, f, unlock=f"{pv.id}={out['receipt']}")) == b"the board met on monday"
    rows = db.query(m.AuditLog).filter(m.AuditLog.action == "case_vault_unlocked").order_by(m.AuditLog.timestamp).all()
    assert [(r.status, r.details.get("reason")) for r in rows] == [("failure", "wrong_password"), ("success", None)]
    assert all(r.case_id == case.id for r in rows)
    assert all("right-password" not in str(r.details) and "wrong" != r.details.get("password") for r in rows)


def test_the_throttle_is_the_auditors_for_the_vault_across_cases(db, people, storage, attempts, vault_password):
    pv = _vault(db, people.olga, password="argon2-hash")
    first, second = _case(db, people, _vaults(pv)), _case(db, people, _vaults(pv))
    for _ in range(3):
        _call(_unlock, db, people, first, pv, "wrong")
    _, err = _call(_unlock, db, people, second, pv, "right-password")
    assert err.status_code == 429, "a new case does not reset the budget"
    assert list(attempts) == [receipts.throttle_key(pv.id, people.uma.id)]


def test_unlocking_is_refused_where_the_rule_or_the_vault_says_so(db, people, storage, settings, attempts,
                                                                  vault_password):
    pv = _vault(db, people.olga, password="argon2-hash")
    zk = _vault(db, people.olga, kind="zero_knowledge")
    case = _case(db, people, _vaults(people.v1, pv, zk))
    _, err = _call(_unlock, db, people, case, people.v1, "x")
    assert err.status_code == 400, "a vault with no password needs no unlocking"
    _, err = _call(_unlock, db, people, case, zk, "x")
    assert err.status_code == 403 and err.detail["reason"] == ca.ZERO_KNOWLEDGE
    _, err = _call(_unlock, db, people, case, people.v2, "x")
    assert err.status_code == 404 and err.detail["reason"] == ca.NO_SUCH_VAULT
    settings[cs.PASSWORD_VAULTS] = cs.REFUSE
    _, err = _call(_unlock, db, people, case, pv, "right-password")
    assert err.status_code == 403 and err.detail["reason"] == ca.PASSWORD_REFUSED
    assert attempts == {}, "no password was checked for a refused unlock"
    assert [r for r, _c in _refused_rows(db)] == [ca.ZERO_KNOWLEDGE, ca.NO_SUCH_VAULT, ca.PASSWORD_REFUSED]


# --------------------------------------------------------------------------- search

def _search(db, people, case, q, mode="prefix", unlock=None, vault=None):
    return cr.search_case(case.id, cr.CaseSearch(q=q, mode=mode, vault_id=vault.id if vault else None), _request(),
                          x_case_unlock=unlock, current_user=people.uma, db=db)


def test_search_matches_names_by_prefix_or_exactly_and_records_no_text(db, people, storage):
    for name in ("Invoice-2026.pdf", "invoice-2025.pdf", "notes.txt"):
        _file(db, storage, people.v1, name=name)
    gone = _kept(db, _file(db, storage, people.v1, name="Invoice-deleted.pdf"))
    case = _case(db, people, _vaults(people.v1))
    out = _search(db, people, case, "invoice")
    assert sorted(r["name"] for r in out["results"]) == ["Invoice-2026.pdf", "Invoice-deleted.pdf",
                                                          "invoice-2025.pdf"]
    assert {r["id"]: r["status"] for r in out["results"]}[str(gone.id)] == ca.KEPT_DELETED
    assert [r["name"] for r in _search(db, people, case, "NOTES.TXT", mode="exact")["results"]] == ["notes.txt"]
    rows = _rows(db, "case_search")
    assert [(r.details["query_length"], r.details["matches"]) for r in rows] == [(7, 3), (9, 1)]
    assert all("invoice" not in str(r.details).lower() and "notes" not in str(r.details).lower() for r in rows)


def test_search_keeps_to_the_case_and_never_reads_a_zero_knowledge_or_locked_vault(db, people, storage):
    pv = _vault(db, people.olga, password="argon2-hash")
    zk = _vault(db, people.olga, kind="zero_knowledge")
    board = _folder(db, people.v1)
    _file(db, storage, people.v1, name="report-in.txt", folder=board)
    _file(db, storage, people.v1, name="report-out.txt")
    _file(db, storage, people.v2, name="report-other-vault.txt")
    _file(db, storage, pv, name="report-locked.txt")
    _file(db, storage, zk, name="report-zk.txt")
    case = _case(db, people, [{"kind": "folder", "target_id": board.id}, *_vaults(pv, zk)])
    out = _search(db, people, case, "report")
    assert [r["name"] for r in out["results"]] == ["report-in.txt"]
    assert set(out["vaults_not_searched"]) == {str(pv.id), str(zk.id)}
    unlocked = _search(db, people, case, "report", unlock=f"{pv.id}={_receipt(case, pv, people.uma)}")
    assert sorted(r["name"] for r in unlocked["results"]) == ["report-in.txt", "report-locked.txt"]


def test_search_reads_at_most_its_cap_of_names_and_says_so(db, people, storage, monkeypatch):
    monkeypatch.setattr(ca, "SEARCH_MAX", 3)
    for i in range(5):
        _file(db, storage, people.v1, name=f"a{i}.txt")
    case = _case(db, people, _vaults(people.v1))
    out = _search(db, people, case, "a")
    assert out["scanned"] == 3 and out["truncated"] is True and len(out["results"]) == 3
    assert _rows(db, "case_search")[-1].details["truncated"] is True


# --------------------------------------------------------------------------- every refusal, recorded

def _every_route(db, people, case, f):
    """Each reading route of the case (and the export's two), as a call."""
    return {
        "tree": lambda who: _tree(db, people, case, people.v1, who=who),
        "vaults": lambda who: _tree(db, people, case, who=who),
        "info": lambda who: cr.case_file_info(case.id, f.id, _request(), x_case_unlock=None, current_user=who, db=db),
        "content": lambda who: _content(db, people, case, f, who=who),
        "preview": lambda who: cr.case_file_preview(case.id, f.id, _request(), kind=None, x_case_unlock=None,
                                                    current_user=who, db=db),
        "unlock": lambda who: cr.unlock_case_vault(case.id, people.v1.id, cr.CaseUnlock(password="x"), _request(),
                                                   current_user=who, db=db),
        "search": lambda who: cr.search_case(case.id, cr.CaseSearch(q="m"), _request(), x_case_unlock=None,
                                             current_user=who, db=db),
        # Exporting checks the case first too, before anything else (and before any code is asked for).
        "export": lambda who: cr.prepare_case_export(case.id, cr.ExportRequest(all=True), _request(),
                                                     x_case_unlock=None, current_user=who, db=db),
        "fetch": lambda who: cr.fetch_case_export(case.id, uuid.uuid4(), _request(), x_case_unlock=None,
                                                  current_user=who, db=db),
    }


@pytest.mark.parametrize("change, reason, status", [
    ("another_auditor", ca.NOT_AUDITOR, 404),
    ("temporary", ca.TEMPORARY, 403),
    ("disabled", rules.ACCESS_OFF, 403),
    ("access_ended", rules.ACCESS_ENDED, 403),
    ("closed", rules.NOT_ACTIVE, 403),
    ("suspended", rules.AUDITOR_NOT_LIVE, 403),
    ("revoked", rules.AUDITOR_NOT_LIVE, 403),
    ("grant_expired", rules.AUDITOR_NOT_LIVE, 403),
    ("deactivated", rules.AUDITOR_NOT_LIVE, 403),
    ("locked", rules.AUDITOR_NOT_LIVE, 403),
])
def test_every_reading_route_refuses_and_records_each_reason(db, people, storage, settings, change, reason, status):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))
    grant = rights.open_grant(db, people.uma.id)
    who = people.uma
    if change == "another_auditor":
        who = people.mallory
    elif change == "temporary":
        people.uma._is_temp_session = True
    elif change == "disabled":
        settings[cs.ACCESS] = cs.DISABLED
    elif change == "access_ended":
        case.access_ends_at = ca.utcnow() - timedelta(seconds=1)
    elif change == "closed":
        case.status = rules.CLOSED
    elif change == "suspended":
        rights.suspend(db, grant, "password_changed")
    elif change == "revoked":
        rights.revoke(db, grant, actor=people.ada)
    elif change == "grant_expired":
        grant.expires_at = ca.utcnow() - timedelta(seconds=1)
    elif change == "deactivated":
        people.uma.is_active = False
    elif change == "locked":
        people.uma.is_locked = True
    db.commit()
    try:
        for name, call in _every_route(db, people, case, f).items():
            before = len(_rows(db, "case_access_refused", "failure"))
            _, err = _call(call, who)
            assert err is not None and err.status_code == status and err.detail["reason"] == reason, name
            after = _rows(db, "case_access_refused", "failure")
            assert len(after) == before + 1 and after[-1].details["reason"] == reason, name
            assert after[-1].case_id == case.id, name
    finally:
        people.uma._is_temp_session = False
    assert storage.opened == [] and _rows(db, "case_file_viewed") == []


def test_an_unknown_case_is_not_found_on_every_route_and_recorded_without_a_case(db, people, storage):
    f = _file(db, storage, people.v1)
    ghost = SimpleNamespace(id=uuid.uuid4())
    for name, call in _every_route(db, people, ghost, f).items():
        _, err = _call(call, people.uma)
        assert err.status_code == 404 and err.detail["reason"] == ca.NO_CASE, name
    assert {c for _r, c in _refused_rows(db)} == {None}


# --------------------------------------------------------------------------- how the routes are made

READING = ("case_tree", "case_file_info", "case_file_content", "case_file_preview", "unlock_case_vault", "search_case")


@pytest.mark.parametrize("name", READING)
def test_each_reading_route_is_a_plain_def_with_a_statement_timeout_and_no_group_or_permission(name):
    fn = getattr(cr, name)
    assert not inspect.iscoroutinefunction(fn), "a plain def: the thread pool runs it"
    source = inspect.getsource(fn)
    assert "limit_statements(db)" in source
    for forbidden in ("require_endpoint_permission", "PermissionEnum", "require_permission", "require_vault_cap"):
        assert forbidden not in source, forbidden


def test_the_reading_routes_bodies_have_the_small_class():
    for path in ("/compliance/cases/{case_id}/search", "/compliance/cases/{case_id}/vaults/{vault_id}/unlock"):
        concrete = path.replace("{case_id}", str(uuid.uuid4())).replace("{vault_id}", str(uuid.uuid4()))
        rule = bl.rule_for("POST", concrete)
        assert rule.name == "case_query" and rule.limit == bl.PUBLIC_LIMIT, path
