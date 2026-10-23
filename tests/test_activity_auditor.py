"""The Activity page for an auditor, offline on a real (SQLite) database (app/api/activity_viewer.py,
app/services/activity_case.py, the case filter in app/services/activity_events.py, the routes in
app/api/api_server.py and app/api/activity_search_router.py).

Who reads the log: an administrator, or an auditor whose right is in force, each read by the right recorded at most
once in ten minutes; live sessions, transfers, the temporary-credential typeahead and the Activity unlock stay an
administrator's. The live signal reaches a live auditor's own session. A case selected limits the events to its own
rows and its vaults; its auditor, while it gives access, reads the names it lets them read (in its folders and time
range, never zero-knowledge, a password vault once unlocked), and a page that shows one is recorded once per set of
events in ten minutes. Where only the vault's password hides a name the case would show, its auditor (a member of the
vault or not) is told so and offered it, and no one else; what their own unlock on the Activity page shows stays.
test_activity_auditor_live.py runs it on a stack.
"""
# ruff: noqa: F811 -- the fixtures of _case_access_helpers are imported by name and used as parameters
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from _case_access_helpers import (  # noqa: E402,F401 -- the fixtures are used by name
    SESSION, TEXT, db, people, quiet, settings, storage)
from _case_access_helpers import case as _case  # noqa: E402
from _case_access_helpers import file as _file  # noqa: E402
from _case_access_helpers import folder as _folder  # noqa: E402
from _case_access_helpers import kept as _kept  # noqa: E402
from _case_access_helpers import receipt as _receipt  # noqa: E402
from _case_access_helpers import rows as _rows  # noqa: E402
from _case_access_helpers import user as _user  # noqa: E402
from _case_access_helpers import vault as _vault  # noqa: E402
from _case_access_helpers import vaults as _vaults  # noqa: E402
from app.api import activity_search_router as asr  # noqa: E402
from app.api import activity_viewer as av  # noqa: E402
from app.api import api_server as api  # noqa: E402
from app.core import auditor_rights as rights  # noqa: E402
from app.core import case_access as ca  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402
from app.core import models as m  # noqa: E402
from app.services import activity_case as ac  # noqa: E402
from app.services import activity_events as ev  # noqa: E402
from app.services import activity_names as an  # noqa: E402
from app.services.audit_logger import AuditLogger  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def denials(monkeypatch):
    out = []
    monkeypatch.setattr(api, "_audit_admin_denial", lambda db_, user, reason: out.append((user.username, reason)))
    monkeypatch.setattr(api, "_current_session_hash", lambda request: SESSION)
    return out


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs), None
    except HTTPException as exc:
        return None, exc


def _event(db, action, *, by, resource_type=None, resource_id=None, vault=None, case=None, **details):
    row = AuditLogger(db).build_row(action=action, status="success", user=by, resource_type=resource_type,
                                    resource_id=str(resource_id) if resource_id is not None else None,
                                    details={**({"vault_id": str(vault.id)} if vault is not None else {}), **details})
    if case is not None:
        row.case_id = case.id
    db.add(row)
    db.commit()
    return row


def _views(rows):
    return [ev.row_view(r) for r in rows]


# --------------------------------------------------------------------------- who reads the log

def test_an_administrator_and_a_live_auditor_read_the_log_and_no_one_else(db, people, denials):
    assert av.require_activity_viewer(current_user=people.bob, db=db) is people.bob
    assert av.require_activity_viewer(current_user=people.uma, db=db) is people.uma
    for who in (people.olga,):
        _, err = _call(av.require_activity_viewer, current_user=who, db=db)
        assert err.status_code == 403
    people.uma._is_temp_session = True
    try:
        _, err = _call(av.require_activity_viewer, current_user=people.uma, db=db)
        assert err.status_code == 403
    finally:
        people.uma._is_temp_session = False
    assert [u for u, _ in denials] == ["olga", "uma"]


@pytest.mark.parametrize("change", ["revoked", "suspended", "expired", "disabled", "deactivated"])
def test_an_auditor_whose_right_is_not_in_force_reads_nothing(db, people, settings, change):
    grant = rights.open_grant(db, people.uma.id)
    if change == "revoked":
        rights.revoke(db, grant, actor=people.ada)
    elif change == "suspended":
        rights.suspend(db, grant, "password_changed")
    elif change == "expired":
        grant.expires_at = rights.utcnow() - timedelta(seconds=1)
    elif change == "disabled":
        settings[cs.ACCESS] = cs.DISABLED
    elif change == "deactivated":
        people.uma.is_active = False
    db.commit()
    _, err = _call(av.require_activity_viewer, current_user=people.uma, db=db)
    assert err.status_code == 403
    assert _rows(db, av.VIEWED) == []


def test_an_auditors_reading_is_recorded_once_in_ten_minutes(db, people):
    now = av.utcnow()
    assert av.note_events_viewed(db, people.uma, now=now)
    assert not av.note_events_viewed(db, people.uma, now=now + timedelta(minutes=9))
    assert av.note_events_viewed(db, people.uma, now=now + timedelta(minutes=11))
    for _ in range(3):
        av.require_activity_viewer(current_user=people.mallory, db=db)
        av.require_activity_viewer(current_user=people.bob, db=db)
    rows = _rows(db, av.VIEWED)
    assert [r.username for r in rows] == ["uma", "uma", "mallory"], "an administrator's reading is not this row"
    assert all(r.case_id is None and "case_number" not in (r.details or {}) for r in rows)


def test_a_reading_whose_record_cannot_be_written_is_refused(db, people, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("the database refuses the row")
    monkeypatch.setattr(AuditLogger, "build_row", broken)
    _, err = _call(av.require_activity_viewer, current_user=people.uma, db=db)
    assert err.status_code == 503


ACTIVITY_VIEWER = {("GET", "/activity/catalog"), ("GET", "/activity/events"), ("GET", "/activity/events/{event_id}"),
                   ("GET", "/activity/usernames"), ("GET", "/activity/saved-searches"),
                   ("POST", "/activity/saved-searches"), ("PATCH", "/activity/saved-searches/{search_id}"),
                   ("DELETE", "/activity/saved-searches/{search_id}"),
                   ("POST", "/activity/saved-searches/{search_id}/default"),
                   ("DELETE", "/activity/saved-searches/{search_id}/default"), ("GET", "/activity/summary"),
                   ("GET", "/activity/export"), ("POST", "/activity/events/search"),
                   ("POST", "/activity/summary/search"), ("POST", "/activity/export")}


def _dependencies(route):
    out, todo = set(), list(route.dependant.dependencies)
    while todo:
        d = todo.pop()
        out.add(d.call)
        todo.extend(d.dependencies)
    return out


def _routes():
    """(path, route) of every route of the app, routers included."""
    from fastapi.routing import APIRoute, _IncludedRouter

    def walk(found, prefix):
        for r in found:
            if isinstance(r, _IncludedRouter):
                yield from walk(r.original_router.routes, prefix + r.include_context.prefix)
            elif isinstance(r, APIRoute):
                yield prefix + r.path, r
    return list(walk(api.app.router.routes, ""))


def test_the_activity_routes_an_auditor_may_use_and_the_ones_that_stay_an_administrators():
    seen = set()
    for path, route in _routes():
        if not path.startswith("/activity"):
            continue
        for method in route.methods or ():
            calls = _dependencies(route)
            if (method, path) in ACTIVITY_VIEWER:
                seen.add((method, path))
                assert av.require_activity_viewer in calls, (method, path)
            else:
                # An administrator's route, or an auditor's own (revealing a name: the compliance router's).
                assert av.require_activity_viewer not in calls, (method, path)
                assert api.require_interactive_admin in calls or any(
                    getattr(c, "__name__", "") in ("require_interactive_admin", "require_admin", "require_live_auditor")
                    for c in calls), (method, path)
    assert seen == ACTIVITY_VIEWER
    for name in ("/activity/now", "/activity/temp-credentials", "/activity/vaults/{vault_id}/unlock"):
        assert any(p == name for p, _r in _routes()), name


def test_no_activity_route_an_auditor_uses_asks_for_an_endpoint_group_or_a_permission():
    import inspect
    for fn in (api.activity_catalog, api.activity_events, api.activity_event, api.activity_usernames,
               api.activity_summary, api.activity_export, asr.search_events, asr.search_summary, asr.export_events):
        source = inspect.getsource(fn)
        for forbidden in ("require_endpoint_permission", "PermissionEnum", "require_permission"):
            assert forbidden not in source, (fn.__name__, forbidden)
    source = inspect.getsource(av)
    assert "endpoint_permission" not in source and "PermissionEnum" not in source


def test_the_live_signal_reaches_an_administrators_and_a_live_auditors_own_session(db, people, monkeypatch):
    from app.core import database
    monkeypatch.setattr(database, "SessionLocal", lambda: _same(db))
    assert api._ws_sees_activity(str(people.bob.id), False)
    assert api._ws_sees_activity(str(people.uma.id), False)
    assert not api._ws_sees_activity(str(people.uma.id), True), "a temporary credential never"
    assert not api._ws_sees_activity(str(people.olga.id), False)
    rights.revoke(db, rights.open_grant(db, people.uma.id), actor=people.ada)
    db.commit()
    assert not api._ws_sees_activity(str(people.uma.id), False)
    assert not api._ws_sees_activity(str(uuid.uuid4()), False)


class _same:
    """The test's session, handed out as a new one whose close() keeps it open."""

    def __init__(self, db):
        self._db = db

    def __getattr__(self, name):
        return getattr(self._db, name)

    def close(self):
        pass


# --------------------------------------------------------------------------- a case selected

def test_who_may_select_a_case(db, people):
    case = _case(db, people, _vaults(people.v1))
    mine = ac.select(db, people.uma, case.id)
    assert mine.names and mine.vault_ids == [str(people.v1.id)]
    theirs = ac.select(db, people.bob, case.id)
    assert not theirs.names, "an administrator reads names as a member would, never through the case"
    for who in (people.mallory, people.olga):
        _, err = _call(ac.select, db, who, case.id)
        assert err.status_code == 404, who.username
    _, err = _call(ac.select, db, people.uma, uuid.uuid4())
    assert err.status_code == 404
    olga_admin = _user(db, "olga2", m.RoleEnum.ADMIN)
    concerned = _case(db, people, _vaults(people.v1), named_user_ids=[olga_admin.id])
    _, err = _call(ac.select, db, olga_admin, concerned.id)
    assert err.status_code == 404, "an administrator the case concerns does not see it here either"
    case.access_ends_at = ca.utcnow() - timedelta(seconds=1)
    db.commit()
    ended = ac.select(db, people.uma, case.id)
    assert not ended.names and ended.vault_ids == [str(people.v1.id)], "a filter still, no names once access ends"


def test_a_case_keeps_its_own_rows_and_the_events_on_its_vaults(db, people, storage):
    f1 = _file(db, storage, people.v1)
    f2 = _file(db, storage, people.v2)
    case = _case(db, people, _vaults(people.v1))
    in_vault = _event(db, "file_download", by=people.olga, resource_type="file", resource_id=f1.id, vault=people.v1)
    the_vault = _event(db, "vault_settings_changed", by=people.olga, resource_type="vault",
                       resource_id=people.v1.id)
    other = _event(db, "file_download", by=people.otto, resource_type="file", resource_id=f2.id, vault=people.v2)
    own = _event(db, "case_search", by=people.uma, resource_type="case", resource_id=case.id, case=case)
    q = ev.build_events_query(db.query(m.AuditLog), m.AuditLog, case_id=case.id, case_vaults=[str(people.v1.id)])
    ids = {r.id for r in q.all()}
    assert {in_vault.id, the_vault.id, own.id} <= ids and other.id not in ids
    assert not any(r.case_id not in (None, case.id) for r in q.all())


def _shown(db, people, case, events_rows, unlock=None, viewer=None):
    selection = ac.select(db, viewer or people.uma, case.id, unlock_header=unlock, session_hash=SESSION)
    views = _views(events_rows)
    for view, names in zip(views, an.names_for(db, viewer or people.uma, views)):
        view["names"] = names
    for view, recorded in zip(views, an.recorded_names_for(db, viewer or people.uma, events_rows)):
        view["recorded_names"] = recorded
    return views, ac.case_names(db, selection, views, events_rows), selection


def test_the_case_shows_its_auditor_the_names_it_lets_them_read(db, people, storage):
    board = _folder(db, people.v1)
    f = _file(db, storage, people.v1, name="minutes.txt", folder=board)
    gone = _kept(db, _file(db, storage, people.v1, name="draft.txt", folder=board))
    out_of_case = _file(db, storage, people.v2, name="secret.txt")
    case = _case(db, people, _vaults(people.v1))
    rows = [_event(db, "file_download", by=people.olga, resource_type="file", resource_id=f.id, vault=people.v1),
            _event(db, "file_delete", by=people.olga, resource_type="file", resource_id=gone.id, vault=people.v1),
            _event(db, "folder_create", by=people.olga, resource_type="folder", resource_id=board.id, vault=people.v1),
            _event(db, "file_download", by=people.otto, resource_type="file", resource_id=out_of_case.id,
                   vault=people.v2)]
    views, shown, _sel = _shown(db, people, case, rows)
    assert [v["names"]["item"] for v in views[:3]] == ["minutes.txt", "draft.txt", "Board minutes"]
    assert all(v["names"]["vault"] == people.v1.name for v in views[:3])
    assert views[3]["names"] == {"vault": an.NOT_SHOWN, "item": an.NOT_SHOWN}, "never outside the case"
    assert [bool(s) for s in shown] == [True, True, True, False]
    # An administrator selecting it reads nothing more than they would.
    views, shown, _sel = _shown(db, people, case, rows, viewer=people.bob)
    assert not any(shown) and views[0]["names"]["item"] == an.NOT_SHOWN


def test_names_keep_to_the_cases_folders_and_time_range(db, people, storage):
    top = _folder(db, people.v1, None, "Company")
    board = _folder(db, people.v1, top, "Board minutes")
    side = _folder(db, people.v1, top, "Holidays")
    inside = _file(db, storage, people.v1, name="minutes.txt", folder=board)
    beside = _file(db, storage, people.v1, name="beach.jpg", folder=side)
    old = _file(db, storage, people.v1, name="old.txt", folder=board)
    old.created_at = old.updated_at = ca.utcnow() - timedelta(days=400)
    db.commit()
    case = _case(db, people, [{"kind": "folder", "target_id": board.id}],
                 files_from=ca.utcnow() - timedelta(days=30))
    rows = [_event(db, "file_download", by=people.olga, resource_type="file", resource_id=x.id, vault=people.v1)
            for x in (inside, beside, old)]
    rows += [_event(db, "folder_create", by=people.olga, resource_type="folder", resource_id=x.id, vault=people.v1)
             for x in (top, side)]
    views, shown, _sel = _shown(db, people, case, rows)
    assert [v["names"]["item"] for v in views] == ["minutes.txt", an.NOT_SHOWN, an.NOT_SHOWN, "Company",
                                                    an.NOT_SHOWN], "the way to the case's folder, never beside it"


def test_a_zero_knowledge_vault_shows_its_label_and_a_password_vault_its_names_once_unlocked(db, people, storage):
    zk = _vault(db, people.olga, kind="zero_knowledge")
    zf = _file(db, storage, zk, name="sealed.bin")
    pv = _vault(db, people.olga, password="argon2-hash")
    pf = _file(db, storage, pv, name="salaries.csv")
    case = _case(db, people, _vaults(zk, pv))
    rows = [_event(db, "file_download", by=people.olga, resource_type="file", resource_id=zf.id, vault=zk),
            _event(db, "file_download", by=people.olga, resource_type="file", resource_id=pf.id, vault=pv)]
    views, _shown_, _sel = _shown(db, people, case, rows)
    assert views[0]["names"] == {"vault": zk.name, "item": an.NOT_SHOWN}
    assert views[1]["names"] == {"vault": pv.name, "item": an.PASSWORD_HIDDEN}, "locked: no file names"
    assert ac.UNLOCK_IN_CASE not in views[0] and views[1][ac.UNLOCK_IN_CASE] is True
    unlock = f"{pv.id}={_receipt(case, pv, people.uma)}"
    views, _shown_, _sel = _shown(db, people, case, rows, unlock=unlock)
    assert views[1]["names"]["item"] == "salaries.csv"
    assert views[0]["names"]["item"] == an.NOT_SHOWN
    assert not any(ac.UNLOCK_IN_CASE in v for v in views)


def test_a_member_of_the_vault_sees_nothing_because_of_the_case(db, people, storage, monkeypatch):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))
    row = _event(db, "file_download", by=people.olga, resource_type="file", resource_id=f.id, vault=people.v1)
    monkeypatch.setattr(an, "readable_vault_ids", lambda db_, viewer, ids: set(ids))
    views, shown, _sel = _shown(db, people, case, [row])
    assert views[0]["names"]["item"] == f.name and shown == [set()]


def test_recorded_names_open_under_the_case_only_where_it_may_name_the_item(db, people, storage, monkeypatch):
    f = _file(db, storage, people.v1, name="minutes.txt")
    case = _case(db, people, _vaults(people.v1))
    row = _event(db, "file_download", by=people.olga, resource_type="file", resource_id=f.id, vault=people.v1)
    row.recorded = {"names": {"vault": str(people.v1.id), "values": {
        "file_name": {"fp": "fp1", "sealed": "sealed-file"}, "vault_name": {"fp": "fp2", "sealed": "sealed-vault"}}}}
    db.commit()
    from app.core import audit_privacy
    monkeypatch.setattr(audit_privacy, "open_name", lambda vault, row_id, key, sealed: f"opened:{sealed}")
    views, shown, _sel = _shown(db, people, case, [row])
    assert views[0]["recorded_names"]["file_name"]["name"] == "opened:sealed-file"
    assert views[0]["recorded_names"]["vault_name"]["name"] == "opened:sealed-vault"
    assert {"recorded:file_name", "recorded:vault"} <= shown[0]
    db.delete(f)
    db.commit()
    views, shown, _sel = _shown(db, people, case, [row])
    assert "file_name" not in (views[0]["recorded_names"] or {}), "an item the case can no longer name stays hidden"


# --------------------------------------------------------------------------- recording what was shown

def test_a_page_showing_names_because_of_the_case_is_recorded_once_per_set_in_ten_minutes(db, people, storage):
    f = _file(db, storage, people.v1)
    g = _file(db, storage, people.v1, name="other.txt")
    case = _case(db, people, _vaults(people.v1))
    rows = [_event(db, "file_download", by=people.olga, resource_type="file", resource_id=x.id, vault=people.v1)
            for x in (f, g)]
    now = ac.utcnow()
    views, shown, selection = _shown(db, people, case, rows)
    for _ in range(5):
        ac.note_names_viewed(db, selection, people.uma, views, shown, now=now)
    (row,) = _rows(db, ac.VIEWED)
    assert row.case_id == case.id and row.details["events"] == 2 and row.details["vault_ids"] == [str(people.v1.id)]
    assert "minutes" not in str(row.details) and "other" not in str(row.details)
    views1, shown1, _s = _shown(db, people, case, rows[:1])
    assert ac.note_names_viewed(db, selection, people.uma, views1, shown1, now=now), "another set"
    assert not ac.note_names_viewed(db, selection, people.uma, views, shown, now=now + timedelta(minutes=9))
    assert ac.note_names_viewed(db, selection, people.uma, views, shown, now=now + timedelta(minutes=11))
    assert len(_rows(db, ac.VIEWED)) == 3
    nothing = _views([_event(db, "sign_in", by=people.uma)])
    assert not ac.note_names_viewed(db, selection, people.uma, nothing, [set()], now=now)


def test_names_whose_record_cannot_be_written_are_not_sent(db, people, storage, monkeypatch):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))
    row = _event(db, "file_download", by=people.olga, resource_type="file", resource_id=f.id, vault=people.v1)
    views, shown, selection = _shown(db, people, case, [row])

    def broken(*a, **k):
        raise ca.Refused(ca.RECORD_FAILED)
    monkeypatch.setattr(ca, "record", broken)
    _, err = _call(ac.note_names_viewed, db, selection, people.uma, views, shown)
    assert err.status_code == 503 and err.detail["reason"] == ca.RECORD_FAILED


def test_the_routes_select_the_case_and_record_before_sending(monkeypatch):
    """The Events list and one event: the case's filter goes into the query, and its names are shown and recorded
    (app/api/api_server.py, _case_names) before the response is made."""
    import inspect
    events = inspect.getsource(api.activity_events)
    assert "_activity_case(db, current_user, case, request)" in events and "**_case_filters(selection)" in events
    # The rows are read by the page reader (from audit_logs, or with the archive), which the selection is handed.
    assert events.count("selection)") == 2 and "_activity_events_page(" in events
    page = inspect.getsource(api._activity_events_page)
    names_at = page.index("_case_names(db, selection, current_user, events, rows)")
    assert names_at < page.index('out["events"] = events')
    one = inspect.getsource(api.activity_event)
    assert "_case_names(db, selection, current_user, [event], [row])" in one
    assert "**_case_filters(selection)" in one
    helper = inspect.getsource(api._case_names)
    assert helper.index("case_names(") < helper.index("note_names_viewed(")
    for fn in (api.activity_summary, api.activity_export):
        assert "_case_filters(_activity_case(db, current_user, case, None))" in inspect.getsource(fn), fn.__name__
    assert "case" in asr.Filters.model_fields


def test_the_summary_tells_only_an_administrator_what_is_happening_now():
    import inspect
    source = inspect.getsource(api.activity_summary)
    assert 'out["now"] = summary.now_panel(db, now, _activity_transfers()) if current_user.role == RoleEnum.ADMIN ' \
           'else None' in source


# --------------------------------------------------------------------------- the edges

def test_an_administrators_temporary_credential_reads_no_log(db, people, denials):
    people.bob._is_temp_session = True
    try:
        _, err = _call(av.require_activity_viewer, current_user=people.bob, db=db)
    finally:
        people.bob._is_temp_session = False
    assert err.status_code == 403 and [u for u, _ in denials] == ["bob"]


def test_a_suspended_auditor_hears_no_signal(db, people, monkeypatch):
    from app.core import database
    monkeypatch.setattr(database, "SessionLocal", lambda: _same(db))
    rights.suspend(db, rights.open_grant(db, people.uma.id), "password_changed")
    db.commit()
    assert rights.open_grant(db, people.uma.id) is not None
    assert not api._ws_sees_activity(str(people.uma.id), False)


def test_a_vault_the_case_may_no_longer_open_shows_no_name(db, people, storage, settings):
    """A password vault approved under with_password, then the deployment refuses such vaults: the stricter rule
    applies, and the vault shows nothing because of the case, not even its name."""
    pv = _vault(db, people.olga, password="argon2-hash")
    f = _file(db, storage, pv, name="salaries.csv")
    case = _case(db, people, _vaults(pv), password_override=False)
    settings[cs.PASSWORD_VAULTS] = cs.REFUSE
    row = _event(db, "file_download", by=people.olga, resource_type="file", resource_id=f.id, vault=pv)
    views, shown, _sel = _shown(db, people, case, [row])
    assert views[0]["names"] == {"vault": an.NOT_SHOWN, "item": an.NOT_SHOWN} and shown == [set()]


def test_a_file_with_its_own_password_is_named_through_a_case_only_under_the_override(db, people, storage, settings):
    """A file with a password of its own is never named because of a case, unless the case passes passwords over
    (as its content opens only then); the file beside it in the same vault is named."""
    own = _file(db, storage, people.v1, name="private-plan.txt", password_hash="file-hash")
    plain = _file(db, storage, people.v1, name="minutes.txt")
    case = _case(db, people, _vaults(people.v1))
    rows = [_event(db, "file_download", by=people.olga, resource_type="file", resource_id=x.id, vault=people.v1)
            for x in (own, plain)]
    views, shown, _sel = _shown(db, people, case, rows)
    assert views[0]["names"] == {"vault": people.v1.name, "item": an.NOT_SHOWN}
    assert views[1]["names"]["item"] == "minutes.txt" and "private-plan.txt" not in str(views)
    settings[cs.PASSWORD_VAULTS] = cs.OVERRIDE
    over = _case(db, people, _vaults(people.v1), password_override=True)
    views, shown, _sel = _shown(db, people, over, rows)
    assert [v["names"]["item"] for v in views] == ["private-plan.txt", "minutes.txt"]


def test_an_item_of_another_vault_is_never_named_through_the_case(db, people, storage):
    """An event that says it is in the case's vault but is about a file of another vault: the file is not named."""
    elsewhere = _file(db, storage, people.v2, name="secret.txt")
    case = _case(db, people, _vaults(people.v1))
    row = _event(db, "file_download", by=people.olga, resource_type="file", resource_id=elsewhere.id,
                 vault=people.v1)
    views, _shown_, _sel = _shown(db, people, case, [row])
    assert views[0]["names"]["vault"] == people.v1.name and views[0]["names"]["item"] != "secret.txt"


def test_recorded_names_of_a_vault_outside_the_case_stay_shut(db, people, storage, monkeypatch):
    f = _file(db, storage, people.v2, name="other.txt")
    case = _case(db, people, _vaults(people.v1))
    row = _event(db, "file_download", by=people.otto, resource_type="file", resource_id=f.id, vault=people.v2)
    row.recorded = {"names": {"vault": str(people.v2.id), "values": {
        "vault_name": {"fp": "fp2", "sealed": "sealed-vault"}, "file_name": {"fp": "fp1", "sealed": "sealed-file"}}}}
    db.commit()
    from app.core import audit_privacy
    monkeypatch.setattr(audit_privacy, "open_name", lambda vault, row_id, key, sealed: f"opened:{sealed}")
    views, shown, _sel = _shown(db, people, case, [row])
    assert "opened:" not in str(views[0]) and shown == [set()]


def test_the_events_route_selects_the_case_through_its_search_form(db, people, storage):
    """The Events list for the case (through its search form, which passes every filter): only the case's events,
    with the file's name shown because of the case and the page recorded once however often it is fetched."""
    from types import SimpleNamespace as NS
    f = _file(db, storage, people.v1, name="minutes.txt")
    g = _file(db, storage, people.v2, name="other.txt")
    case = _case(db, people, _vaults(people.v1))
    mine = _event(db, "file_download", by=people.olga, resource_type="file", resource_id=f.id, vault=people.v1)
    other = _event(db, "file_download", by=people.otto, resource_type="file", resource_id=g.id, vault=people.v2)
    request = NS(headers={})
    for _ in range(3):
        out = asr.search_events(asr.EventsSearch(case=str(case.id), limit=100), request, current_user=people.uma,
                                db=db)
    ids = {e["id"] for e in out["events"]}
    assert str(mine.id) in ids and str(other.id) not in ids
    (shown,) = [e for e in out["events"] if e["id"] == str(mine.id)]
    assert shown["names"]["item"] == "minutes.txt" and "item" in shown["shown_by_case"]
    assert len(_rows(db, ac.VIEWED)) == 1
    plain = asr.search_events(asr.EventsSearch(limit=100), request, current_user=people.uma, db=db)
    assert str(other.id) in {e["id"] for e in plain["events"]}, "without the case, every event"


# --------------------------------------------------------------------------- a password vault in the case

def _locked_world(db, people, storage):
    """olga's vault with a vault password, its folders Company > Board minutes and Company > Holidays, and the events
    a case on Board minutes (files changed in the last 30 days) is about: a file in it, a kept one, one with a password
    of its own, an old one, one beside it, an old one changed in the last days; one deleted for good; the three
    folders; the vault itself."""
    pv = _vault(db, people.olga, password="argon2-hash")
    top = _folder(db, pv, None, "Company")
    board = _folder(db, pv, top, "Board minutes")
    side = _folder(db, pv, top, "Holidays")
    inside = _file(db, storage, pv, name="salaries.csv", folder=board)
    held = _kept(db, _file(db, storage, pv, name="draft.txt", folder=board))
    own = _file(db, storage, pv, name="private.txt", folder=board, password_hash="file-hash")
    old = _file(db, storage, pv, name="old.txt", folder=board)
    old.created_at = old.updated_at = ca.utcnow() - timedelta(days=400)
    beside = _file(db, storage, pv, name="beach.jpg", folder=side)
    # Uploaded long before the case's range, changed inside it: the case names it by the change.
    changed = _file(db, storage, pv, name="agenda.txt", folder=board)
    changed.created_at = ca.utcnow() - timedelta(days=400)
    changed.updated_at = ca.utcnow() - timedelta(days=2)
    db.commit()
    assert changed.created_at < ca.utcnow() - timedelta(days=30) < changed.updated_at, "the times stay as set"
    case = _case(db, people, [{"kind": "folder", "target_id": board.id}], files_from=ca.utcnow() - timedelta(days=30))
    rows = [_event(db, "file_download", by=people.olga, resource_type="file", resource_id=x.id, vault=pv)
            for x in (inside, held, own, old, beside, changed)]
    rows.append(_event(db, "file_delete", by=people.olga, resource_type="file", resource_id=uuid.uuid4(), vault=pv))
    rows += [_event(db, "folder_create", by=people.olga, resource_type="folder", resource_id=x.id, vault=pv)
             for x in (board, top, side)]
    rows.append(_event(db, "vault_settings_changed", by=people.olga, resource_type="vault", resource_id=pv.id))
    return SimpleNamespace(pv=pv, case=case, rows=rows)


# Where the case's auditor is offered the vault's password: the file in the case's folder, the kept one, the old one
# changed in the case's range, the folder and the way to it; never a file with a password of its own, an old one, one
# beside it, one deleted for good, the folder beside it or the vault itself.
OFFERED = [True, True, False, False, False, True, False, True, True, False, False]
NAMED_ONCE_UNLOCKED = ["salaries.csv", "draft.txt", an.NOT_SHOWN, an.NOT_SHOWN, an.NOT_SHOWN, "agenda.txt",
                       an.NOT_SHOWN, "Board minutes", "Company", an.NOT_SHOWN, None]


def _offered(views):
    return [v.get(ac.UNLOCK_IN_CASE) is True for v in views]


def test_a_non_member_auditor_is_told_the_vault_password_hides_what_the_case_would_name(db, people, storage):
    """Not a member of the vault, the case's auditor reads its name and, for each item the case would name once the
    vault is unlocked in the case, that its password hides it (the page offers the password there). That is not a
    name: nothing is recorded as shown for it. Once unlocked: the names, and nothing offered."""
    w = _locked_world(db, people, storage)
    views, shown, _sel = _shown(db, people, w.case, w.rows)
    assert _offered(views) == OFFERED
    assert [v["names"]["item"] for v in views] == [
        an.PASSWORD_HIDDEN if offered else (None if v["resource_type"] == "vault" else an.NOT_SHOWN)
        for v, offered in zip(views, OFFERED)]
    assert all(v["names"]["vault"] == w.pv.name for v in views)
    assert all(s == {"vault"} for s in shown), "a hidden name is not a name shown because of the case"
    unlock = f"{w.pv.id}={_receipt(w.case, w.pv, people.uma)}"
    views, shown, _sel = _shown(db, people, w.case, w.rows, unlock=unlock)
    assert [v["names"]["item"] for v in views] == NAMED_ONCE_UNLOCKED
    assert not any(_offered(views))
    # A receipt given to another session unlocks nothing: still offered.
    other = f"{w.pv.id}={_receipt(w.case, w.pv, people.uma, session='another-session')}"
    views, _shown_, _sel = _shown(db, people, w.case, w.rows, unlock=other)
    assert _offered(views) == OFFERED


def test_no_one_else_is_offered_the_password_in_a_case(db, people, storage, settings, monkeypatch):
    """Without the case selected, to an administrator selecting it (member of the vault or not), under a deployment
    that refuses password vaults to cases or a case that passes passwords over, once the case gives no access, and in
    a zero-knowledge vault: nothing is offered, and nobody is told more than they were."""
    w = _locked_world(db, people, storage)
    plain = _views(w.rows)
    for view, names in zip(plain, an.names_for(db, people.uma, plain)):
        view["names"] = names
    assert not any(_offered(plain)) and all(v["names"]["item"] in (an.NOT_SHOWN, None) for v in plain), "no case"
    views, _s, _sel = _shown(db, people, w.case, w.rows, viewer=people.bob)
    assert not any(_offered(views)) and all(v["names"]["item"] in (an.NOT_SHOWN, None) for v in views)
    with monkeypatch.context() as member:
        member.setattr(an, "readable_vault_ids", lambda db_, viewer, ids: set(ids))
        views, _s, _sel = _shown(db, people, w.case, w.rows, viewer=people.bob)
        assert not any(_offered(views)), "an administrator who reads the vault unlocks it on the Activity page"
        assert views[0]["names"]["item"] == views[4]["names"]["item"] == an.PASSWORD_HIDDEN
        # An auditor who is also a member: offered exactly where the case would name the item.
        views, _s, _sel = _shown(db, people, w.case, w.rows)
        assert _offered(views) == OFFERED and views[4]["names"]["item"] == an.PASSWORD_HIDDEN
    settings[cs.PASSWORD_VAULTS] = cs.REFUSE
    views, _s, _sel = _shown(db, people, w.case, w.rows)
    assert not any(_offered(views)) and all(v["names"]["vault"] == an.NOT_SHOWN for v in views), "refused"
    settings[cs.PASSWORD_VAULTS] = cs.OVERRIDE
    over = _case(db, people, _vaults(w.pv), password_override=True)
    views, _s, _sel = _shown(db, people, over, w.rows)
    assert not any(_offered(views)) and views[0]["names"]["item"] == "salaries.csv", "opened without the password"
    settings[cs.PASSWORD_VAULTS] = cs.WITH_PASSWORD
    w.case.access_ends_at = ca.utcnow() - timedelta(seconds=1)
    db.commit()
    views, _s, sel = _shown(db, people, w.case, w.rows)
    assert not sel.names and not any(_offered(views)), "the case gives no access now"
    zk = _vault(db, people.olga, kind="zero_knowledge", password="argon2-hash")
    zf = _file(db, storage, zk, name="sealed.bin")
    zcase = _case(db, people, _vaults(zk))
    row = _event(db, "file_download", by=people.olga, resource_type="file", resource_id=zf.id, vault=zk)
    views, _s, _sel = _shown(db, people, zcase, [row])
    assert not any(_offered(views)) and views[0]["names"]["item"] == an.NOT_SHOWN


def test_the_offer_follows_the_cases_range_by_upload_or_by_change(db, people, storage):
    """A case on a vault with a vault password, for files uploaded or changed between 30 and 10 days ago. Its auditor
    is offered the password for a file uploaded in the range and changed after it, and for one uploaded before it and
    changed in it, both named once it is given; never for one uploaded before the range and changed after it."""
    pv = _vault(db, people.olga, password="argon2-hash")
    now = ca.utcnow()

    def made(name, uploaded, changed):
        f = _file(db, storage, pv, name=name)
        f.created_at, f.updated_at = now - timedelta(days=uploaded), now - timedelta(days=changed)
        return f
    files = [made("uploaded-in.txt", 20, 2), made("changed-in.txt", 40, 15), made("neither.txt", 40, 2)]
    db.commit()
    assert [(f.created_at, f.updated_at) for f in files] == [
        (now - timedelta(days=u), now - timedelta(days=c)) for u, c in ((20, 2), (40, 15), (40, 2))]
    case = _case(db, people, _vaults(pv), files_from=now - timedelta(days=30), files_to=now - timedelta(days=10))
    rows = [_event(db, "file_download", by=people.olga, resource_type="file", resource_id=f.id, vault=pv)
            for f in files]
    views, _s, _sel = _shown(db, people, case, rows)
    assert _offered(views) == [True, True, False]
    assert [v["names"]["item"] for v in views] == [an.PASSWORD_HIDDEN, an.PASSWORD_HIDDEN, an.NOT_SHOWN]
    views, _s, _sel = _shown(db, people, case, rows, unlock=f"{pv.id}={_receipt(case, pv, people.uma)}")
    assert [v["names"]["item"] for v in views] == ["uploaded-in.txt", "changed-in.txt", an.NOT_SHOWN]
    assert not any(_offered(views))


def test_telling_a_name_is_hidden_decrypts_no_name(db, people, storage):
    """Whether the case would name an item of a locked vault is read from its columns: no file or folder (live or
    kept) is loaded, so no name is decrypted before the vault is unlocked in the case."""
    from sqlalchemy import event as sa_event
    w = _locked_world(db, people, storage)
    models = (m.File, m.Folder, m.HeldFile, m.HeldFolder)
    for obj in [o for o in db.identity_map.values() if isinstance(o, models)]:
        db.expunge(obj)                     # read from the database, not handed back from the session
    loaded = []

    def spy(target, *_args):
        loaded.append(type(target).__name__)
    for model in models:
        sa_event.listen(model, "load", spy)
    try:
        views, _s, _sel = _shown(db, people, w.case, w.rows)
        assert _offered(views) == OFFERED
        assert loaded == []
        # The control: once unlocked in the case, the items it names are loaded (their names decrypted) and seen here.
        views, _s, _sel = _shown(db, people, w.case, w.rows, unlock=f"{w.pv.id}={_receipt(w.case, w.pv, people.uma)}")
        assert views[0]["names"]["item"] == "salaries.csv" and {"File", "HeldFile", "Folder"} <= set(loaded)
    finally:
        for model in models:
            sa_event.remove(model, "load", spy)


def test_the_events_route_offers_the_password_to_the_cases_auditor_only(db, people, storage):
    """Through the Events list and one event: the case's auditor is told the name is hidden by the vault's password
    and offered it there; an administrator selecting the case is not."""
    w = _locked_world(db, people, storage)
    request = SimpleNamespace(headers={})
    out = asr.search_events(asr.EventsSearch(case=str(w.case.id), limit=100), request, current_user=people.uma, db=db)
    mine = {e["id"]: e for e in out["events"]}
    first = mine[str(w.rows[0].id)]
    assert first["names"]["item"] == an.PASSWORD_HIDDEN and first[ac.UNLOCK_IN_CASE] is True
    assert ac.UNLOCK_IN_CASE not in mine[str(w.rows[4].id)]
    one = api.activity_event(str(w.rows[0].id), case=str(w.case.id), request=request, current_user=people.uma, db=db)
    assert one["names"]["item"] == an.PASSWORD_HIDDEN and one[ac.UNLOCK_IN_CASE] is True
    theirs = asr.search_events(asr.EventsSearch(case=str(w.case.id), limit=100), request, current_user=people.bob,
                               db=db)
    assert not any(ac.UNLOCK_IN_CASE in e for e in theirs["events"])


def test_what_the_viewers_own_unlock_shows_stays_and_is_not_offered_again(db, people, storage, monkeypatch):
    """The case's auditor reads the vault and unlocked its names on the Activity page with their own receipt (an
    administrator may hold the auditor right). With the case selected, through the Events list and one event, each
    item keeps what that unlock shows (the name as recorded, or that none was) and nothing is offered. The control:
    the same reader without their receipt is told the password hides the names, and offered it in the case."""
    from app.core import audit_privacy
    from app.core import vault_unlock_receipts as receipts
    w = _locked_world(db, people, storage)
    w.rows[0].recorded = {"names": {"vault": str(w.pv.id), "values": {
        "file_name": {"fp": "fp1", "sealed": "sealed-file"}}}}
    db.commit()
    monkeypatch.setattr(audit_privacy, "open_name", lambda vault, row_id, key, sealed: f"opened:{sealed}")
    monkeypatch.setattr(an, "readable_vault_ids", lambda db_, viewer, ids: set(ids))
    own = receipts.issue(purpose=receipts.PURPOSE_ACTIVITY, session_hash=SESSION, vault_id=w.pv.id,
                         user_id=people.uma.id, credential=receipts.credential_digest(w.pv.password_hash))[0]
    wanted = [str(r.id) for r in w.rows]

    def read(headers):
        request = SimpleNamespace(headers=headers)
        out = asr.search_events(asr.EventsSearch(case=str(w.case.id), limit=100), request, current_user=people.uma,
                                db=db)
        listed = {e["id"]: e for e in out["events"]}
        one = api.activity_event(wanted[0], case=str(w.case.id), request=request, current_user=people.uma, db=db)
        return [listed[i] for i in wanted], one

    views, one = read({})
    assert _offered(views) == OFFERED and one[ac.UNLOCK_IN_CASE] is True, "the control: hidden, and offered"
    assert views[0]["names"]["item"] == one["names"]["item"] == an.PASSWORD_HIDDEN
    views, one = read({an.UNLOCK_HEADER: f"{w.pv.id}:{own}"})
    assert not any(_offered(views)) and ac.UNLOCK_IN_CASE not in one
    assert views[0]["names"]["item"] == one["names"]["item"] == "opened:sealed-file"
    assert [v["names"]["item"] for v in views[1:]] == [an.NOT_RECORDED] * 9 + [None]
