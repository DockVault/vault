"""The Activity page for an auditor, offline on a real (SQLite) database (app/api/activity_viewer.py,
app/services/activity_case.py, the case filter in app/services/activity_events.py, the routes in
app/api/api_server.py and app/api/activity_search_router.py).

Who reads the log: an administrator, or an auditor whose right is in force, each read by the right recorded at most
once in ten minutes; live sessions, transfers, the temporary-credential typeahead and the Activity unlock stay an
administrator's. The live signal reaches a live auditor's own session. A case selected limits the events to its own
rows and its vaults; its auditor, while it gives access, reads the names it lets them read (in its folders and time
range, never zero-knowledge, a password vault once unlocked), and a page that shows one is recorded once per set of
events in ten minutes. test_activity_auditor_live.py runs it on a stack.
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
    assert views[1]["names"] == {"vault": pv.name, "item": an.NOT_SHOWN}, "locked: no file names"
    unlock = f"{pv.id}={_receipt(case, pv, people.uma)}"
    views, _shown_, _sel = _shown(db, people, case, rows, unlock=unlock)
    assert views[1]["names"]["item"] == "salaries.csv"
    assert views[0]["names"]["item"] == an.NOT_SHOWN


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
    names_at = events.index("_case_names(db, selection, current_user, events, rows)")
    assert names_at < events.index('out["events"] = events')
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
