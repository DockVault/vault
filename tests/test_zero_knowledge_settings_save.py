"""A settings save keeps the zero-knowledge switches as saved while they cannot change anything, offline.

GET /settings used to report zero_knowledge_enabled as in effect, and the settings page sends what it was
given back on every save. While the plan lacked zero-knowledge that was "off", so one save in that time
stored zero-knowledge off, and the administrators' force with it, for good: when the plan got zero-knowledge
back, an administrator had to switch them on again.

Now GET /settings reports the switches as saved, what is in effect beside them, and why they are locked
when they cannot change anything (the plan lacks or requires zero-knowledge, its cap is 0, or one vault
type alone is allowed). A save never stores a locked switch: one sent as a settings page may be showing it
(as saved, as in effect, or as a page from before the lock showed it) changes nothing, and any other value
is refused with that reason; and the page leaves locked switches out. The round trips below run the
server's own GET and PUT on a throwaway SQLite database.
"""
import itertools
import re
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from _async_run import run_coroutine  # noqa: E402
from app.api import api_server as api  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.models import Base, RoleEnum, SystemSetting, User  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
ADMIN = SimpleNamespace(id=None, username="admin", role=RoleEnum.ADMIN)
REQUIRED = "This organization requires zero-knowledge vaults. Choose the Zero-knowledge type."
NOT_ENABLED = "Zero-knowledge vaults are not enabled on this deployment."
SWITCHES = ("zero_knowledge_enabled", "force_zero_knowledge")


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: None)
    for name, value in (("plan_zero_knowledge", True), ("plan_force_zero_knowledge", False),
                        ("plan_max_zk_vaults", -1), ("plan_allowed_vault_types", "")):
        monkeypatch.setattr(settings, name, value)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'zk-settings.db'}")
        # GET /settings reads several tables. Each is made as it is, less the indexes over an expression and
        # with SQLite's own clock for Postgres' now(); the few whose column types only Postgres has are left
        # out (it reads none of them).
        metadata = sa.MetaData()
        for table in Base.metadata.sorted_tables:
            copy = table.to_metadata(metadata)
            for index in [i for i in copy.indexes if not all(isinstance(e, sa.Column) for e in i.expressions)]:
                copy.indexes.discard(index)
            for column in copy.columns:
                if column.server_default is not None and "now()" in str(getattr(column.server_default, "arg", "")):
                    column.server_default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
            try:
                copy.create(engine)
            except (sa.exc.OperationalError, sa.exc.CompileError):
                pass
        session = sessionmaker(bind=engine)()
        yield session
        session.close()
        engine.dispose()


def _get(db):
    db.expire_all()
    return run_coroutine(api.get_settings(current_user=ADMIN, db=db))


def _put(db, payload):
    return run_coroutine(api.update_settings(payload=payload, request=SimpleNamespace(headers={}, client=None),
                                             current_user=ADMIN, db=db))


def _refused(db, payload):
    with pytest.raises(HTTPException) as refused:
        _put(db, payload)
    assert refused.value.status_code == 400
    return refused.value.detail


def _stored(db):
    db.expire_all()
    row = db.get(SystemSetting, "global")
    return {k: (row.value or {}).get(k) for k in SWITCHES} if row else {k: None for k in SWITCHES}


def _person(db):
    person = uuid.uuid4()
    db.execute(sa.insert(User.__table__).values(id=person, username=f"person-{person.hex[:8]}",
                                                password_hash="x", role=RoleEnum.USER, is_active=True,
                                                is_locked=False))
    db.commit()
    return SimpleNamespace(id=person)


def _create(db, person, kind):
    try:
        return api._resolve_vault_type_for_create(person, kind, db)
    except HTTPException as exc:
        return exc.detail


def _page_payload(got):
    """What the settings page sends: every key it was given (the old page also sent the two switches as they
    were shown, which was what is in effect)."""
    return {k: v for k, v in got.items() if k in SWITCHES or k == "directory_search_scope"}


def test_a_save_while_the_plan_lacks_zero_knowledge_keeps_the_switches_for_when_it_returns(db, monkeypatch):
    _put(db, {"zero_knowledge_enabled": True, "force_zero_knowledge": True})
    person = _person(db)
    assert _create(db, person, "standard") == REQUIRED

    monkeypatch.setattr(settings, "plan_zero_knowledge", False)            # the plan drops zero-knowledge
    got = _get(db)
    assert (got["zero_knowledge_enabled"], got["force_zero_knowledge"]) == (True, True), "reported as saved"
    assert (got["zero_knowledge_in_effect"], got["force_zero_knowledge_in_effect"]) == (False, False)
    assert got["zero_knowledge_switches_locked"] == "This deployment's plan does not include zero-knowledge vaults."
    _put(db, _page_payload(got))                                          # a save sends it back: nothing changes
    _put(db, {"directory_search_scope": "deployment"})                    # the page now leaves them out
    assert _stored(db) == {"zero_knowledge_enabled": True, "force_zero_knowledge": True}
    # What a page loaded before the change sends back (what was in effect then) is taken out too: it used to
    # store zero-knowledge off for good, and refusing it would refuse that page's whole save.
    _put(db, {"zero_knowledge_enabled": False, "force_zero_knowledge": False, "directory_search_scope": "deployment"})
    assert _stored(db) == {"zero_knowledge_enabled": True, "force_zero_knowledge": True}
    assert _create(db, person, "standard") == "standard"

    monkeypatch.setattr(settings, "plan_zero_knowledge", True)             # the plan gets it back
    got = _get(db)
    assert got["zero_knowledge_switches_locked"] is None
    assert (got["zero_knowledge_in_effect"], got["force_zero_knowledge_in_effect"]) == (True, True)
    assert [_create(db, person, kind) for kind in ("standard", "zero_knowledge")] == [REQUIRED, "zero_knowledge"]


def test_a_switch_never_saved_stays_never_saved_through_a_locked_save(db, monkeypatch):
    monkeypatch.setattr(settings, "plan_zero_knowledge", False)
    got = _get(db)
    assert (got["zero_knowledge_enabled"], got["force_zero_knowledge"]) == (True, False)
    _put(db, _page_payload(got))
    assert _stored(db) == {"zero_knowledge_enabled": None, "force_zero_knowledge": None}


def test_while_the_plan_requires_zero_knowledge_the_administrators_choice_is_kept(db, monkeypatch):
    """The page used to send both switches checked while the plan forced zero-knowledge, saving the
    administrators' own force; once the plan stopped forcing it, their earlier choice was gone."""
    _put(db, {"zero_knowledge_enabled": True, "force_zero_knowledge": False})
    monkeypatch.setattr(settings, "plan_force_zero_knowledge", True)
    got = _get(db)
    assert got["zero_knowledge_switches_locked"] == "This deployment's plan requires zero-knowledge vaults."
    assert (got["zero_knowledge_in_effect"], got["force_zero_knowledge_in_effect"]) == (True, True)
    _put(db, _page_payload(got))
    # What a page from before the change sends under the plan's force (both on) is taken out, not stored
    # and not refused; switching zero-knowledge off, which no page shows here, is refused with the reason.
    _put(db, {"zero_knowledge_enabled": True, "force_zero_knowledge": True})
    assert _stored(db) == {"zero_knowledge_enabled": True, "force_zero_knowledge": False}
    assert "requires zero-knowledge" in _refused(db, {"zero_knowledge_enabled": False})
    monkeypatch.setattr(settings, "plan_force_zero_knowledge", False)
    assert _stored(db) == {"zero_knowledge_enabled": True, "force_zero_knowledge": False}
    assert _create(db, _person(db), "standard") == "standard"


@pytest.mark.parametrize("name, value, reason, change", [
    ("plan_max_zk_vaults", 0, "This deployment's plan allows no zero-knowledge vaults.",
     {"force_zero_knowledge": True}),
    ("plan_allowed_vault_types", "standard", "This deployment does not allow zero-knowledge vaults.",
     {"force_zero_knowledge": True}),
    ("plan_allowed_vault_types", "zero_knowledge",
     "This deployment allows only zero-knowledge vaults, so they cannot be turned off.",
     {"zero_knowledge_enabled": False}),
])
def test_every_lock_keeps_the_saved_switches(db, monkeypatch, name, value, reason, change):
    """Saved zero-knowledge on, force off. A save sending the switches as saved or as in effect changes
    nothing; a value that is neither is refused with the reason."""
    _put(db, {"zero_knowledge_enabled": True, "force_zero_knowledge": False})
    monkeypatch.setattr(settings, name, value)
    got = _get(db)
    assert got["zero_knowledge_switches_locked"] == reason
    _put(db, _page_payload(got))
    _put(db, {"zero_knowledge_enabled": got["zero_knowledge_in_effect"],
              "force_zero_knowledge": got["force_zero_knowledge_in_effect"]})
    assert reason in _refused(db, change)
    assert _stored(db) == {"zero_knowledge_enabled": True, "force_zero_knowledge": False}


def test_a_save_that_would_leave_no_vault_to_make_is_refused(db, monkeypatch):
    """Only zero-knowledge vaults allowed: turning zero-knowledge off would leave nothing to make."""
    monkeypatch.setattr(settings, "plan_allowed_vault_types", "zero_knowledge")
    detail = _refused(db, {"zero_knowledge_enabled": False})
    assert "allows only zero-knowledge vaults, so they cannot be turned off" in detail
    assert _create(db, _person(db), "zero_knowledge") == "zero_knowledge"


def test_switches_that_can_change_something_are_saved_as_sent(db):
    got = _get(db)
    assert got["zero_knowledge_switches_locked"] is None
    for enabled, force in ((False, False), (True, True), (True, False), (False, True)):
        _put(db, {"zero_knowledge_enabled": enabled, "force_zero_knowledge": force})
        assert _stored(db) == {"zero_knowledge_enabled": enabled, "force_zero_knowledge": force}
        got = _get(db)
        assert (got["zero_knowledge_enabled"], got["force_zero_knowledge"]) == (enabled, force)
        assert got["zero_knowledge_in_effect"] is enabled


# Each lock reason, and what it says about the vaults someone in no department can make.
REFUSES_ZERO_KNOWLEDGE = ("This deployment's plan does not include zero-knowledge vaults.",
                          "This deployment's plan allows no zero-knowledge vaults.",
                          "This deployment does not allow zero-knowledge vaults.")
REFUSES_STANDARD = ("This deployment's plan requires zero-knowledge vaults.",
                    "This deployment allows only zero-knowledge vaults, so they cannot be turned off.")


def test_what_the_settings_page_is_told_is_what_people_can_make(db, monkeypatch):
    """For every mix of the plan's zero-knowledge settings, the allowed types and the two saved switches, GET
    /settings reports as in effect what someone in no department can make, and a lock reason that is true of
    it; and /zk-enabled, which the page also reads, says the plan requires zero-knowledge exactly where that
    is the reason. A plan that forces zero-knowledge while the operator allows only standard vaults is the
    case this was wrong for: people make standard vaults there, but the page said the plan requires
    zero-knowledge. A cap with room is used: a cap that is reached is a quota, refused with its own message."""
    person = _person(db)
    for plan_zk, plan_force, cap, allowed, force, enabled in itertools.product(
            (True, False), (True, False), (-1, 0, 2), ("", "standard", "zero_knowledge", "standard,zero_knowledge"),
            (None, True, False), (None, True, False)):
        mix = dict(plan_zk=plan_zk, plan_force=plan_force, cap=cap, allowed=allowed, force=force, enabled=enabled)
        for name, value in (("plan_zero_knowledge", plan_zk), ("plan_force_zero_knowledge", plan_force),
                            ("plan_max_zk_vaults", cap), ("plan_allowed_vault_types", allowed)):
            monkeypatch.setattr(settings, name, value)
        saved = {k: v for k, v in (("force_zero_knowledge", force), ("zero_knowledge_enabled", enabled))
                 if v is not None}
        db.execute(sa.delete(SystemSetting.__table__))
        db.execute(sa.insert(SystemSetting.__table__).values(key="global", value=saved))
        db.commit()
        got = _get(db)
        made = {kind: _create(db, person, kind) == kind for kind in ("standard", "zero_knowledge")}
        assert got["zero_knowledge_in_effect"] is made["zero_knowledge"], (mix, got, made)
        assert got["force_zero_knowledge_in_effect"] is (not made["standard"]), (mix, got, made)
        reason = got["zero_knowledge_switches_locked"]
        if reason in REFUSES_ZERO_KNOWLEDGE:
            assert not made["zero_knowledge"], (mix, reason, made)
        elif reason in REFUSES_STANDARD:
            assert made == {"standard": False, "zero_knowledge": True}, (mix, reason, made)
        else:
            assert reason is None, (mix, reason)
        plan_requires = reason == "This deployment's plan requires zero-knowledge vaults."
        assert _zk_enabled_route(db, person)["plan_force_zero_knowledge"] is plan_requires, (mix, reason)


def test_the_settings_page_leaves_a_locked_switch_out_of_a_save():
    """The page shows a locked switch as in effect, disabled, with the server's reason, and its save leaves a
    disabled switch out (so the saved value is kept)."""
    js = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    start = js.index("const zkLock = settings.zero_knowledge_switches_locked")
    shown = js[start:js.index("const dssEl", start)]
    # Each switch on its own (the force's element is fzkEl, whose name ends in the other's).
    assert re.search(r"(?<!f)zkEl\.checked = zkLock \? settings\.zero_knowledge_in_effect === true", shown)
    assert re.search(r"(?<!f)zkEl\.disabled = !!zkLock;", shown)
    assert re.search(r"fzkEl\.checked = zkLock \? settings\.force_zero_knowledge_in_effect === true", shown)
    assert re.search(r"fzkEl\.disabled = !!zkLock;", shown)
    assert "zk-switches-locked-note" in shown
    save = js[js.index("A zero-knowledge switch the page locked"):js.index("// Branding: send the brand overrides.")]
    assert "['setting-zero-knowledge-enabled', 'zero_knowledge_enabled']" in save
    assert "['setting-force-zero-knowledge', 'force_zero_knowledge']" in save
    assert "if (!el || el.disabled) delete settings[key];" in save
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert html.count('id="zk-switches-locked-note"') == 1


def _zk_enabled_route(db, person):
    from starlette.requests import Request
    request = Request({"type": "http", "method": "GET", "path": "/zk-enabled", "raw_path": b"/zk-enabled",
                       "query_string": b"", "headers": [(b"host", b"vault.example")],
                       "client": ("198.51.100.20", 5000), "server": ("vault.example", 443), "scheme": "https",
                       "root_path": ""})
    return run_coroutine(api.get_zk_enabled(request=request, current_user=person, db=db))


def test_the_vault_form_is_told_a_cap_of_none_is_no_zero_knowledge(db, monkeypatch):
    """/zk-enabled, which the vault form reads: with a cap of 0 neither zero-knowledge nor the force (the
    plan's or the administrators') is reported, and the settings page is not told the plan forces it."""
    _put(db, {"zero_knowledge_enabled": True, "force_zero_knowledge": True})
    person = _person(db)
    monkeypatch.setattr(settings, "plan_force_zero_knowledge", True)
    got = _zk_enabled_route(db, person)
    assert (got["zero_knowledge_enabled"], got["must_use_zk"], got["plan_force_zero_knowledge"]) == (True, True, True)
    monkeypatch.setattr(settings, "plan_max_zk_vaults", 0)
    got = _zk_enabled_route(db, person)
    assert (got["zero_knowledge_enabled"], got["must_use_zk"], got["plan_force_zero_knowledge"]) == \
        (False, False, False)
    assert got["max_zk_vaults"] == 0

@pytest.mark.parametrize("plan, saved, fields", [
    ({}, {"zero_knowledge_enabled": False},
     {"plan_zero_knowledge": True, "max_zk_vaults": -1, "allowed_vault_types": ["standard", "zero_knowledge"]}),
    ({"plan_zero_knowledge": False}, {},
     {"plan_zero_knowledge": False, "max_zk_vaults": -1, "allowed_vault_types": ["standard", "zero_knowledge"]}),
    ({"plan_max_zk_vaults": 0}, {},
     {"plan_zero_knowledge": True, "max_zk_vaults": 0, "allowed_vault_types": ["standard", "zero_knowledge"]}),
    ({"plan_allowed_vault_types": "standard"}, {},
     {"plan_zero_knowledge": True, "max_zk_vaults": -1, "allowed_vault_types": ["standard"]}),
])
def test_the_vault_form_is_told_why_zero_knowledge_is_unavailable(db, monkeypatch, plan, saved, fields):
    """The four answers test_ui_create_vault_modal.py gives the vault form to name the reason (the
    administrators' switch, a plan without zero-knowledge, a cap of 0, an allowlist without it) are the
    server's own."""
    if saved:
        _put(db, saved)
    for name, value in plan.items():
        monkeypatch.setattr(settings, name, value)
    got = _zk_enabled_route(db, _person(db))
    assert (got["zero_knowledge_enabled"], got["must_use_zk"]) == (False, False)
    assert {k: got[k] for k in fields} == fields


def _older_page_payload(got, zk_state):
    """The two switches as the settings page before this release sends them (static/js/app.js up to 0.33.3,
    which the desktop app's 0.2.0 previews bundle): each box checked when GET /settings said true, both
    checked when /zk-enabled said the plan forces zero-knowledge, and both sent as shown, disabled or not."""
    forced = zk_state.get("plan_force_zero_knowledge") is True
    return {"zero_knowledge_enabled": forced or got.get("zero_knowledge_enabled") is True,
            "force_zero_knowledge": forced or got.get("force_zero_knowledge") is True}


def _what_the_previous_release_told_the_page(saved):
    """What GET /settings and /zk-enabled answered before this release, for a tab loaded then and saved after
    the upgrade: zero-knowledge as in effect by the rule of the time (off without the plan, on under its
    force, else the switch, never saved counting as on), the force as saved, and the plan's force wherever the
    plan set it together with zero-knowledge, whatever its cap or the allowed types."""
    plan_zk, plan_force = bool(settings.plan_zero_knowledge), bool(settings.plan_force_zero_knowledge)
    switch = saved.get("zero_knowledge_enabled")
    zk = plan_zk and (plan_force or switch is None or bool(switch))
    return ({"zero_knowledge_enabled": zk, "force_zero_knowledge": saved.get("force_zero_knowledge")},
            {"plan_force_zero_knowledge": plan_force and plan_zk})


def test_a_settings_page_from_before_this_release_still_saves(db, monkeypatch):
    """A settings page from before this release (the desktop app's previews bundle one; a tab can stay open
    across an upgrade) sends both switches on every save, as it showed them. For every mix of the plan, the
    allowed types and the two saved switches, and both for such a page reading this server and for a tab
    loaded before the upgrade, its save is accepted with the rest of the page's settings; where the switches
    are locked nothing about them changes (a switch never saved stays never saved), and where they are not
    they are saved as sent. Under the plan's force such a page sends both switches on, which used to refuse
    the whole save wherever the administrators had not saved both on themselves."""
    person = _person(db)
    refused = []
    for plan_zk, plan_force, cap, allowed, force, enabled in itertools.product(
            (True, False), (True, False), (-1, 0, 2), ("", "standard", "zero_knowledge", "standard,zero_knowledge"),
            (None, True, False), (None, True, False)):
        mix = dict(plan_zk=plan_zk, plan_force=plan_force, cap=cap, allowed=allowed, force=force, enabled=enabled)
        for name, value in (("plan_zero_knowledge", plan_zk), ("plan_force_zero_knowledge", plan_force),
                            ("plan_max_zk_vaults", cap), ("plan_allowed_vault_types", allowed)):
            monkeypatch.setattr(settings, name, value)
        saved = {k: v for k, v in (("force_zero_knowledge", force), ("zero_knowledge_enabled", enabled))
                 if v is not None}
        db.execute(sa.delete(SystemSetting.__table__))
        db.execute(sa.insert(SystemSetting.__table__).values(key="global", value=dict(saved)))
        db.commit()
        got = _get(db)
        locked = got["zero_knowledge_switches_locked"] is not None
        pages = {"this release": _older_page_payload(got, _zk_enabled_route(db, person)),
                 "the previous release": _older_page_payload(*_what_the_previous_release_told_the_page(saved))}
        for source, payload in pages.items():
            db.execute(sa.delete(SystemSetting.__table__))
            db.execute(sa.insert(SystemSetting.__table__).values(key="global", value=dict(saved)))
            db.commit()
            try:
                _put(db, {**payload, "directory_search_scope": "same_department"})
            except HTTPException as exc:
                refused.append((mix, source, payload, exc.detail))
                continue
            db.expire_all()
            assert db.get(SystemSetting, "global").value.get("directory_search_scope") == "same_department", mix
            if locked:
                assert _stored(db) == {k: saved.get(k) for k in SWITCHES}, (mix, source, payload)
            else:
                assert _stored(db) == payload, (mix, source, payload)
    plans = sorted({(source, tuple(mix[k] for k in ("plan_zk", "plan_force", "cap", "allowed")))
                    for mix, source, _payload, _detail in refused})
    assert not refused, f"{len(refused)} saves refused, under {plans}; e.g. {refused[:2]}"
