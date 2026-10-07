"""What a vault's owner and a vault's members see of compliance access (app/core/owner_access.py, the routes under
/me/compliance-access in app/api/compliance_router.py, the vault-detail route's compliance_review), offline on a
real (SQLite) database: only cases on the owner's own vaults, and of those only the owner's vaults; never the
justification or the people named; the notices until they are read; a file's name only as the owner could read
it; the members' neutral banner; VaultService.get_vault untouched. test_ui_owner_access.py shows the page and the
banners in a browser."""
import inspect
import uuid
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.api import compliance_router as cr  # noqa: E402
from app.core import admin_grants  # noqa: E402
from app.core import after_commit  # noqa: E402
from app.core import auditor_rights as rights  # noqa: E402
from app.core import cases  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import legal_holds as holds  # noqa: E402
from app.core import models as m  # noqa: E402
from app.core import owner_access as oa  # noqa: E402
from app.core import owner_notices as on  # noqa: E402
from app.core import vault_unlock_receipts as receipts  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
TEXT = dict(purpose="internal_investigation", legal_basis="legal_obligation",
            justification="Suspected exfiltration of client records, ticket SEC-2041.",
            owner_note="Your vaults are part of an internal review.")


@pytest.fixture
def db():
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        session = make()
        yield session
        session.close()


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    from app.core import sftp_versions
    after_commit.handler(cases._NOTICES, lambda notices: None)
    after_commit.handler(on._NUDGES, lambda items: None)
    monkeypatch.setattr(holds, "deliver", lambda notices: None)
    monkeypatch.setattr(rights, "deliver", lambda notices: None)
    monkeypatch.setattr(on, "contact", lambda db_: None)
    monkeypatch.setattr(sftp_versions, "sftp_same_version",
                        lambda db_, **_k: sftp_versions.VersionCheck(True, sftp_versions.SAME, ("0.34.0",)))
    yield
    after_commit.handler(cases._NOTICES, cases._deliver)
    after_commit.handler(on._NUDGES, on._nudge)


def _user(db, name, role=m.RoleEnum.USER):
    u = m.User(username=name, email=f"{name}@example.test", password_hash="x", role=role, is_active=True,
               is_locked=False)
    db.add(u)
    db.commit()
    if role == m.RoleEnum.ADMIN:
        admin_grants.record(db, u.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR,
                            now=rights.utcnow() - timedelta(days=400))
    db.add(m.SecondFactorEnrollment(user_id=u.id, method="totp", secret_enc="sealed", status="active"))
    db.commit()
    return u


def _vault(db, owner, *, kind="standard", password=None):
    v = m.Vault(id=uuid.uuid4(), name=f"Vault of {owner.username}", owner_id=owner.id, type=kind,
                password_hash=password)
    db.add(v)
    db.commit()
    return v


def _file(db, vault, name):
    f = m.File(id=uuid.uuid4(), vault_id=vault.id, name=name, original_name=name, size_bytes=1, storage_path="x",
               mime_type="text/plain")
    db.add(f)
    db.commit()
    return f


@pytest.fixture
def people(db):
    ada, bob = _user(db, "ada", m.RoleEnum.ADMIN), _user(db, "bob", m.RoleEnum.ADMIN)
    uma, olga, otto, mallory = (_user(db, n) for n in ("uma", "olga", "otto", "mallory"))
    grant = rights.propose(db, uma, proposer=ada, now=rights.utcnow() - timedelta(hours=2))
    rights.approve(db, grant, approver=bob, now=rights.utcnow() - timedelta(hours=1))
    db.commit()
    return SimpleNamespace(ada=ada, bob=bob, uma=uma, olga=olga, otto=otto, mallory=mallory,
                           v1=_vault(db, olga), v2=_vault(db, otto))


def _case(db, people, vaults, *, approve=True, **kw):
    case = cases.request_case(db, people.uma, scope=[{"kind": "vault", "target_id": v.id} for v in vaults],
                              named_user_ids=[people.mallory.id], **{**TEXT, **kw})
    db.commit()
    if approve:
        cases.approve(db, case, approver=people.bob)
        db.commit()
    return case


def _viewed(db, case, vault, file_id):
    """The row a view of a file under the case writes (the case resolver's)."""
    db.add(m.AuditLog(action="case_file_viewed", status="success", user_id=case.auditor_id, username="uma",
                      resource_type="file", resource_id=str(file_id), case_id=case.id,
                      details={"vault_id": str(vault.id)}))
    db.commit()


# --------------------------------------------------------------------------- the owner's page

def test_an_owner_sees_only_cases_on_their_own_vaults_and_only_their_vaults(db, people):
    case = _case(db, people, [people.v1, people.v2])
    page = oa.page(db, people.olga)
    (seen,) = page["cases"]
    assert seen["id"] == str(case.id) and seen["number"] == case.number and seen["status"] == "active"
    assert [v["vault_id"] for v in seen["vaults"]] == [str(people.v1.id)]
    assert seen["auditor"] == "uma" and seen["approved_by"] == "bob" and seen["note"] == TEXT["owner_note"]
    assert [v["vault_id"] for v in oa.page(db, people.otto)["cases"][0]["vaults"]] == [str(people.v2.id)]
    assert oa.page(db, people.mallory)["cases"] == [], "a person named who owns nothing sees nothing"
    assert oa.page(db, people.uma)["cases"] == []


def test_the_page_never_names_the_justification_the_people_named_or_another_owners_vault(db, people):
    _case(db, people, [people.v1, people.v2])
    text = str(oa.page(db, people.olga))
    for hidden in (TEXT["justification"], "mallory", str(people.mallory.id), str(people.v2.id), "otto"):
        assert hidden not in text, hidden


def test_a_case_waiting_for_approval_is_not_on_the_page(db, people):
    case = _case(db, people, [people.v1], approve=False)
    assert oa.page(db, people.olga) == {"cases": [], "unseen": []}
    cases.approve(db, case, approver=people.bob)
    db.commit()
    assert [c["id"] for c in oa.page(db, people.olga)["cases"]] == [str(case.id)]


def test_a_hold_only_case_is_on_the_page(db, people):
    case = holds.place_hold_only(db, people.ada, [people.v1.id], purpose="litigation_hold",
                                 legal_basis="legal_obligation", justification=TEXT["justification"],
                                 owner_note="Kept for a legal matter.")
    db.commit()
    (seen,) = oa.page(db, people.olga)["cases"]
    assert seen["hold_only"] and seen["placed_by"] == "ada" and seen["auditor"] is None
    assert seen["vaults"][0]["hold"] is True and seen["note"] == "Kept for a legal matter."


def test_the_notices_are_unread_until_the_owner_says_so(db, people):
    case = _case(db, people, [people.v1])
    unseen = oa.page(db, people.olga)["unseen"]
    assert [(u["number"], u["kind"]) for u in unseen] == [(case.number, "activation")]
    assert oa.mark_seen(db, people.olga) == 1
    db.commit()
    assert oa.page(db, people.olga)["unseen"] == []
    (row,) = db.query(m.AuditLog).filter(m.AuditLog.action == "owner_notice_seen").all()
    assert row.user_id == people.olga.id and row.details["count"] == 1
    # A later notice is unread again; reading stops at "through".
    cases.extend(db, case, by=people.bob, days=3)
    db.commit()
    newest = db.query(m.ComplianceNoticeOutbox).order_by(m.ComplianceNoticeOutbox.created_at.desc()).first()
    assert oa.mark_seen(db, people.olga, through=newest.created_at - timedelta(seconds=1)) == 0
    assert [u["kind"] for u in oa.page(db, people.olga)["unseen"]] == ["extension"]
    assert oa.mark_seen(db, people.otto) == 0, "only the caller's own notices"


def test_files_opened_show_names_only_as_the_owner_could_read_them(db, people):
    locked = _vault(db, people.olga, password="hash")
    zk = _vault(db, people.olga, kind="zero_knowledge")
    case = _case(db, people, [people.v1, locked, zk, people.v2])
    for vault, name in ((people.v1, "plain.txt"), (locked, "secret.txt"), (zk, None), (people.v2, "others.txt")):
        _viewed(db, case, vault, _file(db, vault, name).id)
    (seen,) = oa.page(db, people.olga)["cases"]
    shown = {o["vault_id"]: (o["name"], o["name_hidden"]) for o in seen["opened"]}
    assert shown == {str(people.v1.id): ("plain.txt", None), str(locked.id): (None, "password"),
                     str(zk.id): (None, "zero_knowledge")}, "never another owner's vault"
    (seen,) = oa.page(db, people.olga, unlocked={str(locked.id)})["cases"]
    assert {o["vault_id"]: o["name"] for o in seen["opened"]}[str(locked.id)] == "secret.txt"


def test_a_receipt_unlocks_only_the_owners_own_vault_for_this_page(db, people):
    locked = _vault(db, people.olga, password="hash")
    others = _vault(db, people.otto, password="hash")
    cred = receipts.credential_digest("hash")
    good, _ = receipts.issue(purpose=receipts.PURPOSE_OWNER, session_hash="s", vault_id=locked.id,
                             user_id=people.olga.id, credential=cred)
    activity, _ = receipts.issue(purpose=receipts.PURPOSE_ACTIVITY, session_hash="s", vault_id=locked.id,
                                 user_id=people.olga.id, credential=cred)
    theirs, _ = receipts.issue(purpose=receipts.PURPOSE_OWNER, session_hash="s", vault_id=others.id,
                               user_id=people.olga.id, credential=cred)
    assert oa.unlocked_vaults(db, people.olga, "s", {str(locked.id): good}) == {str(locked.id)}
    assert oa.unlocked_vaults(db, people.olga, "other-session", {str(locked.id): good}) == set()
    assert oa.unlocked_vaults(db, people.olga, "s", {str(locked.id): activity}) == set()
    assert oa.unlocked_vaults(db, people.olga, "s", {str(others.id): theirs}) == set()
    locked.password_hash = "changed"
    db.commit()
    assert oa.unlocked_vaults(db, people.olga, "s", {str(locked.id): good}) == set(), "a new password voids it"


def test_who_may_unlock_on_the_page(db, people):
    locked = _vault(db, people.olga, password="hash")
    assert oa.unlock_problem(db, people.olga, locked) is None
    assert oa.unlock_problem(db, people.otto, locked)[0] == 404
    assert oa.unlock_problem(db, people.olga, people.v1)[0] == 400
    assert oa.unlock_problem(db, people.olga, _vault(db, people.olga, kind="zero_knowledge"))[0] == 409
    assert oa.unlock_problem(db, people.olga, None)[0] == 404


def test_kept_files_count_what_this_cases_hold_kept_on_each_vault(db, people):
    case = _case(db, people, [people.v1])
    hold = db.query(m.LegalHoldVault).filter(m.LegalHoldVault.case_id == case.id).one()
    for at in (hold.placed_at - timedelta(minutes=1), hold.placed_at + timedelta(minutes=1)):
        db.add(m.HeldFile(id=uuid.uuid4(), vault_id=people.v1.id, kept_reason="deleted", kept_at=at, size_bytes=1,
                          storage_path="x"))
    db.commit()
    assert oa.page(db, people.olga)["cases"][0]["vaults"][0]["kept_files"] == 1


# --------------------------------------------------------------------------- the routes

def test_the_routes(db, people, monkeypatch):
    case = _case(db, people, [people.v1])
    monkeypatch.setattr(api, "_current_session_hash", lambda request: "s")
    request = SimpleNamespace(headers={})
    out = cr.my_compliance_access(request, x_owner_unlock=None, current_user=people.olga, db=db)
    assert [c["id"] for c in out["cases"]] == [str(case.id)] and len(out["unseen"]) == 1
    assert cr.my_compliance_notices_seen(None, current_user=people.olga, db=db) == {"seen": 1}
    assert cr.my_compliance_access(request, x_owner_unlock=None, current_user=people.olga, db=db)["unseen"] == []


def test_the_unlock_route_checks_the_password_on_the_vaults_throttle_and_records_it(db, people, monkeypatch):
    locked = _vault(db, people.olga, password="hash")
    monkeypatch.setattr(api, "_current_session_hash", lambda request: "s")
    checked = []

    def check(user, vault, password):
        checked.append((user.id, vault.id))
        if password != "right":
            raise receipts.UnlockRefused(403, "The vault password is not right.")
    monkeypatch.setattr(receipts, "check_password", check)
    with pytest.raises(HTTPException) as refused:
        cr.unlock_my_vault_names(locked.id, cr.OwnerUnlock(password="wrong"), request=None,
                                 current_user=people.olga, db=db)
    assert refused.value.status_code == 403
    out = cr.unlock_my_vault_names(locked.id, cr.OwnerUnlock(password="right"), request=None,
                                   current_user=people.olga, db=db)
    assert receipts.verify(out["receipt"], purpose=receipts.PURPOSE_OWNER, session_hash="s", vault_id=locked.id,
                           user_id=people.olga.id, credential=receipts.credential_digest("hash"))
    assert checked == [(people.olga.id, locked.id)] * 2
    rows = db.query(m.AuditLog).filter(m.AuditLog.action == "owner_access_unlocked").order_by(m.AuditLog.timestamp).all()
    assert [r.status for r in rows] == ["failure", "success"] and "right" not in str([r.details for r in rows])
    with pytest.raises(HTTPException) as refused:
        cr.unlock_my_vault_names(locked.id, cr.OwnerUnlock(password="right"), request=None,
                                 current_user=people.otto, db=db)
    assert refused.value.status_code == 404


def test_the_unlock_header_is_read_as_vault_receipt_pairs():
    assert cr._owner_receipts(None) == {}
    assert cr._owner_receipts(" a=r1 , b=r2,=x,c=") == {"a": "r1", "b": "r2"}


# --------------------------------------------------------------------------- members

def test_members_see_a_neutral_banner_while_an_active_case_covers_the_vault(db, people):
    case = _case(db, people, [people.v1])
    review = oa.member_review(db, people.v1.id)
    assert review == {"until": case.access_ends_at.isoformat() + "Z", "hold": True}
    assert set(review) == {"until", "hold"}, "no number, purpose, auditor or person concerned"
    assert oa.member_review(db, people.v2.id) is None
    assert oa.member_review(db, people.v1.id, case.access_ends_at) is None, "not once access ended"


def test_no_banner_before_the_approval_for_a_vault_narrowed_out_or_without_a_hold(db, people):
    pending = _case(db, people, [people.v1], approve=False)
    assert oa.member_review(db, people.v1.id) is None
    cases.approve(db, pending, approver=people.bob)
    cases.narrow(db, pending, by=people.uma, scope=[{"kind": "vault", "target_id": people.v1.id}])
    db.commit()
    assert oa.member_review(db, people.v1.id)["hold"] is True
    nohold = _case(db, people, [people.v2], hold=False)
    assert oa.member_review(db, people.v2.id) == {"until": nohold.access_ends_at.isoformat() + "Z", "hold": False}
    other = _vault(db, people.otto)
    case = _case(db, people, [other, people.v2])
    cases.narrow(db, case, by=people.uma, scope=[{"kind": "vault", "target_id": people.v2.id}])
    db.commit()
    assert oa.member_review(db, other.id) is None


def test_a_hold_only_case_shows_members_no_banner(db, people):
    holds.place_hold_only(db, people.ada, [people.v1.id], purpose="litigation_hold", legal_basis="legal_obligation",
                          justification=TEXT["justification"], owner_note="Kept.")
    db.commit()
    assert oa.member_review(db, people.v1.id) is None


def test_a_failure_to_read_it_never_fails_opening_the_vault(db, monkeypatch):
    monkeypatch.setattr(oa, "member_review", lambda db_, vid: (_ for _ in ()).throw(RuntimeError("down")))
    assert oa.member_review_shown(db, uuid.uuid4()) is None


def test_the_banner_is_added_in_the_vault_detail_route_never_in_get_vault():
    from app.services.vault_service import VaultService
    source = inspect.getsource(VaultService.get_vault)
    for name in ("owner_access", "compliance", "cases", "case_rules", "legal_hold", "member_review"):
        assert name not in source, name
    route = inspect.getsource(api.get_vault)
    assert route.count("member_review_shown(db, vault.id)") == 1
    assert "compliance_review" in api.VaultResponse.model_fields


# --------------------------------------------------------------------------- the page and the banners

def _js(name):
    return (ROOT / "static" / "js" / name).read_text(encoding="utf-8")


def test_the_owners_banner_is_the_shared_notice_banner():
    js = _js("compliance.js")
    start = js.index("async function checkAccessBanner(")
    body = js[start:js.index("\n    }\n", start)]
    assert "window.NoticeBanner" in body and "nb.show({" in body and "id: ACCESS_BANNER" in body
    assert "/me/compliance-access/seen" in body
    assert "notice-banner" not in body, "no banner of its own: the recording notice's component"
    banner = _js("notice-banner.js")
    assert "opts.onOpen" in banner and "e.preventDefault(); opts.onOpen();" in banner


def test_the_members_banner_names_nothing_of_the_case():
    js = _js("compliance.js")
    start = js.index("function renderVaultReview(")
    body = js[start:js.index("window.renderVaultReview", start)]
    assert "review.until" in body and "review.hold" in body
    for field in ("number", "purpose", "auditor", "justification", "people"):
        assert field not in body, field
    assert "innerHTML" not in js


def test_the_app_hands_the_vault_and_the_notice_to_the_page():
    app = _js("app.js")
    assert "window.renderVaultReview(vault)" in app
    assert "ev.notification_type === 'compliance_access'" in app
    index = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert 'id="my-access-btn"' in index


def test_the_owners_files_opened_are_found_among_many_of_other_owners(db, people):
    case = _case(db, people, [people.v1, people.v2])
    mine = _file(db, people.v1, "mine.txt")
    others = _file(db, people.v2, "others.txt")
    start = case.approved_at
    rows = [(people.v1, mine, start)] + [(people.v2, others, start + timedelta(seconds=1 + i))
                                         for i in range(oa.OPENED_SHOWN * 5)]
    for vault, f, at in rows:
        db.add(m.AuditLog(action="case_file_viewed", status="success", user_id=case.auditor_id, username="uma",
                          resource_type="file", resource_id=str(f.id), case_id=case.id, timestamp=at,
                          details={"vault_id": str(vault.id)}))
    db.commit()
    (seen,) = oa.page(db, people.olga)["cases"]
    assert [o["name"] for o in seen["opened"]] == ["mine.txt"], "the owner's one, older than a thousand others"
