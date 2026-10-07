"""What a vault's owner and a vault's members see of compliance access, on a running stack: Access to my vaults
(GET /me/compliance-access) lists only the cases on the caller's own vaults and only those vaults, with the
notices until "I've read it"; the vault-detail route carries the members' neutral banner while an approved case
covers the vault, and nothing once it is closed. test_owner_access.py covers the rules offline;
test_ui_owner_access.py the page and the banners in a browser."""
import pytest

from _account_change_helpers import signed_in
from _auditor_helpers import forget_grants, grant_right, new_auditor_account, two_admins
from _owner_notice_helpers import CASE_TEXT, approved_case, forget_cases, owner_with_vault

pytestmark = pytest.mark.integration


@pytest.fixture
def world(admin):
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        olga, olga_c, v1 = owner_with_vault(admin)
        otto, otto_c, v2 = owner_with_vault(admin)
        mia = admin.create_user()
        assert olga_c.post(f"/vaults/{v1}/permissions", json={"user_id": mia["id"], "level": "read"}).status_code \
            in (200, 201)
        made = []
        try:
            yield {"admins": admins, "uma": (uma, uma_c, codes), "olga": (olga, olga_c, v1),
                   "otto": (otto, otto_c, v2), "mia": mia, "cases": made}
        finally:
            forget_cases(made, [v1, v2])
            forget_grants(uma["id"])


def test_an_owner_sees_only_their_own_vaults_in_a_case(world):
    olga, olga_c, v1 = world["olga"]
    otto, otto_c, v2 = world["otto"]
    case = approved_case(world["admins"], world["uma"], [v1, v2])
    world["cases"].append(case["id"])
    page = olga_c.get("/me/compliance-access")
    assert page.status_code == 200, page.text
    (seen,) = page.json()["cases"]
    assert seen["number"] == case["number"] and [v["vault_id"] for v in seen["vaults"]] == [v1]
    assert seen["note"] == CASE_TEXT["owner_note"] and seen["auditor"] == world["uma"][0]["_username"]
    assert CASE_TEXT["justification"] not in page.text and v2 not in page.text and otto["_username"] not in page.text
    assert [v["vault_id"] for v in otto_c.get("/me/compliance-access").json()["cases"][0]["vaults"]] == [v2]
    mia_c = signed_in(world["mia"])
    assert mia_c.get("/me/compliance-access").json() == {"cases": [], "unseen": []}, "a member owns nothing here"


def test_the_notices_stay_unread_until_the_owner_says_so(world):
    olga, olga_c, v1 = world["olga"]
    case = approved_case(world["admins"], world["uma"], [v1])
    world["cases"].append(case["id"])
    unseen = olga_c.get("/me/compliance-access").json()["unseen"]
    assert [(u["number"], u["kind"]) for u in unseen] == [(case["number"], "activation")]
    assert olga_c.post("/me/compliance-access/seen", json={}).json() == {"seen": 1}
    assert olga_c.get("/me/compliance-access").json()["unseen"] == []
    assert len(olga_c.get("/me/compliance-access").json()["cases"]) == 1, "the page stays"


def test_members_see_a_neutral_banner_on_the_vault_while_the_case_is_active(world):
    olga, olga_c, v1 = world["olga"]
    otto, otto_c, v2 = world["otto"]
    mia_c = signed_in(world["mia"])
    assert mia_c.get(f"/vaults/{v1}").json()["compliance_review"] is None
    case = approved_case(world["admins"], world["uma"], [v1])
    world["cases"].append(case["id"])
    r = mia_c.get(f"/vaults/{v1}")
    assert r.status_code == 200
    review = r.json()["compliance_review"]
    assert review == {"until": case["access_ends_at"], "hold": True}
    for hidden in (case["number"], world["uma"][0]["_username"], CASE_TEXT["justification"], "internal"):
        assert hidden not in r.text, hidden
    assert olga_c.get(f"/vaults/{v1}").json()["compliance_review"] == review, "the owner opens it too"
    assert otto_c.get(f"/vaults/{v2}").json()["compliance_review"] is None
    uma, uma_c, codes = world["uma"]
    from _auditor_helpers import compliance_receipt
    r = uma_c.post(f"/compliance/cases/{case['id']}/close", json={"reason": "Concluded."},
                   headers=compliance_receipt(uma_c, "compliance.hold.decide", uma["_password"], codes))
    assert r.status_code == 200, r.text
    assert mia_c.get(f"/vaults/{v1}").json()["compliance_review"] is None


def test_a_temporary_credential_reads_no_owners_notices(world):
    from conftest import ApiClient, unique
    olga, olga_c, v1 = world["olga"]
    case = approved_case(world["admins"], world["uma"], [v1])
    world["cases"].append(case["id"])
    tc = olga_c.post("/auth/temp-credentials", json={"note": unique("owner-tc")}).json()
    try:
        tclient = ApiClient()
        tclient.login(tc["temp_username"], tc["credential"])
        assert tclient.get("/me/compliance-access").status_code == 403
        assert tclient.post("/me/compliance-access/seen", json={}).status_code == 403
        assert len(olga_c.get("/me/compliance-access").json()["unseen"]) == 1, "nothing was marked read"
    finally:
        olga_c.post(f"/temp-creds/{tc['temp_username']}/delete")
