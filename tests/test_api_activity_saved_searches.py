"""API: saved searches on the Activity page, against a running vault.

Each administrator has their own: they list, create, rename, change, delete and choose a default, and
nobody else sees or touches them. Tests use a fresh administrator, so they start from none."""
import pytest

from conftest import ApiClient, unique

PATH = "/activity/saved-searches"


@pytest.fixture
def owner(admin):
    user = admin.create_user(role="admin")
    c = ApiClient()
    c.login(user["_username"], user["_password"])
    yield c
    admin.delete_user(user["id"])


@pytest.fixture
def other_admin(admin):
    user = admin.create_user(role="admin")
    c = ApiClient()
    c.login(user["_username"], user["_password"])
    yield c
    admin.delete_user(user["id"])


def _save(client, name, filters=None, **extra):
    r = client.post(PATH, json={"name": name, "filters": filters or {}, **extra})
    assert r.status_code == 200, r.text
    return r.json()


def test_a_search_is_saved_listed_renamed_changed_and_deleted(owner):
    assert owner.get(PATH).json() == {"searches": [], "limit": 50}
    s = _save(owner, "Failed sign-ins", {"category": ["sign_in"], "status": ["failed"], "range": "7d"})
    assert s["name"] == "Failed sign-ins" and s["is_default"] is False
    assert s["filters"] == {"category": ["sign_in"], "status": ["failed"], "range": "7d"}
    assert [x["id"] for x in owner.get(PATH).json()["searches"]] == [s["id"]]

    r = owner.patch(f"{PATH}/{s['id']}", json={"name": "Sign-ins that failed"})
    assert r.status_code == 200 and r.json()["name"] == "Sign-ins that failed"
    assert r.json()["filters"] == s["filters"]                     # a rename keeps the filters
    r = owner.patch(f"{PATH}/{s['id']}", json={"filters": {"user": "maria"}})
    assert r.json()["filters"] == {"user": "maria"} and r.json()["name"] == "Sign-ins that failed"

    assert owner.delete(f"{PATH}/{s['id']}").status_code == 200
    assert owner.get(PATH).json()["searches"] == []
    assert owner.delete(f"{PATH}/{s['id']}").status_code == 404


def test_the_list_is_in_name_order(owner):
    for name in ("zeta", "Alpha", "beta"):
        _save(owner, name)
    assert [x["name"] for x in owner.get(PATH).json()["searches"]] == ["Alpha", "beta", "zeta"]


def test_one_search_at_a_time_is_the_default(owner):
    a = _save(owner, "a", is_default=True)
    b = _save(owner, "b")
    assert a["is_default"] is True
    listed = owner.post(f"{PATH}/{b['id']}/default").json()["searches"]
    assert {x["name"]: x["is_default"] for x in listed} == {"a": False, "b": True}
    c = _save(owner, "c", is_default=True)
    listed = owner.get(PATH).json()["searches"]
    assert [x["id"] for x in listed if x["is_default"]] == [c["id"]]
    listed = owner.delete(f"{PATH}/{c['id']}/default").json()["searches"]
    assert not any(x["is_default"] for x in listed)


def test_a_name_is_used_once_whatever_its_case(owner):
    first = _save(owner, "Night logins")
    r = owner.post(PATH, json={"name": "night LOGINS", "filters": {}})
    assert r.status_code == 409 and "already have a saved search named" in r.json()["detail"]
    other = _save(owner, "Day logins")
    assert owner.patch(f"{PATH}/{other['id']}", json={"name": "NIGHT logins"}).status_code == 409
    assert owner.patch(f"{PATH}/{first['id']}", json={"name": "night logins"}).status_code == 200   # its own


@pytest.mark.parametrize("body", [
    {"name": "x", "filters": {"vault_id": "abc"}},
    {"name": "x", "filters": {"category": ["not-a-category"]}},
    {"name": "x", "filters": {"range": "1y"}},
    {"name": "", "filters": {}},
    {"name": "x" * 81, "filters": {}},
])
def test_a_search_the_page_could_not_load_is_refused(owner, body):
    r = owner.post(PATH, json=body)
    assert r.status_code == 422, r.text
    assert owner.get(PATH).json()["searches"] == []


def test_one_person_keeps_at_most_fifty(owner):
    for i in range(50):
        _save(owner, f"s{i:02d}")
    r = owner.post(PATH, json={"name": "one more", "filters": {}})
    assert r.status_code == 409 and "Delete one to save another" in r.json()["detail"]
    first = owner.get(PATH).json()["searches"][0]
    owner.delete(f"{PATH}/{first['id']}")
    _save(owner, "one more")


def test_nobody_else_sees_or_touches_them(owner, other_admin, admin, temp_user_client):
    mine = _save(owner, "Mine", {"user": "maria"}, is_default=True)
    assert other_admin.get(PATH).json()["searches"] == []
    assert all(x["id"] != mine["id"] for x in admin.get(PATH).json()["searches"])
    for client in (other_admin, admin):
        assert client.patch(f"{PATH}/{mine['id']}", json={"name": "taken"}).status_code == 404
        assert client.post(f"{PATH}/{mine['id']}/default").status_code == 404
        assert client.delete(f"{PATH}/{mine['id']}/default").status_code == 404
        assert client.delete(f"{PATH}/{mine['id']}").status_code == 404
    # The other administrator may use the same name for a search of their own.
    _save(other_admin, "Mine")
    still = owner.get(PATH).json()["searches"]
    assert [(x["id"], x["name"], x["is_default"], x["filters"]) for x in still] == [
        (mine["id"], "Mine", True, {"user": "maria"})]
    # A non-administrator has no Activity page and no saved searches.
    assert temp_user_client.get(PATH).status_code == 403
    assert temp_user_client.post(PATH, json={"name": "x", "filters": {}}).status_code == 403


def test_an_id_that_is_not_one_is_not_found(owner):
    assert owner.patch(f"{PATH}/not-an-id", json={"name": "x"}).status_code == 404
