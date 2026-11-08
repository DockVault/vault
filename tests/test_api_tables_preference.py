"""The remembered table sorts (the "tables" preference): a small JSON object of one shape is kept for the account;
anything else is dropped, and the density keeps its two values."""
import json

import pytest

pytestmark = pytest.mark.integration


def _put(client, **prefs):
    r = client.put("/users/me/preferences", json=prefs)
    assert r.status_code == 200, r.text
    return client.get("/users/me/preferences").json()


def test_a_real_sort_is_kept_and_read_back(temp_user_client):
    value = json.dumps({"users": {"col": 1, "dir": "asc"}, "vault-members": {"col": 3, "dir": "desc"}})
    got = _put(temp_user_client, tables=value)
    assert json.loads(got["tables"]) == json.loads(value)
    got = _put(temp_user_client, density="compact")
    assert got["density"] == "compact" and json.loads(got["tables"]) == json.loads(value)


@pytest.mark.parametrize("bad", [
    "not json", "[]", json.dumps({"users": {"col": "1", "dir": "asc"}}), json.dumps({"users": {"col": 1, "dir": "up"}}),
    json.dumps({"users": {"col": 1}}), json.dumps({"users": {"col": 1, "dir": "asc", "x": 1}}),
    json.dumps({"a b": {"col": 1, "dir": "asc"}}), json.dumps({"users": {"col": True, "dir": "asc"}}),
    json.dumps({f"t{i}": {"col": 0, "dir": "asc"} for i in range(51)}), "{" + "x" * 2000 + "}",
])
def test_anything_else_is_dropped(temp_user_client, bad):
    before = temp_user_client.get("/users/me/preferences").json().get("tables")
    got = _put(temp_user_client, tables=bad)
    assert got.get("tables") == before
