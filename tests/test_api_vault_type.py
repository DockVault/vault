"""Vault confidentiality `type` column + the creation-policy hook (design item 2).

Today only 'standard' is functional; the hook defaults everything to 'standard'
and refuses the not-yet-built 'zero_knowledge' tier. These guard that contract.
"""
from conftest import unique


def test_create_vault_defaults_to_standard(admin):
    r = admin.post("/vaults", json={"name": unique("v")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["type"] == "standard"
    admin.delete_vault(body["id"])


def test_create_vault_explicit_standard_ok(admin):
    r = admin.post("/vaults", json={"name": unique("v"), "type": "standard"})
    assert r.status_code == 200, r.text
    assert r.json()["type"] == "standard"
    admin.delete_vault(r.json()["id"])


def test_create_zero_knowledge_vault_rejected(admin):
    r = admin.post("/vaults", json={"name": unique("v"), "type": "zero_knowledge"})
    assert r.status_code == 400, r.text
    # and nothing was created under that name
    names = [v["name"] for v in admin.get("/vaults").json()]
    assert not any(n == r.json().get("name") for n in names)


def test_create_unknown_type_rejected(admin):
    r = admin.post("/vaults", json={"name": unique("v"), "type": "totally-bogus"})
    assert r.status_code == 400, r.text


def test_type_is_visible_in_list_and_detail(admin):
    vid = admin.post("/vaults", json={"name": unique("v")}).json()["id"]
    try:
        # single-vault detail
        assert admin.get(f"/vaults/{vid}").json()["type"] == "standard"
        # and in the list
        listed = {v["id"]: v for v in admin.get("/vaults").json()}
        assert listed[vid]["type"] == "standard"
    finally:
        admin.delete_vault(vid)
