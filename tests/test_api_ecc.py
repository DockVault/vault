"""ECC / cryptography router (/ecc/*). Light coverage: hit each endpoint and
assert the contract on the easy-to-construct cases."""


def test_decompress_point_invalid_returns_400(admin):
    r = admin.post("/ecc/decompress-point",
                   json={"compressed_point": "not-base64!!", "curve": "P-384"})
    assert r.status_code in (400, 422)


def test_public_key_for_user_without_keypair(admin):
    r = admin.get("/ecc/keys/public")
    assert r.status_code == 200
    body = r.json()
    assert "has_keypair" in body
    assert isinstance(body["has_keypair"], bool)


def test_register_invalid_public_key_rejected(admin):
    r = admin.post("/ecc/keys/register", json={"public_key": "not a PEM key"})
    assert r.status_code in (400, 422, 500)


def test_decompress_point_requires_field(admin):
    r = admin.post("/ecc/decompress-point", json={})
    assert r.status_code == 422
