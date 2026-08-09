"""The browser chooses a zero-knowledge vault's id, and the server holds it to that.

A zero-knowledge vault's key is locked in the browser and sent in the same request that creates the
vault. The newer lock format stamps the key with the vault it belongs to -- so the id has to exist
before the lock does, and the server assigning it on arrival is too late.

Letting the browser choose it gives away nothing. A vault id is not a secret and grants no access;
access comes from membership rows and from the crypto. The one thing that could go wrong is two
vaults sharing an id, and that is what these tests are about.

Note what the browser tests cannot check. They drive the real page and create real vaults, but they
read the id back out of the *response* -- so a server that quietly ignored the field would still
look correct to them, while every lock minted afterwards would be stamped with an id its vault does
not have. Those vaults would be unopenable, and nobody would find out until someone tried. That is
the gap this file exists to close, and it is why the first test compares against the id SENT.
"""

import uuid

import pytest

from conftest import unique, ensure_ecc_keypair


def _stub(prefix="w"):
    import base64
    return base64.b64encode(f"{prefix}-{uuid.uuid4().hex}".encode()).decode()


def _zk_payload(vault_id=None):
    body = {
        "name": unique("mintid"),
        "type": "zero_knowledge",
        "wrapped_dek": _stub("dek"),
        "ephemeral_public_key": _stub("eph"),
    }
    if vault_id is not None:
        body["id"] = str(vault_id)
    return body


@pytest.mark.integration
def test_the_vault_is_created_under_the_id_the_client_chose(admin):
    """The load-bearing one: the id stored must be the id sent.

    Everything else in this change rests on it. If the server assigned its own id instead, the
    lock -- stamped with the id the browser chose -- would belong to a vault that does not exist.
    """
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        ensure_ecc_keypair(admin)
        chosen = uuid.uuid4()
        r = admin.post("/vaults", json=_zk_payload(chosen))
        assert r.status_code in (200, 201), r.text
        assert r.json()["id"] == str(chosen), "the server did not honour the chosen id"
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})

    try:
        # And it is genuinely addressable under that id, not merely echoed back.
        assert admin.get(f"/vaults/{chosen}").status_code == 200
    finally:
        admin.delete_vault(str(chosen))


@pytest.mark.integration
def test_an_id_already_in_use_is_refused(admin):
    """Two vaults sharing an id would let a key locked for one be opened as the other.

    That is the single property choosing your own id could cost, so it is the one worth pinning.
    """
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        ensure_ecc_keypair(admin)
        chosen = uuid.uuid4()
        first = admin.post("/vaults", json=_zk_payload(chosen))
        assert first.status_code in (200, 201), first.text

        clash = admin.post("/vaults", json=_zk_payload(chosen))
        assert clash.status_code == 409, (
            f"a second vault was allowed to take a live vault's id: {clash.status_code} {clash.text}"
        )
        assert "already in use" in clash.text
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})
        admin.delete_vault(str(chosen))


@pytest.mark.integration
def test_a_standard_vault_may_not_choose_its_id(admin):
    """Only the zero-knowledge path has a reason to.

    A Standard vault's id feeds its at-rest key derivation and names a directory on disk. Nothing
    about that needs a caller's input, and narrowing the field to the branch that justifies it keeps
    a client-controlled value out of places it has no business being.
    """
    r = admin.post("/vaults", json={"name": unique("stdid"), "id": str(uuid.uuid4())})
    assert r.status_code == 400, (
        f"a Standard vault accepted a client-chosen id: {r.status_code} {r.text}"
    )
    assert "zero-knowledge" in r.text


@pytest.mark.integration
def test_a_malformed_id_is_rejected_before_anything_is_built(admin):
    """Rejected at the door by the type, not somewhere deeper where the message would be worse."""
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        ensure_ecc_keypair(admin)
        for bad in ("not-a-uuid", "../../etc/passwd", "x" * 500):
            r = admin.post("/vaults", json=_zk_payload() | {"id": bad})
            assert r.status_code == 422, f"{bad!r} was not rejected: {r.status_code} {r.text}"
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


@pytest.mark.integration
def test_a_client_that_sends_no_id_is_unaffected(admin):
    """The field is optional, and a caller that ignores it must behave exactly as before."""
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        ensure_ecc_keypair(admin)
        r = admin.post("/vaults", json=_zk_payload())
        assert r.status_code in (200, 201), r.text
        assigned = r.json()["id"]
        assert uuid.UUID(assigned)
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})
    admin.delete_vault(assigned)
