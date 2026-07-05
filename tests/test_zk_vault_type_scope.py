"""Temp-credential scope can restrict vault creation BY TYPE (standard vs zero-knowledge).

`vault.create` is the legacy type-agnostic create cap; the per-type `vault.create.standard` /
`vault.create.zero_knowledge` caps let an operator mint a credential that may create only one
kind. Holding `vault.create` still permits both. No create cap at all -> can't create anything.
"""
import contextlib

from conftest import unique, ensure_ecc_keypair, ZK_WRAPPED_DEK_STUB, ZK_EPHEMERAL_STUB


@contextlib.contextmanager
def _zk_on(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _scoped_client(admin, caps):
    scope = {"v": 1, "pages": ["vaults"], "caps": caps, "vault_caps_default": [],
             "temp": {"view": False, "create": False, "invalidate": False, "clear": False, "delegate": False}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "all",
    }).json()
    c = admin.clone_anonymous()
    c.login(body["temp_username"], body["credential"])
    return c


def _mk_standard(c):
    return c.post("/vaults", json={"name": unique("s"), "type": "standard"})


def _mk_zk(c):
    ensure_ecc_keypair(c)   # the temp cred authenticates as its creator, who has a keypair
    return c.post("/vaults", json={"name": unique("z"), "type": "zero_knowledge",
                                   "wrapped_dek": ZK_WRAPPED_DEK_STUB, "ephemeral_public_key": ZK_EPHEMERAL_STUB})


def test_temp_cred_scoped_to_standard_only(admin):
    with _zk_on(admin):
        c = _scoped_client(admin, ["vault.create.standard"])
        r = _mk_standard(c)
        assert r.status_code == 200, r.text
        try:
            rz = _mk_zk(c)
            assert rz.status_code == 403, rz.text        # zero-knowledge is out of scope
        finally:
            admin.delete_vault(r.json()["id"])


def test_temp_cred_scoped_to_zk_only(admin):
    with _zk_on(admin):
        c = _scoped_client(admin, ["vault.create.zero_knowledge"])
        rz = _mk_zk(c)
        rs = None
        try:
            assert rz.status_code == 200, rz.text
            rs = _mk_standard(c)
            assert rs.status_code == 403, rs.text        # standard is out of scope
        finally:
            for r in (rz, rs):
                if r is not None and r.status_code == 200:
                    admin.delete_vault(r.json()["id"])


def test_legacy_vault_create_cap_allows_both_types(admin):
    with _zk_on(admin):
        c = _scoped_client(admin, ["vault.create"])
        rs = _mk_standard(c)
        rz = _mk_zk(c)
        try:
            assert rs.status_code == 200, rs.text
            assert rz.status_code == 200, rz.text
        finally:
            for r in (rs, rz):
                if r.status_code == 200:
                    admin.delete_vault(r.json()["id"])


def test_no_create_cap_cannot_create_any_type(admin):
    with _zk_on(admin):
        c = _scoped_client(admin, [])                    # vaults page, but no create cap
        assert _mk_standard(c).status_code == 403
        assert _mk_zk(c).status_code == 403
