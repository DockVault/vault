"""The Standard key-rotation endpoint used to lie, and this is what it has to do instead.

It archived the stored vault key, minted a replacement, bumped `key_version`, and answered
"Encryption key rotated successfully — new file uploads will use the new key."

None of that was true of the content. A Standard vault's bytes are encrypted under a key derived
from the DEPLOYMENT secret, salted per file with the vault and file ids, and no read path consults
`encrypted_vault_key` or `key_version` at all. The endpoint rotated a key nothing uses and reported
a completed security operation.

That matters more here than almost anywhere else in the product, because of *when* it is called.
An operator reaches for key rotation when they believe a key is compromised. A success message
tells them the content is now protected under a new key, so they stop looking. The endpoint has to
refuse, and it has to change nothing while refusing.
"""

import uuid

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.crypto_compatibility]


def _vault_row(admin, vault_id: str) -> dict:
    """Everything the rotation used to mutate, as the API can see it.

    Deliberately does NOT read `key_version` off `GET /vaults/{id}`: that response model has no
    such field, so it is always None and comparing it would look like coverage while proving
    nothing. The key-history endpoint is where the mutated state is actually visible.
    """
    r = admin.get(f"/vaults/{vault_id}/key-history")
    assert r.status_code == 200, r.text  # a 500 here would make the comparison below vacuous
    history = r.json()
    return {
        "history_version": history.get("current_key_version"),
        "history_entries": len(history.get("history") or []),
    }


def test_rotation_is_refused_and_says_why(admin, temp_vault) -> None:
    """A stable refusal, and a message that tells the operator what is actually true."""
    r = admin.post(f"/vaults/{temp_vault['id']}/rotate-key")
    assert r.status_code == 501, r.text

    detail = r.json()["detail"].lower()
    # It must not leave the reader thinking something was re-keyed.
    assert "not implemented" in detail
    assert "nothing was changed" in detail
    # And it must point at what would actually re-key content, rather than stopping at "no".
    assert "deployment" in detail


def test_a_password_protected_vault_gets_the_same_refusal(admin, temp_vault_pw) -> None:
    """One answer for every Standard vault.

    A password-protected vault previously got a different, narrower rejection about re-wrapping.
    That reason was true but incomplete, and two codes for the same refusal is worse for whoever
    is reading: the operation does not re-key content for ANY standard vault, whatever its
    password state.
    """
    r = admin.post(f"/vaults/{temp_vault_pw['id']}/rotate-key")
    assert r.status_code == 501, r.text
    assert "nothing was changed" in r.json()["detail"].lower()


def test_the_refusal_mutates_nothing(admin, temp_vault) -> None:
    """The acceptance's real requirement: refuse BEFORE touching the database.

    A refusal that still archived the old key and bumped the version would be honest in its
    wording and wrong in its effect -- the endpoint's whole problem was a gap between the two.
    """
    vid = temp_vault["id"]
    before = _vault_row(admin, vid)

    for _ in range(3):  # repeated calls must not accumulate history rows either
        assert admin.post(f"/vaults/{vid}/rotate-key").status_code == 501

    assert _vault_row(admin, vid) == before


def test_content_written_before_a_refused_rotation_still_downloads(admin, temp_vault) -> None:
    """Byte-for-byte, because the point of refusing is that nothing moved."""
    vid = temp_vault["id"]
    name = f"rotation-probe-{uuid.uuid4().hex[:8]}.bin"
    content = b"standard vault content that must survive a refused rotation\n" * 50

    up = admin.post(
        f"/vaults/{vid}/files",
        files=[("files", (name, content, "application/octet-stream"))],
    )
    assert up.status_code in (200, 201), up.text

    listing = admin.get(f"/vaults/{vid}/files").json()
    rows = listing.get("items", listing) if isinstance(listing, dict) else listing
    match = [it for it in rows if it.get("name") == name]
    assert match, f"upload missing from listing: {[it.get('name') for it in rows]}"
    file_id = match[0]["id"]

    assert admin.post(f"/vaults/{vid}/rotate-key").status_code == 501

    got = admin.get(f"/vaults/{vid}/files/{file_id}/download")
    assert got.status_code == 200, got.text
    assert got.content == content, "content changed across a refused rotation"


def test_the_zero_knowledge_rejection_is_unchanged(admin) -> None:
    """A different mechanism with a different reason, and the phase says leave it alone.

    A zero-knowledge vault's content key never reaches the server, so this endpoint was never the
    right tool for it -- that rejection predates this change and keeps its own status and wording.
    """
    from conftest import create_zk_vault

    # Capture and restore. This is a live container with a persistent database, so a flag left
    # flipped outlives the run -- and another test reads the current value as ITS baseline, which
    # would launder the leak into the permanent default.
    before = bool(admin.get("/settings").json().get("zero_knowledge_enabled"))
    assert admin.put("/settings", json={"zero_knowledge_enabled": True}).status_code in (200, 204)
    vault = None
    try:
        vault = create_zk_vault(admin)
        r = admin.post(f"/vaults/{vault['id']}/rotate-key")
        assert r.status_code == 400, r.text
        assert "zero-knowledge" in r.json()["detail"].lower()
    finally:
        if vault:
            admin.post(f"/vaults/{vault['id']}/delete")
        admin.put("/settings", json={"zero_knowledge_enabled": before})


def test_key_history_still_reads(admin, temp_vault) -> None:
    """Read-only and untouched. Refusing to write must not break looking."""
    r = admin.get(f"/vaults/{temp_vault['id']}/key-history")
    assert r.status_code == 200, r.text
    assert "current_key_version" in r.json()


def test_the_refusal_comes_after_the_authorization_checks(admin, temp_user_client) -> None:
    """Order matters, and the change makes it look like it does not.

    The vault lookup now has no purpose except the 404, the owner check and the zero-knowledge
    branch -- so a later tidy-up could reasonably hoist the unconditional 501 to the top of the
    handler. That would answer identically for "not yours", "does not exist" and "not supported",
    telling a stranger that a vault id is real.
    """
    import uuid as _uuid

    owned = admin.create_vault()
    try:
        # A stranger must still be refused for being a stranger, not told about the feature.
        r = temp_user_client.post(f"/vaults/{owned['id']}/rotate-key")
        assert r.status_code in (403, 404), r.text
        assert r.status_code != 501, "a non-owner learned this vault exists"

        # And a vault that does not exist must still be a 404.
        missing = admin.post(f"/vaults/{_uuid.uuid4()}/rotate-key")
        assert missing.status_code == 404, missing.text
    finally:
        admin.delete_vault(owned["id"])


def test_repeated_refusals_leave_the_history_endpoint_working(admin, temp_vault) -> None:
    """The probe used by the no-mutation test must itself stay healthy, or that test compares
    two identical failures and passes on garbage."""
    vid = temp_vault["id"]
    for _ in range(2):
        assert admin.post(f"/vaults/{vid}/rotate-key").status_code == 501
    r = admin.get(f"/vaults/{vid}/key-history")
    assert r.status_code == 200, r.text
    assert r.json().get("current_key_version") is not None


def test_the_remediation_advice_cannot_destroy_data_if_followed(admin, temp_vault) -> None:
    """The first draft of this message told operators to rotate the deployment secret.

    Doing that in place makes every existing file permanently undecryptable -- including the ones
    the operator intended to re-upload, which exist only in the vault. The project README says so
    in bold. So the fix for one misleading server statement introduced a worse one, aimed at
    exactly the person least able to absorb it: someone acting at speed because they believe a key
    is compromised.

    The advice must therefore put the download first and name the hazard.
    """
    detail = admin.post(f"/vaults/{temp_vault['id']}/rotate-key").json()["detail"].lower()

    assert "download" in detail, "the advice omits the step that preserves the data"
    assert "permanently undecryptable" in detail, "the advice does not name the hazard"

    # Order matters as much as presence: the warning is useless after the instruction.
    assert detail.index("download") < detail.index("permanently undecryptable")
