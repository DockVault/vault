"""GET /ecc/vaults/{id}/keys must not be a vault existence / key-topology oracle.

For a vault the caller has no access to, the endpoint used to answer 200 with has_access=false but
ALSO mode and current_dek_version (describing the vault's key topology to a non-member), and 404 for
a vault id that does not exist. Every other vault endpoint answers 403 for the same unauthorized
input. These assert the endpoint now returns 403 for a vault the caller cannot reach, whether or not
it exists, while a MEMBER still gets a normal 200.
"""
import uuid


def test_ecc_keys_are_403_for_a_non_member_not_a_200_oracle(admin, temp_user, temp_user_client):
    v = admin.create_vault()
    vid = v["id"]
    try:
        # A real vault the caller is not a member of -> 403 (was 200 has_access=false + mode + dek_version)
        r_real = temp_user_client.get(f"/ecc/vaults/{vid}/keys")
        assert r_real.status_code == 403, r_real.text
        # A vault id that does not exist -> also 403, so the endpoint no longer confirms existence
        # (was 404). Same answer, so 403-vs-404 can't distinguish "forbidden" from "absent".
        r_none = temp_user_client.get(f"/ecc/vaults/{uuid.uuid4()}/keys")
        assert r_none.status_code == 403, r_none.text
        # The owner (a member) still reaches it normally.
        assert admin.get(f"/ecc/vaults/{vid}/keys").status_code == 200
    finally:
        admin.delete_vault(vid)
