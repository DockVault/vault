"""A temp-credential mint must not become a vault-password oracle for non-members.

The per-vault mint proof used to load ANY vault by id and verify the supplied password with no
membership pre-check: a correct password minted 200, a wrong one 400 -- a boolean oracle that
confirms any vault's password, by id, for any authenticated caller (the minted credential was dead
at USE time, but the oracle was at MINT time, before that gate). The mint now requires that the
OWNING account can itself READ each selected vault, enforced BEFORE the password check, so a
non-member is refused with a uniform 403 that never depends on whether the password was right.

Note on the paired rate-limit: wrong mint passwords now also burn the same failure-only
(vault, account) counter get_vault uses. That is not exercised here -- the dev/test deployment sets
a deliberately high vault-attempt limit so unrelated suites don't trip it, so a 429 is impractical
to reach; the shared counter itself is covered by the vault-access tests.
"""
from conftest import ApiClient, unique

VICTIM_VAULT_PW = "Victim-Vault-Pw-Ab12!"


def _scope(caps=("vault.see_info", "file.download")):
    return {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": list(caps), "temp": {}}


def _mint_selecting(client, vault_id, password):
    return client.post("/auth/temp-credentials", json={
        "validity_minutes": 30,
        "scope": _scope(),
        "vault_access_mode": "selected",
        "selected_vaults": [{
            "vault_id": vault_id,
            "caps": ["vault.see_info", "file.download"],
            "password": password,
        }],
    })


def test_nonmember_mint_is_not_a_vault_password_oracle(admin, temp_user, temp_user_client):
    """A non-member selecting another account's password-protected vault is refused 403 whether the
    password is right or wrong -- so the response reveals nothing about the password."""
    # admin owns a password-protected victim vault; the attacker is a plain (non-member) user.
    va = admin.create_vault(name=unique("mintoracle"), password=VICTIM_VAULT_PW)
    uid = temp_user["id"]
    # Make sure the attacker CAN reach the mint endpoint, so the 403 below is the membership gate,
    # not a missing endpoint permission.
    admin.post(f"/permissions/users/{uid}/grant", json={"endpoint_group": "TEMP_CREDS_MANAGE"})
    try:
        # Positive control: the attacker can mint an ordinary (unrestricted) credential -> has perm.
        ok = temp_user_client.post("/auth/temp-credentials", json={"validity_minutes": 30})
        assert ok.status_code == 200, ok.text
        temp_user_client.post(f"/temp-creds/{ok.json()['temp_username']}/delete")

        # The oracle probes: correct password and wrong password must be INDISTINGUISHABLE.
        # A forbidden vault is SKIPPED (like a nonexistent id), so the outcome does not depend on
        # the password at all -- closing both the password oracle and any existence differential.
        r_right = _mint_selecting(temp_user_client, va["id"], VICTIM_VAULT_PW)
        r_wrong = _mint_selecting(temp_user_client, va["id"], "definitely-not-the-password")
        assert r_right.status_code == r_wrong.status_code, (r_right.text, r_wrong.text)
        # The password-proof branch must never run for a non-member (that would BE the oracle).
        assert "password-protected" not in r_right.text.lower(), r_right.text
        assert "password-protected" not in r_wrong.text.lower(), r_wrong.text
        # And the non-member must not actually be granted the forbidden vault.
        for r in (r_right, r_wrong):
            if r.status_code == 200:
                assert va["id"] not in r.text, r.text
    finally:
        admin.delete(f"/permissions/users/{uid}/revoke/TEMP_CREDS_MANAGE")
        admin.delete_vault(va["id"], vault_password=VICTIM_VAULT_PW)


def test_owner_mint_still_proves_the_password(admin):
    """Positive control: the vault OWNER (a member) is unaffected -- a correct password mints 200,
    a wrong one still returns the password-proof 400 (the membership pre-check does not shadow it)."""
    va = admin.create_vault(name=unique("mintowner"), password=VICTIM_VAULT_PW)
    try:
        good = _mint_selecting(admin, va["id"], VICTIM_VAULT_PW)
        assert good.status_code == 200, good.text
        admin.post(f"/temp-creds/{good.json()['temp_username']}/delete")

        bad = _mint_selecting(admin, va["id"], "wrong-password-xyz")
        assert bad.status_code == 400, bad.text
        assert "password" in bad.text.lower(), bad.text
    finally:
        admin.delete_vault(va["id"], vault_password=VICTIM_VAULT_PW)
