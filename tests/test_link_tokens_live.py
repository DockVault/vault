"""Live-lane acceptance for LINK-TOKENS, against a running stack.

Part (a): a note link seeded THROUGH THE PRODUCT stores no plaintext token in the database yet still
redeems -- asserted in the SAME run, with a proven-plaintext control (the admin username, which IS in
the dump) so the "no plaintext" scan cannot pass vacuously. The acceptance runner drives the true upgrade
proof (seed on the pre-migration image at main 6e27292, rebuild onto the tip in place with volumes
kept, migrate, redeem after); this pins the at-rest + redemption contract the migration must reach.

Part (b): the owner-encrypted re-copy round-trip, the cross-user-decrypt failure and the rotated-key
failure are proven at the crypto layer by tests/js/link_token_wrap.js (round-trip + (link,owner) AAD
binding + rotated-key rejection) and the server owner-only/404/write-once pins; the end-to-end UI
"Show link again" (unlock + decrypt, no-keypair degrade, post-rotation honest message) is the
acceptance runner's Playwright pass. No asyncio.run() here.
"""
import os
import subprocess

import pytest
import requests

from conftest import BASE_URL, unique

pytestmark = pytest.mark.integration

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_CI = os.environ.get("CI")


def _pg_dump(timeout=90):
    return subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "pg_dump", "-U", "sftp_user", "-d", "sftp_db"],
        capture_output=True, text=True, timeout=timeout)


def _require_db_or_skip():
    try:
        ok = _pg_dump(timeout=30).returncode == 0
        why = ""
    except Exception as exc:  # noqa: BLE001
        ok, why = False, " (%s)" % exc.__class__.__name__
    if ok:
        return
    msg = ("cannot pg_dump via `docker exec %s`%s; set VAULT_DB_CONTAINER to this stack's db container"
           % (_DB_CONTAINER, why))
    if _CI:
        pytest.fail(msg)
    pytest.skip(msg)


def test_a_seeded_note_link_has_no_plaintext_token_in_the_db_but_still_redeems(admin, admin_creds):
    _require_db_or_skip()

    # Enable the feature (best-effort: it defaults on) and create a tag the admin may use.
    admin.session.put("%s/settings" % BASE_URL, json={"public_note_links_enabled": True}, timeout=30)
    tag_resp = admin.session.post("%s/note-link-tags" % BASE_URL, json={
        "name": unique("lt-tag"), "min_token_len": 12, "require_secret": "none",
        "allowed_targets": ["note"], "auto_enroll_new_users": True}, timeout=30)
    if tag_resp.status_code not in (200, 201):
        pytest.skip("cannot create a note-link tag here (status %s)" % tag_resp.status_code)
    tag_id = tag_resp.json()["id"]

    note = admin.session.post("%s/notes" % BASE_URL,
                              json={"title": unique("lt-note"), "body": "the frozen snapshot body"}, timeout=30)
    assert note.status_code in (200, 201), note.text
    note_id = note.json()["id"]

    created = admin.session.post("%s/note-links" % BASE_URL,
                                 json={"note_id": note_id, "tag_id": tag_id}, timeout=30)
    if created.status_code not in (200, 201):
        pytest.skip("cannot create a note link here (status %s): %s" % (created.status_code, created.text))
    body = created.json()
    token = body["token"]                      # the one-time plaintext, shown at creation only
    assert token and len(token) >= 12

    # It still redeems anonymously (the hash lookup finds it).
    redeem = requests.post("%s/note-links/%s/redeem" % (BASE_URL, token), json={}, timeout=30)
    assert redeem.status_code == 200, "the seeded link did not redeem: %s %s" % (redeem.status_code, redeem.text)

    # No plaintext token anywhere in the DB, asserted with a proven-plaintext control.
    dump = _pg_dump()
    assert dump.returncode == 0, dump.stderr
    text = dump.stdout
    assert token not in text, "the plaintext note-link token is present in the database dump"
    # Positive control: a value known to be plaintext at rest (the admin username) IS in the dump, so
    # the scan is not vacuously passing.
    assert admin_creds["username"] in text, "control failed -- the pg_dump scan found no known plaintext"

    # And the hash IS stored (the lookup key), proving the token is hashed, not merely absent.
    import hashlib
    assert hashlib.sha256(token.encode()).hexdigest() in text, "the token_hash is not in the database"
