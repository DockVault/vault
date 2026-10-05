"""A web app older than key proofs, against a server that requires them: it fails safely.

DockVault Desktop serves the web app of an older release (v0.27.0) against whatever server it is pointed
at, so for a while it talks to servers that want a key proof with every change to a zero-knowledge vault's
keys, which it cannot make. Each such change has to be refused before any of it is applied, with a sentence
the older app shows as it is, and without signing anyone out:

* creating a zero-knowledge vault is refused, and no vault is created;
* sharing a vault is refused at its key grant, which the older app sends first, so no access row is written;
* removing a member, which the older app always does by rotating the key first, stops at the rotation: the
  member keeps their access and the key does not change;
* after each refusal the person is still signed in, and reading still works.

The older app is the v0.27.0 static tree, taken from the repository's tag (or from the published image when
the tag has not been fetched) and served in place of the server's own through the browser's request routing.
Every API request still goes to the server under test.
"""

from __future__ import annotations

import io
import os
import subprocess
import tarfile
import urllib.parse

import pytest
from playwright.sync_api import expect

from conftest import BASE_URL, unique
from test_ui_e2e import _create_zk_vault_via_ui, _login
from test_ui_zk_key_proof import PASSPHRASE, SHARE, _keyed, _psql, zk  # noqa: F401 (zk is a fixture)
from test_ui_zk_rekey_notice import _open_vault

pytestmark = pytest.mark.ui

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OLD_TAG = "v0.27.0"
OLD_IMAGE = f"ghcr.io/dockvault/vault:{OLD_TAG}"
REFUSED = "update DockVault Desktop"      # from the server's sentence for a change made without a proof

_TYPES = {".js": "application/javascript", ".css": "text/css", ".html": "text/html; charset=utf-8",
          ".png": "image/png", ".svg": "image/svg+xml", ".woff2": "font/woff2", ".json": "application/json",
          ".ico": "image/x-icon", ".webmanifest": "application/manifest+json"}


def _static_files(tar_bytes: bytes) -> dict:
    """{"/static/...": bytes} from a tar whose members are under static/."""
    files = {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        for member in tar.getmembers():
            name = member.name.lstrip("./")
            if member.isfile() and name.startswith("static/"):
                files["/" + name] = tar.extractfile(member).read()
    return files


def _from_the_tag():
    out = subprocess.run(["git", "-C", REPO, "archive", "--format=tar", OLD_TAG, "static"],
                         capture_output=True, timeout=120)
    return _static_files(out.stdout) if out.returncode == 0 else None


def _from_the_image():
    def docker(*args, timeout=600):
        return subprocess.run(["docker", *args], capture_output=True, timeout=timeout)

    if docker("image", "inspect", OLD_IMAGE).returncode != 0 and docker("pull", OLD_IMAGE,
                                                                        timeout=1200).returncode != 0:
        return None
    made = docker("create", OLD_IMAGE)
    if made.returncode != 0:
        return None
    container = made.stdout.decode().strip()
    try:
        copied = docker("cp", f"{container}:/app/static", "-")
        return _static_files(copied.stdout) if copied.returncode == 0 else None
    finally:
        docker("rm", "-f", container)


@pytest.fixture(scope="module")
def old_app():
    files = _from_the_tag() or _from_the_image()
    if not files or "/static/index.html" not in files or "/static/js/app.js" not in files:
        pytest.skip(f"the {OLD_TAG} web app is not available here (no tag, and no image to copy it from)")
    return files


def _serve(context, files: dict) -> list:
    """Serve the older app's page and static files in this browser context; everything else goes to the
    server. Returns the list of static paths served, as they are served."""
    origin = urllib.parse.urlsplit(BASE_URL)
    served = []

    def handle(route):
        url = urllib.parse.urlsplit(route.request.url)
        if (url.scheme, url.netloc) != (origin.scheme, origin.netloc) or not (
                url.path == "/" or url.path.startswith("/static/")):
            route.continue_()
            return
        path = "/static/index.html" if url.path == "/" else url.path
        body = files.get(path)
        if body is None:
            route.fulfill(status=404, body="")
            return
        served.append(path)
        route.fulfill(status=200, body=body, headers={
            "Content-Type": _TYPES.get(os.path.splitext(path)[1], "application/octet-stream"),
            "Cache-Control": "no-store"})

    context.route("**/*", handle)
    return served


def _refusal(page, text):
    """The error the older app shows for a refused step, as a locator (one toast)."""
    toast = page.locator("#toast-container .toast-error", has_text=text)
    expect(toast).to_have_count(1, timeout=15000)
    return toast


def _still_signed_in(page, vid):
    expect(page.locator("#dashboard-screen")).to_be_visible()
    assert page.evaluate("() => !!authToken"), "a refusal signed the person out"
    assert page.evaluate("async (v) => (await apiRequest(`/ecc/vaults/${v}/keys`, { silent: true })).has_access",
                         vid) is True, "reading the vault's keys stopped working"


def test_the_older_web_app_cannot_change_a_zero_knowledge_vaults_keys_and_nothing_half_applies(
        browser, zk, old_app):  # noqa: F811 (zk is the fixture imported above)
    owner, co = zk()
    kept, ck = zk()        # a member the older app tries to remove
    added, ca = zk()       # someone the older app tries to share with
    _keyed(ck)
    _keyed(ca)
    today = browser.new_context(base_url=BASE_URL)
    older = browser.new_context(base_url=BASE_URL)
    served = _serve(older, old_app)
    vid = None
    try:
        # With today's app: the owner's encryption key, a vault, and a member who holds its key.
        page = today.new_page()
        _login(page, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page, co, PASSPHRASE)
        assert page.evaluate(SHARE, [vid, kept["id"]]) is True
        co.post(f"/vaults/{vid}/permissions", json={"user_id": kept["id"], "level": "read"}).raise_for_status()
        before = _psql(f"SELECT dek_version || '|' || (SELECT count(*) FROM vault_member_keys k WHERE "
                       f"k.vault_id = v.id AND k.is_active) || '|' || (SELECT count(*) FROM vault_key_proofs p "
                       f"WHERE p.vault_id = v.id) FROM vaults v WHERE v.id = '{vid}'")
        assert before == "1|2|1", before

        # The older app, in its own browser.
        old = older.new_page()
        asked = []
        old.on("request", lambda r: asked.append(r.url) if "/key-proof" in r.url else None)
        _login(old, owner["_username"], owner["_password"])
        assert "/static/js/app.js" in served and old.evaluate("() => typeof zkKeyProofRequest") == "undefined", (
            "the page is not the older app")
        # Open the encryption key once, so no later step stops at a passphrase prompt.
        old.evaluate("() => { window.__unlocked = zkEnsureUnlocked().then(() => true, e => String(e)); }")
        expect(old.locator("#confirm-modal-input")).to_be_visible(timeout=10000)
        old.fill("#confirm-modal-input", PASSPHRASE)
        old.click("#confirm-modal-confirm-btn")
        assert old.evaluate("() => window.__unlocked") is True

        # 1. Creating a zero-knowledge vault: refused, and nothing is created.
        name = unique("oldzk")
        old.click('.sidebar-item[data-section="vaults"]')
        old.click("#create-vault-btn")
        expect(old.locator("#create-vault-modal")).to_be_visible()
        old.fill("#vault-name", name)
        old.select_option("#vault-type", "zero_knowledge")
        expect(old.locator("#vault-label-group")).to_be_visible(timeout=5000)
        old.fill("#vault-label", name)
        old.click("#create-vault-form button[type=submit]")
        _refusal(old, REFUSED)
        assert _psql(f"SELECT count(*) FROM vaults WHERE name = '{name}'") == "0", "the refused create made a vault"
        old.locator("#create-vault-modal .close-modal-btn").first.click()
        _still_signed_in(old, vid)

        # 2. Sharing: the key grant goes first and is refused, so no access row follows it.
        _open_vault(old, vid)
        old.click('[data-vault-tab="permissions"]')
        old.click("#add-permission-btn")
        expect(old.locator("#vault-grant-modal")).to_be_visible(timeout=5000)
        old.fill("#vault-grant-search", added["_username"])
        old.wait_for_selector(f'#vault-grant-list input[value="{added["id"]}"]', timeout=8000)
        old.check(f'#vault-grant-list input[value="{added["id"]}"]')
        old.click("#vault-grant-confirm")
        _refusal(old, "1 grant(s) failed")
        assert added["id"] not in {p["user_id"] for p in co.get(f"/vaults/{vid}/permissions").json()}
        assert _psql(f"SELECT count(*) FROM vault_member_keys WHERE vault_id = '{vid}' "
                     f"AND user_id = '{added['id']}'") == "0"
        assert ca.get(f"/ecc/vaults/{vid}/keys").status_code == 403
        _still_signed_in(old, vid)

        # 3. Removing a member: the older app rotates the key first, the rotation is refused, and the
        #    removal stops there. The member keeps their access; the key is unchanged.
        old.click('[data-vault-tab="permissions"]')
        old.click(f'button[data-action="revoke-permission"][data-user-id="{kept["id"]}"]')
        expect(old.locator("#confirm-modal-message")).to_contain_text("The vault key will be rotated")
        old.click("#confirm-modal-confirm-btn")
        expect(_refusal(old, "Access was NOT revoked")).to_contain_text(REFUSED)
        assert kept["id"] in {p["user_id"] for p in co.get(f"/vaults/{vid}/permissions").json()}
        assert ck.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True
        _still_signed_in(old, vid)

        assert _psql(f"SELECT dek_version || '|' || (SELECT count(*) FROM vault_member_keys k WHERE "
                     f"k.vault_id = v.id AND k.is_active) || '|' || (SELECT count(*) FROM vault_key_proofs p "
                     f"WHERE p.vault_id = v.id) FROM vaults v WHERE v.id = '{vid}'") == before
        assert not asked, f"the older app asked for a key-proof challenge: {asked}"
    finally:
        older.close()
        today.close()
        if vid:
            co.delete_vault(vid)
