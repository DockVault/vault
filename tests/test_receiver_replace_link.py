"""Getting an upload link back, without making the link recoverable.

The ask was a "Copy link" button so a drop vault's link can be retrieved after creation. It cannot be
built as written, and the reason is deliberate: the token IS the credential and is stored only as its
sha256, with no prefix kept. The server cannot show the old URL again because it does not have it —
which is exactly what stops a database read (a backup, a dump, a replica, an admin with SELECT) from
minting working upload links.

So the link is REPLACED instead. A new token is minted, shown once, and the previous one stops
working immediately. Everything else — the tag, the caps, the expiry, the drop vault and everything
already uploaded into it — is untouched.

Alongside that, the card can still Copy a link that was created in THIS page session, because the
plaintext is briefly in memory. That is held in a plain object and never persisted: writing a bearer
credential to disk is the thing hashing the token was protecting against.

WHAT MAKES THIS TESTABLE HONESTLY: `GET /u/{token}` serves the upload PAGE unconditionally and
returns 200 for any token at all, so it says nothing about whether a link works. The first run of this
check used it and reported that replacement had done nothing. The question has to be asked of
`POST /receivers/{token}/upload-session`, which is where a token is actually resolved.

Lanes:
  * integration — mint, replace, and prove the old token stops opening a session while the new one
                  opens. The only lane that can prove any of it.
  * unit        — the endpoint mints rather than reveals, refuses someone else's link, and never puts
                  a token in the audit log.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "app" / "api" / "api_server.py"
APP_JS = ROOT / "static" / "js" / "app.js"


def _endpoint_body(src, verb, path):
    marker = f'@app.{verb}("{path}")'
    start = src.index(marker)
    nxt = re.search(r"^@app\.[a-z]+\(", src[start + len(marker):], re.M)
    return src[start:start + len(marker) + (nxt.start() if nxt else len(src))]


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
def test_the_endpoint_mints_a_new_token_and_never_reveals_the_old_one():
    src = API.read_text(encoding="utf-8")
    body = _endpoint_body(src, "post", "/receivers/{receiver_id}/replace-link")

    assert "_receiver_token_hash(cand)" in body, "a replacement must be hashed like any other token"
    assert "r.token_hash = token_hash" in body, "the stored hash must be replaced"
    # The old plaintext does not exist to be returned, and nothing here should pretend otherwise.
    assert "r.token_hash," not in body.replace("r.token_hash = token_hash", ""), (
        "the endpoint must not read the stored hash back out for any purpose")


@pytest.mark.unit
def test_only_the_owner_can_replace_a_link_and_not_from_a_temp_session():
    src = API.read_text(encoding="utf-8")
    body = _endpoint_body(src, "post", "/receivers/{receiver_id}/replace-link")
    assert "Receiver.owner_id == current_user.id" in body, (
        "minting a new credential for someone else's link must be impossible")
    assert "_is_temp_session" in body, (
        "a temporary session must not be able to mint a new bearer credential")
    assert "r.revoked" in body, "a revoked link must not be brought back by replacing its token"


@pytest.mark.unit
def test_replacing_a_link_is_gated_exactly_as_creating_one_is():
    """A replacement is a new bearer credential, so it carries both of creation's gates.

    Without them, a session that could not pass the step-up to create a link could mint one here
    instead — and a deployment that had switched upload links off kept issuing live URLs for the
    links it already had. The integration lane below proves the behaviour; this pins the shape so
    a refactor that drops one gate is caught offline too.
    """
    src = API.read_text(encoding="utf-8")
    create = _endpoint_body(src, "post", "/receivers")
    replace = _endpoint_body(src, "post", "/receivers/{receiver_id}/replace-link")
    # Anchor on creation first: if the gate moved there, the assertion below would be about nothing.
    assert '@require_step_up("receiver.create")' in create
    assert "receiver_policy.public_receivers_enabled(" in create

    assert '@require_step_up("receiver.create")' in replace, (
        "replace-link must demand the same step-up as create: it mints the same kind of credential")
    assert "receiver_policy.public_receivers_enabled(_global_settings_blob(db))" in replace, (
        "replace-link must honour the upload-links kill switch")


@pytest.mark.unit
def test_the_new_token_is_never_written_to_the_audit_log():
    """The row records THAT the link was replaced, not what it was replaced with."""
    src = API.read_text(encoding="utf-8")
    body = _endpoint_body(src, "post", "/receivers/{receiver_id}/replace-link")
    audit_call = body[body.index("_audit_access_change("):]
    audit_call = audit_call[:audit_call.index("\n\n")] if "\n\n" in audit_call else audit_call
    assert "token" not in audit_call, (
        "the audit row must not carry the token — a log that records bearer credentials is a second "
        "copy of every link")


@pytest.mark.unit
def test_a_session_held_url_is_kept_in_memory_only():
    app = APP_JS.read_text(encoding="utf-8")
    assert "const rcSessionUrls = Object.create(null);" in app, (
        "session URLs need somewhere to live for the Copy button")
    # The one thing that would undo the hashing: persisting it.
    for sink in ("localStorage.setItem('rcSessionUrls'", "sessionStorage.setItem('rcSessionUrls'",
                 "localStorage.setItem(\"rcSessionUrls\""):
        assert sink not in app, f"a plaintext upload-link URL must never be persisted ({sink})"


# --------------------------------------------------------------------------- integration lane

@pytest.mark.integration
def test_replacing_a_link_kills_the_old_token_and_mints_a_working_one(admin):
    settings = admin.get("/settings").json()
    if settings.get("public_receivers_enabled") is not True:
        pytest.skip("upload links are disabled on this deployment")
    tags = admin.get("/receiver-tags").json()
    open_tag = next((t for t in tags if t["name"] in ("Drop vault", "Drop box")), None)
    if not open_tag:
        pytest.skip("no open upload-link tag is available to this account")

    made = admin.post("/receivers", json={"tag_id": open_tag["id"], "label": "replace-check",
                                          "max_total_bytes": 10 * 1024 * 1024})
    assert made.status_code in (200, 201), made.text
    rec = made.json()
    old_token = rec["token"]

    def opens(token):
        """Ask the route that actually RESOLVES a token.

        GET /u/{token} serves the page for any token whatsoever and returns 200 regardless, so it
        cannot answer this. Using it is how the first version of this check concluded, wrongly, that
        replacement had done nothing at all.
        """
        r = admin.post(f"/receivers/{token}/upload-session",
                       json={"filename": "a.txt", "total_size": 5, "total_chunks": 1})
        return r.status_code

    # Anchor: the link works before we touch it, or everything below passes for the wrong reason.
    assert opens(old_token) in (200, 201), "the freshly created link should accept an upload session"

    replaced = admin.post(f"/receivers/{rec['id']}/replace-link")
    assert replaced.status_code in (200, 201), replaced.text
    new_token = replaced.json()["token"]
    assert new_token != old_token, "replacing a link must actually change the token"

    assert opens(old_token) == 404, "the old token must stop working the moment it is replaced"
    assert opens(new_token) in (200, 201), "the new token must work"

    rows = admin.get("/audit/log?action=receiver_link_replaced").json()
    assert rows, "replacing a link is an access change and must be audited"
    assert new_token not in str(rows[0]) and old_token not in str(rows[0]), (
        "no token may appear in the audit log")


def _open_tag_or_skip(admin):
    settings = admin.get("/settings").json()
    if settings.get("public_receivers_enabled") is not True:
        pytest.skip("upload links are disabled on this deployment")
    tags = admin.get("/receiver-tags").json()
    open_tag = next((t for t in tags if t["name"] in ("Drop vault", "Drop box")), None)
    if not open_tag:
        pytest.skip("no open upload-link tag is available to this account")
    return open_tag


def _mint(admin, open_tag, label):
    made = admin.post("/receivers", json={"tag_id": open_tag["id"], "label": label,
                                          "max_total_bytes": 10 * 1024 * 1024})
    assert made.status_code in (200, 201), made.text
    return made.json()


@pytest.mark.integration
def test_replace_link_refuses_once_upload_links_are_switched_off(admin):
    """The kill switch must stop new URLs being minted for existing links, not only new links."""
    open_tag = _open_tag_or_skip(admin)
    rec = _mint(admin, open_tag, "kill-switch-check")

    admin.put("/settings", json={"public_receivers_enabled": False})
    try:
        create = admin.post("/receivers", json={"tag_id": open_tag["id"], "label": "x",
                                                "max_total_bytes": 1024 * 1024})
        assert create.status_code == 403, f"anchor: create should be refused while off: {create.text}"
        replace = admin.post(f"/receivers/{rec['id']}/replace-link")
        assert replace.status_code == 403, (
            f"upload links are switched off, yet a new URL was minted: {replace.status_code} "
            f"{replace.text}")
        assert replace.json()["detail"] == create.json()["detail"], (
            "the two refusals should say the same thing")
    finally:
        admin.put("/settings", json={"public_receivers_enabled": True})


@pytest.mark.integration
def test_replace_link_demands_the_same_step_up_as_create(admin):
    """With a step-up required for creating a link, replacing one is refused the same way.

    The link is minted BEFORE the requirement is switched on, so the setup itself is not gated.
    The session admin holds no second-factor enrolment, so both calls come back 403 with the same
    second_factor_required body — that equality is the assertion, so the test does not depend on
    which of the step-up's reasons applies to this account.
    """
    from _sf_helpers import set_action_require_otp

    open_tag = _open_tag_or_skip(admin)
    rec = _mint(admin, open_tag, "step-up-check")

    set_action_require_otp(admin, "receiver.create", True)
    try:
        create = admin.post("/receivers", json={"tag_id": open_tag["id"], "label": "x",
                                                "max_total_bytes": 1024 * 1024})
        assert create.status_code == 403, f"anchor: create should be gated now: {create.text}"
        assert create.json()["detail"].get("second_factor_required") is True, create.text

        replace = admin.post(f"/receivers/{rec['id']}/replace-link")
        assert replace.status_code == 403, (
            f"create needs a step-up but replace minted a live URL without one: "
            f"{replace.status_code} {replace.text}")
        assert replace.json()["detail"] == create.json()["detail"], (
            f"replace must be refused exactly as create is: {replace.json()} vs {create.json()}")
    finally:
        set_action_require_otp(admin, "receiver.create", False)
