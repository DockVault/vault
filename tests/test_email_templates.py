"""Email Studio — HTML email templates (CRUD, sanitize-on-save, malicious-content blocking, preview).

Admin-only. The stored body is ALWAYS the sanitized result. Clearly-malicious input (a script tag,
event handler, etc.) is rejected AND raises a security event tied to the acting user. The preview
endpoint sanitizes + personalizes without raising an event (it runs live as the admin types).
"""

import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

_UUID = "11111111-1111-1111-1111-111111111111"


def _delete_all_templates(admin):
    for t in admin.get("/email/templates").json().get("templates", []):
        admin.delete(f"/email/templates/{t['id']}")


@pytest.fixture
def clean_templates(admin):
    _delete_all_templates(admin)
    yield
    _delete_all_templates(admin)


def _tpl(**over):
    body = {"name": unique("tpl"), "subject": "Hello {{user.username}}",
            "body_html": "<p>Hi <strong>{{user.username}}</strong></p>"}
    body.update(over)
    return body


# -- CRUD + sanitize ---------------------------------------------------------------------------

def test_template_crud_and_sanitize_on_save(admin, clean_templates):
    r = admin.post("/email/templates", json=_tpl(
        body_html='<p>ok</p><b>keep</b><span style="x">s</span>'))
    assert r.status_code == 201, r.text
    t = r.json()
    assert "style=" not in t["body_html"]           # disallowed attr stripped on save
    assert "<b>keep</b>" in t["body_html"] and "<p>ok</p>" in t["body_html"]

    got = admin.get(f"/email/templates/{t['id']}").json()
    assert got["body_html"] == t["body_html"]        # stored body is the sanitized one
    assert any(x["id"] == t["id"] for x in admin.get("/email/templates").json()["templates"])

    r2 = admin.put(f"/email/templates/{t['id']}", json=_tpl(name="Renamed", body_html="<p>v2</p>"))
    assert r2.status_code == 200 and r2.json()["name"] == "Renamed"
    assert "<p>v2</p>" in r2.json()["body_html"]

    assert admin.delete(f"/email/templates/{t['id']}").status_code == 204
    assert admin.get(f"/email/templates/{t['id']}").status_code == 404


def test_template_links_profile_preview(admin, clean_templates):
    prof = admin.post("/email/profiles", json={
        "name": unique("p"), "smtp_server": "smtp.example.com", "smtp_port": 587,
        "from_email": "sender@example.com", "from_name": "Sender"}).json()
    try:
        t = admin.post("/email/templates", json=_tpl(profile_id=prof["id"])).json()
        listed = next(x for x in admin.get("/email/templates").json()["templates"] if x["id"] == t["id"])
        assert listed["profile"]["smtp_server"] == "smtp.example.com"
        assert listed["profile"]["from_email"] == "sender@example.com"
    finally:
        admin.delete(f"/email/profiles/{prof['id']}")


def test_template_profile_id_must_exist(admin, clean_templates):
    assert admin.post("/email/templates", json=_tpl(profile_id=_UUID)).status_code == 400


def test_template_subject_rejects_control_chars(admin, clean_templates):
    assert admin.post("/email/templates", json=_tpl(
        subject="Hi\r\nBcc: evil@example.com")).status_code == 400


@pytest.mark.parametrize("name", [""])
def test_template_name_required(admin, clean_templates, name):
    assert admin.post("/email/templates", json=_tpl(name=name)).status_code == 422


# -- malicious content blocking + security event -----------------------------------------------

@pytest.mark.parametrize("evil", [
    "<p>hi</p><script>alert(1)</script>",
    '<div onclick="steal()">x</div>',
    '<a href="javascript:alert(1)">x</a>',
    "<iframe src=//evil></iframe>",
    '<img src=x onerror="alert(1)">',
])
def test_malicious_body_is_blocked_on_save(admin, clean_templates, evil):
    n_before = len(admin.get("/email/templates").json()["templates"])
    assert admin.post("/email/templates", json=_tpl(body_html=evil)).status_code == 400
    assert len(admin.get("/email/templates").json()["templates"]) == n_before   # nothing stored


def test_malicious_save_raises_attributable_security_event(admin, admin_creds, clean_templates):
    # Act as a FRESH admin (a never-before-seen username) so the alert can ONLY exist if THIS save
    # raised it — the (event_type, username, ip) dedup can't fold it into an earlier test's row.
    fresh = admin.create_user(role="admin")
    c = admin.clone_anonymous()
    c.login(fresh["_username"], fresh["_password"])
    try:
        assert c.post("/email/templates",
                      json=_tpl(body_html="<p>x</p><script>evil()</script>")).status_code == 400
        alerts = admin.get("/api/security/alerts?limit=100").json()["alerts"]
        mine = [a for a in alerts if a["event_type"] == "malicious_email_content"
                and a["username"] == fresh["_username"]]
        assert mine, "no attributable malicious_email_content alert was raised for this admin"
        a = mine[0]
        assert a["severity"] == "warning"
        assert (a.get("details") or {}).get("surface") == "email_template"
        assert "script_tag" in (a.get("details") or {}).get("reasons", [])
    finally:
        admin.delete_user(fresh["id"])


def test_benign_style_block_is_allowed_no_alert(admin, clean_templates):
    # A <style> block (unsupported inline CSS in v1) is stripped by the sanitizer, NOT treated as an
    # attack: the save succeeds and no security event is filed against the admin. Uses a fresh admin
    # so we can assert zero attributed alerts.
    fresh = admin.create_user(role="admin")
    c = admin.clone_anonymous()
    c.login(fresh["_username"], fresh["_password"])
    try:
        r = c.post("/email/templates", json=_tpl(body_html="<style>.x{color:red}</style><p>hi</p>"))
        assert r.status_code == 201, r.text
        assert "<style" not in r.json()["body_html"].lower()   # silently stripped
        alerts = admin.get("/api/security/alerts?limit=100").json()["alerts"]
        assert not [a for a in alerts if a["event_type"] == "malicious_email_content"
                    and a["username"] == fresh["_username"]]
    finally:
        admin.delete_user(fresh["id"])   # clean_templates removes the created template


def test_malicious_block_also_applies_on_update(admin, clean_templates):
    t = admin.post("/email/templates", json=_tpl()).json()
    r = admin.put(f"/email/templates/{t['id']}", json=_tpl(body_html="<script>x</script>"))
    assert r.status_code == 400
    # the stored body is unchanged (still the original safe one)
    assert "<script" not in admin.get(f"/email/templates/{t['id']}").json()["body_html"].lower()


def test_benign_html_mentioning_script_word_is_allowed(admin, clean_templates):
    # detect_malicious matches real tags, not escaped text — a template teaching about scripts saves.
    r = admin.post("/email/templates", json=_tpl(
        body_html="<p>To include a &lt;script&gt; tag, contact support.</p>"))
    assert r.status_code == 201, r.text


# -- preview -----------------------------------------------------------------------------------

def test_preview_sanitizes_personalizes_and_drops_unknown_images(admin, clean_templates):
    r = admin.post("/email/templates/preview", json={
        "subject": "Hi {{user.username}}",
        "body_html": (f'<p>Hello <strong>{{{{user.username}}}}</strong></p>'
                      f'<script>alert(1)</script><img data-resource-id="{_UUID}">'),
        "sample_username": "sampleuser"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "sampleuser" in body["html"]              # token substituted
    assert "<script" not in body["html"].lower()      # sanitized
    assert _UUID not in body["html"]                  # dangling image (no such resource) dropped
    assert body["subject"] == "Hi sampleuser"         # subject personalized (plain)


def test_preview_does_not_raise_security_event(admin, clean_templates):
    # Fresh admin so "no alert" is provable despite dedup (a new username has no row to fold into).
    fresh = admin.create_user(role="admin")
    c = admin.clone_anonymous()
    c.login(fresh["_username"], fresh["_password"])
    try:
        r = c.post("/email/templates/preview", json={"body_html": "<script>alert(1)</script>"})
        assert r.status_code == 200                    # preview never rejects — shows the cleaned result
        assert "<script" not in r.json()["html"].lower()
        alerts = admin.get("/api/security/alerts?limit=100").json()["alerts"]
        assert not [a for a in alerts if a["event_type"] == "malicious_email_content"
                    and a["username"] == fresh["_username"]]   # ...and files no event, ever
    finally:
        admin.delete_user(fresh["id"])


def test_subject_is_not_html_scanned_but_stored_literally(admin, clean_templates):
    # Detection is body-only: a subject is a plain-text header (inert), so HTML in it is stored
    # literally and raises no alert — but control chars are still rejected (see the CRLF test).
    fresh = admin.create_user(role="admin")
    c = admin.clone_anonymous()
    c.login(fresh["_username"], fresh["_password"])
    try:
        r = c.post("/email/templates", json=_tpl(subject="<b>Sale</b> <script>x</script>"))
        assert r.status_code == 201, r.text
        assert admin.get(f"/email/templates/{r.json()['id']}").json()["subject"] == "<b>Sale</b> <script>x</script>"
        alerts = admin.get("/api/security/alerts?limit=100").json()["alerts"]
        assert not [a for a in alerts if a["event_type"] == "malicious_email_content"
                    and a["username"] == fresh["_username"]]
    finally:
        admin.delete_user(fresh["id"])


@pytest.mark.parametrize("bad", [
    {"body_html": "<p>" + "a" * 1_000_001 + "</p>"},
    {"subject": "x" * 256},
])
def test_oversize_fields_are_422(admin, clean_templates, bad):
    assert admin.post("/email/templates", json=_tpl(**bad)).status_code == 422


def test_list_omits_body_get_includes_it(admin, clean_templates):
    t = admin.post("/email/templates", json=_tpl(
        body_html=f'<p>x</p><img data-resource-id="{_UUID}">')).json()
    listed = next(x for x in admin.get("/email/templates").json()["templates"] if x["id"] == t["id"])
    assert "body_html" not in listed                    # list is lightweight
    got = admin.get(f"/email/templates/{t['id']}").json()
    assert "body_html" in got
    assert got["referenced_resource_ids"] == [_UUID]    # a valid-format ref is kept in the stored body
    assert "unknown_tokens" in got


def test_update_relinks_and_unlinks_profile(admin, clean_templates):
    a = admin.post("/email/profiles", json={"name": unique("a"), "smtp_server": "a.example",
                                            "smtp_port": 587, "from_email": "a@example.com"}).json()
    b = admin.post("/email/profiles", json={"name": unique("b"), "smtp_server": "b.example",
                                            "smtp_port": 587, "from_email": "b@example.com"}).json()
    try:
        t = admin.post("/email/templates", json=_tpl(profile_id=a["id"])).json()
        r = admin.put(f"/email/templates/{t['id']}", json=_tpl(profile_id=b["id"]))
        assert r.json()["profile_id"] == b["id"] and r.json()["profile"]["smtp_server"] == "b.example"
        r2 = admin.put(f"/email/templates/{t['id']}", json=_tpl())   # no profile_id -> unlink
        assert r2.json()["profile_id"] is None and r2.json()["profile"] is None
    finally:
        admin.delete(f"/email/profiles/{a['id']}")
        admin.delete(f"/email/profiles/{b['id']}")


def test_deleting_linked_profile_nulls_template_link(admin, clean_templates):
    prof = admin.post("/email/profiles", json={"name": unique("p"), "smtp_server": "p.example",
                                               "smtp_port": 587, "from_email": "p@example.com"}).json()
    t = admin.post("/email/templates", json=_tpl(profile_id=prof["id"])).json()
    assert admin.delete(f"/email/profiles/{prof['id']}").status_code == 204
    got = admin.get(f"/email/templates/{t['id']}").json()   # template survives, link nulled (FK SET NULL)
    assert got["profile_id"] is None and got["profile"] is None
    assert any(x["id"] == t["id"] for x in admin.get("/email/templates").json()["templates"])


def test_preview_reports_unknown_tokens_and_referenced_ids(admin, clean_templates):
    r = admin.post("/email/templates/preview", json={
        "body_html": f'<p>{{{{totally_unknown}}}}</p><img data-resource-id="{_UUID}">'})
    body = r.json()
    assert body["unknown_tokens"] == ["totally_unknown"]
    assert body["referenced_resource_ids"] == [_UUID]
    assert _UUID not in body["html"]                    # dangling image dropped from the render


def test_unauthenticated_is_rejected(admin, clean_templates):
    anon = admin.clone_anonymous()
    assert anon.get("/email/templates").status_code in (401, 403)
    assert anon.post("/email/templates/preview", json={"body_html": "<p>x</p>"}).status_code in (401, 403)


def test_temp_credential_gets_interactive_admin_message(admin, clean_templates):
    tc = admin.post("/auth/temp-credentials", json={"note": unique("t")}).json()
    ct = ApiClient(BASE_URL)
    ct.login(tc["temp_username"], tc["credential"])
    r = ct.get("/email/templates")
    assert r.status_code == 403
    assert "temporary credential" in r.text.lower()     # the interactive-gate message, not plain role denial


# -- authz -------------------------------------------------------------------------------------

def test_templates_reject_non_admin_and_temp_credential(admin, clean_templates):
    t = admin.post("/email/templates", json=_tpl()).json()
    # non-admin
    u = admin.create_user(role="user")
    cu = admin.clone_anonymous()
    cu.login(u["_username"], u["_password"])
    # admin acting through a temporary credential
    tc = admin.post("/auth/temp-credentials", json={"note": unique("t")}).json()
    ct = ApiClient(BASE_URL)
    ct.login(tc["temp_username"], tc["credential"])
    try:
        for c in (cu, ct):
            assert c.get("/email/templates").status_code == 403
            assert c.post("/email/templates", json=_tpl()).status_code == 403
            assert c.get(f"/email/templates/{t['id']}").status_code == 403
            assert c.put(f"/email/templates/{t['id']}", json=_tpl()).status_code == 403
            assert c.delete(f"/email/templates/{t['id']}").status_code == 403
            assert c.post("/email/templates/preview", json={"body_html": "<p>x</p>"}).status_code == 403
    finally:
        admin.delete_user(u["id"])
