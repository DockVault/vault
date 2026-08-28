"""API: the file preview-render endpoint (Standard vaults; sanitized, CSP-locked HTML).

Renders a text file to a sandbox-ready HTML document. Gated like /download (rendering reveals
content): a Standard vault only, the download capability + download scope, a size cap, and a refusal
for zero-knowledge vaults (the server holds only ciphertext). Deliberately member-only: a share
recipient is refused (a render does not meter a share's download cap, so it must not be a way around
it -- the recipient uses /download, which burns the cap).
"""
import uuid

from conftest import ApiClient, create_zk_vault, unique


def _upload(client, vault_id, name, content):
    r = client.post(f"/vaults/{vault_id}/files",
                    files=[("files", (name, content, "text/plain"))])
    r.raise_for_status()
    return r.json()["files"][0]["id"]


def _render(client, vault_id, file_id, **params):
    return client.get(f"/vaults/{vault_id}/files/{file_id}/preview-render", params=params or None)


def test_markdown_renders_sanitized_and_csp_locked(admin, temp_vault):
    vid = temp_vault["id"]
    fid = _upload(admin, vid, unique("doc") + ".md",
                  b"# Title\n\n<script>alert(1)</script>\n\nHello **world** and [x](javascript:alert(2))\n")
    r = _render(admin, vid, fid)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["kind"] == "markdown"
    html = data["html"]
    assert "<h1>" in html and "<strong>world</strong>" in html
    assert "<script" not in html.lower()
    assert "javascript:" not in html.lower()
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    # defence-in-depth headers on the JSON response
    assert r.headers.get("X-Content-Type-Options") == "nosniff"


def test_source_file_is_highlighted(admin, temp_vault):
    vid = temp_vault["id"]
    fid = _upload(admin, vid, unique("s") + ".py", b"def add(a, b):\n    return a + b\n")
    r = _render(admin, vid, fid)
    assert r.status_code == 200
    data = r.json()
    assert data["kind"] == "code"
    assert 'class="highlight"' in data["html"] and ".highlight" in data["html"]


def test_html_file_is_rendered_but_stripped(admin, temp_vault):
    vid = temp_vault["id"]
    fid = _upload(admin, vid, unique("p") + ".html",
                  b"<h2>Doc</h2><iframe src='//evil'></iframe><b>bold</b>")
    r = _render(admin, vid, fid)
    assert r.status_code == 200 and r.json()["kind"] == "html"
    html = r.json()["html"]
    assert "<h2>Doc</h2>" in html and "<b>bold</b>" in html and "<iframe" not in html.lower()


def test_too_large_is_refused(admin, temp_vault):
    vid = temp_vault["id"]
    fid = _upload(admin, vid, unique("big") + ".md", b"x" * (2 * 1024 * 1024 + 1))
    r = _render(admin, vid, fid)
    assert r.status_code == 413


def test_missing_file_is_404(admin, temp_vault):
    r = _render(admin, temp_vault["id"], str(uuid.uuid4()))
    assert r.status_code == 404


def test_zero_knowledge_vault_render_is_refused(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    zk = None
    try:
        zk = create_zk_vault(admin, name=unique("zkrender"))
        # The ZK refusal is decided before any file lookup, so a random id still hits it.
        r = _render(admin, zk["id"], str(uuid.uuid4()))
        assert r.status_code == 400
        assert "zero-knowledge" in r.json()["detail"].lower()
    finally:
        if zk:
            admin.delete_vault(zk["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def test_share_recipient_cannot_render(admin):
    """A rendered preview is member-only: it does NOT meter a share's per-recipient download cap, so
    a share recipient is refused (403). This closes the bypass where a recipient who had exhausted
    their max_downloads could still read the file's content via preview-render, unmetered."""
    assert admin.put("/settings", json={"sharing_enabled": True}).status_code == 200
    v = admin.create_vault(name=unique("prendshare"))
    try:
        vid = v["id"]
        fid = _upload(admin, vid, unique("doc") + ".md", b"# shared secret\n")
        tag = admin.post("/share-tags", json={
            "name": unique("prtag"), "auto_enroll_new_users": True,
            "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10,
            "max_downloads_cap": 100}).json()
        share = admin.post("/shares", json={
            "vault_id": vid, "tag_id": tag["id"], "target_type": "vault",
            "claim_audience": "anyone_internal", "max_downloads": 1}).json()
        u = admin.create_user(role="user")
        c = ApiClient()
        c.login(u["_username"], u["_password"])
        assert c.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200
        # The recipient CAN download (metered against the cap) ...
        assert c.get(f"/vaults/{vid}/files/{fid}/download").status_code == 200
        # ... but preview-render refuses a share recipient outright, so it is not a way around the
        # download cap regardless of how many downloads remain.
        assert _render(c, vid, fid).status_code == 403
    finally:
        admin.delete_vault(v["id"])
        admin.put("/settings", json={"sharing_enabled": False})


def test_upload_only_credential_cannot_render(admin):
    """Rendering reveals the content, so it needs the download capability + scope. A scoped
    credential with see_files + upload but NO file.download is refused (like /download)."""
    v = admin.create_vault(name=unique("prend"))
    try:
        vid = v["id"]
        fid = _upload(admin, vid, unique("secret") + ".md", b"# secret\n")
        caps = ["vault.see_info", "vault.see_files", "file.upload"]  # deliberately no file.download
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps,
                 "temp": {"view": False, "create": False, "invalidate": False,
                          "clear": False, "delegate": False}}
        body = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": caps}]}).json()
        c = admin.clone_anonymous()
        c.login(body["temp_username"], body["credential"])
        r = _render(c, vid, fid)
        assert r.status_code == 403, r.text
    finally:
        admin.delete_vault(v["id"])
