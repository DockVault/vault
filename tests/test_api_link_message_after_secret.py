"""On a file link or note link with a PIN, the owner's message comes only with the right PIN, on a running stack.

The prompt for the PIN, a peek and a wrong PIN all answer without the message; the right PIN answers with it.
"""
import pytest

from conftest import unique

pytestmark = pytest.mark.integration

MESSAGE = "Only for the one who has the code."


@pytest.fixture
def links(admin):
    before = admin.get("/settings").json()
    admin.put("/settings", json={"public_file_links_enabled": True, "public_note_links_enabled": True})
    v = admin.create_vault(name=unique("pinmsg"))
    try:
        fid = admin.post(f"/vaults/{v['id']}/files", files=[("files", ("a.txt", b"x", "text/plain"))]).json()["files"][0]["id"]
        tag = admin.post("/note-link-tags", json={"name": unique("pt"), "auto_enroll_new_users": True,
                                                  "allowed_targets": ["file", "folder", "note"]})
        assert tag.status_code == 200, tag.text
        public = admin.post("/public-links", json={
            "vault_id": v["id"], "target_type": "file", "target_file_id": fid, "tag_id": tag.json()["id"],
            "secret_kind": "pin", "pin": "4821", "message": MESSAGE})
        assert public.status_code == 200, public.text
        note = admin.post("/notes", json={"title": unique("n"), "body": "hello"}).json()
        noted = admin.post("/note-links", json={"note_id": note["id"], "tag_id": tag.json()["id"],
                                                "secret_kind": "pin", "pin": "4821", "message": MESSAGE})
        assert noted.status_code in (200, 201), noted.text
        yield {"public": public.json()["token"], "note": noted.json()["token"]}
    finally:
        admin.delete_vault(v["id"])
        admin.put("/settings", json={"public_file_links_enabled": before.get("public_file_links_enabled"),
                                     "public_note_links_enabled": before.get("public_note_links_enabled")})


@pytest.mark.parametrize("kind,path", [("public", "/public-links/{}/redeem"), ("note", "/note-links/{}/redeem")])
def test_the_message_comes_only_with_the_right_pin(admin, links, kind, path):
    anon = admin.clone_anonymous()
    url = path.format(links[kind])
    for body, error in (({"peek": True}, "secret_required"), ({}, "secret_required"),
                        ({"secret": "0000"}, "wrong_secret"),
                        # A file link's peek checks a PIN sent with it; a note link's peek never checks one.
                        ({"peek": True, "secret": "1111"}, "wrong_secret" if kind == "public" else "secret_required")):
        r = anon.post(url, json=body)
        assert r.status_code == 401 and r.json()["detail"]["error"] == error, (body, r.text)
        assert MESSAGE not in r.text and "message" not in r.text, (body, r.text)
    right = anon.post(url, json={"peek": True, "secret": "4821"} if kind == "public" else {"secret": "4821"})
    assert right.status_code == 200, right.text
    assert right.json()["message"] == MESSAGE
