"""Live API: a public file or folder link capped at N downloads delivers exactly N.

Redeeming a link spends one use and returns a single-use download grant; the download that follows
spends nothing more. The download must therefore not refuse a link because that redeem spent its
last use: a one-download link has to deliver its one download, and a folder link capped at one has to
deliver one file. What the download does still refuse: a link that is gone or revoked, the switched-
off feature, an owner or vault that may no longer publish, a file outside the link, and a grant that
was used, belongs to another link or address, or was minted after the link expired.

The caps are checked from both sides: the bytes a recipient actually receives, and the counters the
owner sees on the link (use_count for redeems, download_count for completed transfers).
"""
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

from conftest import unique

pytestmark = pytest.mark.integration

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
_PASSWORD = "Recipient-Pass9"


def _psql(sql, timeout=30):
    result = subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=timeout)
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout.strip()


def _redis(*args):
    result = subprocess.run(["docker", "exec", _REDIS_CONTAINER, "redis-cli", *args],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout


def _grants_held_for(link_id):
    """The download grants Redis holds for this link. A grant is stored under the hash of its secret,
    and its value starts with the link id."""
    held = []
    for key in [k for k in _redis("--scan", "--pattern", "publiclink:grant:*").split("\n") if k]:
        if _redis("GET", key).startswith(f"{link_id}|"):
            held.append(key)
    return held


@pytest.fixture
def files_enabled(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_file_links_enabled", "public_note_link_user_cap")}
    r = admin.put("/settings", json={"public_file_links_enabled": True, "public_note_link_user_cap": 100})
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json=snap)


@pytest.fixture
def vault(admin):
    v = admin.create_vault(name=unique("capped"))
    yield v
    admin.delete_vault(v["id"])


def _tag(admin, *, password=False, cap=None):
    """A link tag: with password=True and cap=1 it is the shipped Confidential tag's policy."""
    payload = {"name": unique("captag"), "min_token_len": 20, "auto_enroll_new_users": True,
               "allowed_targets": ["note", "file", "folder"], "default_ttl_hours": 24,
               "max_ttl_hours": 24, "max_uses_cap": cap,
               "require_secret": "password" if password else "none"}
    if password:
        payload.update(password_min_len=8, password_require_alnum=True)
    r = admin.post("/note-link-tags", json=payload)
    assert r.status_code in (200, 201), r.text
    return r.json()


def _upload(admin, vault_id, name, content, folder_id=None):
    params = {"folder_id": folder_id} if folder_id else None
    r = admin.post(f"/vaults/{vault_id}/files", params=params,
                   files=[("files", (name, content, "application/octet-stream"))])
    assert r.status_code in (200, 201), r.text
    items = admin.get(f"/vaults/{vault_id}/files", params=params).json()["items"]
    return next(it["id"] for it in items if it.get("name") == name and it.get("type") == "file")


def _folder(admin, vault_id, name):
    r = admin.post(f"/vaults/{vault_id}/folders", json={"name": name})
    assert r.status_code in (200, 201), r.text
    return r.json()["folder"]["id"]


def _link(admin, vault_id, tag, *, file_id=None, folder_id=None, max_uses=None, password=None):
    body = {"vault_id": vault_id, "tag_id": tag["id"], "ttl_hours": 1, "max_uses": max_uses}
    if file_id:
        body.update(target_type="file", target_file_id=file_id)
    else:
        body.update(target_type="folder", target_folder_id=folder_id)
    if password:
        body.update(password=password, secret_kind="password")
    r = admin.post("/public-links", json=body)
    assert r.status_code == 200, r.text
    link = r.json()
    assert link["max_uses"] == max_uses
    return link


def _card(admin, link_id):
    return next(l for l in admin.get("/public-links").json()["links"] if l["id"] == link_id)


def _counts(admin, link_id, use_count, download_count):
    """Wait for the owner's counters to reach the expected values, then require exactly those. The
    download count is written once the server has sent the last byte, a moment after the recipient
    has the whole file, so it can trail the response briefly."""
    deadline = time.monotonic() + 10
    while True:
        card = _card(admin, link_id)
        if (card["use_count"], card["download_count"]) == (use_count, download_count) \
                or time.monotonic() > deadline:
            break
        time.sleep(0.2)
    assert (card["use_count"], card["download_count"]) == (use_count, download_count), card
    return card


def _redeem(session, token, secret=None, peek=False):
    body = {}
    if secret is not None:
        body["secret"] = secret
    if peek:
        body["peek"] = True
    return session.post(f"{session.base_url}/public-links/{token}/redeem", json=body, timeout=30)


def _download(session, token, file_id, grant):
    return session.get(f"{session.base_url}/public-links/{token}/download/{file_id}",
                       headers={"X-Download-Grant": grant}, timeout=60)


def _recipient(base_url):
    s = requests.Session()
    s.base_url = base_url
    return s


def test_a_one_download_password_link_delivers_exactly_once(admin, base_url, files_enabled, vault):
    content = os.urandom(200_000)
    file_id = _upload(admin, vault["id"], "contract.pdf", content)
    link = _link(admin, vault["id"], _tag(admin, password=True, cap=1), file_id=file_id,
                 max_uses=1, password=_PASSWORD)
    token = link["token"]
    person = _recipient(base_url)

    # Opening the page: the link asks for its password, then shows the file. Neither spends the use.
    assert _redeem(person, token, peek=True).status_code == 401
    shown = _redeem(person, token, secret=_PASSWORD, peek=True)
    assert shown.status_code == 200 and shown.json()["grant"] is None
    assert shown.json()["name"] == "contract.pdf" and shown.json()["size"] == len(content)
    _counts(admin, link["id"], 0, 0)

    # The Download click: redeem for real, then fetch with the grant.
    redeemed = _redeem(person, token, secret=_PASSWORD)
    assert redeemed.status_code == 200, redeemed.text
    grant = redeemed.json()["grant"]
    got = _download(person, token, file_id, grant)
    assert got.status_code == 200, got.text
    assert got.content == content
    assert _counts(admin, link["id"], 1, 1)["status"] == "exhausted"

    # The one download is spent: the link refuses another redeem, and the grant cannot be reused.
    assert _redeem(person, token, secret=_PASSWORD).status_code == 404
    assert _redeem(person, token, secret=_PASSWORD, peek=True).status_code == 404
    assert _download(person, token, file_id, grant).status_code == 404
    _counts(admin, link["id"], 1, 1)


@pytest.mark.parametrize("cap", [2, 3])
def test_a_capped_link_delivers_exactly_its_cap(admin, base_url, files_enabled, vault, cap):
    content = os.urandom(50_000)
    file_id = _upload(admin, vault["id"], f"report-{cap}.bin", content)
    link = _link(admin, vault["id"], _tag(admin, cap=cap), file_id=file_id, max_uses=cap)
    person = _recipient(base_url)

    for n in range(1, cap + 1):
        redeemed = _redeem(person, link["token"])
        assert redeemed.status_code == 200, f"redeem {n} of {cap}: {redeemed.text}"
        got = _download(person, link["token"], file_id, redeemed.json()["grant"])
        assert got.status_code == 200, f"download {n} of {cap}: {got.status_code}"
        assert got.content == content
    assert _redeem(person, link["token"]).status_code == 404
    _counts(admin, link["id"], cap, cap)


@pytest.mark.parametrize("cap", [1, 2])
def test_a_capped_folder_link_delivers_that_many_files_then_refuses(admin, base_url, files_enabled,
                                                                      vault, cap):
    folder_id = _folder(admin, vault["id"], unique("dir"))
    contents = {}
    for name in ("a.txt", "b.txt", "c.txt"):
        content = os.urandom(4_000)
        contents[_upload(admin, vault["id"], name, content, folder_id=folder_id)] = content
    link = _link(admin, vault["id"], _tag(admin, cap=cap), folder_id=folder_id, max_uses=cap)
    person = _recipient(base_url)

    listing = _redeem(person, link["token"], peek=True)
    assert listing.status_code == 200 and listing.json()["grant"] is None
    entries = [e["id"] for e in listing.json()["entries"] if not e["is_folder"]]
    assert sorted(entries) == sorted(contents)

    delivered = []
    for file_id in entries[:cap]:
        redeemed = _redeem(person, link["token"])
        assert redeemed.status_code == 200, redeemed.text
        got = _download(person, link["token"], file_id, redeemed.json()["grant"])
        assert got.status_code == 200, got.status_code
        assert got.content == contents[file_id]
        delivered.append(file_id)
    assert len(delivered) == cap
    # The next file is refused: the link has no use left to redeem.
    assert _redeem(person, link["token"]).status_code == 404
    _counts(admin, link["id"], cap, cap)


def test_parallel_redeems_of_a_one_download_link_give_one_grant_and_one_delivery(
        admin, base_url, files_enabled, vault):
    content = os.urandom(30_000)
    file_id = _upload(admin, vault["id"], "race.bin", content)
    link = _link(admin, vault["id"], _tag(admin, cap=1), file_id=file_id, max_uses=1)
    racers = 8                      # below the per-address limit of ten redeems a minute per link
    start = threading.Barrier(racers)

    def race(_):
        s = _recipient(base_url)
        start.wait(timeout=30)
        return _redeem(s, link["token"])

    with ThreadPoolExecutor(max_workers=racers) as pool:
        results = list(pool.map(race, range(racers)))
    statuses = sorted(r.status_code for r in results)
    assert statuses == [200] + [404] * (racers - 1), statuses
    [winner] = [r for r in results if r.status_code == 200]
    assert len(_grants_held_for(link["id"])) == 1, "only the winning redeem may leave a grant"

    got = _download(_recipient(base_url), link["token"], file_id, winner.json()["grant"])
    assert got.status_code == 200 and got.content == content
    assert _grants_held_for(link["id"]) == []
    _counts(admin, link["id"], 1, 1)


def test_parallel_downloads_with_one_grant_deliver_once(admin, base_url, files_enabled, vault):
    content = os.urandom(300_000)
    file_id = _upload(admin, vault["id"], "once.bin", content)
    link = _link(admin, vault["id"], _tag(admin, cap=3), file_id=file_id, max_uses=3)
    grant = _redeem(_recipient(base_url), link["token"]).json()["grant"]
    racers = 8
    start = threading.Barrier(racers)

    def race(_):
        s = _recipient(base_url)
        start.wait(timeout=30)
        return _download(s, link["token"], file_id, grant)

    with ThreadPoolExecutor(max_workers=racers) as pool:
        results = list(pool.map(race, range(racers)))
    statuses = sorted(r.status_code for r in results)
    assert statuses == [200] + [404] * (racers - 1), statuses
    assert next(r for r in results if r.status_code == 200).content == content
    _counts(admin, link["id"], 1, 1)


@pytest.mark.parametrize("how", ["revoke", "kill switch"])
def test_a_grant_is_refused_once_the_link_is_revoked_or_the_feature_is_off(admin, base_url,
                                                                         files_enabled, vault, how):
    file_id = _upload(admin, vault["id"], "stop.bin", os.urandom(10_000))
    link = _link(admin, vault["id"], _tag(admin, password=True, cap=1), file_id=file_id,
                 max_uses=1, password=_PASSWORD)
    person = _recipient(base_url)
    grant = _redeem(person, link["token"], secret=_PASSWORD).json()["grant"]
    assert grant
    if how == "revoke":
        assert admin.post(f"/public-links/{link['id']}/revoke").status_code == 200
        assert _download(person, link["token"], file_id, grant).status_code == 404
    else:
        assert admin.put("/settings", json={"public_file_links_enabled": False}).status_code == 200
        try:
            assert _download(person, link["token"], file_id, grant).status_code == 404
        finally:
            assert admin.put("/settings", json={"public_file_links_enabled": True}).status_code == 200
    _counts(admin, link["id"], 1, 0)


def test_a_link_deleted_after_its_redeem_refuses_the_download(admin, base_url, files_enabled, vault):
    file_id = _upload(admin, vault["id"], "gone.bin", os.urandom(10_000))
    link = _link(admin, vault["id"], _tag(admin, cap=1), file_id=file_id, max_uses=1)
    person = _recipient(base_url)
    grant = _redeem(person, link["token"]).json()["grant"]
    assert admin.delete(f"/public-links/{link['id']}").status_code in (200, 204)
    assert _download(person, link["token"], file_id, grant).status_code == 404


def test_link_previews_and_page_visits_spend_nothing(admin, base_url, files_enabled, vault):
    content = os.urandom(20_000)
    file_id = _upload(admin, vault["id"], "preview.pdf", content)
    link = _link(admin, vault["id"], _tag(admin, password=True, cap=1), file_id=file_id,
                 max_uses=1, password=_PASSWORD)
    page = f"{base_url}/p/{link['token']}"
    for agent in ("Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
                  "WhatsApp/2.23.20.0", "facebookexternalhit/1.1", "TelegramBot (like TwitterBot)",
                  "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
                  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"):
        assert requests.get(page, headers={"User-Agent": agent}, timeout=30).status_code == 200
        assert requests.head(page, headers={"User-Agent": agent}, timeout=30).status_code < 500
    person = _recipient(base_url)
    for _ in range(2):              # a visit, then a return visit, each unlocked without a download
        assert _redeem(person, link["token"], peek=True).status_code == 401
        assert _redeem(person, link["token"], secret=_PASSWORD, peek=True).status_code == 200
    _counts(admin, link["id"], 0, 0)

    # The person then downloads, and gets the file.
    grant = _redeem(person, link["token"], secret=_PASSWORD).json()["grant"]
    got = _download(person, link["token"], file_id, grant)
    assert got.status_code == 200 and got.content == content
    _counts(admin, link["id"], 1, 1)


def test_a_redeem_that_loses_the_last_use_leaves_no_usable_grant(admin, base_url, files_enabled,
                                                                 vault):
    """Two redeems race for a link's last use: one passes the link's checks, mints its grant, and only
    then finds, at the conditional update, that the other has spent the use. Held here
    deterministically: a database transaction locks the link's row, the redeem mints its grant and
    waits on the lock, and the transaction spends the last use and commits. The redeem must answer
    404 and leave no grant behind."""
    file_id = _upload(admin, vault["id"], "lost.bin", os.urandom(10_000))
    link = _link(admin, vault["id"], _tag(admin, cap=1), file_id=file_id, max_uses=1)
    lid = link["id"]
    holder = subprocess.Popen(
        ["docker", "exec", "-i", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
         "-v", "ON_ERROR_STOP=1", "-q"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    marker = f"lost-race-{lid}"
    outcome = {}
    try:
        holder.stdin.write(f"BEGIN; SELECT id, '{marker}' FROM public_links WHERE id = '{lid}' FOR UPDATE;\n")
        holder.stdin.flush()
        _wait_for(f"SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%{marker}%' "
                  "AND state = 'idle in transaction'", "the row lock to be held")

        def redeem():
            outcome["response"] = _redeem(_recipient(base_url), link["token"])

        racer = threading.Thread(target=redeem)
        racer.start()
        _wait_for("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                  "AND query ILIKE 'UPDATE public_links%'", "the redeem to wait on the row lock")
        holder.stdin.write(f"UPDATE public_links SET use_count = max_uses WHERE id = '{lid}'; COMMIT;\n")
        holder.stdin.flush()
        racer.join(timeout=30)
        assert not racer.is_alive(), "the redeem never returned"
    finally:
        holder.stdin.close()
        try:
            holder.wait(timeout=20)
        except subprocess.TimeoutExpired:
            holder.kill()
            _psql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE query LIKE '%{marker}%' "
                  "AND pid <> pg_backend_pid()")
    assert outcome["response"].status_code == 404, outcome["response"].text
    assert _grants_held_for(lid) == [], "a redeem that lost the last use left its grant behind"
    _counts(admin, lid, 1, 0)


def _wait_for(count_sql, what, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if int(_psql(count_sql) or 0) >= 1:
            return
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {what}")


def test_a_grant_minted_before_the_link_expired_still_delivers(admin, base_url, files_enabled, vault):
    content = os.urandom(10_000)
    file_id = _upload(admin, vault["id"], "late.bin", content)
    link = _link(admin, vault["id"], _tag(admin, cap=1), file_id=file_id, max_uses=1)
    person = _recipient(base_url)
    grant = _redeem(person, link["token"]).json()["grant"]
    time.sleep(2)
    # The link expires a second ago: after the grant was minted, before its download.
    _psql(f"UPDATE public_links SET expires_at = (now() AT TIME ZONE 'utc') - interval '1 second' "
          f"WHERE id = '{link['id']}'")
    assert _card(admin, link["id"])["status"] in ("expired", "exhausted")
    got = _download(person, link["token"], file_id, grant)
    assert got.status_code == 200 and got.content == content


def test_a_grant_minted_after_the_link_expired_is_refused(admin, base_url, files_enabled, vault):
    file_id = _upload(admin, vault["id"], "early.bin", os.urandom(10_000))
    link = _link(admin, vault["id"], _tag(admin, cap=2), file_id=file_id, max_uses=2)
    person = _recipient(base_url)
    grant = _redeem(person, link["token"]).json()["grant"]
    # The link's expiry moved to an hour before the grant was minted (an expiry the redeem could not
    # have passed): the grant must not deliver.
    _psql(f"UPDATE public_links SET expires_at = (now() AT TIME ZONE 'utc') - interval '1 hour' "
          f"WHERE id = '{link['id']}'")
    assert _download(person, link["token"], file_id, grant).status_code == 404
