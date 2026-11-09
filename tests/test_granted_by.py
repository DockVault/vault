"""Who granted a vault's access, and who shared an item, are named without a query per row.

A vault's access lists name who gave each grant: the members' list always did, and a department grant
now does too (vault_group_access keeps added_by like vault_members does). The 'Shared with me' list
names each card's sharer from one lookup for the whole list instead of one users query per card.

Lanes:
  * unit        — the department list selects added_by and names it from one lookup; the shared-with-me
                  list loads the sharers once and hands them to the card builder; the access UI shows
                  the chip for a department row.
  * integration — a department grant made over HTTP comes back with the granter's id and username.
"""
import re
from pathlib import Path

import pytest

from conftest import unique

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "app" / "api" / "api_server.py"
APP_JS = ROOT / "static" / "js" / "app.js"


def _function(src: Path, head: str) -> str:
    text = src.read_text(encoding="utf-8")
    start = text.index(head)
    nxt = re.search(r"\n(?:@app\.|async def |def )", text[start + len(head):])
    return text[start: start + len(head) + (nxt.start() if nxt else len(text))]


@pytest.mark.unit
def test_department_rows_carry_the_granter_from_one_lookup():
    body = _function(API, "async def list_vault_group_access(")
    assert "vault_group_access.c.added_by" in body
    assert '"added_by_username"' in body and '"added_by"' in body
    # One users query for every row, not one per row.
    assert body.count("db.query(User.id, User.username)") == 1
    assert "User.id.in_(" in body


@pytest.mark.unit
def test_shared_with_me_names_the_sharers_with_one_query():
    lister = _function(API, "async def list_shared_with_me(")
    assert "db.query(User.id, User.username).filter(User.id.in_(creator_ids))" in lister
    assert "_shared_with_me_dict(db, claim, share, sharer_names)" in lister
    card = _function(API, "def _shared_with_me_dict(")
    assert "sharer_names.get(share.creator_id)" in card


@pytest.mark.unit
def test_the_access_ui_shows_who_granted_a_department():
    body = _function(APP_JS, "async function loadVaultGroupAccess(")
    assert "<th>Granted by</th>" in body
    assert "People.placeholder({ id: a.added_by, username: a.added_by_username }" in body


@pytest.fixture
def temp_group(admin):
    r = admin.post("/groups", json={"name": unique("grantedby")})
    r.raise_for_status()
    group = r.json()
    yield group
    admin.delete(f"/groups/{group['id']}")


@pytest.mark.integration
def test_a_department_grant_names_who_granted_it(admin, admin_creds, temp_vault, temp_group):
    r = admin.post(f"/vaults/{temp_vault['id']}/group-access",
                   json={"group_id": temp_group["id"], "permission": "read"})
    assert r.status_code in (200, 201), r.text
    rows = admin.get(f"/vaults/{temp_vault['id']}/group-access").json()
    row = next(g for g in rows if str(g.get("group_id")) == str(temp_group["id"]))
    assert row.get("added_by"), f"a department grant should carry who made it: {row}"
    assert row.get("added_by_username") == admin_creds["username"], row
    # The same person the members' list would name for a grant by the same account.
    me = admin.get("/users/me").json()
    assert str(row["added_by"]) == str(me["id"]), (row, me.get("id"))
