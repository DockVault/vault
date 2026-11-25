"""The Activity page's details drawer names the account a row is about where the row recorded its name: an
administrator's row about another account (a refusal lifted, an identity unlinked, a decision on an administrator
request) reads "alice (user <id>)" under Affected, where it read only "user <id>", and its copy button still copies
the id. The text is the SHIPPED function, lifted out of ``static/js/activity.js`` verbatim and run under Node, as
``test_activity_page_helpers.py`` runs the page's other helpers; what the browser draws is the UI lane.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "static" / "js" / "activity.js").read_text(encoding="utf-8")
UID = "3f2a9c1e-5b7d-4e2f-9a10-6c8d2e4f1b3a"


def _fn(name: str) -> str:
    """One function of the page, verbatim, up to its closing brace."""
    start = JS.index(f"\n    function {name}(") + 1
    return JS[start:JS.index("\n    }\n", start) + 7]


def _affected(ev: dict) -> str:
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    body = _fn("affectedText") + f"console.log(JSON.stringify(affectedText({json.dumps(ev)})));\n"
    done = subprocess.run([node, "-"], input=body, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ))
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip(), "the harness wrote nothing"
    return json.loads(done.stdout)


def test_a_row_about_another_account_names_it_beside_its_id():
    ev = {"action": "sso_refusal_cleared", "resource_type": "user", "resource_id": UID,
          "details": {"user_id": UID, "provider_id": "p", "identity_id": "i", "target_username": "alice"}}
    assert _affected(ev) == f"alice (user {UID})"


@pytest.mark.parametrize("ev, shown", [
    ({"resource_type": "user", "resource_id": UID, "details": {"user_id": UID}}, f"user {UID}"),
    ({"resource_type": "user", "resource_id": UID, "details": None}, f"user {UID}"),
    ({"resource_type": "user", "resource_id": UID}, f"user {UID}"),
    ({"resource_type": "user", "resource_id": UID, "details": {"target_username": ""}}, f"user {UID}"),
    ({"resource_type": "user", "resource_id": UID, "details": {"target_username": 7}}, f"user {UID}"),
    # Another kind of thing is named by its own fields (Vault, File, Folder); a name about an account is not its.
    ({"resource_type": "sso_admin_request", "resource_id": "r1", "details": {"target_username": "alice"}},
     "sso_admin_request r1"),
], ids=["no-name", "no-details", "details-absent", "empty-name", "not-text", "not-an-account"])
def test_without_a_recorded_name_of_the_account_it_shows_the_type_and_id(ev, shown):
    assert _affected(ev) == shown


def test_the_drawer_shows_it_as_text_and_copies_the_id():
    body = _fn("detailBody")
    block = body[body.index("if (ev.resource_type) {"):]
    block = block[:block.index("'Affected'")]
    block = block + body[body.index("'Affected'"):][:200]
    assert "affectedText(ev)" in block, block
    assert "copyText(ev.resource_id || text)" in block, block
    assert "el('span', 'act-d-value act-mono', text)" in block, block
    assert "innerHTML" not in _fn("affectedText") + block
