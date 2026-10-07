"""The notices to vaults' owners on a running stack (app/core/owner_notices.py): written in the very transaction of
the step they tell of, sent by email from the outbox by the web process's own sender, with a real SMTP server kept
inside the web container (_owner_notice_helpers.py).

  * a legal hold's notification and outbox row are inserted by the placing transaction itself (the same
    transaction id on the case, the hold, the notification and the outbox row), and the email reaches the owner;
  * SMTP down: tried again after a minute, then 5 and 15 (the test moves the time forward), then failed, with a
    security alert, while the notice in the app stands;
  * the web container restarted between the commit and the send: the email still goes out, from the new process;
  * an address changed after the notice was written does not reroute it; an administrator's change made before
    sends a copy to the address before it.

test_owner_notices.py covers the rules offline.
"""
import subprocess
import time

import pytest

from _account_change_helpers import API, in_api_container, psql
from _auditor_helpers import compliance_receipt, two_admins
from _owner_notice_helpers import (mail_to, outbox, owner_with_vault, sender_held, sending_to_sink, start_sink,
                                   wait_for)
from conftest import BASE_URL

pytestmark = pytest.mark.integration

TEXT = {"purpose": "litigation_hold", "legal_basis": "legal_obligation",
        "justification": "Preserve the records named in the claim served last week.",
        "owner_note": "Files deleted from your vault are kept for a legal matter."}
SUBJECT = "Access to your vaults: case "


@pytest.fixture
def admins(admin):
    with two_admins(admin) as people:
        yield people


@pytest.fixture
def placed(admin):
    """The cases and vaults a test made, released and removed straight in the database afterwards."""
    made = {"cases": [], "vaults": []}
    yield made
    for vid in made["vaults"]:
        psql(f"UPDATE legal_hold_vaults SET released_at = now() WHERE vault_id = '{vid}' AND released_at IS NULL")
        for table in ("held_files", "held_folders", "held_name_history"):
            psql(f"DELETE FROM {table} WHERE vault_id = '{vid}'")
    for cid in made["cases"]:
        psql(f"DELETE FROM compliance_cases WHERE id = '{cid}'")
    in_api_container("from app.core import legal_hold_marker\nlegal_hold_marker.check_at_start()\n")


def _place(who, vault_id, placed):
    account, client, codes = who
    r = client.post("/compliance/holds", json={"vault_ids": [vault_id], **TEXT},
                    headers=compliance_receipt(client, "compliance.hold.place", account["_password"], codes))
    assert r.status_code == 201, r.text
    case = r.json()
    placed["cases"].append(case["id"])
    placed["vaults"].append(vault_id)
    return case


def _status(case_id):
    return psql(f"SELECT coalesce(notice_email_status, '') FROM compliance_cases WHERE id = '{case_id}'")


def test_the_notice_commits_with_the_hold_and_reaches_the_owner_by_email(admin, admins, placed):
    owner, _client, vid = owner_with_vault(admin)
    with sending_to_sink(admin):
        with sender_held():
            case = _place(admins["ada"], vid, placed)
            # One transaction wrote the case, the hold, the owner's notification and the outbox row.
            xids = psql(
                "SELECT (SELECT xmin::text FROM compliance_cases WHERE id = '{c}') || '|' || "
                "(SELECT xmin::text FROM legal_hold_vaults WHERE case_id = '{c}') || '|' || "
                "(SELECT string_agg(DISTINCT xmin::text, ',') FROM notifications WHERE user_id = '{u}' "
                "AND type = 'compliance_access') || '|' || "
                "(SELECT string_agg(DISTINCT xmin::text, ',') FROM compliance_notice_outbox WHERE case_id = '{c}')"
                .format(c=case["id"], u=owner["id"])).split("|")
            assert len(xids) == 4 and len(set(xids)) == 1 and xids[0], xids
            assert outbox(case["id"]) == [["hold_placed", "pending", "0", owner["id"]]]
            assert _status(case["id"]) == "queued"
            address = psql(f"SELECT address_enc FROM compliance_notice_outbox WHERE case_id = '{case['id']}'")
            assert owner["email"] not in address and address.startswith("cenc1:"), "the address is sealed"
        sent = mail_to(owner["email"], SUBJECT + case["number"])
        assert sent, "the owner's email never arrived"
        text = sent[0]["text"]
        assert "Legal hold on your vaults" in text and case["number"] in text
        assert TEXT["justification"] not in text
    assert wait_for(lambda: outbox(case["id"])[0][1] == "sent", timeout=30)
    assert _status(case["id"]) == "sent"
    assert psql("SELECT count(*) FROM audit_logs WHERE action = 'owner_notice_email_sent' "
                f"AND case_id = '{case['id']}'") == "1"
    assert psql("SELECT count(*) FROM audit_logs WHERE action = 'owner_notice_written' "
                f"AND case_id = '{case['id']}'") == "1"


def _send_pass():
    """One pass of the sender in another process of the web container (the web process's own sender may take the
    row first: either way the row is tried once when it is due)."""
    in_api_container("from app.core import owner_notices\nowner_notices.send_due()\n")


def test_smtp_down_is_tried_again_then_fails_with_an_alert(admin, admins, placed):
    owner, _client, vid = owner_with_vault(admin)
    with sending_to_sink(admin, port=9):          # nothing listens there: every send fails at once
        case = _place(admins["ada"], vid, placed)
        assert wait_for(lambda: outbox(case["id"])[0][2] == "1", timeout=60), outbox(case["id"])
        row = f"case_id = '{case['id']}'"
        wait = psql("SELECT round(extract(epoch FROM next_attempt_at - created_at)) FROM compliance_notice_outbox "
                    f"WHERE {row}")
        assert outbox(case["id"])[0][1] == "retrying" and 59 <= int(float(wait)) <= 62, wait
        assert _status(case["id"]) == "retrying"
        for attempts, minutes in ((2, 5), (3, 15)):
            psql("UPDATE compliance_notice_outbox SET next_attempt_at = (now() AT TIME ZONE 'utc'), "
                 f"created_at = (now() AT TIME ZONE 'utc') WHERE {row}")
            _send_pass()
            assert wait_for(lambda: outbox(case["id"])[0][2] == str(attempts), timeout=60)
            gap = psql("SELECT round(extract(epoch FROM next_attempt_at - (now() AT TIME ZONE 'utc')) / 60) "
                       f"FROM compliance_notice_outbox WHERE {row}")
            assert int(float(gap)) in (minutes - 1, minutes), (attempts, gap)
        assert psql("SELECT count(*) FROM security_alerts WHERE event_type = 'owner_notice_email_failed' "
                    f"AND user_id = '{owner['id']}'") == "0"
        psql(f"UPDATE compliance_notice_outbox SET next_attempt_at = (now() AT TIME ZONE 'utc') WHERE {row}")
        _send_pass()
        assert wait_for(lambda: outbox(case["id"])[0][1] == "failed", timeout=60), outbox(case["id"])
    assert outbox(case["id"])[0][2] == "4"
    assert _status(case["id"]) == "failed"
    assert psql("SELECT count(*) FROM security_alerts WHERE event_type = 'owner_notice_email_failed' "
                f"AND user_id = '{owner['id']}' AND NOT resolved") == "1"
    assert psql("SELECT count(*) FROM audit_logs WHERE action = 'owner_notice_email_failed' "
                f"AND case_id = '{case['id']}' AND status = 'failure'") == "1"
    # The notice in the app stands.
    assert psql(f"SELECT count(*) FROM notifications WHERE user_id = '{owner['id']}' "
                "AND type = 'compliance_access'") == "1"
    psql(f"DELETE FROM security_alerts WHERE event_type = 'owner_notice_email_failed' AND user_id = '{owner['id']}'")


def _healthy():
    import requests
    try:
        return requests.get(f"{BASE_URL}/health", timeout=5).status_code == 200
    except requests.RequestException:
        return False


def test_a_restart_between_the_commit_and_the_send_still_delivers(admin, admins, placed):
    owner, _client, vid = owner_with_vault(admin)
    with sending_to_sink(admin):
        with sender_held():
            case = _place(admins["ada"], vid, placed)
            assert outbox(case["id"])[0][1] == "pending"
            r = subprocess.run(["docker", "restart", API], capture_output=True, text=True, timeout=180)
            assert r.returncode == 0, r.stderr
            assert wait_for(_healthy, timeout=180, every=2), "the web container did not come back"
            start_sink()
            assert outbox(case["id"])[0][1] == "pending", "nothing was sent while the lock was held"
        sent = mail_to(owner["email"], SUBJECT + case["number"], timeout=120)
        assert sent, "the email was lost across the restart"
    assert wait_for(lambda: outbox(case["id"])[0][1] == "sent", timeout=30)


def test_an_address_changed_after_the_notice_does_not_reroute_it(admin, admins, placed):
    owner, _client, vid = owner_with_vault(admin)
    first = owner["email"]
    moved = first.replace("@", "-moved@")
    with sending_to_sink(admin):
        with sender_held():
            case = _place(admins["ada"], vid, placed)
            assert admin.patch(f"/users/{owner['id']}", json={"email": moved}).status_code == 200
        assert mail_to(first, SUBJECT + case["number"]), "the notice went nowhere"
        time.sleep(3)
        assert not mail_to(moved, SUBJECT + case["number"], timeout=0), "the notice followed the new address"


def test_an_administrators_recent_change_of_the_address_sends_a_copy_to_the_one_before(admin, admins, placed):
    owner, _client, vid = owner_with_vault(admin)
    first = owner["email"]
    moved = first.replace("@", "-new@")
    with sending_to_sink(admin):
        assert admin.patch(f"/users/{owner['id']}", json={"email": moved}).status_code == 200
        case = _place(admins["ada"], vid, placed)
        assert mail_to(moved, SUBJECT + case["number"]), "the owner's address got nothing"
        assert mail_to(first, SUBJECT + case["number"]), "the address before the change got no copy"
    assert wait_for(lambda: outbox(case["id"])[0][1] == "sent", timeout=30)
    assert psql("SELECT sent_to::text FROM compliance_notice_outbox "
                f"WHERE case_id = '{case['id']}'") == '["address", "previous"]'
