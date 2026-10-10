"""The retention screen's list of waiting changes on a running stack: the audit log's integrity chain's, not the
database's (app/core/audit_chain_pending.py, GET /settings/managed and its cancel route).

Someone who can write to the database but holds no key edits managed_setting_changes behind the app's back:
- the waiting change's row says a value that keeps more and a date a year away: the screen still lists the
  sealed value and the date the pruner applies it on;
- the row says cancelled: the change is still listed, with what the database says beside it, and an
  administrator's cancel is sealed in the chain (it used to answer 409, the change hidden);
- a pending row with no request seal: it is not listed, and its cancel is no change (404), with no audit row.

The changes are made to the minimum age of administration rows, as in test_retention_live.py, and every one
ends cancelled through the route, so the stack's chain and database agree afterwards.
"""
import uuid

import pytest

from _account_change_helpers import psql, second_admin
from test_retention_live import KEY, _cancel_waiting, _put, _row, _wait_for, chain_started  # noqa: F401

pytestmark = pytest.mark.integration


def _listed(admin):
    return [p for p in admin.get("/settings/managed").json()["pending"] if p["key"] == KEY]


def _cancel_rows(change_id):
    return psql("SELECT count(*) FROM audit_logs WHERE action = 'setting_change_cancelled' "
                f"AND details->>'change_id' = '{change_id}'")


def test_the_waiting_list_and_its_cancel_are_the_chains_whatever_the_table_says(admin):
    start = _row(admin, KEY)["value"]
    try:
        with second_admin(admin) as (account, client):
            assert _put(client, account["_password"], KEY, start + 1).json()["status"] == "applied"
            assert _wait_for(lambda: _row(admin, KEY)["value"] == start + 1)
            body = _put(client, account["_password"], KEY, start).json()
            assert body["status"] == "pending", body
            change = body["change"]
            (sealed,) = _listed(admin)
            assert (sealed["id"], sealed["old"], sealed["new"], sealed["requested_by"]) == (
                change["id"], start + 1, start, account["_username"])
            request_seq = psql("SELECT seq FROM audit_seals WHERE kind = 'request' "
                               f"AND detail->>'request' = '{change['id']}'")
            assert request_seq and sealed["request_seq"] == int(request_seq)

            # A value that keeps more, a year away, written into the row: the list says what the seal holds.
            psql(f"UPDATE managed_setting_changes SET new_value = '{start + 50}', setting = '{start + 50}', "
                 f"effective_at = effective_at + interval '300 days' WHERE id = '{change['id']}'")
            (shown,) = _listed(admin)
            assert (shown["old"], shown["new"], shown["setting"], shown["effective_at"], shown["database"]) == (
                start + 1, start, start, sealed["effective_at"], None)

            # The row marked cancelled: still listed, said beside it, and cancelled through the chain.
            psql(f"UPDATE managed_setting_changes SET status = 'cancelled' WHERE id = '{change['id']}'")
            (shown,) = _listed(admin)
            assert (shown["id"], shown["database"], shown["cancellable"]) == (change["id"], "cancelled", True)
            r = admin.post(f"/settings/managed/changes/{change['id']}/cancel")
            assert r.status_code == 200, r.text
            assert (r.json()["change"]["new"], r.json()["change"]["status"]) == (start, "cancelled")
            assert psql("SELECT count(*) FROM audit_seals WHERE kind = 'cancel' "
                        f"AND detail->>'cancels' = '{request_seq}' AND detail->>'by' = 'admin'") == "1"
            assert _cancel_rows(change["id"]) == "1"
            assert _listed(admin) == []
            assert admin.post(f"/settings/managed/changes/{change['id']}/cancel").status_code == 409

            # A pending row with no request seal: not listed, and no change to cancel.
            planted = str(uuid.uuid4())
            try:
                psql("INSERT INTO managed_setting_changes (id, key, setting, old_value, new_value, status, "
                     "requested_by_name, requested_at, effective_at) VALUES "
                     f"('{planted}', '{KEY}', '1', '{start + 1}', '1', 'pending', 'someone', now(), "
                     "now() + interval '7 days')")
                assert _listed(admin) == []
                r = admin.post(f"/settings/managed/changes/{planted}/cancel")
                assert r.status_code == 404, r.text
                assert _cancel_rows(planted) == "0"
                assert psql(f"SELECT status FROM managed_setting_changes WHERE id = '{planted}'") == "pending"
            finally:
                psql(f"DELETE FROM managed_setting_changes WHERE id = '{planted}'")
    finally:
        _cancel_waiting(admin, KEY)
