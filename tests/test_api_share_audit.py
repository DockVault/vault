"""Share audit-trail coverage.

Every share lifecycle transition writes a name-redacted audit row (ids + counts only). This file
covers share_expired — the lazy active->expired transition, emitted once when a claim is attempted on
a share past its expiry. The other events (share_created, share_claimed, share_opened,
share_downloaded, share_revoked, and the per-recipient kick) are exercised by their feature tests.
"""
import os
import subprocess

from conftest import unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    r = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, f"psql failed ({_DB}): {r.stderr.strip()}"
    return (r.stdout or "").strip()


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin):
    r = admin.post("/share-tags", json={"name": unique("autag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10})
    assert r.status_code == 200, r.text
    return r.json()


def _make_share(admin, v, tag):
    r = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"],
                                    "target_type": "vault", "claim_audience": "anyone_internal"})
    assert r.status_code == 200, r.text
    return r.json()  # includes the show-once link_token


def _expired_count(share_id):
    return int(_psql(f"SELECT count(*) FROM audit_logs WHERE action='share_expired' "
                     f"AND details->>'share_id'='{share_id}'") or "0")


def test_expired_claim_audits_once(admin, temp_user_client):
    """Claiming a share past its expiry is denied (410) and writes exactly ONE 'share_expired' audit
    row. A second attempt stays 410 but does NOT re-emit — the event fires on the active->expired
    transition only. The row is name-redacted (ids only, never the vault name)."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("auexp"))
    try:
        share = _make_share(admin, v, _tag(admin))
        assert _expired_count(share["id"]) == 0  # freshly created -> not expired yet

        # Force the share past its expiry deterministically (mirrors the concurrency tests' psql use).
        _psql(f"UPDATE shares SET expires_at = now() - interval '1 hour' WHERE id='{share['id']}'")

        r1 = temp_user_client.post("/shares/claim", json={"token": share["link_token"]})
        assert r1.status_code == 410, r1.text
        assert _expired_count(share["id"]) == 1, "expected exactly one share_expired audit row"

        r2 = temp_user_client.post("/shares/claim", json={"token": share["link_token"]})
        assert r2.status_code == 410, r2.text
        assert _expired_count(share["id"]) == 1, "share_expired must not re-emit on a second attempt"

        detail = _psql(f"SELECT details::text FROM audit_logs WHERE action='share_expired' "
                       f"AND details->>'share_id'='{share['id']}' LIMIT 1")
        assert v["name"] not in detail, "audit details must not leak the vault name"
    finally:
        admin.delete_vault(v["id"])
