"""Infrastructure / configuration / abuse-resistance hardening regression tests.

Covers the framework rate limiter wiring, the brute-force login alerting that was dead
code, the proxy-aware transport-security scheme, the production weak-secret startup gate, and the
container/compose/dependency hardening. Live-HTTP tests hit http://localhost:8200; the config-gate
and proxy-scheme tests run inside the vault-api container (they import app modules that need the
credential manager); the rest are static source locks.
"""
import os
import subprocess
from pathlib import Path

import pytest

from conftest import unique

ROOT = Path(__file__).resolve().parent.parent


def _read(name):
    return (ROOT / name).read_text(encoding="utf-8", errors="ignore")


def _in_container(env_overrides=None, args=None, stdin=None, timeout=90):
    """Run a command in the vault-api container; skip cleanly if docker is unavailable."""
    container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    cmd = ["docker", "exec"]
    if stdin is not None:
        cmd.append("-i")
    for k, v in (env_overrides or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [container] + list(args or [])
    try:
        return subprocess.run(
            cmd, input=stdin, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")


def test_general_api_rate_limiter_is_attached(admin):
    r = admin.get("/api/dashboard/stats")
    assert r.status_code == 200, r.text
    for h in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"):
        assert h in r.headers, f"missing {h} -- the rate-limit middleware is not attached"


def test_health_is_excluded_from_rate_limiting(anon):
    r = anon.get("/health")
    assert r.status_code == 200
    assert "X-RateLimit-Limit" not in r.headers


def test_repeated_failed_logins_raise_brute_force_alerts(admin, anon):
    uniq = unique("bruteforce")
    for i in range(12):
        anon.post("/auth/login", json={"username": uniq, "password": f"wrong-{i}"})
    alerts = admin.get("/api/security/alerts", params={"limit": 200}).json().get("alerts", [])
    mine = [a for a in alerts if uniq in (a.get("message") or "") or a.get("username") == uniq]
    severities = {a.get("severity") for a in mine}
    assert "warning" in severities, f"expected a WARNING alert for {uniq}; got {mine}"
    assert "critical" in severities, f"expected a CRITICAL brute-force alert for {uniq}; got {mine}"


def test_failed_login_username_is_sanitized_in_alerts(admin, anon):
    # A CRLF-carrying login username must not survive into the persisted SecurityAlert (which the
    # admin alerts API returns) or the logs -- otherwise it forges log lines (CWE-117). Drive the
    # brute-force path (as the sibling test does) with a hostile username and assert the stored
    # alert message/username carry no CR/LF.
    base = unique("crlf")
    hostile = base + "\r\nInjectedForgedLogLine"
    for i in range(12):
        anon.post("/auth/login", json={"username": hostile, "password": f"wrong-{i}"})
    alerts = admin.get("/api/security/alerts", params={"limit": 200}).json().get("alerts", [])
    mine = [a for a in alerts
            if base in (a.get("message") or "") or base in (a.get("username") or "")]
    assert mine, f"expected an alert recording the hostile username {base!r}"
    for a in mine:
        msg = a.get("message") or ""
        uname = a.get("username") or ""
        assert "\r" not in msg and "\n" not in msg, f"CRLF survived into alert message: {msg!r}"
        assert "\r" not in uname and "\n" not in uname, f"CRLF survived into alert username: {uname!r}"


def test_error_paths_do_not_leak_exception_text():
    # WebSocket frames bypass the HTTP 500-sanitizer, and a non-500 HTTPException renders its detail
    # verbatim -- so neither the /ws auth path nor the ECC register/decompress paths may echo str(e).
    api = _read("app/api/api_server.py")
    assert 'f"Invalid token: {str(e)}"' not in api, "WS token error must not frame str(e) to the client"
    assert '"message": "Authentication failed"' in api, "WS token failure should send a generic frame"
    ecc = _read("app/api/ecc_router.py")
    assert 'f"Invalid public key format: {str(e)}"' not in ecc, "ECC register must not echo str(e) at 400"
    assert 'f"Invalid compressed point: {str(e)}"' not in ecc, "decompress-point must not echo str(e) at 400"
    # Lock the NEW register duplicate-race branch specifically: this exact detail string is unique to
    # the IntegrityError->409 mapping (distinct from the precheck's "encryption key is already set up"),
    # so removing/weakening that branch actually fails this assertion (a whole-file "IntegrityError"
    # substring would not -- it also occurs in the unrelated ZK share-invite handler).
    assert "A public key is already registered for this account" in ecc, \
        "the duplicate-register race must map to a generic 409, not a str(e) 400"


def test_db_throttle_hit_counts_and_denies():
    # The durable DB-fallback throttle (now shared by the password login path AND the SFTP key-offer
    # path) must count attempts and deny over its limit. Also proves it is a reusable @staticmethod
    # callable without an AuthService instance.
    proc = _in_container(args=[
        "python", "-c",
        "import uuid; from app.services.auth_service import AuthService; "
        "k='thr-'+uuid.uuid4().hex; "
        "res=[AuthService._db_throttle_hit(k,'thr_probe',2,60) for _ in range(3)]; "
        "print('ALLOWED='+str([a for a,_ in res])); print('RETRY3='+str(res[2][1]))"
    ])
    assert "ALLOWED=[True, True, False]" in proc.stdout, f"{proc.stdout}\n{proc.stderr}"
    assert "RETRY3=0" not in proc.stdout, "an over-limit deny must carry a positive retry-after"


def test_sftp_key_clear_resets_db_fallback_row():
    # A successful SSH key auth must clear the DURABLE DB-fallback counter (not only the Redis one),
    # or a legitimate multi-key client would accumulate offers it never resets and lock itself out
    # mid-window while Redis is down (the counting fallback path). ip in TEST-NET-3 so no collision.
    script = "\n".join([
        "import uuid",
        "from app.services.auth_service import AuthService",
        "from app.sftp.sftp_server import _sftp_key_clear",
        "from app.core.database import get_db_context",
        "from app.core.models import RateLimitRecord",
        "ip = '203.0.113.7'",
        "u = 'probe-' + uuid.uuid4().hex[:8]",
        "ident = ip + ':' + u",
        "for _ in range(3):",
        "    AuthService._db_throttle_hit(ident, 'sftp_pk', 2, 300)",
        "with get_db_context() as db:",
        "    before = db.query(RateLimitRecord).filter(RateLimitRecord.identifier==ident, RateLimitRecord.action=='sftp_pk').count()",
        "_sftp_key_clear(ip, u)",
        "with get_db_context() as db:",
        "    after = db.query(RateLimitRecord).filter(RateLimitRecord.identifier==ident, RateLimitRecord.action=='sftp_pk').count()",
        "print('BEFORE=%d AFTER=%d' % (before, after))",
    ])
    proc = _in_container(args=["python", "-"], stdin=script)
    assert "BEFORE=1 AFTER=0" in proc.stdout, f"{proc.stdout}\n{proc.stderr}"


def test_login_and_sftp_throttles_fail_closed():
    # Both the DB-fallback login throttle and the SFTP key-offer throttle must fail CLOSED on a Redis
    # outage -- they used to fail OPEN (silently disabling throttling while Redis was down).
    auth = _read("app/services/auth_service.py")
    assert "Fails CLOSED" in auth, "the DB throttle fallback docstring should state fail-closed"
    assert "return False, max(1, min(window, 5))" in auth, \
        "the DB throttle must deny (not allow) on its own error"
    sftp = _read("app/sftp/sftp_server.py")
    body = sftp[sftp.index("def _sftp_key_throttled"):sftp.index("def _sftp_key_clear")]
    assert "fail_open=False" in body, "the SFTP key throttle must ask the limiter to fail closed"
    assert "except RateLimiterUnavailable" in body, "the SFTP key throttle must drop to the DB fallback"
    assert "_db_throttle_hit" in body, "the SFTP key throttle must reuse the durable DB fallback"
    assert "return False  # never let the throttle itself break auth" not in sftp, \
        "the SFTP throttle must not swallow errors to 'not throttled'"


def test_toggle_active_enforces_seat_cap_on_reactivation():
    # Re-activating a user consumes a seat, so the toggle-active endpoint must enforce the plan's
    # user cap on the inactive->active transition -- otherwise an admin at the cap could deactivate
    # a user, create a replacement (a seat freed up), then reactivate the original via the toggle to
    # land above the cap. The cap can't be exercised against an uncapped live instance, so this
    # static guard locks the wiring (mirrors the already-guarded PATCH /users/{id} path).
    src = _read("app/api/user_management_api.py")
    body = src[src.index("async def toggle_user_active"):src.index("async def toggle_user_locked")]
    assert "_enforce_user_cap" in body, \
        "toggle-active must enforce the seat cap on reactivation"
    assert "if not user.is_active:" in body, \
        "the seat-cap check must gate on the inactive->active (reactivation) transition"
    assert body.index("_enforce_user_cap") < body.index("user.is_active = not user.is_active"), \
        "the seat-cap check must run BEFORE is_active is flipped (so the active count excludes this user)"


def test_sftp_revocation_subscriber_survives_half_open_redis():
    # The SFTP session-termination pub/sub subscriber must bound its socket and actively
    # health-check, so a HALF-OPEN Redis connection (TCP dropped without a clean close) is detected
    # instead of blocking forever -- which would silently disable live SFTP session revocation until
    # the process restarts. A static guard (no live outage harness needed) locks these settings on
    # the exact client that subscribes to the revocation channel.
    sftp = _read("app/sftp/sftp_server.py")
    end = sftp.index("subscribe('session_terminations')")
    start = sftp.rindex("redis.Redis(", 0, end)
    block = sftp[start:end]
    assert "socket_timeout=" in block, \
        "the revocation subscriber must bound every read with a socket_timeout"
    assert "socket_connect_timeout=" in block, \
        "the revocation subscriber must bound reconnects with a socket_connect_timeout"
    assert "socket_keepalive=True" in block, \
        "the revocation subscriber must keepalive-probe the idle pub/sub socket"
    assert "health_check_interval=" in block, \
        "the revocation subscriber must actively health-check the pub/sub socket"


def test_security_alerts_are_deduped_under_sustained_attack(admin, anon):
    # A sustained brute-force must NOT append a new alert row per attempt: repeats of the same
    # (event_type, username) within the cooldown window collapse into one row that records a
    # repeat_count -- otherwise the table floods and real alerts get buried.
    from collections import Counter
    uniq = unique("dedup")
    for i in range(12):
        anon.post("/auth/login", json={"username": uniq, "password": f"wrong-{i}"})
    alerts = admin.get("/api/security/alerts", params={"limit": 300}).json().get("alerts", [])
    mine = [a for a in alerts if a.get("username") == uniq]
    assert mine, f"expected at least one alert for {uniq}"
    by_type = Counter(a.get("event_type") for a in mine)
    for et, n in by_type.items():
        assert n == 1, f"event_type {et!r} should be deduped to one row, got {n}"
    assert any((a.get("details") or {}).get("repeat_count", 1) > 1 for a in mine), \
        "the deduped alert should carry a repeat_count > 1 recording the collapsed repeats"


def test_detection_degraded_signal_fires_and_is_throttled():
    # When the Redis event counter is unavailable the monitor emits a DETECTION_DEGRADED alert so
    # operators know threshold-based detection is blind. A rapid second signal is throttled IN-PROCESS
    # (at most one DB write per cooldown per process), so an outage can't hammer a hot alert row.
    script = "\n".join([
        "from app.core.database import get_db_context",
        "from app.services.security_monitor import SecurityMonitor, SecurityEventType",
        "from app.core.models import SecurityAlert",
        "with get_db_context() as db:",
        "    m = SecurityMonitor(db)",
        "    m._signal_detection_degraded()",
        "    a1 = db.query(SecurityAlert).filter(SecurityAlert.event_type==SecurityEventType.DETECTION_DEGRADED).order_by(SecurityAlert.timestamp.desc()).first()",
        "    ok = a1 is not None and (a1.details or {}).get('reason') == 'redis_counter_unavailable'",
        "    id1 = str(a1.id); rc1 = int((a1.details or {}).get('repeat_count', 1))",
        "    m._signal_detection_degraded()",
        "    a2 = db.query(SecurityAlert).filter(SecurityAlert.event_type==SecurityEventType.DETECTION_DEGRADED).order_by(SecurityAlert.timestamp.desc()).first()",
        "    id2 = str(a2.id); rc2 = int((a2.details or {}).get('repeat_count', 1))",
        "    print('OK=%s SAME=%s THROTTLED=%s' % (ok, id1==id2, rc2==rc1))",
    ])
    proc = _in_container(args=["python", "-"], stdin=script)
    assert "OK=True" in proc.stdout, f"the degraded signal must create a DETECTION_DEGRADED alert\n{proc.stdout}\n{proc.stderr}"
    assert "SAME=True" in proc.stdout, f"the second signal must not create a duplicate row\n{proc.stdout}"
    assert "THROTTLED=True" in proc.stdout, f"the rapid 2nd signal must be throttled in-process (no DB bump)\n{proc.stdout}"


def test_alert_dedup_key_is_per_user_and_severity(admin):
    # The dedup key must include user_id (so different users' user_id-keyed alerts -- bulk-delete /
    # rapid-vault-access set no username/ip -- don't collapse into one (type, NULL, NULL) row) AND
    # severity (so a CRITICAL escalation opens its own row even when a path reuses one event_type).
    # security_alerts.user_id has a FK to users, so use two real users; the script cleans up its rows.
    u1 = admin.create_user(role="user")
    u2 = admin.create_user(role="user")
    try:
        script = "\n".join([
            "from app.core.database import get_db_context",
            "from app.services.security_monitor import SecurityMonitor, SecurityEventType, SecurityAlertLevel",
            "from app.core.models import SecurityAlert",
            f"ua = '{u1['id']}'; ub = '{u2['id']}'",
            "ET = SecurityEventType.BULK_FILE_DELETION",
            "with get_db_context() as db:",
            "    m = SecurityMonitor(db)",
            "    a1 = m._raise_alert(event_type=ET, severity=SecurityAlertLevel.WARNING, message='dedupkeytest', user_id=ua)",
            "    b1 = m._raise_alert(event_type=ET, severity=SecurityAlertLevel.WARNING, message='dedupkeytest', user_id=ub)",
            "    a2 = m._raise_alert(event_type=ET, severity=SecurityAlertLevel.WARNING, message='dedupkeytest', user_id=ua)",
            "    ac = m._raise_alert(event_type=ET, severity=SecurityAlertLevel.CRITICAL, message='dedupkeytest', user_id=ua)",
            "    out = 'DIFFUSER=%s DEDUP=%s DIFFSEV=%s' % (str(a1.id)!=str(b1.id), str(a1.id)==str(a2.id), str(a1.id)!=str(ac.id))",
            "    for x in {str(a1.id), str(b1.id), str(ac.id)}:",
            "        db.query(SecurityAlert).filter(SecurityAlert.id == x).delete()",
            "    db.commit()",
            "    print(out)",
        ])
        proc = _in_container(args=["python", "-"], stdin=script)
        assert "DIFFUSER=True" in proc.stdout, f"different users must not collapse into one alert row\n{proc.stdout}\n{proc.stderr}"
        assert "DEDUP=True" in proc.stdout, f"same (user, type, severity) within cooldown must dedup\n{proc.stdout}"
        assert "DIFFSEV=True" in proc.stdout, f"a CRITICAL escalation must open its own row (severity in the key)\n{proc.stdout}"
    finally:
        admin.delete_user(u1["id"])
        admin.delete_user(u2["id"])


def test_bulk_file_deletion_raises_alert(admin, temp_user_client):
    # Rapidly deleting many files must raise a BULK_FILE_DELETION alert (the recorder is now wired
    # into the delete route). Threshold 10 / 60s window. A FRESH user does the deletes so the
    # per-user alert dedup can't collapse this run into a prior bulk-delete alert with another vault;
    # admin views the (admin-only) alerts and filters to this vault.
    v = temp_user_client.create_vault()
    vid = v["id"]
    try:
        fids = []
        for i in range(10):
            r = temp_user_client.post(f"/vaults/{vid}/files",
                                      files=[("files", (f"bulk{i}.bin", b"xxxxxxxx", "application/octet-stream"))])
            assert r.status_code == 200, r.text
            fids.append(r.json()["files"][0]["id"])
        for fid in fids:
            r = temp_user_client.post(f"/vaults/{vid}/files/{fid}/delete")
            assert r.status_code == 200, r.text
        alerts = admin.get("/api/security/alerts", params={"limit": 300}).json().get("alerts", [])
        bulk = [a for a in alerts
                if a.get("event_type") == "bulk_file_deletion" and (a.get("details") or {}).get("vault_id") == vid]
        assert bulk, "deleting 10 files should raise a bulk_file_deletion alert for this vault"
    finally:
        temp_user_client.delete_vault(vid)


def test_folder_delete_raises_bulk_alert(admin, temp_user_client):
    # A folder delete wipes its whole subtree in ONE request -- the highest-throughput deletion
    # vector. It must feed the bulk-deletion detector as one N-file record, not go undetected.
    v = temp_user_client.create_vault()
    vid = v["id"]
    try:
        fr = temp_user_client.post(f"/vaults/{vid}/folders", json={"name": "bulkdir"})
        assert fr.status_code == 200, fr.text
        folder_id = fr.json()["folder"]["id"]
        for i in range(10):
            r = temp_user_client.post(f"/vaults/{vid}/files?folder_id={folder_id}",
                                      files=[("files", (f"ff{i}.bin", b"xxxx", "application/octet-stream"))])
            assert r.status_code == 200, r.text
        dr = temp_user_client.post(f"/vaults/{vid}/folders/{folder_id}/delete")
        assert dr.status_code == 200, dr.text
        alerts = admin.get("/api/security/alerts", params={"limit": 300}).json().get("alerts", [])
        bulk = [a for a in alerts
                if a.get("event_type") == "bulk_file_deletion" and (a.get("details") or {}).get("vault_id") == vid]
        assert bulk, "deleting a folder of 10 files should raise a bulk_file_deletion alert"
    finally:
        temp_user_client.delete_vault(vid)


def test_all_delete_paths_feed_bulk_detector():
    # Bulk-deletion detection must cover every deletion vector, not just single-file web deletes: the
    # folder-delete _purge, SFTP rmdir _purge, and SFTP single-file remove call vault_service.delete_file
    # directly, so each must also feed record_file_deletion (SFTP is not behaviorally testable here).
    api = _read("app/api/api_server.py")
    sftp = _read("app/sftp/sftp_server.py")
    assert api.count("record_file_deletion(") >= 2, "web single-file AND folder delete must record deletions"
    assert sftp.count("record_file_deletion(") >= 2, "SFTP remove AND rmdir must record deletions"


def test_noisy_dead_recorders_stay_removed():
    # record_vault_access (INFO rapid-vault-access = normal browsing noise on a hot read path) and
    # record_rate_limit_violation (login rate-limits are already recorded via record_failed_login;
    # no single clean chokepoint) were removed as dead. Guard against reintroduction.
    src = _read("app/services/security_monitor.py")
    assert "def record_vault_access" not in src, "record_vault_access was removed as noisy/dead"
    assert "def record_rate_limit_violation" not in src, "record_rate_limit_violation was removed as dead"
    # the live recorders remain
    assert "def record_failed_login" in src and "def record_file_deletion" in src


def test_progress_complete_clears_dangling_record():
    # complete_operation must delete the Redis operation:* record. Uploads used to call start_operation
    # but never complete_operation, so every finished/failed upload left a dangling record until TTL.
    script = "\n".join([
        "import uuid",
        "from app.services.activity_monitor import ProgressTracker",
        "from app.core.database import redis_client",
        "t = ProgressTracker()",
        "oid = 'upload_' + uuid.uuid4().hex",
        "t.start_operation(operation_id=oid, user_id='u', username='u', operation_type='upload', file_name='f', total_size=0)",
        "key = t._get_operation_key(oid)",
        "before = bool(redis_client.exists(key))",
        "res_ok = t.complete_operation(oid, success=True)",
        "after = bool(redis_client.exists(key))",
        "oid2 = 'upload_' + uuid.uuid4().hex",
        "t.start_operation(operation_id=oid2, user_id='u', username='u', operation_type='upload', file_name='f', total_size=0)",
        "res_fail = t.complete_operation(oid2, success=False)",
        "print('BEFORE=%s AFTER=%s OK=%s FAIL=%s' % (before, after, (res_ok or {}).get('status'), (res_fail or {}).get('status')))",
    ])
    proc = _in_container(args=["python", "-"], stdin=script)
    assert "BEFORE=True AFTER=False" in proc.stdout, f"complete_operation must clear the record\n{proc.stdout}\n{proc.stderr}"
    assert "OK=completed FAIL=failed" in proc.stdout, f"the success flag must drive the operation status\n{proc.stdout}"


def test_activity_monitor_dead_code_removed_and_complete_wired():
    # The dead progress/traffic code is gone; the live methods remain; and the upload finalizer now
    # completes the operation record.
    src = _read("app/services/activity_monitor.py")
    for gone in ("class ActivityStats", "def update_progress", "def get_all_operations", "def get_operation"):
        assert gone not in src, f"{gone} should have been removed"
    for keep in ("def start_operation", "def complete_operation", "def is_cancelled", "def cancel_operation"):
        assert keep in src, f"{keep} must remain"
    api = _read("app/api/api_server.py")
    assert "tracker.complete_operation(operation_id" in api, "the upload finalizer must complete the operation record"


def test_cleanup_old_alerts_prunes_old_resolved(admin):
    # cleanup_old_alerts must delete old RESOLVED alerts beyond the retention window (and keep recent
    # ones + unresolved ones). Reads settings.security_alert_retention_days, not a hard-coded 90.
    u = admin.create_user(role="user")
    try:
        script = "\n".join([
            "import datetime",
            "from app.core.database import get_db_context",
            "from app.services import security_monitor",
            "security_monitor._last_alert_cleanup_at = None  # ensure the once/hour throttle allows this run",
            "from app.services.security_monitor import SecurityMonitor",
            "from app.core.models import SecurityAlert",
            f"uid = '{u['id']}'",
            "with get_db_context() as db:",
            "    m = SecurityMonitor(db)",
            "    old = SecurityAlert(event_type='bulk_file_deletion', severity='warning', message='old', user_id=uid, resolved=True, timestamp=datetime.datetime(2000,1,1,tzinfo=datetime.timezone.utc), details={})",
            "    recent = SecurityAlert(event_type='bulk_file_deletion', severity='warning', message='new', user_id=uid, resolved=True, timestamp=datetime.datetime.now(datetime.timezone.utc), details={})",
            "    db.add(old); db.add(recent); db.commit()",
            "    old_id=str(old.id); recent_id=str(recent.id)",
            "    m.cleanup_old_alerts()",
            "    old_gone = db.query(SecurityAlert).filter(SecurityAlert.id==old_id).first() is None",
            "    recent_kept = db.query(SecurityAlert).filter(SecurityAlert.id==recent_id).first() is not None",
            "    db.query(SecurityAlert).filter(SecurityAlert.id==recent_id).delete(); db.commit()",
            "    print('OLD_GONE=%s RECENT_KEPT=%s' % (old_gone, recent_kept))",
        ])
        proc = _in_container(args=["python", "-"], stdin=script)
        assert "OLD_GONE=True" in proc.stdout, f"old resolved alert should be pruned\n{proc.stdout}\n{proc.stderr}"
        assert "RECENT_KEPT=True" in proc.stdout, f"recent alert should be kept\n{proc.stdout}"
    finally:
        admin.delete_user(u["id"])


def test_normalize_scope_tolerates_bad_list_fields_and_rotate_key_cap():
    # normalize_scope must not 500 on a null/scalar list field (it should coerce to []), and
    # vault.rotate_key must be a recognized cap (else scoped temp creds can never rotate a vault key).
    script = "\n".join([
        "from app.core.temp_scope import normalize_scope, VAULT_CAPS",
        "s = normalize_scope({'pages': None, 'caps': 5, 'vault_caps_default': None})",
        "ok = isinstance(s, dict) and s['pages']==[] and s['caps']==[] and s['vault_caps_default']==[]",
        "rk = 'vault.rotate_key' in VAULT_CAPS",
        "print('OK=%s ROTATE=%s' % (ok, rk))",
    ])
    proc = _in_container(args=["python", "-"], stdin=script)
    assert "OK=True ROTATE=True" in proc.stdout, f"{proc.stdout}\n{proc.stderr}"


def test_temp_credential_auth_equalizes_timing():
    # A missing / inactive / used / expired temp credential must not be distinguishable from a live
    # one by response time: authenticate_temporary_credential does a dummy verify on the not-found
    # branch and verifies the credential BEFORE any state branch (mirroring authenticate_user).
    src = _read("app/services/auth_service.py")
    start = src.index("def authenticate_temporary_credential")
    body = src[start:src.index("\n    def ", start + 1)]
    assert "verify_temporary_credential(credential, _DUMMY_PASSWORD_HASH)" in body, \
        "the not-found branch must do a constant-cost dummy verify"
    real = body.index("verify_temporary_credential(credential, temp_cred.credential_hash)")
    state = body.index("temp_cred.is_active")
    assert real < state, "the credential must be verified BEFORE the is_active/used/expired state checks"


def test_entrypoint_privilege_drop_fails_closed():
    # The container starts as root to chown volumes, then drops to appuser. An initgroups failure must
    # NOT be swallowed (that would keep root's supplementary groups), and the drop must be verified.
    src = _read("docker-entrypoint.py")
    drop = src[src.index("os.initgroups"):src.index("os.execvp", src.index("os.initgroups"))]
    assert "except OSError:\n            pass" not in drop, "initgroups failure must not be blindly swallowed"
    assert "os.setgroups(" in drop, "must fall back to an explicit minimal group set"
    assert "os.getgroups()" in drop and "sys.exit(1)" in drop, "must verify the drop and fail closed"


def test_launch_targets_use_module_form():
    # Every live launch site must invoke the packaged servers via `python -m` —
    # a script-path invocation would put the module's own directory (not the app
    # root) on sys.path and break the absolute app.* imports.
    rc = _read("run_combined.py")
    assert '_spawn("app.api.api_server"' in rc, "run_combined must spawn the web server as a module"
    assert '_spawn("app.sftp.sftp_server"' in rc, "run_combined must spawn the SFTP server as a module"
    for compose in ("deploy/docker-compose.yml", "deploy/docker-compose.secure.yml"):
        dc = _read(compose)
        assert '["python", "-m", "app.api.api_server"]' in dc, f"{compose}: web command must use -m"
        assert '["python", "-m", "app.sftp.sftp_server"]' in dc, f"{compose}: sftp command must use -m"
        assert '"api_server.py"' not in dc and '"sftp_server.py"' not in dc, f"{compose}: no script-path launch"


def test_static_and_brand_anchor_at_app_root(anon):
    # The server modules live under app/, but static/ and brand/ sit at the APP ROOT —
    # they are anchored via app.core.paths.PROJECT_ROOT, not the serving module's
    # __file__. A wrong anchor silently 404s the SPA and orphans the brand volume
    # (the named volume mounts at /app/brand while uploads would land elsewhere).
    r = anon.get("/static/js/ecc_crypto.js")
    assert r.status_code == 200, "static assets must be served from the app root"
    proc = _in_container(args=["python", "-c",
        "from app.core.paths import PROJECT_ROOT; from app.api import api_server; "
        "print('ROOT=' + str(PROJECT_ROOT)); print('BRAND=' + api_server.BRAND_ASSET_DIR)"])
    assert "ROOT=/app" in proc.stdout, \
        f"PROJECT_ROOT must be /app in-container\n{proc.stdout}\n{proc.stderr}"
    assert "BRAND=/app/brand" in proc.stdout, \
        f"brand dir must stay on the mounted volume\n{proc.stdout}\n{proc.stderr}"


def test_baked_healthcheck_is_scheme_aware():
    # The baked HEALTHCHECK must honour API_USE_HTTPS, else an HTTPS deploy of the bare image reports
    # perpetually unhealthy.
    df = _read("Dockerfile")
    assert "API_USE_HTTPS" in df, "the baked healthcheck must read API_USE_HTTPS"


def test_deploy_scripts_hardened():
    # Deploy-script hardening (owner-validated on-host; here we lock the source):
    smp = _read("scripts/setup_master_password.py")
    assert "iterations=600000" in smp, "PBKDF2 must use >=600k iterations (match the runtime decryptor)"
    assert "'production'" in smp, "the ENVIRONMENT fallback must default to production, not development"
    assert "0o600" in smp, "secret files must be written mode 0600"
    ss = _read("setup-secure.sh")
    assert "REDIS_PASSWORD" in ss, "setup-secure.sh must generate a REDIS_PASSWORD"
    assert "ALLOWED_HOSTS" in ss, "setup-secure.sh must write ALLOWED_HOSTS"


def test_setup_scripts_at_root_and_secure_shim():
    # The two user-facing setup scripts live at the repo ROOT (not deploy/), and the root
    # docker-compose.secure.yml include-shim makes `docker compose -f docker-compose.secure.yml
    # up` auto-load root .env with no --env-file and no moving .env into deploy/.
    assert (ROOT / "setup-secure.sh").exists(), "setup-secure.sh must live at the repo root"
    assert (ROOT / "setup-secure.ps1").exists(), "setup-secure.ps1 must live at the repo root"
    assert not (ROOT / "deploy" / "setup-secure.sh").exists(), "setup-secure.sh must NOT remain in deploy/"
    assert not (ROOT / "deploy" / "setup-secure.ps1").exists(), "setup-secure.ps1 must NOT remain in deploy/"

    # Lock the path anchors: a root-anchored script must NOT climb to the parent (that would
    # write .env/certs to the parent directory when run from a nested checkout).
    sh = _read("setup-secure.sh")
    assert 'cd "$(dirname "$0")"' in sh, "setup-secure.sh must anchor at its own dir (repo root)"
    assert '"$(dirname "$0")/.."' not in sh, "setup-secure.sh must not climb to the parent dir"
    ps = _read("setup-secure.ps1")
    assert "= $ScriptDir" in ps, "setup-secure.ps1 $Root must be its own dir (repo root)"
    assert "Split-Path -Parent $ScriptDir" not in ps, "setup-secure.ps1 must not climb to the parent dir"

    # Root secure include-shim exists, pins the project name (for volume stability), and includes
    # the real deploy file.
    shim = _read("docker-compose.secure.yml")
    assert "name: dockvault-vault" in shim, "root secure shim must pin the project name"
    assert "deploy/docker-compose.secure.yml" in shim and "include:" in shim, \
        "root secure shim must include: deploy/docker-compose.secure.yml"

    # SECURITY.md moved under .github/ (GitHub still renders it); no stray root copy.
    assert (ROOT / ".github" / "SECURITY.md").exists(), "SECURITY.md must live under .github/"
    assert not (ROOT / "SECURITY.md").exists(), "no duplicate SECURITY.md at the root"

    # No doc/compose/source still points at the OLD deploy/setup-secure.* location.
    for name in ("README.md", ".env.example", "CLAUDE.md", ".github/SECURITY.md",
                 "deploy/docker-compose.secure.yml", "app/core/config.py", "app/api/api_server.py"):
        assert "deploy/setup-secure" not in _read(name), \
            f"{name} still references the moved deploy/setup-secure path"


def _secure_compose_config(profile):
    """Render the secure stack via `docker compose config` under COMPOSE_PROFILES=profile;
    skip cleanly if docker/compose is unavailable or the render fails for an env reason."""
    import shutil
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    env = dict(os.environ, COMPOSE_PROFILES=profile, VAULT_DB_PASSWORD="testpw",
               RUN_SFTP="", SFTP_HOST_PORT="2322")
    try:
        r = subprocess.run(["docker", "compose", "-f", "docker-compose.secure.yml", "config"],
                           cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=90)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"docker compose unavailable: {exc}")
    if r.returncode != 0:
        pytest.skip(f"docker compose config failed: {r.stderr[:200]}")
    return r.stdout


def test_secure_compose_combined_default_and_split_profile():
    # DEFAULT (combined): ONE 'vault' container runs run_combined.py; the split pair is absent.
    combined = _secure_compose_config("combined")
    assert "run_combined.py" in combined, "combined mode must run run_combined.py"
    assert "app.api.api_server" not in combined and "app.sftp.sftp_server" not in combined, \
        "combined mode must NOT render the split vault-api/vault-sftp commands"
    # SPLIT: vault-api + vault-sftp run their own commands; the combined launcher is absent.
    split = _secure_compose_config("split")
    assert "app.api.api_server" in split and "app.sftp.sftp_server" in split, \
        "split mode must render both the web and sftp services"
    assert "run_combined.py" not in split, "split mode must NOT run the combined launcher"
    # Both modes mount the SAME named volumes -> switching modes never loses data.
    for vol in ("vault_storage", "vault_keys"):
        assert vol in combined and vol in split, f"{vol} must be mounted in both modes"


def test_setup_scripts_write_combined_profile_scheme():
    # The setup scripts must write the new combined/split scheme (RUN_SFTP for SFTP-in-combined),
    # NOT the retired first-run `COMPOSE_PROFILES=sftp`, or the primary deploy path renders no app.
    for name in ("setup-secure.sh", "setup-secure.ps1"):
        s = _read(name)
        assert "COMPOSE_PROFILES=combined" in s, f"{name} must write COMPOSE_PROFILES=combined"
        assert "RUN_SFTP=1" in s, f"{name} must set RUN_SFTP=1 when SFTP is enabled in combined mode"
        # Must not WRITE the retired sftp profile (a quoted env-line value). Bare mentions in
        # migration comments / "sftp -> split" messages are fine (they have a space after).
        assert 'COMPOSE_PROFILES=sftp"' not in s and "COMPOSE_PROFILES=sftp'" not in s, \
            f"{name} must not write the retired sftp profile"
    # .env.example ships the mode + the SFTP toggle so a manual `cp .env.example .env` just works.
    envx = _read(".env.example")
    assert "COMPOSE_PROFILES=combined" in envx and "RUN_SFTP=" in envx, \
        ".env.example must ship COMPOSE_PROFILES=combined and RUN_SFTP"


def test_env_example_documents_every_settings_field():
    # .env.example must document every pydantic Settings field (so a self-hoster can discover
    # each knob) — this lock catches a new config field that never got a .env.example entry.
    import re
    cfg = _read("app/core/config.py")
    m = re.search(r"class Settings\(BaseSettings\):(.*?)\n(?:settings = Settings|class )", cfg, re.S)
    assert m, "could not locate the Settings class in app/core/config.py"
    fields = re.findall(r"^    ([a-z_][a-z0-9_]*)\s*:\s*[^=\n]+=\s*Field", m.group(1), re.M)
    assert len(fields) > 40, "sanity: expected many Settings fields"
    env = _read(".env.example")
    documented = set(re.findall(r"^\s*#?\s*([A-Z_][A-Z0-9_]*)\s*=", env, re.M))
    missing = sorted(f.upper() for f in fields if f.upper() not in documented)
    assert not missing, f".env.example is missing these Settings keys: {missing}"
    # The non-Settings toggles a self-hoster sets must be documented too.
    for k in ("RUN_SFTP", "COMPOSE_PROFILES", "SFTP_HOST_PORT", "WEB_HOST_PORT",
              "CORS_ALLOW_ORIGINS", "ALLOWED_HOSTS"):
        assert k in documented, f".env.example must document {k}"


def test_secure_compose_web_port_parameterized():
    # The web host port is configurable via WEB_HOST_PORT (default 443), not hard-coded, in BOTH the
    # combined and split services, so a self-hoster can publish on a different port.
    sc = _read("deploy/docker-compose.secure.yml")
    assert sc.count("${WEB_HOST_PORT:-443}:8000") == 2, "both web services must publish via WEB_HOST_PORT"
    assert '- "443:8000"' not in sc, "the web host port must not be hard-coded"


def test_secure_compose_honours_web_host_port_override():
    # A WEB_HOST_PORT override must actually take effect in the rendered compose.
    import shutil
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    env = dict(os.environ, COMPOSE_PROFILES="combined", VAULT_DB_PASSWORD="testpw",
               RUN_SFTP="", SFTP_HOST_PORT="2322", WEB_HOST_PORT="8443")
    try:
        r = subprocess.run(["docker", "compose", "-f", "docker-compose.secure.yml", "config"],
                           cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=90)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"docker compose unavailable: {exc}")
    if r.returncode != 0:
        pytest.skip(f"docker compose config failed: {r.stderr[:200]}")
    assert "8443" in r.stdout, "WEB_HOST_PORT=8443 override must render as the published host port"


def test_claude_md_carries_config_sync_rule():
    # CLAUDE.md must document the rule that a new config field is updated in .env.example AND the
    # setup tooling in the same change (test_env_example_documents_every_settings_field enforces the
    # .env.example half; this locks the documented rule so the practice isn't silently dropped).
    md = _read("CLAUDE.md")
    low = md.lower()
    assert ".env.example" in md and "setup tooling" in low and "app/core/config.py" in md, \
        "CLAUDE.md must document keeping config, .env.example, and the setup tooling in sync"


def test_app_version_from_version_file_not_hardcoded():
    import re
    # A committed VERSION file (valid semver) is the single source of truth for the app's version.
    ver = _read("VERSION").strip()
    assert re.match(r"^\d+\.\d+\.\d+", ver), f"VERSION must be semver-ish, got {ver!r}"
    # branding reads it as the default (not a hardcoded literal); BRAND_APP_VERSION can override.
    br = _read("app/config/branding.py")
    assert "default_factory=_read_version_file" in br, "app_version must default to the VERSION file"
    assert 'default="1.0.0"' not in br, "app_version must not be a hardcoded 1.0.0"
    # api_server.py must no longer report a hardcoded version.
    api = _read("app/api/api_server.py")
    assert 'version="1.0.0"' not in api and '"version": "1.0.0"' not in api, \
        "api_server.py must report branding.app_version, not a hardcoded 1.0.0"
    assert "version=branding.app_version" in api, "the FastAPI app must use branding.app_version"


def test_update_check_admin_gated_and_default_off():
    import re
    api = _read("app/api/api_server.py")
    assert '@app.get("/api/update-status")' in api, "the update-status endpoint must exist"
    m = re.search(r'@app\.get\("/api/update-status"\)\s*\n(?:async )?def \w+\((.*?)\):', api, re.S)
    assert m and "require_interactive_admin" in m.group(1), \
        "update-status must be gated by an interactive admin (not public like /version)"
    # Default OFF in config (opt-in; air-gapped installs make no outbound calls).
    cfg = _read("app/core/config.py")
    assert "update_check_enabled: bool = Field(default=False)" in cfg, "update check must default OFF"
    assert "managed_deployment: bool = Field(default=False)" in cfg
    envx = _read(".env.example")
    assert "UPDATE_CHECK_ENABLED=false" in envx and "MANAGED_DEPLOYMENT=false" in envx
    # The phone-home is documented for the operator.
    assert "UPDATE_CHECK_ENABLED" in _read(".github/SECURITY.md"), \
        "SECURITY.md must document the update-check phone-home"


def test_release_workflow_and_upgrade_docs():
    import re
    wf = _read(".github/workflows/release.yml")
    # Builds + pushes to GHCR, stamps the version, triggers on a version tag.
    assert "ghcr.io/" in wf and "build-push-action" in wf, "release.yml must build+push to GHCR"
    assert "APP_VERSION=" in wf, "release.yml must stamp the version via the build-arg"
    assert "v*.*.*" in wf, "release.yml must trigger on a version tag"
    # Every action is pinned to a full commit SHA (supply-chain hardening for a public security repo).
    for use in re.findall(r"uses:\s*(\S+)", wf):
        assert re.search(r"@[0-9a-f]{40}\b", use), f"action not pinned to a full SHA: {use}"
    # The compose image is overridable for the pull-based upgrade path.
    assert "${DOCKVAULT_IMAGE:-dockvault-vault:latest}" in _read("deploy/docker-compose.secure.yml"), \
        "compose image must honour DOCKVAULT_IMAGE"
    assert "DOCKVAULT_IMAGE=" in _read(".env.example")
    # README documents BOTH upgrade paths + the migration caveat.
    r = _read("README.md")
    assert "## Upgrading" in r, "README must have an Upgrading section"
    assert "up -d --build" in r and "pull" in r, "both upgrade paths (build + pull) must be documented"
    assert "migration" in r.lower(), "the DB-migration caveat must be documented"


def test_readme_documents_deployment_modes():
    # The README must explain the combined (default) vs split deployment modes and the combined-mode
    # trade-offs a self-hoster needs to know, so the toggle isn't a silent behaviour change.
    r = _read("README.md")
    low = r.lower()
    assert "combined" in low and "split" in low, "README must document combined vs split modes"
    assert "COMPOSE_PROFILES" in r and "RUN_SFTP" in r, "README must name the mode + SFTP toggles"
    # The key limitation: the healthcheck only covers the web half in combined mode.
    assert "healthcheck" in low and "/health" in r, "README must note the healthcheck covers only web"


def test_public_docs_reference_only_shipped_windows_scripts():
    # Operator docs MAY reference a Windows helper that actually ships in this repo (e.g.
    # deploy/setup-secure.ps1), but must never point a self-hoster at a .ps1 that isn't part of this repo
    # (a dev-only helper that doesn't ship here), which would only misdirect.
    import re
    for name in (".env.example", "docker-compose.yml", "deploy/docker-compose.yml", "README.md"):
        for script in re.findall(r"[A-Za-z0-9_-]+\.ps1", _read(name)):
            # Shipped helpers live under deploy/ (the docs reference them as deploy/<name>.ps1;
            # the regex extracts the bare basename).
            assert (ROOT / script).exists() or (ROOT / "deploy" / script).exists(), \
                f"{name} references a Windows script that is not shipped here: {script}"


def test_user_detail_endpoints_enforce_ownership():
    # The endpoint-permission catalog's requires_ownership flag is display-only and is NOT enforced by
    # require_endpoint_permission, so the user-detail handlers must enforce own-or-admin themselves: a
    # non-admin explicitly granted USER_VIEW must not be able to read another user's record.
    for name in ("app/api/api_server.py", "app/api/user_management_api.py"):
        src = _read(name)
        assert "current_user.id != user_id" in src, f"{name}: user-detail must enforce own-or-admin ownership"


def _import_config(env_overrides):
    return _in_container(env_overrides=env_overrides, args=["python", "-c", "from app.core import config"])


def test_production_rejects_sample_admin_password():
    proc = _import_config({"ENVIRONMENT": "production", "ADMIN_PASSWORD": "change_this_secure_password"})
    assert proc.returncode == 1, f"sample admin password should fail-closed in production\n{proc.stdout}\n{proc.stderr}"


def test_production_rejects_env_example_placeholder():
    proc = _import_config({"ENVIRONMENT": "production", "ADMIN_PASSWORD": "REPLACE_ME"})
    assert proc.returncode == 1, f"placeholder should fail-closed in production\n{proc.stdout}"


def test_production_allows_strong_admin_password():
    proc = _import_config({"ENVIRONMENT": "production", "ADMIN_PASSWORD": "Xq7-strong-Rand-92hf"})
    assert proc.returncode == 0, f"strong admin password should boot\n{proc.stdout}\n{proc.stderr}"


def test_development_allows_sample_admin_password():
    proc = _import_config({"ENVIRONMENT": "development", "ADMIN_PASSWORD": "change_this_secure_password"})
    assert proc.returncode == 0, "development must not be gated"


def test_production_allows_blank_admin_password_post_bootstrap():
    proc = _import_config({"ENVIRONMENT": "production", "ADMIN_PASSWORD": ""})
    assert proc.returncode == 0, "blank admin password must not fail startup (post-bootstrap)"


def test_jwt_algorithm_must_be_canonical_hmac():
    # A non-HMAC or mis-cased JWT_ALGORITHM must fail closed at BOOT (defeats alg-confusion and the
    # PyJWT case-sensitivity 500). Only the exact canonical HMAC names boot.
    assert _import_config({"JWT_ALGORITHM": "HS256"}).returncode == 0
    for bad in ("RS256", "none", "hs256", "ES256"):
        proc = _import_config({"JWT_ALGORITHM": bad})
        assert proc.returncode == 1, f"JWT_ALGORITHM={bad!r} must fail-closed at boot\n{proc.stdout}"


def test_development_rejects_env_example_placeholder():
    # The shipped .env.example placeholder is a publicly known credential and must be refused in
    # EVERY environment — a bare `docker compose up` ships ENVIRONMENT=development and previously
    # seeded admin/REPLACE_ME on a plaintext listener.
    proc = _import_config({"ENVIRONMENT": "development", "ADMIN_PASSWORD": "REPLACE_ME"})
    assert proc.returncode == 1, f"shipped placeholder must fail-closed even in development\n{proc.stdout}\n{proc.stderr}"


def test_production_rejects_short_admin_password():
    # A weak-but-unlisted value below the 12-char floor must not boot a reachable (production) deploy.
    proc = _import_config({"ENVIRONMENT": "production", "ADMIN_PASSWORD": "weakpass"})
    assert proc.returncode == 1, f"a <12-char admin password should fail-closed in production\n{proc.stdout}\n{proc.stderr}"


def test_nonstandard_env_rejects_weak_admin_password():
    # Fail-safe: any non-development environment ("staging", "prod", a typo) is treated as reachable
    # and gets the strict blocklist + length tier — not only the literal "production".
    proc = _import_config({"ENVIRONMENT": "staging", "ADMIN_PASSWORD": "password"})
    assert proc.returncode == 1, f"a weak password must fail-closed in any non-development env\n{proc.stdout}\n{proc.stderr}"


def test_development_allows_short_nonplaceholder_password():
    # Dev convenience preserved: only the shipped placeholder is blocked in development; a short,
    # non-placeholder value still boots (the blocklist + length floor apply outside development).
    proc = _import_config({"ENVIRONMENT": "development", "ADMIN_PASSWORD": "devpass1"})
    assert proc.returncode == 0, f"development must allow a short non-placeholder password\n{proc.stdout}\n{proc.stderr}"


def test_dev_compose_publishes_loopback_only():
    # The plaintext trial must bind to loopback so it isn't reachable off-host.
    dc = _read("deploy/docker-compose.yml")
    assert '- "127.0.0.1:8200:8000"' in dc, "trial API port must publish on loopback (127.0.0.1)"
    assert '- "8200:8000"' not in dc, "trial API port must not publish on all interfaces"


_PLAINTEXT_WARN_SELFTEST = r'''
from app.api import api_server as a
f = a._should_warn_plaintext_transport
assert f(False, "production", "") is True, "plaintext + production + no proxy should warn"
assert f(False, "staging", "") is True, "plaintext + any non-dev + no proxy should warn"
assert f(False, "development", "") is False, "development suppresses the warning"
assert f(True, "production", "") is False, "in-process HTTPS does not warn"
assert f(False, "production", "10.0.0.0/8") is False, "a configured trusted proxy suppresses the warning"
print("PLAINTEXT_WARN_OK")
'''


def test_plaintext_transport_warning_condition():
    # Locks the net-new startup-warning logic (plaintext AND non-development AND no trusted proxy).
    proc = _in_container(args=["python", "-"], stdin=_PLAINTEXT_WARN_SELFTEST)
    assert "PLAINTEXT_WARN_OK" in proc.stdout, f"{proc.stdout}\n{proc.stderr}"


_SCHEME_SELFTEST = r'''
from app.api import api_server
from app.core import net_utils
sc = api_server._external_scheme

class _H(dict):
    def get(self, k, d=None): return super().get(k, d)

class _Req:
    def __init__(self, peer, xfp=None):
        self.client = type("C", (), {"host": peer})()
        self.headers = _H({"x-forwarded-proto": xfp} if xfp else {})
        self.url = type("U", (), {"scheme": "http"})()

net_utils.settings.trusted_proxies = ""
net_utils._trusted_networks.cache_clear()
assert sc(_Req("172.18.0.5", "https")) == "http", "untrusted peer must not honour XFP"
assert sc(_Req("8.8.8.8", "https")) == "http", "public peer must not honour XFP"

net_utils.settings.trusted_proxies = "172.16.0.0/12"
net_utils._trusted_networks.cache_clear()
try:
    assert sc(_Req("172.18.0.5", "https")) == "https", "trusted proxy XFP should be honoured"
    assert sc(_Req("172.18.0.5", "http")) == "http", "trusted proxy forwarding http stays http"
    assert sc(_Req("8.8.8.8", "https")) == "http", "a direct public client is still ignored"
finally:
    net_utils.settings.trusted_proxies = ""
    net_utils._trusted_networks.cache_clear()
print("SCHEME_OK")
'''


def test_forwarded_proto_scheme_resolution():
    proc = _in_container(args=["python", "-"], stdin=_SCHEME_SELFTEST)
    assert "SCHEME_OK" in proc.stdout, (
        f"external-scheme self-test failed (rc={proc.returncode})\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )


def test_requirements_drop_unused_and_refresh_crypto():
    active = [l.strip() for l in _read("requirements.txt").splitlines()
              if l.strip() and not l.strip().startswith("#")]
    names = {l.split("==")[0].split("[")[0].strip().lower() for l in active}
    assert "requests" not in names, "unused requests should be removed from the image deps"
    assert "python-jose" not in names, "the unmaintained python-jose should be dropped in favour of PyJWT"
    assert "pyjwt" in names, "the JWT path is now the maintained PyJWT"
    assert "cryptography==44.0.1" in active, "cryptography should carry the CVE-2024-12797 fix"
    assert "python-multipart==0.0.18" in active, "python-multipart should carry the multipart-DoS fix"
    assert "fastapi==0.115.6" in active, "fastapi should pair with starlette>=0.40 (CVE-2024-47874)"
    assert "starlette==0.41.3" in active, "starlette should be >=0.40 (CVE-2024-47874)"


def test_no_stray_import_of_dropped_libs_in_shipped_code():
    patt = "^import requests|^from jose\\b|^import jose\\b"
    hits = subprocess.run(["git", "grep", "-lE", patt], cwd=str(ROOT),
                          capture_output=True, text=True)
    prod = [p for p in hits.stdout.splitlines() if p and not p.startswith("tests/")]
    assert not prod, f"dropped libs still imported in shipped code: {prod}"


def test_dockerignore_excludes_git_metadata():
    lines = {l.strip() for l in _read(".dockerignore").splitlines()}
    assert ".git" in lines, "VCS metadata should be kept out of the shipped image"


def test_master_password_kdf_iterations_raised():
    ss = _read("app/core/startup_security.py")
    assert "iterations=600000" in ss, "master-password KDF should use 600k iterations"
    assert "iterations=100000" not in ss, "the old 100k iteration count should be gone"


def test_dead_fail_open_permission_code_stays_removed():
    # Regression guard: two dead, fail-open permission paths were removed because they would
    # silently allow-all if ever wired in. They must not creep back:
    #   - the module-level `require_permission` decorator (allowed through when the user object
    #     had no _permission_service attribute), and
    #   - the EndpointPermissionChecker / get_endpoint_info catalog checker ("endpoint not in
    #     catalog -> allow"), which the live require_endpoint_permission never consulted.
    authz = _read("app/core/authorization.py")
    assert "\ndef require_permission(" not in authz, \
        "the fail-open module-level require_permission decorator must stay removed"
    # the live, non-fail-open PermissionService.require_permission METHOD must remain
    assert "    def require_permission(" in authz

    ep = _read("app/core/endpoint_permissions.py")
    assert "class EndpointPermissionChecker" not in ep, "dead fail-open EndpointPermissionChecker must stay removed"
    assert "def get_endpoint_info" not in ep, "dead get_endpoint_info (only the checker used it) must stay removed"
    assert "def require_endpoint_permission(" in ep, "the live endpoint gate must remain"


def test_broken_whole_file_crypto_stays_removed():
    # The whole-file AES-GCM writer had a 9-byte magic vs a 5-byte header field, so every
    # round-trip always failed -- a latent foot-gun if re-wired. It was removed; only the live
    # secure-delete helper remains. Guard against reintroduction.
    src = _read("app/services/encrypted_file_storage.py")
    for gone in ("def encrypt_and_save", "def load_and_decrypt", "def verify_file_format", "MAGIC_BYTES"):
        assert gone not in src, f"removed whole-file crypto symbol reappeared: {gone}"
    assert "def secure_delete" in src, "the live secure_delete helper must remain"


def test_zk_seal_names_locks_vault_row():
    # Parity: zk_seal_names must serialize its seal-epoch read + writes under the SAME Vault-row lock its
    # siblings (rename_file / create_folder / retire_dek_versions) hold — otherwise a concurrent retire
    # could strand a name's member key and make the name permanently undecryptable.
    src = _read("app/api/api_server.py")
    start = src.index("async def zk_seal_names")
    end = src.index("\n@app.", start)   # up to the next route
    assert "with_for_update()" in src[start:end], \
        "zk_seal_names must lock the Vault row before reading the seal epoch (parity with its siblings)"


def test_dev_compose_hardening():
    dc = _read("deploy/docker-compose.yml")
    assert "vault_local_dev_pw" not in dc, "the source-controlled default DB password must be dropped"
    assert dc.count("- ALL") >= 2, "cap_drop [ALL] expected on both app services"
    assert "mem_limit:" in dc, "container memory ceilings expected"
    assert "pids_limit:" in dc
    assert "--requirepass" in dc, "redis requirepass wiring expected"


def test_secure_compose_hardening():
    sc = _read("deploy/docker-compose.secure.yml")
    assert sc.count("- ALL") >= 2, "cap_drop [ALL] expected on both app services"
    assert "mem_limit:" in sc
    assert "--requirepass" in sc
