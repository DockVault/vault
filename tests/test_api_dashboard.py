"""Dashboard, monitoring, and security/audit endpoints."""
import pytest


def test_dashboard_stats(admin):
    r = admin.get("/api/dashboard/stats")
    assert r.status_code == 200
    body = r.json()
    assert "role" in body


def test_dashboard_recent_events(admin):
    r = admin.get("/api/dashboard/recent-events", params={"limit": 5})
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_dashboard_active_connections_admin(admin):
    r = admin.get("/api/dashboard/active-connections")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_monitoring_metrics(admin):
    r = admin.get("/api/monitoring/metrics")
    assert r.status_code == 200
    body = r.json()
    for key in ("activeUsers", "totalFiles", "tempCreds"):
        assert key in body


def test_legacy_dashboard_stats_admin(admin):
    r = admin.get("/dashboard/stats")
    assert r.status_code == 200
    body = r.json()
    assert "total_users" in body
    assert "total_vaults" in body


# ---- security endpoints (admin-only) --------------------------------------
def test_security_metrics_admin(admin):
    r = admin.get("/api/security/metrics", params={"hours": 24})
    assert r.status_code == 200
    assert "failed_logins" in r.json()


def test_security_alerts_admin(admin):
    r = admin.get("/api/security/alerts", params={"limit": 10})
    assert r.status_code == 200
    assert "alerts" in r.json()


def test_security_metrics_forbidden_for_non_admin(temp_user_client):
    r = temp_user_client.get("/api/security/metrics")
    assert r.status_code == 403


def test_active_connections_forbidden_for_non_admin(temp_user_client):
    r = temp_user_client.get("/api/dashboard/active-connections")
    assert r.status_code == 403
