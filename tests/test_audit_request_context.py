"""Audit rows carry the channel a request came in on, and its method, route and user agent.

The web process sets a request context per HTTP request; the SFTP process sets a process default channel.
AuditLogger fills the row from them when the caller did not say. A route template is stored, never the
raw path, which for a link route holds its token.
"""
import pytest

from app.core import request_context as rc
from app.services.audit_logger import AuditLogger

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("path, channel", [
    ("/l/abcdefghij", "public_link"),
    ("/note-links/abcdefghij/redeem", "public_link"),
    ("/p/abcdefghij", "public_link"),
    ("/public-links/abcdefghij/redeem", "public_link"),
    ("/public-links/abcdefghij/download/0f0e", "public_link"),
    ("/u/abcdefghij", "upload_link"),
    ("/receivers/abcdefghij/upload-session", "upload_link"),
    ("/receivers/abcdefghij/upload-session/s1/chunks/0", "upload_link"),
    ("/devices", "device_sync"),
    ("/devices/7/grants", "device_sync"),
    # The owner's own management routes for links are the web app.
    ("/note-links", "web"),
    ("/note-links/7/revoke", "web"),
    ("/public-links/7/revoke", "web"),
    ("/receivers", "web"),
    ("/receivers/7/pause", "web"),
    ("/vaults/1/files", "web"),
    ("/devicesx", "web"),
    ("/", "web"),
])
def test_a_path_maps_to_its_channel(path, channel):
    assert rc.channel_for_path(path) == channel


class _Route:
    path = "/vaults/{vault_id}/files/{file_id}/download"


def test_the_endpoint_is_the_route_template_once_routing_has_run():
    scope = {}
    ctx = rc.RequestContext("GET", "/vaults/1/files/2/download", "curl/8", "web", scope)
    assert ctx.endpoint == "/vaults/1/files/2/download"      # before routing
    scope["route"] = _Route()                                 # routing fills the same scope
    assert ctx.endpoint == "/vaults/{vault_id}/files/{file_id}/download"


def test_an_unrouted_link_path_is_stored_without_its_token():
    ctx = rc.RequestContext("GET", "/l/SeCrEtToKeN123", None, "public_link", {})
    assert "SeCrEtToKeN123" not in (ctx.endpoint or "")


def test_long_values_are_bounded_to_their_columns():
    ctx = rc.RequestContext("GET", "/" + "a" * 900, "x" * 2000, "web", {})
    assert len(ctx.user_agent) == rc.MAX_USER_AGENT
    assert len(ctx.endpoint) <= rc.MAX_ENDPOINT


class _FakeDB:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        pass


def _row(**kwargs):
    db = _FakeDB()
    AuditLogger(db).log_action(action="file_download", status="success", **kwargs)
    return db.added[0]


def test_a_row_written_during_a_request_carries_the_request():
    scope = {"route": _Route()}
    token = rc.set_request_context(rc.RequestContext("GET", "/vaults/1/files/2/download", "Mozilla/5.0", "web", scope))
    try:
        row = _row()
    finally:
        rc.reset_request_context(token)
    assert (row.channel, row.method, row.endpoint, row.user_agent) == (
        "web", "GET", "/vaults/{vault_id}/files/{file_id}/download", "Mozilla/5.0")


def test_what_the_caller_says_wins_over_the_context():
    token = rc.set_request_context(rc.RequestContext("GET", "/x", "ua", "web", {}))
    try:
        row = _row(channel="sftp", method="PUT", endpoint="/y", user_agent="other")
    finally:
        rc.reset_request_context(token)
    assert (row.channel, row.method, row.endpoint, row.user_agent) == ("sftp", "PUT", "/y", "other")


def test_a_row_outside_any_request_uses_the_process_channel():
    try:
        rc.set_process_default_channel(None)
        assert _row().channel is None
        rc.set_process_default_channel("sftp")
        assert _row().channel == "sftp"
        rc.set_process_default_channel("not-a-channel")
        assert _row().channel is None
    finally:
        rc.set_process_default_channel(None)


def test_an_unknown_channel_from_a_caller_is_not_stored():
    token = rc.set_request_context(rc.RequestContext("GET", "/x", None, "web", {}))
    try:
        assert _row(channel="made-up").channel == "web"
    finally:
        rc.reset_request_context(token)


class _NameDB(_FakeDB):
    """A fake session that answers the username lookup for one id."""

    def __init__(self, users):
        super().__init__()
        self.users, self.asked = users, []

    def query(self, *_cols):
        db = self

        class _Q:
            def filter(self, cond):
                db.asked.append(cond.right.value)
                return self

            def scalar(self):
                return db.users.get(db.asked[-1])
        return _Q()


def test_a_row_given_only_a_user_id_stores_the_name_too():
    import uuid
    uid = uuid.uuid4()
    db = _NameDB({uid: "maria"})
    AuditLogger(db).log_action(action="device_refresh", status="success", user_id=uid)
    assert db.added[0].username == "maria" and db.asked == [uid]
    db = _NameDB({uid: "maria"})
    AuditLogger(db).log_action(action="device_refresh", status="success", user_id=uid, username="given")
    assert db.added[0].username == "given" and db.asked == []        # a name the caller gave is kept


def test_a_row_without_an_address_takes_the_requests():
    from app.core import net_utils
    token = net_utils.set_client_ip("198.51.100.23")
    try:
        assert _row().ip_address == "198.51.100.23"
        assert _row(ip_address="203.0.113.5").ip_address == "203.0.113.5"      # the caller's wins
    finally:
        net_utils.reset_client_ip(token)
    assert _row().ip_address is None                                          # outside a request
