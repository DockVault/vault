"""Offline unit tests for the general-API rate-limit CLASSIFIER (no app boot, DB, or network).

This is the layer that decides which per-user budget each endpoint draws from, and a misclassification
here silently throttled a real operation: every resumable-upload CHUNK PUT was funnelled into the
small operation-level 'upload' bucket (20/min), so any file over ~95 MiB got a 429 mid-upload. These
run in the offline/preflight lane so that class of bug is caught without CI or a live stack.
"""
import pytest

from app.core.rate_limiter import classify_api_rate_limit, API_RATE_LIMIT_CLASSES

pytestmark = pytest.mark.unit


def test_chunk_puts_are_their_own_high_volume_class():
    # THE regression guard: a chunk PUT must NOT share the operation-level 'upload' bucket, or a big
    # upload throttles itself mid-transfer.
    cls = classify_api_rate_limit("PUT", "/vaults/abc/uploads/sess1/chunks/42")
    assert cls == "upload_chunk", f"chunk PUT classified as {cls!r} (the 429-during-big-upload bug)"


def test_upload_init_and_complete_are_operation_class():
    assert classify_api_rate_limit("POST", "/vaults/abc/uploads") == "upload"        # resumable init
    assert classify_api_rate_limit("POST", "/vaults/abc/files") == "upload"           # direct multipart
    assert classify_api_rate_limit("POST", "/vaults/abc/uploads/sess1/complete") == "upload"


def test_download_class():
    assert classify_api_rate_limit("GET", "/vaults/abc/files/f1/download") == "download"


@pytest.mark.parametrize("path", [
    "/audit/events", "/audit/log", "/notifications", "/notifications/unread-count",
    "/monitor/stats", "/api/security/metrics", "/api/security/alerts", "/api/monitoring/metrics",
])
def test_polled_reads_are_poll_class(path):
    assert classify_api_rate_limit("GET", path) == "poll"
    assert classify_api_rate_limit("GET", path + "/") == "poll"   # trailing slash must not matter


def test_auth_class():
    assert classify_api_rate_limit("POST", "/auth/login") == "auth"
    assert classify_api_rate_limit("POST", "/auth/signup") == "auth"
    assert classify_api_rate_limit("POST", "/api/logout") == "auth"


def test_default_class_for_everything_else():
    assert classify_api_rate_limit("GET", "/vaults") == "default"
    assert classify_api_rate_limit("POST", "/shares") == "default"
    # poll is GET-only: a POST to a poll path stays default
    assert classify_api_rate_limit("POST", "/notifications") == "default"
    # a non-chunk PUT under /vaults is not upload_chunk
    assert classify_api_rate_limit("PUT", "/vaults/abc/files/f1") == "default"


def test_new_classes_are_registered():
    for cls in ("upload_chunk", "poll"):
        assert cls in API_RATE_LIMIT_CLASSES


def test_a_gigabyte_upload_only_touches_the_chunk_bucket():
    # ~205 chunk PUTs for a 1 GiB file at 5 MiB chunks — all must be 'upload_chunk', so the small
    # operation-level 'upload' bucket only ever sees init + complete (2 requests).
    classes = {classify_api_rate_limit("PUT", f"/vaults/v/uploads/s/chunks/{i}") for i in range(205)}
    assert classes == {"upload_chunk"}
