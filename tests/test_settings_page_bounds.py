"""What the Settings page says about limits matches what the server enforces.

Two ways the page drifted from the server before: the session-length field refused values the
server accepts, and the SFTP file-limit note warned of a staging cap that streaming uploads -- the
default -- never meet.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from app.core import upload_policy

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
_MB = 1024 * 1024


def _arith(node):
    """Value of a constant expression made only of whole numbers, * and +."""
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        return _arith(node.left) * _arith(node.right)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _arith(node.left) + _arith(node.right)
    raise AssertionError("not a whole-number * / + expression: %s" % ast.dump(node))


def _server_constant(name):
    """A module-level arithmetic constant in api_server.py, read without importing the server."""
    tree = ast.parse((ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8"))
    hits = [n for n in tree.body if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    assert len(hits) == 1, name
    return _arith(hits[0].value)


def _input_attrs(element_id):
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    tags = re.findall(r'<input\b[^>]*\bid="%s"[^>]*>' % re.escape(element_id), html)
    assert len(tags) == 1, element_id
    return dict(re.findall(r'\b([a-z-]+)="([^"]*)"', tags[0]))


def test_the_session_length_field_offers_exactly_what_the_server_accepts():
    attrs = _input_attrs("setting-session-timeout")
    assert int(attrs["max"]) == _server_constant("SESSION_TIMEOUT_MAX_MINUTES") == 30 * 24 * 60
    assert 1 <= int(attrs["min"]) <= 5


@pytest.mark.parametrize("eff_bytes, tmpfs_mb, streaming, shown", [
    (10240 * _MB, 512, True, None),      # the default: streaming never stages, so no SFTP-only cap
    (10240 * _MB, 512, False, 512),      # buffered: the tmpfs is the lower cap
    (100 * _MB, 512, False, 100),        # buffered, admin limit below the tmpfs: that limit binds
    (0, 512, False, 512),                # no file-size limit configured: the tmpfs is the cap
    (10240 * _MB, 0, False, None),       # tmpfs unbounded / not mounted: nothing extra
])
def test_the_sftp_staging_cap_is_shown_only_when_an_upload_would_stage(eff_bytes, tmpfs_mb, streaming, shown):
    assert upload_policy.sftp_staging_cap_mb(eff_bytes, tmpfs_mb, streaming) == shown


def test_the_settings_response_takes_the_staging_cap_from_the_helper():
    """The GET /settings value comes from the one helper, fed the streaming flag -- the condition the
    SFTP upload path also uses before it applies its staging clamp."""
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
    assert code.count('data["sftp_effective_max_file_mb"] =') == 1
    assert code.count("_uploadp.sftp_staging_cap_mb(") == 1
    call = code[code.index("_uploadp.sftp_staging_cap_mb("):]
    call = call[:call.index(")") + 1]
    assert "settings.sftp_streaming_upload" in call and "settings.sftp_staging_tmpfs_mb" in call
    sftp = (ROOT / "app" / "sftp" / "sftp_server.py").read_text(encoding="utf-8")
    assert "if not settings.sftp_streaming_upload:\n                _eff_max = _staging_capped_max(" in sftp
