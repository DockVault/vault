"""Two read paths that consult file expiry, run rather than read.

tests/test_file_expiry.py pins that each read path applies the rule; a pin on the text stays green
with the filter moved somewhere it does nothing. These two are driven for real, against a session that
applies the filters it is given (tests/_memory_db.py), each with the file live, expired, and expired
while enforcement is postponed:

* claiming a file share (``_claim_resolved_share``): an expired file's share is refused as no longer
  available, the same answer as for a share whose vault has gone;
* SFTP's name lookup (``SFTPServerInterface._resolve_file``), which stat, open, remove and rename all
  go through: an expired file is not found, and a live file of the same name still is.

tests/test_file_expiry_live.py covers both on a running stack.
"""
import types
import uuid
from datetime import timedelta

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core import file_expiry  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.models import File, ShareClaim, Vault  # noqa: E402
from app.sftp import sftp_server as SFTP  # noqa: E402
from _memory_db import MemoryDB  # noqa: E402

pytestmark = pytest.mark.unit

NS = types.SimpleNamespace


@pytest.fixture(params=["live", "expired", "expired-postponed"])
def state(request, monkeypatch):
    monkeypatch.setattr(settings, "enforce_file_expiry", request.param != "expired-postponed")
    return request.param


def _deadline(state):
    now = file_expiry.utc_now()
    return now + timedelta(days=1) if state == "live" else now - timedelta(minutes=1)


# ---------------------------------------------------------------------------------------------
# Claiming a file share
# ---------------------------------------------------------------------------------------------


def test_a_file_share_whose_file_expired_cannot_be_claimed(monkeypatch, state):
    user = NS(id=uuid.uuid4())
    vault = NS(id=uuid.uuid4(), is_active=True, type="standard", password_hash=None)
    f = NS(id=uuid.uuid4(), vault_id=vault.id, expires_at=_deadline(state))
    share = NS(id=uuid.uuid4(), vault_id=vault.id, target_type="file", target_file_id=f.id,
               status="active", expires_at=None, claim_audience="anyone_internal",
               audience_user_ids=None, audience_department_ids=None)
    # The recipient claimed it before, so a claim that gets past the checks re-opens that one.
    claim = NS(id=uuid.uuid4(), share_id=share.id, user_id=user.id, revoked=False)
    db = MemoryDB({Vault: [vault], File: [f], ShareClaim: [claim]})
    monkeypatch.setattr(S, "_user_group_ids", lambda db, uid: [])
    monkeypatch.setattr(S, "_share_claim_dict", lambda c, s: {"reopened": str(c.id)})

    if state == "expired":
        with pytest.raises(HTTPException) as refused:
            S._claim_resolved_share(db, share, user, request=None)
        assert refused.value.status_code == 403
        assert refused.value.detail == "That share is no longer available."
    else:
        assert S._claim_resolved_share(db, share, user, request=None) == {"reopened": str(claim.id)}


# ---------------------------------------------------------------------------------------------
# SFTP's name lookup
# ---------------------------------------------------------------------------------------------


def test_sftp_does_not_find_an_expired_file(monkeypatch, state):
    monkeypatch.setattr(SFTP, "name_blind_index", lambda vault_id, name: f"bi:{name}")
    vid = uuid.uuid4()
    now = file_expiry.utc_now()

    def _file(name, created, expires_at):
        return NS(id=uuid.uuid4(), vault_id=vid, folder_id=None, name=name, original_name=name,
                  name_bi=f"bi:{name}", created_at=created, expires_at=expires_at)

    # Two rows of one name: the lookup takes the newest, which is the one that may have expired.
    older = _file("report.pdf", now - timedelta(days=2), None)
    newer = _file("report.pdf", now - timedelta(days=1), _deadline(state))
    alone = _file("alone.txt", now - timedelta(days=1), _deadline(state))
    db = MemoryDB({File: [older, newer, alone]})

    def resolve(name):
        return SFTP.SFTPServerInterface._resolve_file(None, db, vid, None, name)

    if state == "expired":
        assert resolve("alone.txt") is None
        assert resolve("report.pdf") is older, "the live file of that name is still found"
    else:
        assert resolve("alone.txt") is alone
        assert resolve("report.pdf") is newer
