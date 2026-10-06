"""Sealed compliance text on a running stack's Postgres (app/core/security.py, seal_case_field).

A case written with the deployment's own ENCRYPTION_KEY opens back in the web container, and a dump of the
whole database holds none of its text. test_case_sealing.py covers the construction offline.
"""
import subprocess
import uuid

import pytest

from _account_change_helpers import DB, in_api_container, psql
from conftest import skip_if_container_absent

_WRITE = """
import sys, uuid
from app.core import security
from app.core.database import SessionLocal
from app.core.models import ComplianceCase, User
case_id, marker = uuid.UUID(sys.argv[1]), sys.argv[2]
db = SessionLocal()
try:
    admin = db.query(User).filter(User.username == 'admin').one()
    db.add(ComplianceCase(id=case_id, purpose='internal_investigation', legal_basis='f', auditor_id=admin.id,
                          auditor_username=admin.username,
                          justification_enc=security.seal_case_field(case_id, marker + '-justification', 'justification'),
                          owner_note_enc=security.seal_case_field(case_id, marker + '-note', 'owner_note'),
                          objection_enc=security.seal_case_field(case_id, marker + '-objection', 'objection')))
    db.commit()
    row = db.get(ComplianceCase, case_id)
    print('OPENED', security.open_case_field(case_id, row.justification_enc, 'justification'))
finally:
    db.close()
"""


def test_a_sealed_case_opens_back_and_a_dump_of_the_database_holds_none_of_its_text():
    case_id, marker = uuid.uuid4(), f"SEALCHECK{uuid.uuid4().hex[:12]}"
    script = _WRITE.replace("sys.argv[1]", repr(str(case_id))).replace("sys.argv[2]", repr(marker))
    try:
        out = in_api_container(script).stdout
        assert f"OPENED {marker}-justification" in out
        assert psql(f"SELECT count(*) FROM compliance_cases WHERE id = '{case_id}' "
                    "AND justification_enc LIKE 'cenc1:%' AND owner_note_enc LIKE 'cenc1:%'") == "1"
        try:
            dump = subprocess.run(["docker", "exec", DB, "pg_dump", "-U", "sftp_user", "-d", "sftp_db",
                                   "--data-only"], capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=300)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            pytest.skip(f"docker unavailable: {exc}")
        skip_if_container_absent(dump, DB)
        assert dump.returncode == 0, dump.stderr[-400:]
        assert str(case_id) in dump.stdout          # the dump does hold the case's row
        assert marker not in dump.stdout
    finally:
        psql(f"DELETE FROM compliance_cases WHERE id = '{case_id}'")
