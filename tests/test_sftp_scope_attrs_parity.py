"""The SFTP server copies every attribute a temporary credential's sign-in stamps on its account.

The SFTP server reloads the account on each operation and copies the credential's attributes onto it
from a list (SFTPServerInterface._SCOPE_ATTRS). An attribute attach_scope stamps and the list leaves
out reads as absent over SFTP: the credential's scope silently widens, or its audit rows lose the
credential's name. The list is read from the source, because importing the SFTP server starts its
runtime."""
import ast
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.temp_scope import attach_scope

pytestmark = pytest.mark.unit

SFTP = Path(__file__).resolve().parents[1] / "app" / "sftp" / "sftp_server.py"


def _copied_attrs():
    tree = ast.parse(SFTP.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "_SCOPE_ATTRS" for t in node.targets):
            return {e.value for e in node.value.elts if isinstance(e, ast.Constant)}
    raise AssertionError("_SCOPE_ATTRS not found")


def test_every_attribute_a_temporary_sign_in_stamps_is_copied_over_sftp():
    account = SimpleNamespace()
    credential = SimpleNamespace(id=uuid.uuid4(), temp_username="temp_contractor", scope=None,
                                 vault_access_mode="all", can_create_temp_credentials=False)
    attach_scope(None, account, credential)
    stamped = {k for k in vars(account) if k.startswith("_")}
    assert "_temp_cred_username" in stamped and account._temp_cred_username == "temp_contractor"
    assert stamped <= _copied_attrs(), stamped - _copied_attrs()
