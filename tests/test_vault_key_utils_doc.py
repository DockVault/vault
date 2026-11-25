"""What app/core/vault_key_utils.py says of itself stays true of the code.

Its docstring once promised a key per vault that isolates vaults from each other, a vault password that adds
a layer of encryption, and keys that rotate per vault. None held: no read or write of a vault's content uses
the key the module makes, file contents are keyed from ENCRYPTION_KEY, and the rotation route refuses. A reader
who trusts a module's own account of its security should find there what the code does, so the docstring
names where content is really keyed, and the readers of the stored key stay without a caller.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "app" / "core" / "vault_key_utils.py"


def _docstring():
    import app.core.vault_key_utils as module

    return module.__doc__ or ""


def test_the_docstring_promises_no_isolation_or_layer_the_code_does_not_give():
    doc = _docstring()
    for promise in ("Vault isolation", "Password + encryption layers", "Can rotate keys per-vault",
                    "Each vault has a unique encryption key"):
        assert promise not in doc, promise


def test_the_docstring_names_where_content_is_keyed_and_why_rotation_refuses():
    doc = _docstring()
    assert "ENCRYPTION_KEY" in doc and "_gcm_stream_subkey" in doc
    assert "rotate_vault_encryption_key" in doc and "password_hash" in doc
    # The names it points to are there to be found.
    security = (ROOT / "app" / "core" / "security.py").read_text(encoding="utf-8")
    assert re.search(r"^def _gcm_stream_subkey\(", security, re.M)
    server = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert re.search(r"^async def rotate_vault_encryption_key\(", server, re.M)


def test_nothing_outside_the_module_reads_content_with_the_stored_key():
    # The docstring says no read or write of a vault's content uses this key; these are the module's readers of it.
    readers = ("get_vault_fernet", "get_vault_key_bytes", "get_vault_key_for_version")
    module_source = MODULE.read_text(encoding="utf-8")
    assert all(f"def {name}(" in module_source for name in readers)
    callers = sorted(f"{path.relative_to(ROOT).as_posix()}: {name}"
                     for path in (ROOT / "app").rglob("*.py") if path != MODULE
                     for name in readers if name in path.read_text(encoding="utf-8"))
    assert not callers, f"code outside the module now reads the stored vault key: {callers}"
