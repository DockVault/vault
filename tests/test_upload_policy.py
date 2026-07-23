"""Pure unit tests for app/core/upload_policy.py (no app/DB deps — imported by path)."""
import importlib.util
import pathlib

import pytest

pytestmark = pytest.mark.unit

_p = pathlib.Path(__file__).resolve().parents[1] / "app" / "core" / "upload_policy.py"
_spec = importlib.util.spec_from_file_location("upload_policy_under_test", _p)
up = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(up)


def test_parse_allowed_exts():
    assert up.parse_allowed_exts(None) is None
    assert up.parse_allowed_exts([]) is None
    assert up.parse_allowed_exts(["   "]) is None
    assert up.parse_allowed_exts("pdf") is None            # a non-list is "no restriction"
    assert up.parse_allowed_exts(["PDF", ".TxT", "png"]) == {"pdf", "txt", "png"}


def test_file_ext():
    assert up.file_ext("a.txt") == "txt"
    assert up.file_ext("archive.TAR.GZ") == "gz"
    assert up.file_ext("noext") == ""
    assert up.file_ext("") == ""


def test_file_type_allowed():
    assert up.file_type_allowed("a.pdf", None) is True     # no restriction
    assert up.file_type_allowed("a.pdf", {"pdf"}) is True
    assert up.file_type_allowed("a.exe", {"pdf"}) is False
    assert up.file_type_allowed("noext", {"pdf"}) is False
    assert up.file_type_allowed("noext", {""}) is True      # empty ext explicitly allowed


def test_effective_max_file_bytes():
    env = 1024 ** 3  # 1 GB
    assert up.effective_max_file_bytes(env, None) == env
    assert up.effective_max_file_bytes(env, 0) == env
    assert up.effective_max_file_bytes(env, "bad") == env
    assert up.effective_max_file_bytes(env, 100) == 100 * 1024 * 1024   # admin can lower it
    assert up.effective_max_file_bytes(env, 10 ** 9) == env             # can't raise above env
