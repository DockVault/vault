"""The published release the setup scenario installs: the highest final one not above the checkout."""

from __future__ import annotations

import importlib.util
import io
import json
import random
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "pick_published_release", _ROOT / ".github" / "scripts" / "pick_published_release.py")
assert _SPEC and _SPEC.loader
_PICK = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _PICK
_SPEC.loader.exec_module(_PICK)


def _release(tag: str, *, draft: bool = False, prerelease: bool = False) -> dict:
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease}


def test_the_highest_version_wins_whatever_the_list_order():
    releases = [_release(t) for t in ("v0.32.6", "v0.33.0", "v0.9.0", "v0.33.1", "v0.10.0")]
    for seed in range(5):
        random.Random(seed).shuffle(releases)
        assert _PICK.pick(releases, "0.33.1") == "v0.33.1"


def test_a_maintenance_release_listed_first_does_not_displace_the_newer_line():
    """GitHub lists by creation time, so an older line's later patch comes first."""
    releases = [_release("v0.33.2"), _release("v0.34.0"), _release("v0.33.1")]

    assert _PICK.pick(releases, "0.34.0") == "v0.34.0"
    # On the maintenance branch itself, whose VERSION is on the older line, that line's release.
    assert _PICK.pick(releases, "0.33.2") == "v0.33.2"


def test_nothing_above_the_checkout_is_installed():
    releases = [_release("v0.34.0"), _release("v0.33.1")]

    assert _PICK.pick(releases, "0.33.5") == "v0.33.1"
    assert _PICK.pick(releases, "0.33.0") is None


def test_drafts_and_prereleases_are_not_published_releases():
    releases = [
        _release("v0.34.1", draft=True),
        _release("v0.34.0", prerelease=True),
        _release("v0.33.1"),
    ]

    assert _PICK.pick(releases, "0.34.1") == "v0.33.1"


def test_entries_that_are_not_final_releases_are_skipped():
    releases = [
        "not an object",
        {"tag_name": "v0.40.0"},                                   # no draft/prerelease flags
        {"tag_name": 7, "draft": False, "prerelease": False},
        _release("v0.40.0-rc1"),
        _release("0.40.0"),
        _release("v0.40"),
        _release("v00.1.0"),
        _release("v0.33.1"),
    ]

    assert _PICK.pick(releases, "1.0.0") == "v0.33.1"


def test_a_list_that_is_not_a_list_is_an_error():
    with pytest.raises(ValueError):
        _PICK.pick({"message": "API rate limit exceeded"}, "0.33.1")


def test_the_command_prints_the_tag_or_nothing(tmp_path, monkeypatch, capsys):
    version = tmp_path / "VERSION"
    version.write_bytes(b"0.34.0\n")

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(
        [_release("v0.33.2"), _release("v0.34.0")])))
    assert _PICK.main(["--version-file", str(version)]) == 0
    assert capsys.readouterr().out == "v0.34.0\n"

    monkeypatch.setattr(sys, "stdin", io.StringIO("[]"))
    assert _PICK.main(["--version-file", str(version)]) == 0
    assert capsys.readouterr().out == ""


def test_the_command_fails_on_unreadable_input(tmp_path, monkeypatch, capsys):
    version = tmp_path / "VERSION"
    version.write_bytes(b"0.34.0\n")

    for body in ("", "<html>", '{"message": "Bad credentials"}'):
        monkeypatch.setattr(sys, "stdin", io.StringIO(body))
        assert _PICK.main(["--version-file", str(version)]) == 2
        assert capsys.readouterr().out == ""
