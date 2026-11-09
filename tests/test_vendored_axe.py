"""The vendored accessibility engine (tests/vendor/axe-core): the file is the one its README names, it sits
under tests/ only, and the image leaves it out."""
import hashlib
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "tests" / "vendor" / "axe-core"
SHA256 = "20c09fe157a8a34a30e241aaa1fcdade657734f08ab379ecfbeb7d45cc46e878"
VERSION = "4.14.0"


def test_the_vendored_file_is_the_one_its_readme_names():
    data = (VENDOR / "axe.min.js").read_bytes()
    assert hashlib.sha256(data).hexdigest() == SHA256
    assert data.startswith(f"/*! axe v{VERSION}".encode())
    readme = (VENDOR / "README.md").read_text(encoding="utf-8")
    assert SHA256 in readme and f"axe-core-{VERSION}.tgz" in readme


def test_its_licences_travel_with_it():
    assert (VENDOR / "LICENSE").read_text(encoding="utf-8").startswith("Mozilla Public License, version 2.0")
    assert "MIT License" in (VENDOR / "LICENSE-3RD-PARTY.txt").read_text(encoding="utf-8")


def test_it_is_a_test_file_only():
    # Never served: nothing under static/ is axe, and no page loads it.
    assert not list((ROOT / "static").rglob("axe*.js"))
    for page in (ROOT / "static").glob("*.html"):
        assert "axe" not in page.read_text(encoding="utf-8").lower().replace("maxe", ""), page.name
    # Never in the image: the build context leaves tests/ out.
    ignored = [line.strip() for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()]
    assert "tests/" in ignored
