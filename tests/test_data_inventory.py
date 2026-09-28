"""docs/data-inventory.md stays a complete list an operator can put in a record of processing.

It says, for every store of personal data, which fields, why, for how long and how it is erased. An
inventory that silently misses the table a release adds is worse than none, because an operator
relies on it being whole. So every table the models declare must be named in it (the ones that hold
no personal data are named too, under "Other tables"), every setting it tells an operator to use must
be a real one, and the README and the security policy must point to it.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "docs" / "data-inventory.md"


def _text():
    return INVENTORY.read_text(encoding="utf-8")


def _entries(text):
    """The tables the inventory gives an entry: the first cell of a row in one of its tables, or the
    'Other tables' paragraph. A name mentioned in passing elsewhere (the release summary) is not one."""
    named = set()
    for line in text.splitlines():
        if line.startswith("| `"):
            named.update(re.findall(r"`([a-z_]+)`", line.split("|")[1]))
    assert text.count("\n### Other tables\n") == 1
    others = text.split("\n### Other tables\n", 1)[1].split("\n### ", 1)[0]
    named.update(re.findall(r"`([a-z_]+)`", others))
    return named


def test_every_table_the_models_declare_is_in_the_inventory():
    from app.core.models import Base

    tables = sorted(Base.metadata.tables)
    assert len(tables) > 50                     # the whole model, not a partial import
    entries = _entries(_text())
    missing = [t for t in tables if t not in entries]
    assert not missing, ("tables with no entry in docs/data-inventory.md; say what personal data "
                         f"each holds, or list it under 'Other tables': {missing}")


def test_every_setting_the_inventory_names_exists():
    text = _text()
    config = (ROOT / "app" / "core" / "config.py").read_text(encoding="utf-8")
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    names = sorted(set(re.findall(r"`([A-Z][A-Z0-9_]{3,})`", text)))
    assert "AUDIT_LOG_RETENTION_DAYS" in names and len(names) >= 8
    unknown = [n for n in names
               if not re.search(rf"^\s*{n.lower()}\s*:", config, re.M)
               and not re.search(rf"^#?\s*{n}=", example, re.M)]
    assert not unknown, f"the inventory names settings that do not exist: {unknown}"


def test_the_readme_and_the_security_policy_point_to_it():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    policy = (ROOT / ".github" / "SECURITY.md").read_text(encoding="utf-8")
    assert "](docs/data-inventory.md)" in readme
    assert "](../docs/data-inventory.md)" in policy
    assert (ROOT / "README.md").parent.joinpath("docs/data-inventory.md").is_file()
    assert (ROOT / ".github").joinpath("../docs/data-inventory.md").resolve().is_file()
