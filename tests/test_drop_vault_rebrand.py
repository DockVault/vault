"""The open upload-link tag is seeded as "Drop vault" — and no existing tag is ever renamed.

The rename itself is one string. The risk is the other half: a deployment that already exists must
come through an upgrade with its tags exactly as they were, because an admin may have renamed,
re-described or built policy around them. So this pins the seed AND the absence of any statement that
would rewrite tags already in the database.

"New deployments only" holds by construction here rather than by a flag: the starter catalog is
written by `_seed_default_receiver_tags`, which `should_seed_default_receiver_tags` allows only when
there are no receiver tags at all AND receivers were never explicitly enabled. Nothing else writes a
tag name except the admin-facing create/rename endpoints, which are a person acting deliberately.

A consequence worth stating, because it looks like an inconsistency and is not: which name a running
deployment shows tells you when it was seeded. Fresh installs say "Drop vault"; anything seeded
before the rename still says "Drop box", and that is the correct outcome, not drift.
"""
import re
from pathlib import Path

import pytest

from app.core import receiver_policy as rp

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.unit
def test_the_seeded_open_tag_is_named_drop_vault():
    names = {t["name"] for t in rp.DEFAULT_RECEIVER_TAGS}
    assert "Drop vault" in names, f"the starter catalog should seed a Drop vault tag: {names}"
    assert "Drop box" not in names, f"the old name is still being seeded: {names}"


@pytest.mark.unit
def test_seeding_is_still_restricted_to_a_fresh_deployment():
    """The guard that makes this a new-deployment change rather than a rename."""
    assert rp.should_seed_default_receiver_tags(has_existing_tags=False,
                                                receivers_already_enabled=False) is True
    # Any sign of prior use must stop it. Both are checked: an install with tags already, and one
    # where receivers were turned on deliberately before any tag existed.
    assert rp.should_seed_default_receiver_tags(has_existing_tags=True,
                                                receivers_already_enabled=False) is False
    assert rp.should_seed_default_receiver_tags(has_existing_tags=False,
                                                receivers_already_enabled=True) is False
    assert rp.should_seed_default_receiver_tags(has_existing_tags=True,
                                                receivers_already_enabled=True) is False


@pytest.mark.unit
def test_nothing_renames_a_tag_that_already_exists():
    """The half that would turn a rebrand into a data migration.

    A rename shipped as a startup statement would look harmless in review and would quietly rewrite
    a name an admin had chosen. There must be no such statement.
    """
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")

    # No bulk SQL against the tag table's name column.
    bulk = re.findall(r'"UPDATE receiver_tags[^"]*"', src)
    assert not bulk, f"a startup statement rewrites receiver tags: {bulk}"

    # And no targeted rename of the old name anywhere in the application.
    for path in (ROOT / "app").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r'name\s*=\s*["\']Drop vault["\'].*Drop box', text), (
            f"{path.name} appears to rewrite the old tag name")
        assert "Drop box" not in text or path.name == "receiver_policy.py", (
            f"{path.name} still mentions the old name; it should only survive in deployments that "
            f"already have it, never in shipped code")
