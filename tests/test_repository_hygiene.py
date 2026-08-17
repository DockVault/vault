"""Byte-level guards for the repository's tracked text and binary contract."""

import re
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


ROOT = Path(__file__).resolve().parent.parent
TEXT_SUFFIXES = {
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".txt",
    ".yaml",
    ".yml",
}
TEXT_NAMES = {
    ".dockerignore",
    ".editorconfig",
    ".env.example",
    ".gitattributes",
    ".gitignore",
    "Dockerfile",
    "LICENSE",
    "VERSION",
}
BINARY_SUFFIXES = {".png", ".woff2"}
BOMS = (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")
SEMVER_LF = re.compile(
    rb"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\n"
)



def _tracked_relative_paths() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [
        Path(raw.decode("utf-8"))
        for raw in result.stdout.split(b"\0")
        if raw
    ]


def _is_contract_text(path: Path) -> bool:
    return (
        path.name in TEXT_NAMES
        or path.name.startswith("Dockerfile.")
        or path.suffix.lower() in TEXT_SUFFIXES
    )


def _attributes(paths: list[Path], *names: str) -> dict[Path, dict[str, str]]:
    result = subprocess.run(
        ["git", "check-attr", "-z", *names, "--", *(path.as_posix() for path in paths)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    fields = result.stdout.decode("utf-8").split("\0")
    if fields and not fields[-1]:
        fields.pop()
    assert len(fields) % 3 == 0, f"unexpected git check-attr output: {fields!r}"
    values: dict[Path, dict[str, str]] = {}
    for index in range(0, len(fields), 3):
        path, name, value = fields[index:index + 3]
        values.setdefault(Path(path), {})[name] = value
    return values


def test_tracked_text_contract_is_explicit_and_bytes_are_clean():
    errors = []
    paths = [path for path in _tracked_relative_paths() if _is_contract_text(path)]
    attributes = _attributes(paths, "text", "eol")

    for path in paths:
        attrs = attributes.get(path, {})
        if attrs.get("text") != "set" or attrs.get("eol") != "lf":
            errors.append(f"{path}: expected explicit text/eol=lf attributes, got {attrs}")

        data = (ROOT / path).read_bytes()
        if data.startswith(BOMS):
            errors.append(f"{path}: byte-order mark is forbidden")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            errors.append(f"{path}: not strict UTF-8 ({exc})")
        if path.suffix.lower() == ".ps1" and not data.isascii():
            errors.append(f"{path}: PowerShell scripts must remain ASCII")
        if b"\r" in data:
            errors.append(f"{path}: CR or CRLF line ending found")
        if data and not data.endswith(b"\n"):
            errors.append(f"{path}: final LF is required")

    assert not errors, "\n".join(errors)


def test_version_is_exact_ascii_semver_with_one_lf():
    data = (ROOT / "VERSION").read_bytes()
    assert SEMVER_LF.fullmatch(data), (
        "VERSION must contain only canonical ASCII X.Y.Z followed by one LF; "
        f"got {data!r}"
    )


def test_tracked_binary_assets_are_explicitly_non_text():
    paths = [
        path
        for path in _tracked_relative_paths()
        if path.suffix.lower() in BINARY_SUFFIXES
    ]
    assert paths, "binary asset inventory unexpectedly empty"
    attributes = _attributes(paths, "text")
    errors = [
        f"{path}: expected binary/-text attribute, got {attributes.get(path, {})}"
        for path in paths
        if attributes.get(path, {}).get("text") != "unset"
    ]
    assert not errors, "\n".join(errors)


# --- what the README says about migrations ------------------------------------------------------
#
# A security product must not understate what it does to an operator's database. The README used to
# say the app "does not yet alter existing columns automatically" while it was altering them
# extensively -- adding columns and indexes, tightening constraints, converting types, and rewriting
# data -- and to promise that "a release that changes the schema will call out the migration step in
# its notes", which nothing produced or enforced. Both are retired; these keep them retired.

RETIRED_README_CLAIMS = (
    "does **not** yet alter",
    "will call out the migration step",
)


def test_the_readme_no_longer_understates_what_boot_does_to_the_database():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    still_there = [claim for claim in RETIRED_README_CLAIMS if claim in readme]
    assert not still_there, (
        "the README has gone back to claiming %s. The app does alter existing columns on boot, and "
        "the release notes do not describe the migration -- docs/upgrade-matrix.json does, and the "
        "release gate enforces it." % still_there)


def test_the_readme_describes_the_machinery_that_replaced_those_claims():
    """The other half. Deleting a false claim and saying nothing is not the same as being honest.

    Each of these corresponds to something enforced elsewhere in the suite: the health state, the
    forward-only contract, the descriptor, and the tool that reads it.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for promised in ("forward-only", "upgrade-matrix.json", "dockvault.py update", "503"):
        assert promised in readme, (
            "the README no longer mentions %r. If that machinery has been removed, the claims it "
            "replaced need revisiting too; if it is only the wording, restore it." % promised)


def test_the_contributor_rules_require_a_schema_change_to_declare_itself():
    """The rule that keeps the descriptor honest, next to the existing config-sync rule.

    The release gate refuses an undeclared version, so this is not what makes it happen -- it is
    what stops the description being written weeks later from memory, at release time.
    """
    guide = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    assert "docs/upgrade-matrix.json" in guide, (
        "CLAUDE.md no longer tells a contributor to declare a schema change; the release gate will "
        "catch it, but only after the fact")
    assert "ADD COLUMN IF NOT EXISTS` is a no-op" in guide or "no-op where the column already" in guide, (
        "the note about ADD COLUMN not tightening an existing column is gone. That is the mistake "
        "that put two columns out of step for several releases")
