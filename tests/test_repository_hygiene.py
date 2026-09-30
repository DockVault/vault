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



def test_semgrep_plugin_state_is_never_committed():
    """The Semgrep editor plugin writes its OAuth access and refresh tokens into .semgrep/ once
    someone signs in, so the directory must stay ignored and untracked."""
    ignored = subprocess.run(
        ["git", "check-ignore", "-q", ".semgrep/guardian.yml"], cwd=ROOT, check=False
    )
    assert ignored.returncode == 0
    assert not any(path.parts[0] == ".semgrep" for path in _tracked_relative_paths())


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


# --- what the public documents say about release lines -------------------------------------------
#
# Once a second line is supported, the published texts are what an operator acts on: which image
# tag follows their line, which lines get fixes, and what a rollback is protected from. Each claim
# below is enforced elsewhere: the tags by the release gate and workflow, the rollback mark by the
# data-requirements check, the approval rule by the credential-change code.

def _public(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_the_security_policy_states_the_lines_the_tags_and_the_backport_rule():
    policy = _public(".github/SECURITY.md")
    assert "| 0.33.x, the latest line | Yes |" in policy
    # The row it replaces read "The minor line before the latest, 0.33.x and later lines only".
    assert "0.33.x and later lines only" not in policy
    assert "until six\nmonths after the next minor release ships" in policy
    assert ("Low\n  findings are fixed in the next regular release, and in the supported previous "
            "line in the same\n  release window.") in policy
    assert "`ghcr.io/dockvault/vault:vX.Y.Z`, which never changes" in policy
    assert "tagged `:vX.Y` (for example `:v0.33`)" in policy
    assert "so a patch release of an older line never moves them" in policy
    assert "](../docs/guides/maintenance-releases.md)" in policy


def test_the_security_policy_and_readme_publish_the_accepted_approval_residuals():
    policy = _public(".github/SECURITY.md")
    readme = _public("README.md")
    assert "creates several administrator accounts and waits 14 days" in policy
    assert ("an administrator whose current password someone else set can still approve another\n"
            "  administrator's credential change") in policy
    assert "0.34.0 refuses such approvals." in policy
    assert ("until 0.34.0, an administrator whose current password someone else set\ncan still "
            "approve another administrator's change") in readme


def test_the_readme_names_the_line_tags_and_separates_end_of_life_from_support():
    readme = _public("README.md")
    assert "The newest release of each\nrelease line is also `:vX.Y`" in readme
    assert "(plus `:latest`)" not in readme
    assert "End-of-life is not the end of security support." in readme
    assert "](.github/SECURITY.md)" in readme
    assert "](docs/guides/maintenance-releases.md)" in readme


def test_the_readme_says_which_rollbacks_the_data_mark_protects():
    readme = _public("README.md")
    assert "From 0.33.1 on, an image also refuses to start on data a newer release has changed" in readme
    assert "0.33.0 and earlier do not read the mark, so a\nrollback to one of them is not protected" in readme
    assert "`ALLOW_START_ON_NEWER_DATA=true`" in readme


def test_the_supply_chain_document_describes_the_moving_tags_and_the_codeql_workflow():
    evidence = _public("docs/supply-chain-controls.md")
    assert "Both release tags must resolve to one registry digest" not in evidence
    assert "`:latest` only for\n  the highest version released" in evidence
    assert "No CodeQL workflow exists in source" not in evidence
    assert "(`.github/workflows/codeql.yml`)" in evidence and (ROOT / ".github/workflows/codeql.yml").is_file()


def test_the_maintenance_release_guide_exists_and_stays_public():
    guide = _public("docs/guides/maintenance-releases.md")
    for heading in ("## Release lines", "## Image tags", "## For an install on an older line",
                    "### What the release gate accepts", "### A fix on several lines",
                    "### After each release"):
        assert heading in guide
    assert "git cat-file -t vX.Y.Z" in guide and "git tag -a vX.Y.Z" in guide
    # Every script the guide tells a maintainer to run exists.
    for script in re.findall(r"\.github/scripts/[a-z_]+\.py", guide):
        assert (ROOT / script).is_file(), script
    # Written for anyone: no local paths (a Windows drive, or a drive as a shell mounts it), and no
    # short work-item codes (one or two capitals and a number).
    leak = re.search(r"[A-Z]:[\\/]|(?<![\w.])/[a-z]/|\b[A-Z]{1,2}[0-9]{1,2}[a-z]?\b", guide)
    assert leak is None, leak.group(0)


def test_every_test_file_a_docstring_names_exists():
    """A docstring that says another test file proves something live sends a reader to look for it.
    If that file was never written, or was renamed, the claim is empty and nothing says so."""
    import ast

    tests = ROOT / "tests"
    present = {p.name for p in tests.glob("*.py")}
    missing = []
    for path in sorted(tests.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        nodes = [tree] + [n for n in ast.walk(tree)
                          if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        for node in nodes:
            for name in re.findall(r"\btest_\w+\.py\b", ast.get_docstring(node) or ""):
                if name not in present:
                    missing.append(f"{path.name} names {name}")
    assert not missing, missing
