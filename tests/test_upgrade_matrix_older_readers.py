"""What earlier releases' readers make of main's matrix once references below the id-only boundary
carry only the advisory id.

Every deployed host tool and running app reads main's docs/upgrade-matrix.json, so the short form is
safe only if none of them tells an operator something different, apart from the two costs stated
below for the host tools of 0.30.0 to 0.32.x: a release below the boundary asked for by name, and a
container running one. The in-app check is not affected: up to 0.26.0 it reads no findings, and
from 0.27.0 on it reads only those of the release it runs. The readers are taken from the
release tags themselves (`git show vX.Y.Z:...`), not copied, so the check is against the code that
is actually installed. The two forms compared are the committed matrix with every reference written
out in full and the same matrix shortened by `matrix_sync.py compact`; whichever form is committed,
the comparison stays meaningful.

These tests need the release tags, as the other matrix tests do: a checkout without them fails.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[1]
_MATRIX = _ROOT / "docs" / "upgrade-matrix.json"
_RELEASE_TAG = re.compile(r"v((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2})", re.ASCII)

#: The host tools whose update list merges main's matrix into their own copy and prints a line per
#: release from each reference's own title and fixed_in: the first and the last release of that code.
_HOST_TOOLS = ("v0.30.0", "v0.32.6")
#: The host tools that end the description of a move with what it fixes and what it brings back,
#: comparing the running version's list with the target's: the first and the last release of that code.
_MOVE_SUMMARY_TOOLS = ("v0.31.0", "v0.32.6")
#: The first release whose readers take a short reference's title and fix from its advisory.
_FIRST_ID_READER = "v0.33.0"
#: How many releases the host tools of 0.30.0 to 0.32.x list (`offered[:15]`).
_LISTED = 15


def _load_file(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_SYNC = _load_file("matrix_sync_for_older_readers", _ROOT / ".github" / "scripts" / "matrix_sync.py")
_UM = _SYNC._validator()


def _vkey(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.lstrip("v").split("."))


def _at(tag: str, path: str) -> bytes:
    done = subprocess.run(["git", "-C", str(_ROOT), "show", f"{tag}:{path}"],
                          capture_output=True, check=False)
    if done.returncode != 0:
        pytest.fail(f"cannot read {path} at {tag} ({done.stderr.decode(errors='replace').strip()}); "
                    "these tests need the release tags (a full clone with tags)")
    return done.stdout


@pytest.fixture(scope="module")
def shipped(tmp_path_factory):
    """Loads a file as it shipped in a release tag, as a module of its own."""
    directory = tmp_path_factory.mktemp("shipped")

    def load(tag: str, path: str):
        name = f"{Path(path).stem}_{tag.replace('.', '_')}"
        copy_of = directory / tag / Path(path).name
        copy_of.parent.mkdir(parents=True, exist_ok=True)
        copy_of.write_bytes(_at(tag, path))
        return _load_file(name, copy_of)

    return load


def _released_tags() -> list[str]:
    """Every release tag, newest first, as the host tools list them."""
    done = subprocess.run(["git", "-C", str(_ROOT), "tag", "-l", "v*"],
                          capture_output=True, text=True, check=True)
    tags = [t for t in done.stdout.split() if _RELEASE_TAG.fullmatch(t)]
    if _FIRST_ID_READER not in tags:
        pytest.fail(f"no {_FIRST_ID_READER} tag in this checkout; these tests need the release tags")
    return sorted(tags, key=_vkey, reverse=True)


def _written_out(matrix: dict) -> dict:
    """The matrix with every short reference written out from its advisory."""
    result = copy.deepcopy(matrix)
    for entry in result["versions"].values():
        refs = entry.get("vulnerabilities") or []
        for position, ref in enumerate(refs):
            if set(ref) == {"advisory"}:
                advisory = result["advisories"][ref["advisory"]]
                refs[position] = {"advisory": ref["advisory"], "title": advisory["title"],
                                  "fixed_in": advisory["fixed_in"]}
    return result


@pytest.fixture(scope="module")
def forms() -> dict:
    committed = json.loads(_MATRIX.read_bytes())
    full = _written_out(committed)
    short, shortened = _SYNC.compact(full)
    assert shortened > 0, "nothing below the boundary to shorten, so nothing here is compared"
    return {"full": full, "short": short}


def _pairs(reader, matrix: dict, version: str) -> list[tuple]:
    return sorted(((v.get("title"), v.get("fixed_in")) for v in reader(matrix, version)), key=repr)


@pytest.mark.parametrize("newer", [(), ("v0.33.1", "v0.33.2")], ids=["as-released", "two-later"])
@pytest.mark.parametrize("tool_tag", _HOST_TOOLS)
def test_an_older_host_tool_lists_the_same_releases_with_the_same_notes(tool_tag, newer, forms,
                                                                        shipped):
    """`dockvault.py update` of 0.30.0 to 0.32.x: the list of releases and the note beside each.

    The list is the 15 newest release tags that its own matrix does not mark end-of-life, and each
    note is support_line() over its own matrix merged with main's. A later release only moves the
    list up, so the case with two more releases shows the boundary keeps holding.
    """
    tool = shipped(tool_tag, "dockvault.py")
    local = json.loads(_at(tool_tag, "docs/upgrade-matrix.json"))
    tags = sorted(set(_released_tags()) | set(newer), key=_vkey, reverse=True)
    listed = [t for t in tags if not tool.is_eol(local, t)][:_LISTED]
    assert _vkey(listed[-1]) >= _vkey(_UM.ID_ONLY_REFERENCES_BELOW), (
        f"the {tool_tag} host tool lists {listed[-1]}, below the id-only boundary")

    printed = {}
    for name, main in forms.items():
        merged, source = tool.merge_lifecycle_matrix(local, main, tags[0])
        assert source == "main"
        printed[name] = [(t, tool.support_line(merged, t)) for t in listed]
        if hasattr(tool, "_declares_version"):
            # From 0.31.0 the list ends with a warning when every release in it is affected.
            printed[name].append(all(tool.version_vulnerabilities(merged, t) for t in listed
                                     if tool._declares_version(merged, t)))

    assert printed["short"] == printed["full"]


@pytest.mark.parametrize("tool_tag", _HOST_TOOLS)
def test_an_older_host_tool_asked_for_an_older_release_still_warns(tool_tag, forms, shipped):
    """`dockvault.py update --tag vX` of 0.30.0 to 0.32.x, for a release below the boundary.

    The first accepted cost of the short form. The tool merges main's references into its own by (title,
    fixed_in), and a short reference has neither, so the advisories its own copy already knew are
    shown as before and those published later collapse into one entry without a title that reads
    "no fix released yet". The release is still reported as not secure, and nothing names a fix
    that the full form does not name. From the boundary on, nothing changes.
    """
    tool = shipped(tool_tag, "dockvault.py")
    local = json.loads(_at(tool_tag, "docs/upgrade-matrix.json"))
    tags = _released_tags()
    targets = [t for t in tags if not tool.is_eol(local, t)]
    below = [t for t in targets if _vkey(t) < _vkey(_UM.ID_ONLY_REFERENCES_BELOW)]
    assert below, "no release below the boundary is offered, so nothing here is compared"
    merged = {name: tool.merge_lifecycle_matrix(local, main, tags[0])[0]
              for name, main in forms.items()}

    for target in targets:
        full = _pairs(tool.version_vulnerabilities, merged["full"], target)
        short = _pairs(tool.version_vulnerabilities, merged["short"], target)
        if target not in below:
            assert short == full, target
            continue
        assert tool.version_support(merged["short"], target).get("secure") is False, target
        assert short, target
        assert set(short) - set(full) <= {(None, None)}, target


def _move(tool, matrix: dict, current: str, target: str) -> tuple[int, set]:
    """What the host tool says a move does: how many of the running version's findings the target
    does not have, and which of the target's findings the running version does not have, both by
    (title, fixed_in) as the tool compares them."""
    now = {(v.get("title"), v.get("fixed_in")) for v in tool.version_vulnerabilities(matrix, current)}
    after = [(v.get("title"), v.get("fixed_in")) for v in tool.version_vulnerabilities(matrix, target)]
    return len(now - set(after)), {key for key in after if key not in now}


@pytest.mark.parametrize("tool_tag", _MOVE_SUMMARY_TOOLS)
def test_an_older_host_tool_on_an_older_running_release_misreads_only_its_own_findings(
        tool_tag, forms, shipped):
    """`dockvault.py update` of 0.31.0 to 0.32.x on a host whose container runs a release below
    the boundary (a checkout newer than the running release).

    The second accepted cost of the short form. After the target's own warnings the tool says what
    the move fixes and what it brings back, comparing the running version's findings with the
    target's by (title, fixed_in). The running version's short references collapse into one entry
    without a title, so "Moving to vX fixes N known vulnerabilities" counts wrong (for the newest
    release far too few), and a target that is itself affected is said, in red, to bring back
    findings that the running version has as well. Nothing it names as brought back is missing
    from the running version, nothing really brought back goes unnamed, and a target with no
    findings is never said to bring anything back. From the boundary on, nothing changes.
    """
    tool = shipped(tool_tag, "dockvault.py")
    local = json.loads(_at(tool_tag, "docs/upgrade-matrix.json"))
    tags = _released_tags()
    listed = [t for t in tags if not tool.is_eol(local, t)][:_LISTED]
    merged = {name: tool.merge_lifecycle_matrix(local, main, tags[0])[0]
              for name, main in forms.items()}
    boundary = _vkey(_UM.ID_ONLY_REFERENCES_BELOW)
    said_brought_back = 0

    for current in forms["full"]["versions"]:
        if not tool._declares_version(merged["short"], current):
            continue
        has = {(v.get("title"), v.get("fixed_in"))
               for v in tool.version_vulnerabilities(merged["full"], current)}
        for target in listed:
            full_fixed, full_back = _move(tool, merged["full"], current, target)
            short_fixed, short_back = _move(tool, merged["short"], current, target)
            if _vkey(current) >= boundary:
                assert (short_fixed, short_back) == (full_fixed, full_back), (current, target)
                continue
            assert full_back <= short_back, (current, target)
            assert short_back - full_back <= has, (current, target)
            if not tool.version_vulnerabilities(merged["full"], target):
                assert not short_back, (current, target)
            said_brought_back += len(short_back - full_back)

    assert said_brought_back, "no move below the boundary misreads anything; restate this cost"


@pytest.mark.parametrize("reader", [
    pytest.param((_FIRST_ID_READER, "dockvault.py", "version_vulnerabilities"),
                 id="host-tool-0.33.0"),
    pytest.param((_FIRST_ID_READER, "app/services/update_check.py", "_version_vulnerabilities"),
                 id="in-app-0.33.0"),
    pytest.param((None, "dockvault.py", "version_vulnerabilities"), id="host-tool-this-tree"),
    pytest.param((None, "app/services/update_check.py", "_version_vulnerabilities"),
                 id="in-app-this-tree"),
])
def test_readers_from_0_33_0_resolve_the_same_title_and_fix_on_every_version(reader, forms,
                                                                            shipped):
    tag, path, function = reader
    if tag is None:
        module = _load_file(f"{Path(path).stem}_this_tree", _ROOT / path)
    else:
        module = shipped(tag, path)
    read = getattr(module, function)

    for version in forms["full"]["versions"]:
        assert _pairs(read, forms["short"], version) == _pairs(read, forms["full"], version), version
