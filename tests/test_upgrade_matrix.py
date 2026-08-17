"""The upgrade matrix, and the gate that makes it complete.

`docs/upgrade-matrix.json` says what it takes to move between released versions. Its worth rests
entirely on being complete -- a claim about upgrading means nothing if a release can decline to make
one -- so the release gate refuses to cut a tag whose version is absent from it.

These tests cover three things: that the committed file is valid and says what it should, that the
validator rejects each way of getting it wrong, and that the gate fails closed. The override that
lets a security fix ship without a declaration is tested for what it does NOT waive as much as for
what it does.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "docs" / "upgrade-matrix.json"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / ".github" / "scripts" / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


um = _load("upgrade_matrix_under_test", "upgrade_matrix.py")
gate = _load("release_gate_under_test", "release_gate.py")


def _valid():
    """A minimal matrix that passes, as the starting point for each rejection case."""
    return {
        "schema_version": 1,
        "about": "test fixture",
        "kinds": {"direct": "one step", "blocked": "do not"},
        "versions": {
            "0.1.0": {"released": "2026-01-01", "notes": "first"},
            "0.2.0": {"released": "2026-01-02", "notes": "second"},
        },
        "edges": [{"from": "0.1.0", "to": "0.2.0", "kind": "direct",
                   "reversible": True, "requires_backup": False}],
    }


# --- the committed file ------------------------------------------------------------------------

def test_the_committed_matrix_is_valid():
    um.validate_matrix(um.load_matrix(MATRIX_PATH))


def test_every_released_tag_has_an_entry_and_a_way_to_reach_it():
    """The backfill is checked against git, not against a list typed into the test.

    A hand-copied list would drift the moment a release is cut, and would then agree with a matrix
    that had drifted the same way.
    """
    tags = subprocess.run(
        ["git", "tag", "-l", "v*.*.*"], cwd=ROOT, capture_output=True, text=True, timeout=60)
    # A git that FAILED is not a checkout without tags, and folding them together reproduces the
    # very mistake this check was written to fix -- one level down. `git tag -l` does not fail on a
    # repository with no tags; it prints nothing and exits 0. A non-zero exit means something else
    # is wrong, everywhere, so it fails everywhere.
    assert tags.returncode == 0, (
        "git tag -l failed, which is not the same as having no tags: %s"
        % (tags.stderr or "").strip()[:200])
    if not tags.stdout.strip():
        # Skipping here is only acceptable on a developer's partial checkout. In CI it means the
        # check did not run in the job that gates publication -- which is exactly how this test
        # spent its first day doing nothing: the default checkout is shallow and tagless, so
        # `git tag -l` returned nothing and this skipped, silently and only there.
        if os.environ.get("CI"):
            pytest.fail(
                "no release tags visible in CI, so this check cannot run. The checkout needs "
                "fetch-tags; a silent skip here removes the only guard on the matrix matching the "
                "releases that exist")
        pytest.skip("no release tags in this checkout")
    released = sorted(
        (line[1:] for line in tags.stdout.split() if line.startswith("v")),
        key=lambda v: tuple(int(p) for p in v.split(".")))

    data = um.validate_matrix(um.load_matrix(MATRIX_PATH))
    missing = [v for v in released if v not in data["versions"]]
    assert not missing, (
        f"released but undeclared in docs/upgrade-matrix.json: {missing}. The release gate would "
        "have refused these; they predate it, so add them")

    # And each is reachable, which is the assertion the gate itself makes.
    for version in released:
        um.assert_release_declared(data, version)

    # The converse, which matters more than it looks. Adjacency completeness is satisfied by any
    # chain of entries, so a version that was never released could be invented to bridge a gap --
    # and the file would validate while describing a release nobody can install. Every declared
    # version must correspond to a real tag.
    #
    # Checked here rather than in the validator on purpose: at release time the tag being cut does
    # exist, but the validator runs without a guaranteed view of the tag list, and a check that
    # silently passes when it cannot see tags would be worse than no check.
    #
    # The version in VERSION is exempt: a release-prep commit bumps it and adds the matrix entry
    # together, and the tag only appears afterwards. Without the exemption the two rules deadlock --
    # the gate refuses to cut a version the matrix does not declare, and this refuses a declared
    # version that is not yet tagged, so main would be red for the whole window between the two.
    # It holds only if the bump and the entry land in the same commit, which is what release prep
    # does and what the gate independently enforces at tag time by comparing tag to VERSION.
    preparing = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    phantom = [v for v in data["versions"] if v not in released and v != preparing]
    assert not phantom, (
        f"docs/upgrade-matrix.json declares {phantom}, which are not released tags and are not the "
        f"version being prepared ({preparing}). A version that does not exist can satisfy the "
        "adjacency rule while describing a release nobody can get")


def test_the_committed_matrix_declares_every_released_edge_direct():
    """Pins the fact the backfill rests on, so a later edit cannot quietly contradict it.

    Every released pair really is schema-identical: across all seven tags the boot DDL string set
    is byte-identical and the model differs only in comment text. If a future edge is not direct,
    that is fine and expected -- but it should be a deliberate edit, not a silent one.
    """
    data = um.load_matrix(MATRIX_PATH)
    kinds = {edge["kind"] for edge in data["edges"]}
    assert kinds == {"direct"}, (
        f"the matrix now declares {kinds}; if a released upgrade has stopped being direct, update "
        "this test deliberately")


# --- rejection cases ---------------------------------------------------------------------------

@pytest.mark.parametrize("mutate, expected", [
    (lambda m: m.update({"schema_version": 2}), "schema_version"),
    (lambda m: m.update({"schema_version": "1"}), "schema_version"),
    (lambda m: m.pop("versions"), "versions"),
    (lambda m: m.update({"versions": {}}), "versions"),
    (lambda m: m.update({"surprise": 1}), "unknown key"),
    (lambda m: m.pop("about"), "'about'"),
    (lambda m: m.update({"about": "   "}), "must not be empty"),
    (lambda m: m.update({"kinds": {"direct": "one step"}}), "must describe exactly"),
    (lambda m: m.update({"kinds": {"direct": "a", "blocked": "b", "other": "c"}}),
     "must describe exactly"),
    (lambda m: m.update({"kinds": 5}), "must be an object"),
    (lambda m: m["kinds"].update({"direct": ""}), "must not be empty"),
    (lambda m: m["versions"].update({"nope": {"released": "2026-01-03", "notes": "x"}}),
     "malformed"),
    (lambda m: m["versions"]["0.1.0"].update({"released": "yesterday"}), "malformed"),
    (lambda m: m["versions"]["0.1.0"].update({"extra": 1}), "unknown key"),
    (lambda m: m["versions"]["0.1.0"].update({"notes": ""}), "must not be empty"),
    (lambda m: m["edges"][0].update({"to": "9.9.9"}), "not a declared version"),
    (lambda m: m["edges"][0].update({"from": "9.9.9"}), "not a declared version"),
    (lambda m: m["edges"][0].update({"to": "0.1.0"}), "to itself"),
    (lambda m: m["edges"][0].update({"kind": "maybe"}), "kind must be one of"),
    (lambda m: m["edges"].append({"from": "0.1.0", "to": "0.2.0", "kind": "direct",
                             "reversible": True, "requires_backup": False}),
     "duplicate edge"),
    (lambda m: m.update({"edges": []}), "no edge declared between adjacent releases"),
    (lambda m: m["edges"][0].update({"reason": "because"}), "only meaningful on a blocked edge"),
    (lambda m: m["edges"][0].update({"kind": "blocked"}), "reason"),
    (lambda m: m["edges"][0].update({"kind": "blocked", "reason": "r", "via": ["0.1.0"]}),
     "unknown key"),
    (lambda m: m["edges"][0].update({"conditions": [{"id": "Bad Id", "summary": "s"}]}),
     "malformed"),
    (lambda m: m["edges"][0].update({"conditions": [{"id": "ok", "summary": ""}]}),
     "must not be empty"),
    (lambda m: m["edges"][0].update({"conditions": [{"id": "ok", "summary": "s", "huh": 1}]}),
     "unknown key"),
    (lambda m: m["edges"][0].update(
        {"conditions": [{"id": "dup", "summary": "a"}, {"id": "dup", "summary": "b"}]}),
     "repeated"),
])
def test_the_validator_rejects(mutate, expected):
    data = _valid()
    mutate(data)
    with pytest.raises(um.UpgradeMatrixError) as caught:
        um.validate_matrix(data)
    assert expected in str(caught.value), f"expected {expected!r}, got {caught.value}"


def test_the_shapes_a_real_non_trivial_upgrade_will_need_are_accepted():
    """Both richer edge shapes, so the rejections above are not all the schema is exercised against.

    Not hypothetical: the next release already needs the first one. The boot DDL now lowercases
    every email behind a unique index, and where two accounts differ only in case the index is
    skipped and the deployment boots without it -- an upgrade that is direct, but not unconditional.
    """
    data = _valid()
    data["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "third"}
    data["versions"]["0.4.0"] = {"released": "2026-01-04", "notes": "fourth"}
    data["edges"].append({
        "from": "0.2.0", "to": "0.3.0", "kind": "direct",
        "reversible": False, "requires_backup": True,
        "conditions": [{
            "id": "email-case-collision",
            "summary": "Two accounts whose addresses differ only in case keep working, but the "
                       "case-insensitive unique index is not created.",
            "detect": "SELECT lower(email) FROM users GROUP BY 1 HAVING count(*) > 1",
        }],
    })
    data["edges"].append({
        "from": "0.3.0", "to": "0.4.0", "kind": "blocked",
        "reversible": False, "requires_backup": True,
        "reason": "the 0.4.0 boot rewrites a column 0.3.0 still writes to.",
    })
    um.validate_matrix(data)


def test_parsing_refuses_oversized_and_malformed_input(tmp_path):
    big = tmp_path / "big.json"
    big.write_bytes(b"{" + b" " * (um.MAX_BYTES + 1) + b"}")
    with pytest.raises(um.UpgradeMatrixError, match="larger than"):
        um.load_matrix(big)

    bom = tmp_path / "bom.json"
    bom.write_bytes(b"\xef\xbb\xbf{}")
    with pytest.raises(um.UpgradeMatrixError, match="BOM"):
        um.load_matrix(bom)

    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(um.UpgradeMatrixError, match="not valid UTF-8 JSON"):
        um.load_matrix(broken)

    listy = tmp_path / "list.json"
    listy.write_text("[]", encoding="utf-8")
    with pytest.raises(um.UpgradeMatrixError, match="must be a JSON object"):
        um.load_matrix(listy)

    with pytest.raises(um.UpgradeMatrixError, match="cannot read"):
        um.load_matrix(tmp_path / "absent.json")


# --- what the gate does with it ------------------------------------------------------------------

def test_an_undeclared_release_is_refused():
    data = _valid()
    with pytest.raises(um.UpgradeMatrixError, match="no entry"):
        um.assert_release_declared(data, "0.3.0")


def test_a_declared_release_with_no_way_in_is_refused():
    """A version entry alone is a name, not a declaration."""
    data = _valid()
    data["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "third"}
    with pytest.raises(um.UpgradeMatrixError, match="no edge from 0.2.0"):
        um.assert_release_declared(data, "0.3.0")


def test_the_earliest_release_needs_no_inbound_edge():
    um.assert_release_declared(_valid(), "0.1.0")


def _repo(tmp_path, version, matrix):
    """A throwaway repository shaped the way the gate expects: one commit, one tag, on main."""
    # newline="" so the LF survives: Python's text mode rewrites it to CRLF on Windows, and the
    # gate rejects a VERSION that is not exactly X.Y.Z followed by one LF -- correctly, since that
    # is a real way for a release to be malformed.
    (tmp_path / "VERSION").write_text(version + "\n", encoding="utf-8", newline="")
    (tmp_path / "docs").mkdir(exist_ok=True)
    (tmp_path / "docs" / "upgrade-matrix.json").write_text(
        json.dumps(matrix), encoding="utf-8", newline="")

    def git(*args, check=True):
        done = subprocess.run(["git", *args], cwd=tmp_path, capture_output=True, text=True,
                              timeout=60)
        if check:
            assert done.returncode == 0, " ".join(args) + ": " + (done.stderr or "")[:300]
        return done

    git("init", "-q", "-b", "main")
    git("config", "user.email", "test@example.test")
    git("config", "user.name", "test")
    git("add", "-A")
    git("commit", "-qm", version)
    # Tag every version the matrix declares, not only the one being cut: the gate now checks that
    # a declared version corresponds to a real release, so a fixture that declares versions it
    # never tagged is describing a repository that could not exist.
    for declared in sorted(set(matrix.get("versions", {})) | {version}):
        git("tag", f"v{declared}")
    # The gate requires the tagged commit to be an ancestor of the main ref it is given.
    return tmp_path


def _run_gate(repo, version, tmp_path, **kwargs):
    return gate.validate_release(
        repo,
        ref=f"refs/tags/v{version}",
        event_sha="HEAD",
        main_ref="main",
        repository_owner="DockVault",
        **kwargs,
    )


def test_the_gate_refuses_a_release_the_matrix_does_not_declare(tmp_path):
    """The whole point: you cannot cut a release without saying how to reach it."""
    matrix = _valid()
    repo = _repo(tmp_path, "0.3.0", matrix)
    with pytest.raises(gate.ReleaseGateError, match="no entry in docs/upgrade-matrix.json"):
        _run_gate(repo, "0.3.0", tmp_path)


def test_the_gate_passes_a_declared_release(tmp_path):
    matrix = _valid()
    matrix["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "third"}
    matrix["edges"].append({"from": "0.2.0", "to": "0.3.0", "kind": "direct",
                            "reversible": True, "requires_backup": False})
    repo = _repo(tmp_path, "0.3.0", matrix)
    metadata = _run_gate(repo, "0.3.0", tmp_path)
    assert metadata.version == "0.3.0"
    assert metadata.upgrade_entry_waived is False




def test_an_inbound_edge_marked_blocked_is_not_a_way_in(tmp_path):
    """A release whose only route in says "do not take this route" has not declared a route.

    The gate originally compared only (from, to) and ignored kind, so a blocked edge satisfied it --
    the matrix would say in so many words that the upgrade must not be taken, and the tag would be
    cut anyway.
    """
    matrix = _valid()
    matrix["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "third"}
    matrix["versions"]["0.4.0"] = {"released": "2026-01-04", "notes": "fourth"}
    matrix["edges"].append({"from": "0.2.0", "to": "0.3.0", "kind": "direct",
                            "reversible": True, "requires_backup": False})
    matrix["edges"].append({
        "from": "0.3.0", "to": "0.4.0", "kind": "blocked",
        "reversible": False, "requires_backup": True,
        "reason": "0.4.0 rewrites a column 0.3.0 still writes to.",
    })
    repo = _repo(tmp_path, "0.4.0", matrix)
    with pytest.raises(gate.ReleaseGateError, match="marked blocked"):
        _run_gate(repo, "0.4.0", tmp_path)


def test_a_waiver_in_the_file_lets_an_undeclared_release_through(tmp_path):
    """The escape hatch, which lives in the matrix rather than in a command-line flag.

    A flag would have to be threaded through a tag-triggered workflow to be reachable at all, and
    once passed it would leave no trace in anything published -- a waived release would look exactly
    like a declared one. Declared in the file, the omission is in the release commit, in the diff,
    and in the published asset.
    """
    matrix = _valid()
    matrix["waivers"] = [{"version": "0.3.0", "reason": "security fix; path declared next release"}]
    repo = _repo(tmp_path, "0.3.0", matrix)
    metadata = _run_gate(repo, "0.3.0", tmp_path)
    assert metadata.upgrade_entry_waived is True


def test_a_waiver_does_not_excuse_a_broken_file(tmp_path):
    """The distinction the hatch exists for.

    Shipping without a declared upgrade path is a judgement call a maintainer can make. Shipping a
    matrix that does not validate is not: it breaks the published asset and every consumer of it,
    for every version, not only this one.
    """
    broken = _valid()
    broken["waivers"] = [{"version": "0.3.0", "reason": "urgent"}]
    broken["edges"][0]["to"] = "9.9.9"
    repo = _repo(tmp_path, "0.3.0", broken)
    with pytest.raises(gate.ReleaseGateError, match="not a declared version"):
        _run_gate(repo, "0.3.0", tmp_path)


def test_a_waiver_goes_stale_once_the_version_is_declared():
    """So the hatch cannot quietly become the normal route.

    Left in place, a waiver would keep excusing a version that no longer needs excusing, and the
    next person to read the file would find a permanent-looking exemption.
    """
    data = _valid()
    data["waivers"] = [{"version": "0.2.0", "reason": "no longer true"}]
    with pytest.raises(um.UpgradeMatrixError, match="declared anyway"):
        um.validate_matrix(data)


def test_the_waiver_is_reported_as_a_job_output(tmp_path):
    """The workflow exports this; a waiver the workflow cannot see cannot be acted on."""
    matrix = _valid()
    matrix["waivers"] = [{"version": "0.3.0", "reason": "urgent"}]
    repo = _repo(tmp_path, "0.3.0", matrix)
    out = tmp_path / "gh-output"
    gate.write_github_outputs(out, _run_gate(repo, "0.3.0", tmp_path))
    assert "upgrade_entry_waived=true" in out.read_text(encoding="utf-8")

    gate.write_github_outputs(
        out, gate.ReleaseMetadata(version="0.3.0", tag="v0.3.0", sha="abc", image="x"))
    assert "upgrade_entry_waived=false" in out.read_text(encoding="utf-8")


def test_the_workflow_exports_the_waiver_output():
    """Written by the script AND declared by the job, or nothing downstream can read it.

    Checked because the first version of this wrote the value to GITHUB_OUTPUT and stopped there:
    the job did not export it, so it was invisible to every later job, and the commit message
    claimed an audit trail that did not exist.
    """
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    validate_job = workflow.split("  validate:", 1)[1].split("\n  tests:", 1)[0]
    outputs = validate_job.split("outputs:", 1)[1].split("steps:", 1)[0]
    assert "upgrade_entry_waived:" in outputs, (
        "the validate job does not export upgrade_entry_waived, so no later job can see it")


def test_a_release_with_no_matrix_at_all_is_refused(tmp_path):
    """The gate must fail closed when the file is missing, not treat absence as nothing to check."""
    repo = _repo(tmp_path, "0.2.0", _valid())
    (repo / "docs" / "upgrade-matrix.json").unlink()
    with pytest.raises(gate.ReleaseGateError, match="cannot read"):
        _run_gate(repo, "0.2.0", tmp_path)


# --- the workflow ---------------------------------------------------------------------------

def _publish_steps():
    """The publish job's steps, in order, as (name, body) pairs.

    Parsed from the text rather than with a YAML library. PyYAML is not in the test lock, and the
    lock is pip-compile generated and guarded by a supply-chain contract, so adding a dependency
    for two assertions is not proportionate. This is scoped to one file with consistent
    indentation, and it fails loudly if that shape changes rather than passing quietly.
    """
    import re

    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    publish = workflow.split("\n  publish:\n", 1)
    assert len(publish) == 2, "the publish job has been renamed"
    # Up to the next top-level job, which is a name at exactly two spaces of indent. Splitting on
    # "\n  " alone stops at the very next line instead, since every nested line starts with it.
    body = re.split(r"\n  [A-Za-z_][\w-]*:\n", publish[1], maxsplit=1)[0]
    chunks = body.split("\n      - ")[1:]
    assert len(chunks) > 3, f"only found {len(chunks)} steps in publish; the shape has changed"
    steps = []
    for chunk in chunks:
        first = chunk.splitlines()[0]
        name = first.split("name:", 1)[1].strip() if first.startswith("name:") else first.strip()
        steps.append((name, chunk))
    return steps


def test_the_release_workflow_publishes_the_matrix_verbatim():
    """The asset has to be the file the gate validated.

    Checked for ORDER and for being unconditional, not just for the presence of a string. The grep
    version of this passed for a step that had been disabled with `if: false`, moved after the
    release, or dropped into a job with no checkout -- it asserted a rename, not a contract.
    """
    steps = _publish_steps()
    names = [name for name, _ in steps]

    staging = [i for i, n in enumerate(names) if "upgrade matrix" in n.lower()]
    release = [i for i, n in enumerate(names) if n == "Create GitHub Release"]
    assert staging, f"no step stages the upgrade matrix; steps are {names}"
    assert release, f"no step creates the release; steps are {names}"
    assert staging[0] < release[0], "the matrix is staged after the release is created"
    assert "\n        if:" not in steps[staging[0]][1], (
        "the staging step is now conditional, so the asset can be silently omitted")

    files = steps[release[0]][1].split("files:", 1)
    assert len(files) == 2, "the release step no longer lists files"
    assert "upgrade.json" in files[1], f"upgrade.json is not attached; block is {files[1][:200]!r}"


def test_staging_the_asset_reproduces_the_committed_file_byte_for_byte(tmp_path):
    """Run the staging command for real, rather than trusting that `cp` means what it says.

    If it is ever replaced by a generator this fails, which is the point: a re-serialised copy
    would be valid JSON and could still disagree with the repository it claims to describe.
    """
    import shutil

    steps = dict(_publish_steps())
    name = next(n for n in steps if "upgrade matrix" in n.lower())
    command = steps[name].split("run:", 1)[1].strip().splitlines()[0].strip()
    assert command.startswith("cp "), (
        f"the asset is no longer a straight copy ({command!r}); prove the published file still "
        "matches the committed one")

    source, destination = command.split()[1:3]
    shutil.copy(ROOT / source, tmp_path / destination)
    assert (tmp_path / destination).read_bytes() == (ROOT / source).read_bytes()
    assert (ROOT / source) == MATRIX_PATH, (
        f"the staged file is {source}, not the one the gate validates")


def test_every_workflow_that_runs_pytest_fetches_tags():
    """Because fixing one of them and assuming the rest is how this went wrong the first time.

    The check above compares the matrix against the releases that exist, and it reads them from
    `git tag -l`. actions/checkout does not fetch tags by default, so any workflow that runs the
    suite without asking for them turns that check into a hard failure -- which is the designed
    behaviour, but it should be caught here rather than discovered in CI.

    File-level rather than per-step: a workflow that runs pytest anywhere and never asks for tags
    is the regression worth catching, and matching checkout blocks to jobs would be more parsing
    than the question deserves.
    """
    workflows = ROOT / ".github" / "workflows"
    offenders = []
    for path in sorted(workflows.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        if "-m pytest" not in text or "actions/checkout" not in text:
            continue
        if "fetch-tags: true" not in text and "fetch-depth: 0" not in text:
            offenders.append(path.name)
    assert not offenders, (
        "these workflows run pytest but check out without tags, so the released-versions check "
        f"will fail in them: {', '.join(offenders)}. Add `fetch-tags: true` to their checkout")


# --- what the last round of attacks found ---------------------------------------------------

def test_a_backport_released_after_a_later_version_does_not_have_to_lie(tmp_path):
    """Cutting 0.9.1 after 0.10.0 has shipped must not require asserting 0.9.1 -> 0.10.0.

    Adjacency is by version order, so inserting a backport makes (0.9.1, 0.10.0) newly adjacent and
    the naive rule demands an edge out of the backport into a release that predates its fix. There
    is no honest answer to that demand: `direct` claims an untested and backwards hop, `blocked`
    admits the pair is not really adjacent. The price of shipping a backport would be a false
    declaration, which is precisely what this gate exists to prevent -- so the requirement is
    skipped where the later version was released earlier.
    """
    data = _valid()
    data["versions"]["0.2.1"] = {"released": "2026-02-01", "notes": "backport, shipped later"}
    data["edges"].append({"from": "0.2.0", "to": "0.2.1", "kind": "direct",
                          "reversible": True, "requires_backup": False})
    um.validate_matrix(data)   # no edge 0.2.1 -> ... is demanded

    repo = _repo(tmp_path, "0.2.1", data)
    assert _run_gate(repo, "0.2.1", tmp_path).version == "0.2.1"


def test_the_backport_exemption_does_not_let_a_release_be_orphaned():
    """The narrow shape of that exemption, because skipping the rule outright opens a hole.

    If the backport's insertion is used as cover to also drop the real predecessor link, the later
    version ends up with no way in at all. Something released no later than it must still lead in.
    """
    data = _valid()
    # 0.1.5 sorts between the two but shipped after both: the backport shape. Its own inbound edge
    # is declared; 0.2.0's is not, so 0.2.0 is left with no way in at all.
    data["versions"]["0.1.5"] = {"released": "2026-02-01", "notes": "backport"}
    data["edges"] = [{"from": "0.1.0", "to": "0.1.5", "kind": "direct",
                      "reversible": True, "requires_backup": False}]
    with pytest.raises(um.UpgradeMatrixError, match="older than 0.2.0"):
        um.validate_matrix(data)


def test_an_ordinary_forward_gap_is_still_rejected():
    """Non-vacuity for the two above: the relaxed rule still catches the case it is meant to."""
    data = _valid()
    data["versions"]["0.3.0"] = {"released": "2026-03-01", "notes": "later in both senses"}
    with pytest.raises(um.UpgradeMatrixError, match=r"0\.2\.0 -> 0\.3\.0"):
        um.validate_matrix(data)


def test_the_gate_rejects_a_version_that_was_never_released(tmp_path):
    """Closed at the gate, not only in the test lane.

    A fabricated predecessor satisfies adjacency and supplies the inbound edge the gate looks for,
    so without this the matrix could describe a release nobody can install and still cut a tag.
    """
    data = _valid()
    data["versions"]["0.1.5"] = {"released": "2026-01-15", "notes": "never existed"}
    data["edges"] = [
        {"from": "0.1.0", "to": "0.1.5", "kind": "direct",
         "reversible": True, "requires_backup": False},
        {"from": "0.1.5", "to": "0.2.0", "kind": "direct",
         "reversible": True, "requires_backup": False},
    ]
    repo = _repo(tmp_path, "0.2.0", data)
    subprocess.run(["git", "tag", "-d", "v0.1.5"], cwd=repo, capture_output=True, timeout=60)
    with pytest.raises(gate.ReleaseGateError, match="not released versions"):
        _run_gate(repo, "0.2.0", tmp_path)


def test_a_repeated_json_key_is_rejected(tmp_path):
    """json.loads keeps the last one and says nothing, so a reviewer reads the block that lost."""
    path = tmp_path / "dupe.json"
    path.write_text(
        '{"schema_version": 1, "schema_version": 2, "about": "x"}', encoding="utf-8", newline="")
    with pytest.raises(um.UpgradeMatrixError, match="repeats the key"):
        um.load_matrix(path)


def test_a_version_with_a_leading_zero_is_rejected():
    """"0.10.00" and "0.10.0" would be two keys for one release, and one could never match a tag."""
    data = _valid()
    data["versions"]["0.02.0"] = {"released": "2026-01-05", "notes": "x"}
    with pytest.raises(um.UpgradeMatrixError, match="malformed"):
        um.validate_matrix(data)


def test_a_symlinked_matrix_is_refused(tmp_path):
    """The gate must validate the same bytes the release publishes.

    A symlink would let those differ, which defeats the one property the copy-verbatim step exists
    to guarantee.
    """
    real = tmp_path / "real.json"
    real.write_bytes(MATRIX_PATH.read_bytes())
    link = tmp_path / "link.json"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("this platform/user cannot create symlinks")
    with pytest.raises(um.UpgradeMatrixError, match="regular file"):
        um.load_matrix(link)


def test_the_release_workflow_does_not_redirect_the_gate_to_another_file():
    """The gate reads docs/upgrade-matrix.json; the staging step copies that same path.

    Passing --upgrade-matrix in the workflow would let the gate validate one file while the release
    published another, and nothing else would notice.
    """
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "--upgrade-matrix" not in workflow, (
        "release.yml now points the gate at a specific matrix path; make sure it is the same file "
        "the staging step copies, or the published asset is not the one that was validated")
