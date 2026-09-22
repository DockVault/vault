"""The algorithm label is a security control, and it must recognise more than one generation.

`VaultMemberKey.wrapping_algorithm` is the only thing separating two kinds of row that share a
table, and it is a filter in a `db.delete()`. Comparing it with `==` against a single string means
a row written by a newer build is invisible: not rejected, not logged, just absent from the query.

Absent from *these* queries, in particular:

  * the prune, where an invisible row is a revoked member's wrap that is never deleted;
  * `_team_rotation_owed`, where an invisible row means the server stops requiring the team-keypair
    rotation that actually revokes someone, and accepts a cheap DEK-only rotation instead.

The second is the one that keeps me up: revocation returns 200 and the removed member can still
read every new file, because their retained team private key unwraps a DEK wrapped to a team
public key nobody rotated.

The unit tests below pin the vocabulary and guard the *shape* of every query, and pin that the
canonical write label and the client's v2 wrap-writer flag move together -- a mislabel is exactly
the failure this control exists to prevent. The integration tests prove the two failures above are
actually closed, by writing a chosen-generation label directly into the database, which stays the
cleanest way to exercise the prune against a specific generation regardless of what the writer
currently emits. The widening landed before the writer, which is why the filters were ready for it.
"""

import os
import re
import subprocess
import uuid

import pytest

from conftest import unique, ensure_ecc_keypair

from app.core.key_wrap_algorithms import (
    DIRECT_DEK_ALGO,
    DIRECT_DEK_ALGO_LEGACY,
    DIRECT_DEK_ALGO_V1,
    DIRECT_DEK_ALGO_V2,
    DIRECT_DEK_ALGOS,
    NAME_INDEX_ALGO,
    NAME_INDEX_ALGOS,
    TEAMPRIV_ALGO,
    TEAMPRIV_ALGO_V1,
    TEAMPRIV_ALGO_V2,
    TEAMPRIV_ALGOS,
    classify,
    is_direct_dek,
    is_name_index,
    is_teampriv,
)

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app")
_CRYPTO_JS = os.path.join(os.path.dirname(_APP), "static", "js", "ecc_crypto.js")


# =================================================================================================
# The vocabulary itself
# =================================================================================================

@pytest.mark.unit
def test_the_vocabularies_are_pairwise_disjoint():
    """A label naming two kinds would make one filter match the other's rows.

    The two member-key kinds sit on different epoch axes, so the prune would then apply one
    axis's floor to the other axis's rows -- deleting a team-private wrap needed to unwrap a live
    DEK epoch, which locks the whole vault out with nothing on the server able to undo it. The
    name-index kind has no epoch at all, so a shared label there would put epoch-less rows in
    front of an epoch filter.
    """
    assert not (DIRECT_DEK_ALGOS & TEAMPRIV_ALGOS)
    assert not (NAME_INDEX_ALGOS & DIRECT_DEK_ALGOS)
    assert not (NAME_INDEX_ALGOS & TEAMPRIV_ALGOS)


@pytest.mark.unit
def test_what_we_write_is_something_we_accept():
    """The write constants must be members of the sets the queries accept.

    This is the specific mistake the module is shaped to prevent: advancing the label a writer
    stamps, without adding it to the set the reader matches. Every row minted after that point is
    invisible to revocation.
    """
    assert DIRECT_DEK_ALGO in DIRECT_DEK_ALGOS
    assert TEAMPRIV_ALGO in TEAMPRIV_ALGOS
    assert NAME_INDEX_ALGO in NAME_INDEX_ALGOS


@pytest.mark.unit
def test_an_unregistered_label_classifies_as_unknown_rather_than_as_a_guess():
    """A label nobody registered gets no guess -- the prune reports it instead."""
    assert classify("ECDH-P384-SOMETHING-NOBODY-REGISTERED") is None
    assert classify("") is None
    assert classify(None) is None
    assert classify(TEAMPRIV_ALGO) == "teampriv"
    assert classify(DIRECT_DEK_ALGO) == "direct"
    assert classify(NAME_INDEX_ALGO) == "name_index"


@pytest.mark.unit
def test_the_index_key_write_site_stamps_a_name_index_label_and_never_a_member_key_one():
    """The name-index wrap is a THIRD kind. Its write site used to omit the label and take the
    column default -- a member-key label -- so every index row was a direct DEK wrap to any query
    that filters by kind. The fix is a label of its own, not an existing constant: stamping
    DIRECT_DEK_ALGO_V2 there would fix the generation and keep the kind wrong.
    """
    router = open(os.path.join(_APP, "api", "ecc_router.py"), encoding="utf-8").read()
    flat = re.sub(r"\s+", " ", router)
    sites = [m.start() for m in re.finditer(r"(?<!class )VaultMemberIndexKey\(", flat)]
    assert sites, "the index-key write site moved"
    for at in sites:
        call = flat[at:flat.index("))", at)]
        assert "wrapping_algorithm=NAME_INDEX_ALGO" in call, call[:160]
    # And that label is a name-index label and NOT a member-key label of either kind.
    assert is_name_index(NAME_INDEX_ALGO)
    assert not is_direct_dek(NAME_INDEX_ALGO) and not is_teampriv(NAME_INDEX_ALGO)


@pytest.mark.unit
def test_the_legacy_column_default_is_a_known_direct_wrap():
    """Rows predating the explicit labels must classify, or the tripwire never stops ringing.

    `get_vault_keys` skips the algorithm filter on its direct read path specifically so it does
    not exclude rows written under the model's column default. Those rows are real. If the
    vocabulary did not recognise the default, every prune on a deployment old enough to hold one
    would report unclassified rows forever -- and an alarm that is always on is not an alarm.
    """
    assert classify(DIRECT_DEK_ALGO_LEGACY) == "direct"


@pytest.mark.unit
def test_registering_a_label_is_a_claim_about_epochs_not_just_a_name():
    """Every registered label feeds a filter that DELETES, so registration is a promise.

    The stale-key prune picks a floor per kind and removes rows below it. A label in one of these
    sets is therefore asserted to sit on that kind's epoch axis -- not merely to be readable. Both
    reserved next-generation labels are in, ahead of any writer, which is deliberate: the filters
    must accept them the day the first one appears, because a late widening fails silently rather
    than loudly.

    The obligation that creates runs the other way. A future generation that changes how versions
    are assigned has to revisit these sets BEFORE shipping a writer, or the prune will delete its
    rows against a floor that does not apply to them -- and this server cannot reconstruct a
    wrapped key it has removed.
    """
    assert DIRECT_DEK_ALGO_V2 in DIRECT_DEK_ALGOS
    assert TEAMPRIV_ALGO_V2 in TEAMPRIV_ALGOS
    # The canonical write constants are now generation 2: the v2 grammar ships as the default writer.
    # Both generations stay in the accept-sets so rows written by older builds keep reading.
    assert DIRECT_DEK_ALGO == DIRECT_DEK_ALGO_V2
    assert TEAMPRIV_ALGO == TEAMPRIV_ALGO_V2


def _wrap_writer_flag_on() -> bool:
    """The client's version-2 WRAP-writer flag, read from the shipped browser source.

    Parsed rather than imported because it lives in a browser module. The value the browser ships
    is the one that has to agree with the label the server stamps.
    """
    with open(_CRYPTO_JS, encoding="utf-8") as fh:
        src = fh.read()
    m = re.search(r"this\.ZK_WRAP_WRITE_V2\s*=\s*(true|false)\s*;", src)
    assert m, "could not find the ZK_WRAP_WRITE_V2 assignment in ecc_crypto.js"
    return m.group(1) == "true"


@pytest.mark.unit
def test_the_wrap_writer_flag_and_the_canonical_label_agree():
    """A v2 wrap must never be stamped with a v1 label, nor a v1 wrap with a v2 label.

    The client flag decides which wrap FORMAT the browser writes; the server's canonical
    ``DIRECT_DEK_ALGO`` / ``TEAMPRIV_ALGO`` decide the LABEL every new row is stamped with. They are
    one switch spread over two files, and either half alone is a lie the row carries forever: the
    flag on with a v1 label stores v2 bytes under a name that says v1, and a filter keyed on the
    label then misfiles the row -- the prune and ``_team_rotation_owed`` failures this whole module
    exists to prevent. So the two are pinned to move together, in the same change.

    (mutation: set ``ZK_WRAP_WRITE_V2`` back to false without reverting the label, or revert the
    canonical label to generation 1 without the flag -> this reds.)
    """
    flag_on = _wrap_writer_flag_on()
    label_is_v2 = (DIRECT_DEK_ALGO == DIRECT_DEK_ALGO_V2
                   and TEAMPRIV_ALGO == TEAMPRIV_ALGO_V2)
    label_is_v1 = (DIRECT_DEK_ALGO == DIRECT_DEK_ALGO_V1
                   and TEAMPRIV_ALGO == TEAMPRIV_ALGO_V1)
    # One generation is selected for writing, never a mix -- a v2 direct label beside a v1 team
    # label would get one kind right and mislabel the other.
    assert label_is_v2 or label_is_v1, (
        f"the canonical write labels are a mixed generation: direct={DIRECT_DEK_ALGO!r}, "
        f"team={TEAMPRIV_ALGO!r}")
    assert flag_on == label_is_v2, (
        "the client v2 wrap-writer flag and the server's canonical wrap label disagree: "
        f"ZK_WRAP_WRITE_V2={flag_on}, canonical label is generation "
        f"{'2' if label_is_v2 else '1'} -- a wrap would be written in one format and stamped with "
        "the other")


# =================================================================================================
# The shape of every query -- these are the tests that catch the NEXT site, not this one
# =================================================================================================

def _app_sources():
    for root, _dirs, files in os.walk(_APP):
        if "__pycache__" in root:
            continue
        for name in files:
            if name.endswith(".py"):
                path = os.path.join(root, name)
                with open(path, encoding="utf-8") as fh:
                    yield path, fh.read()


@pytest.mark.unit
def test_no_query_compares_the_algorithm_column_for_equality():
    """Equality against one string is the bug. Membership over a set is the fix.

    Written as a source-shape rule rather than a behavioural check because it has to fail for a
    site that does not exist yet -- someone adding a seventh query next year, copying the pattern
    from the six that were here before this change.
    """
    offenders = []
    for path, src in _app_sources():
        rel = os.path.relpath(path, _APP)
        for lineno, line in enumerate(src.splitlines(), 1):
            if "wrapping_algorithm ==" in line or "wrapping_algorithm !=" in line:
                offenders.append(f"{rel}:{lineno}: {line.strip()}")
        # A line-at-a-time scan is defeated by the formatting black would apply to a long filter,
        # which puts the column on one line and the operator on the next. Collapse the whole file
        # and look again; the line-based pass above is only there to report a useful location.
        flat = re.sub(r"\s+", " ", src)
        for hit in re.finditer(r"wrapping_algorithm\s*[=!]=", flat):
            snippet = flat[max(0, hit.start() - 40):hit.end() + 40]
            if not any(rel in o for o in offenders):
                offenders.append(f"{rel}: (wrapped across lines) ...{snippet}...")
    assert not offenders, (
        "compare the algorithm column with .in_(DIRECT_DEK_ALGOS) or .in_(TEAMPRIV_ALGOS); "
        "equality against a single label makes next-generation rows invisible:\n  "
        + "\n  ".join(offenders)
    )


@pytest.mark.unit
def test_every_membership_test_uses_a_whole_vocabulary():
    """`.in_([ONE_LABEL])` is the original bug wearing the fix's clothes.

    Banning `==` is not enough on its own: a single-element membership passes that rule, reads as
    the approved idiom, and is just as blind to the next generation. The argument has to be one of
    the two frozensets.
    """
    allowed = {"DIRECT_DEK_ALGOS", "TEAMPRIV_ALGOS", "ALL_KNOWN_ALGOS"}
    offenders = []
    for path, src in _app_sources():
        flat = re.sub(r"\s+", " ", src)
        for m in re.finditer(r"wrapping_algorithm\.in_\(\s*([^)]*)\)", flat):
            arg = m.group(1).strip()
            if arg not in allowed:
                offenders.append(f"{os.path.relpath(path, _APP)}: .in_({arg})")
    assert not offenders, (
        "pass a whole vocabulary, not an inline collection:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.unit
def test_every_label_the_app_writes_is_one_the_app_accepts():
    """No raw string literals at write sites.

    Two vault-creation sites used to stamp the labels as literals while every other site used the
    constants. That is not merely untidy: it splits the source of truth, so changing the constant
    gives creation one generation and granting another, and the prune's filter matches one of them.
    """
    literals = []
    for path, src in _app_sources():
        for lineno, line in enumerate(src.splitlines(), 1):
            if line.strip().startswith("#") or "Column(" in line:
                continue
            # Both shapes of write: the keyword argument at a construction, and the attribute
            # assignment the re-share upsert uses. The second was invisible to an earlier version
            # of this scan, which is exactly the kind of gap it exists to close.
            m = re.search(r"wrapping_algorithm\s*=\s*(.)", line)
            if m and m.group(1) in "'\"":
                literals.append(f"{os.path.relpath(path, _APP)}:{lineno}: {line.strip()}")
    assert not literals, (
        "write the label through the constants in app/core/key_wrap_algorithms.py:\n  "
        + "\n  ".join(literals)
    )


@pytest.mark.unit
def test_every_member_key_construction_sets_the_label_explicitly():
    """An omitted field falls back to the column default, and the default is a DIRECT wrap.

    That fallback is silent and, on a hierarchical vault, wrong: the row would be treated as a
    direct-DEK wrap and pruned against the DEK floor instead of the team floor. Guarding the
    omission here is what makes it safe for the vocabulary to classify the legacy default at all.
    """
    missing = []
    for path, src in _app_sources():
        flat = re.sub(r"\s+", " ", src)
        # `class VaultMemberKey(Base)` is the declaration, not a construction. The index-key table
        # has the same column with the same (member-key) default, so its constructions are held
        # to the same rule.
        for m in re.finditer(r"(?<!class )VaultMember(?:Index)?Key\(", flat):
            depth, i = 0, m.end() - 1
            while i < len(flat):
                if flat[i] == "(":
                    depth += 1
                elif flat[i] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            call = flat[m.end():i]
            if "wrapping_algorithm" not in call:
                missing.append(f"{os.path.relpath(path, _APP)}: {flat[m.start():m.end()]}{call[:90]}...")
    assert not missing, (
        "pass wrapping_algorithm explicitly; omitting it falls back to the column default:\n  "
        + "\n  ".join(missing)
    )


# =================================================================================================
# The two failures, proven closed against a real database
# =================================================================================================

def _psql(sql: str) -> str:
    result = subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    return (result.stdout or "").strip()


def _needs_db():
    """Skip unless the database is genuinely reachable, not merely unless docker is installed."""
    import shutil
    if shutil.which("docker") is None:
        pytest.skip("writing a next-generation label needs direct database access")
    probe = subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", "SELECT 1;"],
        capture_output=True, text=True, timeout=20,
    )
    if probe.returncode != 0:
        pytest.skip(f"database container {_DB_CONTAINER!r} is not reachable")


def _stub(prefix="w"):
    import base64
    return base64.b64encode(f"{prefix}-{uuid.uuid4().hex}".encode()).decode()


def _create_hier_vault(admin):
    ensure_ecc_keypair(admin)
    r = admin.post("/vaults", json={
        # Nameless (no sealed name): these tests exercise team/DEK-epoch retirement in isolation,
        # and a sealed name would pin epoch 1 so its stale wraps could never be retired.
        "type": "zero_knowledge",
        "key_wrapping_mode": "hierarchical",
        "team_public_key": "TEAMPUB-" + uuid.uuid4().hex,
        "team_wrapped_dek": _stub("tdek"),
        "team_dek_ephemeral_public_key": _stub("teph"),
        "wrapped_team_privkey": _stub("tpriv"),
        "team_privkey_ephemeral_public_key": _stub("tpeph"),
    })
    r.raise_for_status()
    return r.json()


def _relabel(vault_id, key_version, label) -> None:
    """Stamp a label onto an existing row. The only way to make one: nothing writes v2 yet."""
    safe_vault = str(vault_id).replace("'", "''")
    safe_label = str(label).replace("'", "''")
    out = _psql(
        "UPDATE vault_member_keys "
        f"SET wrapping_algorithm = '{safe_label}' "
        f"WHERE vault_id = '{safe_vault}' AND key_version = {int(key_version)};"
    )
    assert out.startswith("UPDATE"), out
    assert out != "UPDATE 0", "expected a row to relabel"


def _rows_at(vault_id, key_version) -> int:
    safe_vault = str(vault_id).replace("'", "''")
    return int(_psql(
        "SELECT count(*) FROM vault_member_keys "
        f"WHERE vault_id = '{safe_vault}' AND key_version = {int(key_version)};"
    ))


@pytest.mark.integration
def test_a_stale_next_generation_wrap_is_pruned_like_any_other(admin):
    """The security property: a stale wrap is deleted whatever generation stamped it.

    A team rotation advances the team epoch, which makes every epoch-1 team-private row stale --
    including the one belonging to a member who was removed. If the prune's filter only matches
    generation 1, a generation-2 row sails through it and stays readable forever, while the
    endpoint reports success and the audit record says rows were retired.
    """
    _needs_db()
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        v = _create_hier_vault(admin)
        vid = v["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})

    try:
        me = admin.get("/users/me").json()["id"]
        # Rotate the team keypair: epoch 1 rows become stale, epoch 2 rows are the live ones.
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [{"user_id": str(me), "wrapped_dek": _stub("tpriv"),
                             "ephemeral_public_key": _stub("tpeph")}],
            "team_public_key": "TEAMPUB-" + uuid.uuid4().hex,
            "team_dek_wrapped": _stub("tdek"), "team_dek_ephemeral_public_key": _stub("teph"),
        })
        assert r.status_code == 200, r.text
        assert _rows_at(vid, 1) == 1, "the stale epoch-1 row should still be there before pruning"

        # Make the stale row look like something a newer build wrote.
        _relabel(vid, 1, TEAMPRIV_ALGO_V2)

        r = admin.post(f"/ecc/vaults/{vid}/retire-version")
        assert r.status_code == 200, r.text
        assert r.json()["rows_deleted"] >= 1

        assert _rows_at(vid, 1) == 0, (
            "a stale next-generation team-private wrap survived the prune -- a removed member "
            "would keep it, and the endpoint reported success"
        )
        # And the live epoch is untouched: the fix must not over-delete.
        assert _rows_at(vid, 2) == 1
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True
    finally:
        admin.delete_vault(vid)


@pytest.mark.integration
def test_a_deactivated_next_generation_wrap_still_forces_a_team_rotation(admin):
    """The silent one: rotation-owed must fire on a next-generation row too.

    A deactivated team-private row at the current epoch is the signature of a bare revoke, and it
    obliges the next rekey to rotate the team keypair. If the detector cannot see the row, the
    server accepts a cheap DEK-only rotation -- and the removed member's retained team private key
    unwraps the new DEK, because the team public key it was wrapped to never changed. Revocation
    reports success and changes nothing.
    """
    _needs_db()
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        v = _create_hier_vault(admin)
        vid = v["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})

    try:
        safe_vault = str(vid).replace("'", "''")
        _relabel(vid, 1, TEAMPRIV_ALGO_V2)
        out = _psql(
            "UPDATE vault_member_keys SET is_active = FALSE "
            f"WHERE vault_id = '{safe_vault}' AND key_version = 1;"
        )
        assert out == "UPDATE 1", out

        # A routine DEK-only rotation must now be refused.
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None, "member_keys": [],
            "team_dek_wrapped": _stub("tdek"), "team_dek_ephemeral_public_key": _stub("teph"),
        })
        assert r.status_code == 400, (
            "a DEK-only rotation was accepted while a deactivated next-generation team-private "
            f"row sat at the current epoch: {r.status_code} {r.text}"
        )
        assert "team keypair must be rotated" in r.text
    finally:
        admin.delete_vault(vid)


@pytest.mark.integration
def test_the_prune_reports_rows_whose_label_it_cannot_place(admin):
    """The tripwire, for the generation after next.

    Widening the sets fixes today's labels. It cannot fix a label nobody registered. Such a row
    matches neither branch of the hierarchical delete, so it survives -- and surviving silently is
    exactly the bug. The prune counts them instead, and deliberately does not delete them: this
    server cannot reconstruct a wrapped key it removes, so tidying up a row of unknown meaning
    risks locking a member out permanently.
    """
    _needs_db()
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        v = _create_hier_vault(admin)
        vid = v["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})

    try:
        me = admin.get("/users/me").json()["id"]
        clean = admin.post(f"/ecc/vaults/{vid}/retire-version")
        assert clean.status_code == 200, clean.text
        assert clean.json()["unclassified_rows"] == 0, "a healthy vault must report none"

        # Rotate first. Without this the row sits at version 1 with both floors at 1, so no branch
        # could delete it whatever its label, and "it survived" would prove nothing at all.
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [{"user_id": str(me), "wrapped_dek": _stub("tpriv"),
                             "ephemeral_public_key": _stub("tpeph")}],
            "team_public_key": "TEAMPUB-" + uuid.uuid4().hex,
            "team_dek_wrapped": _stub("tdek"), "team_dek_ephemeral_public_key": _stub("teph"),
        })
        assert r.status_code == 200, r.text

        _relabel(vid, 1, "ECDH-P384-SOMETHING-NOBODY-REGISTERED")
        r = admin.post(f"/ecc/vaults/{vid}/retire-version")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["unclassified_rows"] == 1, (
            "an unrecognised label passed through the prune without being counted"
        )
        assert body["unclassified_rows_deleted"] == 0
        assert _rows_at(vid, 1) == 1, (
            "an unrecognised row below the team floor must be reported, not deleted -- this "
            "server cannot reconstruct a wrapped key it removes"
        )
    finally:
        admin.delete_vault(vid)
