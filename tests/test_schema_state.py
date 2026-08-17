"""A deployment that is missing schema must say so, and stop saying so once it is fixed.

The boot-time DDL replay wraps each statement so one failure cannot brick a boot. That is right,
and it used to be the end of the story: the step printed and nothing else happened, so `/health`
answered 200, the container healthcheck agreed, and the tool that waits on it agreed. The first
real sign was a 500 from whichever endpoint needed the column that never arrived.

Each step now records its outcome, and `/health` answers 503 when any of them failed. These tests
drive that against a running deployment, because the interesting part is the chain rather than any
one link: endpoint -> container healthcheck -> Docker's verdict -> the tool that reads it.

Everything here cleans up after itself. The failure is simulated by writing a row that names a
statement the deployment does not have, never by breaking real schema: the point is to exercise
the reporting, and a test that damaged a deployment to prove reporting works would be a poor trade.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import time

import pytest
import requests

from conftest import skip_for_older_deployment, skip_if_container_absent

# Marked per test: one of these reads only source and needs nothing running, and the conftest
# treats a test carrying both unit and integration as a usage error rather than guessing.

# A step id that cannot collide with a real one: real ids are the first 32 hex characters of a
# statement's SHA-256, and this names a statement no release has ever carried. Being absent from
# the declared list is also what makes the deployment forget it on the next boot, which is the
# recovery path exercised below.
FAKE_STEP = "0000dead0000beef0000dead0000beef"


def _db_container():
    return os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql, on_error="fail"):
    container = _db_container()
    try:
        probe = subprocess.run(
            ["docker", "exec", container, "sh", "-c", "echo $POSTGRES_USER; echo $POSTGRES_DB"],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.skip(f"cannot reach the docker engine: {exc}")
    if probe.returncode != 0:
        pytest.skip(f"cannot reach the database container {container}")
    lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
    user, database = lines[0], (lines[1] if len(lines) > 1 else lines[0])

    out = subprocess.run(
        ["docker", "exec", container, "psql", "-U", user, "-d", database, "-tAc", sql],
        capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        detail = (out.stderr or "").strip()[:300]
        if on_error == "older":
            skip_for_older_deployment(
                f"cannot read schema-step recording from the deployment database: {detail}")
        raise AssertionError(f"query failed: {detail}\n  sql: {sql}")
    return out.stdout.strip()


def _forget_the_fake_step():
    """Never through the raising helper: this runs in teardown, where an exception would replace
    the failure the test is trying to report."""
    container = _db_container()
    subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         f'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" '
         f'-c "DELETE FROM schema_steps WHERE step_id = \'{FAKE_STEP}\'"'],
        capture_output=True, text=True, timeout=60, check=False)


@pytest.mark.integration
def test_a_clean_boot_records_every_step_and_reports_a_complete_schema(base_url):
    """The baseline, and a non-vacuity guard for everything below.

    If nothing were being recorded the table would be empty, `check_schema_state` would answer
    `unknown`, and the failure tests could pass for the wrong reason.
    """
    counts = _psql(
        "SELECT outcome || '=' || count(*) FROM schema_steps GROUP BY outcome",
        on_error="older")
    if not counts:
        # This check calls itself the non-vacuity guard for everything below it, and an empty
        # table is the state that makes those checks pass for the wrong reason. A deployment
        # built from the commit under test must have recorded steps, so there it is a finding;
        # an older image genuinely predates the recording and still skips.
        skip_for_older_deployment("no schema steps are recorded on this deployment")

    tallies = dict(part.split("=") for part in counts.split())
    assert int(tallies.get("applied", 0)) > 20, (
        f"only {tallies.get('applied', 0)} steps recorded as applied; the replay records ~70, so "
        "either recording is broken or the list has shrunk dramatically")
    assert "failed" not in tallies, (
        f"this deployment has failed schema steps: {tallies}. That is the state the rest of this "
        "file simulates, so it cannot also be the starting state")

    body = requests.get(f"{base_url}/health", timeout=10).json()
    assert body["schema"] == "complete", body


def _restart_api():
    api = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    done = subprocess.run(["docker", "restart", api], capture_output=True, text=True, timeout=180)
    skip_if_container_absent(done, api)
    assert done.returncode == 0, (
        f"could not restart {api}. Callers restart it after the destructive half of their check, "
        "so treating this as untestable would leave the deployment in the state the test built "
        f"and say nothing ran: {(done.stderr or '').strip()[:200]}")


def _wait_for_health(base_url):
    # With a delay, deliberately. Without one the loop spends its forty attempts inside a few
    # milliseconds -- a refused connection returns immediately -- and reports the deployment dead
    # while it is still starting.
    for _ in range(60):
        try:
            response = requests.get(f"{base_url}/health", timeout=5)
        except requests.RequestException:
            time.sleep(2)
            continue
        if response.status_code in (200, 503):
            return response
        time.sleep(2)
    pytest.fail("the deployment did not come back after a restart")


# Three statements the deployment really replays at boot, all naming one column. Breaking their
# precondition is how a genuine boot-time failure is produced here.
#
# Writing a fabricated schema_steps row instead does not work, and the reason is the feature
# working correctly: the boot prunes rows for statements it no longer declares, so an invented step
# is deleted before the state is computed. The failure has to be real.
#
# Renaming the column rather than violating a constraint on it: the obvious alternative -- insert a
# row that makes SET NOT NULL impossible -- founders on the table's foreign keys, which want a real
# vault and a real user. A rename needs no rows at all and is undone by one statement.
BROKEN_COLUMN = "key_version"
DECOY_COLUMN = "key_version_schema_state_test"


def _break_the_boot_steps():
    _psql(f"ALTER TABLE vault_member_keys RENAME COLUMN {BROKEN_COLUMN} TO {DECOY_COLUMN}")


def _undo():
    """Teardown that cannot raise, because it runs while a failure may be in flight."""
    container = _db_container()
    subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         f'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c '
         f'"ALTER TABLE vault_member_keys RENAME COLUMN {DECOY_COLUMN} TO {BROKEN_COLUMN}"'],
        capture_output=True, text=True, timeout=60, check=False)


@pytest.mark.integration
@pytest.mark.disruptive
def test_a_deployment_that_booted_with_a_failed_step_reports_it_and_recovers(base_url):
    """The whole chain, on a genuine failure, in the sequence it really happens in.

    A real boot-time step is made to fail by breaking its precondition, rather than by writing a
    record and hoping the deployment believes it. The state is read once per boot -- re-reading it
    on every healthcheck would put a database round trip in that path forever to re-derive a
    constant, and the cost was measurable as a memory rise during large downloads.

    Recovery is asserted in the same test because it is the half that makes recording safe at all:
    a deployment that could report incomplete and never stop would be worse than the silence this
    replaced.
    """
    try:
        _break_the_boot_steps()
        _restart_api()
        response = _wait_for_health(base_url)
        assert response.status_code == 503, (
            f"a deployment whose boot could not apply a step answered {response.status_code}; "
            "nothing downstream can act on that")
        body = response.json()
        assert body["schema"] == "incomplete" and body["status"] == "degraded", body
        # Unauthenticated: it says THAT the schema is wrong, never what is wrong with it.
        for internal in ("vault_member_keys", "key_version", "NOT NULL"):
            assert internal not in response.text, (
                f"/health leaked {internal!r}; the statement and the database's error belong in "
                "schema_steps, for someone with database access")
        assert _psql(
            "SELECT count(*) FROM schema_steps WHERE outcome = 'failed'") != "0", (
            "health reported incomplete but nothing is recorded as failed, so the two are not "
            "reading the same thing")
    finally:
        _undo()

    _restart_api()
    recovered = _wait_for_health(base_url)
    assert recovered.status_code == 200, (
        f"still {recovered.status_code} after a boot that could apply every step: "
        f"{recovered.text[:200]}")
    assert recovered.json()["schema"] == "complete"
    assert _psql("SELECT count(*) FROM schema_steps WHERE outcome = 'failed'") == "0"


@pytest.mark.unit
def test_the_recorded_detail_keeps_only_the_error_line():
    """A Postgres error's DETAIL section is the offending ROW, column by column.

    The statements replayed at boot include data migrations over `users`, so an unfiltered error
    would put real addresses into this table and from there into every database backup. The first
    line names the constraint and the relation, which is what someone debugging needs.
    """
    import importlib.util
    import sys

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "api_server_for_detail", root / "app" / "api" / "api_server.py")
    # Importing the whole API module is heavy and has side effects; read the class out of the
    # source instead and exercise it in isolation.
    source = (root / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    start = source.index("class _SchemaStepRecorder:")
    end = source.index("\ndef ", start)
    namespace = {}
    exec(compile(source[start:end], "<recorder>", "exec"), namespace)  # noqa: S102
    safe = namespace["_SchemaStepRecorder"]._safe_detail

    postgres_error = (
        'null value in column "email" of relation "users" violates not-null constraint\n'
        "DETAIL:  Failing row contains (7f3a, alice@example.com, hunter2, admin).")
    kept = safe(postgres_error)
    assert kept == (
        'null value in column "email" of relation "users" violates not-null constraint')
    assert "alice@example.com" not in kept and "hunter2" not in kept, (
        "the row's contents are being persisted")

    assert safe(None) is None
    assert safe("") is None
    assert len(safe("x" * 5000)) <= 500


COLLIDER = "schema_state_case_twin"


def _create_a_case_collision():
    """Two accounts whose addresses differ only in case -- the real precondition.

    The index has to come off first, since it is exactly what forbids this pair. That is also what
    an upgrading deployment looks like: it holds the collision from before the index existed.
    """
    existing = _psql("SELECT email FROM users WHERE email IS NOT NULL LIMIT 1")
    if not existing:
        pytest.skip("no addressed account to collide with")
    _psql("DROP INDEX IF EXISTS uq_users_email_lower")
    _psql(
        "INSERT INTO users (id, username, email, password_hash, role, sftp_enabled, "
        "sftp_password_auth) VALUES (gen_random_uuid(), '%s', '%s', 'x', 'USER', false, false)"
        % (COLLIDER, existing.upper()))


def _remove_the_case_collision():
    container = _db_container()
    subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         f'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" '
         f"-c \"DELETE FROM users WHERE username = '{COLLIDER}'\""],
        capture_output=True, text=True, timeout=60, check=False)


@pytest.mark.integration
@pytest.mark.disruptive
def test_a_deliberately_skipped_step_is_visible_without_being_fatal(base_url):
    """The third state, which is a real condition rather than a failure.

    A deployment holding two addresses differing only in case boots WITHOUT the case-insensitive
    unique index, deliberately: refusing to start would strand it mid-update, and nulling the newer
    duplicate would destroy what may be someone's only way to log in. Reporting that as failed
    would restart a container serving correctly; reporting nothing is how the difference from a
    fresh install stayed invisible.
    """
    try:
        _create_a_case_collision()
        _restart_api()
        response = _wait_for_health(base_url)
        assert response.status_code == 200, (
            "a deliberately skipped step now takes the container down, which reverses a decision "
            "made on purpose")
        assert response.json()["schema"] == "partial", response.text
        assert _psql("SELECT count(*) FROM schema_steps WHERE outcome = 'skipped'") != "0"
        assert _psql(
            "SELECT count(*) FROM pg_indexes WHERE indexname = 'uq_users_email_lower'") == "0", (
            "the index exists, so this did not reproduce the condition it claims to")
    finally:
        _remove_the_case_collision()

    _restart_api()
    recovered = _wait_for_health(base_url)
    assert recovered.status_code == 200
    assert recovered.json()["schema"] == "complete", (
        "the deployment still reports partial once the colliding account is gone")
    assert _psql(
        "SELECT count(*) FROM pg_indexes WHERE indexname = 'uq_users_email_lower'") == "1", (
        "the index was not rebuilt once the collision was resolved")


@pytest.mark.unit
def test_a_boot_that_could_not_record_reports_unknown_rather_than_complete():
    """The reassurance this surface exists to stop giving.

    Recording is best-effort and swallowed, deliberately -- a recorder that could abort a boot
    would make honest health more dangerous than silence. But rows left by an EARLIER boot then
    describe a deployment whose current boot recorded nothing, and `_read_schema_state` would
    happily call that complete.

    An earlier version of this claimed to handle it and did not: the recorder set a flag, and
    nothing carried the flag out to health.
    """
    import importlib.util
    import sys

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "health_recorded_flag", root / "app" / "core" / "health.py")
    health = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = health
    spec.loader.exec_module(health)

    # Whatever the table would say, a boot that could not record does not get to claim completeness.
    health._read_schema_state = lambda: "complete"
    assert health.refresh_schema_state(recorded=False) == "unknown"
    assert health.check_schema_state() == "unknown"

    assert health.refresh_schema_state(recorded=True) == "complete", (
        "the flag now overrides in both directions; a successful boot must still report the table")
