"""What the SFTP server puts in the container log.

Everything this server printed went straight to `docker logs` — read by whoever operates the
deployment, pasted into bug reports, and shipped wherever stdout goes. Two of those lines carried
the plaintext **filename**, and for a zero-knowledge vault the client seals that name before it is
ever sent: it sat encrypted in the database and in the clear in the log beside it. Seventeen more
printed the raw exception, which is not the application's to vouch for — a driver can put a query
fragment, a host path, or a value from the offending row into that string.

The static tests are the ones that scale: they enumerate every call site, so a new one cannot be
added in the old shape. The live test is the one that proves it end to end, by driving a real SFTP
upload of a sentinel filename and reading the container's own log back.
"""

import importlib.util
import json
import os
import shutil
import re
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parent.parent
SFTP_SRC = ROOT / "app" / "sftp" / "sftp_server.py"
EVENTS_SRC = ROOT / "app" / "core" / "safe_log.py"
VAULT_SVC = ROOT / "app" / "services" / "vault_service.py"
STORAGE_SVC = ROOT / "app" / "services" / "encrypted_file_storage.py"
ACTIVITY_SVC = ROOT / "app" / "services" / "activity_monitor.py"


def _call_sites() -> list:
    src = SFTP_SRC.read_text(encoding="utf-8")
    calls = re.findall(r"safe_event\((.*?)\)\s*$", src, re.M | re.S)
    assert len(calls) >= 40, f"only found {len(calls)} call sites; the scan is not seeing them"
    return calls


def _load_events():
    """Import the emitter alone.

    It deliberately imports nothing from the application, so this needs no database, no config
    and no running server — which is what lets these run in the offline lane where CI executes
    them.
    """
    spec = importlib.util.spec_from_file_location("_dv_safe_log", EVENTS_SRC)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------------------------
# Static: every call site, so a new one cannot regress
# ---------------------------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.crypto_compatibility
def test_the_server_prints_only_through_the_event_emitter() -> None:
    """One exit means one place to enforce the rule; forty-five ad-hoc prints meant forty-five.

    Widened past sftp_server.py deliberately. The SFTP process is not its only writer: the
    vault service prints from the blob-replacement and delete routines that the SFTP
    finalizer and remove path call straight into, so a storage path could still land in the
    same container log next to a clean event line. A rule enforced at one of two doors is
    not enforced. Widened again to the encrypted-file storage layer (whose secure-delete
    failure printed the file's on-disk PATH via the raw OSError) and the activity monitor
    (which printed the raw exception from every Redis broadcast/operation failure).
    """
    offenders = []
    for path in (SFTP_SRC, VAULT_SVC, STORAGE_SVC, ACTIVITY_SVC):
        for lineno, ln in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            # Any direct write, not only a line that begins with print(.
            if re.search(r"(?<![\w.])print\s*\(|sys\.std(out|err)\.write|traceback\.print_",
                         ln):
                offenders.append(f"{path.name}:{lineno}: {ln.strip()}")
    assert offenders == [], offenders


@pytest.mark.unit
@pytest.mark.crypto_compatibility
def test_no_event_can_carry_a_filename_or_a_raw_exception() -> None:
    """The two things the old lines leaked, checked at every call site at once."""
    for call in _call_sites():
        assert "filename" not in call, f"an event carries the filename: {call!r}"
        assert "file_name" not in call, f"an event carries the filename: {call!r}"
        # `e`/`ex` are passed positionally as the exception OBJECT and the emitter prints only its
        # class. What must never appear is the interpolated text.
        assert "{e}" not in call and "{ex}" not in call, f"an event interpolates a message: {call!r}"
        assert "str(e" not in call, f"an event stringifies an exception: {call!r}"


@pytest.mark.unit
@pytest.mark.crypto_compatibility
def test_no_event_carries_a_host_filesystem_path() -> None:
    """A path tells an attacker about the deployment and an operator nothing they need."""
    for call in _call_sites():
        for banned in ("_SFTP_TMP_DIR", "host_key_path", "writepath", "tmp_path", "storage_path"):
            assert banned not in call, f"an event carries a host path via {banned}: {call!r}"


@pytest.mark.unit
@pytest.mark.crypto_compatibility
def test_session_tokens_stay_truncated() -> None:
    """Existing good behaviour. The conversion had to preserve it, not rediscover it."""
    for call in _call_sites():
        if "session=" in call:
            assert "[:8]" in call, f"a session token is logged untruncated: {call!r}"


@pytest.mark.unit
@pytest.mark.crypto_compatibility
def test_the_emitter_drops_unknown_fields_and_redacts_unsafe_values(monkeypatch) -> None:
    """Whitelisting by name AND validating by shape is what stops a new call site widening the
    log by accident."""
    events = _load_events()
    written = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: written.append(" ".join(map(str, a))))

    events.safe_event("probe.code", vault="11111111-2222-3333-4444-555555555555", bytes=1234)
    assert written[-1] == "event probe.code bytes=1234 vault=11111111-2222-3333-4444-555555555555"

    # A field nobody whitelisted is dropped, not printed.
    events.safe_event("probe.code", filename="secret-merger-terms.pdf")
    assert written[-1] == "event probe.code", written[-1]

    # `reason` is no longer whitelisted at all, so free text is DROPPED rather than merely
    # redacted -- the stronger outcome, and the reason the unused permissive names were removed.
    events.safe_event("probe.code", reason="/app/storage/.sftp_tmp/secret-merger-terms.pdf")
    assert written[-1] == "event probe.code", written[-1]

    # A whitelisted field carrying an unsafe VALUE is redacted rather than trusted. This is the
    # backstop behind the name whitelist, and it has to hold on its own: a filename like
    # `payroll-2026.xlsx` MATCHES the value pattern, so the name list is the real defence.
    events.safe_event("probe.code", session="/app/storage/secret-merger-terms.pdf")
    assert "secret" not in written[-1], written[-1]
    assert "<redacted>" in written[-1], written[-1]

    # A trailing newline must not slip past: `$` matches before one, so this needs fullmatch.
    events.safe_event("probe.code", session="abcd1234\n")
    assert "<redacted>" in written[-1], written[-1]

    # The event code bypasses the field whitelist, so it is shape-checked too. Note what that
    # can and cannot do: it stops line forgery and stray characters, but a lowercase filename
    # has exactly the same shape as an event code, so no runtime check can tell them apart.
    # The real guarantee is that every code is a literal, which the static test below enforces.
    events.safe_event("forged\nsftp fake.event")
    assert written[-1] == "event invalid-code", written[-1]
    events.safe_event("Has Spaces And Caps")
    assert written[-1] == "event invalid-code", written[-1]

    # The exception class survives; its message never does.
    events.safe_event("probe.code", ValueError("connect to 10.0.0.5 failed for user bob"))
    assert written[-1] == "event probe.code err=ValueError", written[-1]

    # A peer arrives as paramiko's (host, port) tuple; str() on it would fail the shape check and
    # be redacted, which is safe but useless. The host survives, the ephemeral port does not.
    events.safe_event("probe.code", peer=("203.0.113.7", 51234))
    assert written[-1] == "event probe.code peer=203.0.113.7", written[-1]


@pytest.mark.unit
@pytest.mark.crypto_compatibility
def test_the_audit_still_scrubs_names_and_no_longer_stores_exception_text() -> None:
    """Re-proving existing behaviour, which this phase asks for explicitly.

    The audit deliberately keeps identifying an object by UUID while dropping its name, because
    those names are encrypted one table over and persisting the plaintext would hand them back to
    anyone who can read a backup.
    """
    audit = (ROOT / "app" / "services" / "audit_logger.py").read_text(encoding="utf-8")
    assert '_name_keys = ("file_name", "folder_name", "old_name", "new_name")' in audit
    assert "k not in _name_keys" in audit

    sftp = SFTP_SRC.read_text(encoding="utf-8")
    assert "self.client_address, type(e).__name__" in sftp, (
        "the login-failure audit is storing raw exception text again; it lands in the row's "
        "reason and error_message, which is the same hazard one table over"
    )


# ---------------------------------------------------------------------------------------------
# Live: the container's own log, after a real upload
# ---------------------------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.sftp
@pytest.mark.crypto_compatibility
def test_a_real_upload_leaves_no_filename_in_the_container_log(admin, temp_vault) -> None:
    """The end-to-end claim, read back from the container's own log.

    A static scan proves no call site *can* print the name. This proves the running server *does
    not*, which is the property an operator actually cares about -- and it is the one a future
    refactor into some other logging mechanism would still have to satisfy.
    """
    paramiko = pytest.importorskip("paramiko")
    if shutil.which("docker") is None:
        pytest.skip("reading the container's own log needs the docker CLI")
    from conftest import ADMIN_PASS, ADMIN_USER, BASE_URL

    # Read EVERY container that could hold the line, not one guessed from whichever variable
    # happens to be set. Falling back to the API container in split mode reads a log the SFTP
    # server never writes to -- where the sentinel is absent for reasons unrelated to this fix,
    # so the test would pass while proving nothing. Combined deployments put both halves in one
    # container; split puts them in two; checking both is correct for either.
    candidates = [c for c in (os.environ.get("VAULT_SFTP_CONTAINER"),
                              os.environ.get("VAULT_API_CONTAINER"),
                              "vault-sftp") if c]
    containers = list(dict.fromkeys(candidates))
    host = urlsplit(BASE_URL).hostname or "127.0.0.1"
    port = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
    sentinel = f"acquisition-terms-{uuid.uuid4().hex[:8]}-CONFIDENTIAL.txt"

    since = None
    reachable = []
    for name in containers:
        stamp = subprocess.run(
            # Trailing Z, or the docker CLI parses this in the CLI HOST's timezone rather than
            # UTC. West of UTC that puts the window in the future and the log comes back empty.
            ["docker", "exec", name, "date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
            capture_output=True, text=True, timeout=30,
        )
        if stamp.returncode == 0:
            reachable.append(name)
            since = since or stamp.stdout.strip()
    assert reachable, f"none of these containers exist: {containers}"

    vault_name = temp_vault["name"]
    transport = paramiko.Transport((host, port))
    transport.banner_timeout = 30
    try:
        transport.connect(username=ADMIN_USER, password=ADMIN_PASS)
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            with sftp.open(f"/{vault_name}/{sentinel}", "wb") as fh:
                fh.write(b"x" * 64)
            names = [a.filename for a in sftp.listdir_attr(f"/{vault_name}")]
            assert sentinel in names, f"the upload did not land: {names}"
        finally:
            sftp.close()
    finally:
        transport.close()

    combined = ""
    for name in reachable:
        logs = subprocess.run(
            ["docker", "logs", "--since", since, name],
            capture_output=True, text=True, timeout=60,
        )
        combined += logs.stdout + logs.stderr
    offending = [ln for ln in combined.splitlines() if sentinel in ln]
    assert not offending, (
        "the uploaded filename appears in the container log:\n" + "\n".join(offending)
    )

    # Non-vacuity: the upload must actually have been logged, or its name being absent from an
    # empty log would prove nothing at all.
    assert "event upload.stored" in combined, (
        "no upload event was logged, so the missing filename means nothing:\n" + combined[-2000:]
    )


@pytest.mark.unit
@pytest.mark.crypto_compatibility
def test_events_are_flushed() -> None:
    """Without this the container's log is empty and nobody notices.

    The server writes to a pipe rather than a terminal, so Python block-buffers stdout. This
    process is long-lived and low-volume, so the buffer can take days to fill -- `docker logs`
    for the SFTP container returned nothing at all, while every event sat unread in memory. It
    was found because the live test below refuses to pass against an empty log.
    """
    src = EVENTS_SRC.read_text(encoding="utf-8")
    assert "flush=True" in src, "events are buffered and will not reach the container log"


@pytest.mark.integration
@pytest.mark.sftp
@pytest.mark.crypto_compatibility
def test_the_stored_audit_row_identifies_the_file_without_naming_it(admin, temp_vault) -> None:
    """Behavioural proof, which a source grep is not.

    The previous check asserted the scrubber was still WRITTEN. That breaks on a reformat and
    passes on a scrubber that no longer works. What matters is the row: the object identified by
    UUID, and its plaintext name absent -- because those names are encrypted one table over, and
    persisting them here would hand them back to anyone who can read a backup.
    """
    paramiko = pytest.importorskip("paramiko")
    from conftest import ADMIN_PASS, ADMIN_USER, BASE_URL

    host = urlsplit(BASE_URL).hostname or "127.0.0.1"
    port = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
    sentinel = f"board-pack-{uuid.uuid4().hex[:8]}-SENSITIVE.txt"

    transport = paramiko.Transport((host, port))
    transport.banner_timeout = 30
    try:
        transport.connect(username=ADMIN_USER, password=ADMIN_PASS)
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            with sftp.open(f"/{temp_vault['name']}/{sentinel}", "wb") as fh:
                fh.write(b"y" * 32)
        finally:
            sftp.close()
    finally:
        transport.close()

    rows = admin.get("/audit/log", params={"action": "file_upload", "limit": 100}).json()
    entries = rows.get("logs", rows) if isinstance(rows, dict) else rows
    uploads = [r for r in entries if isinstance(r, dict) and r.get("action") == "file_upload"]
    assert uploads, "the SFTP upload produced no audit row at all"

    blob = json.dumps(uploads[:10])
    assert sentinel not in blob, f"the plaintext filename is stored in the audit row: {blob[:400]}"
    # Non-vacuity: the row must still identify the object, or scrubbing everything would pass.
    assert any(r.get("resource_id") for r in uploads[:10]), (
        "no audit row carries a resource_id, so the absence of the name proves nothing"
    )


@pytest.mark.unit
@pytest.mark.crypto_compatibility
def test_every_event_code_is_a_literal() -> None:
    """The one input the field whitelist cannot protect.

    A runtime shape check cannot help here: `upload.rejected.payroll-2026.xlsx` has exactly the
    same shape as a legitimate code. So the guarantee has to be structural -- every code is a
    quoted literal, never built from a value. An f-string in this position would print whatever
    it interpolated, straight past every other defence in the module.
    """
    import ast

    checked = 0
    for path in (SFTP_SRC, VAULT_SVC, STORAGE_SVC, ACTIVITY_SVC):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name != "safe_event" or not node.args:
                continue
            checked += 1
            first = node.args[0]
            assert isinstance(first, ast.Constant) and isinstance(first.value, str), (
                f"{path.name}:{first.lineno}: the event code is computed, not a literal -- "
                "it would print whatever it interpolated"
            )
    assert checked >= 45, f"only inspected {checked} call sites; the walk is not finding them"
