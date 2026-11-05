"""What AuditLogger.build_row asks of other modules about a row before the row is written.

build_row makes every audit row, for the web app and the SFTP server alike (nothing else constructs an
AuditLog). Once it has filled a row from its arguments and from the request, it calls these hooks, in
this order, once each:

    provenance(row)             how the recorded address was learned (row.ip_via);
    case(row)                   the compliance case the request acts under (row.case_id);
    privacy(row, raw_details)   what is recorded of the row's personal values (row.privacy_version,
                                row.recorded, and what stays in the row's own fields and details);
                                raw_details is the caller's details as given;
    seal_nonce(row)             the value per row under which the log's integrity chain commits to the
                                row's personal values (row.seal_nonce);
    kept_records(row, db)       what the row's being written keeps in the database: a row of the compliance
                                category that records a step taken keeps the data marker that stops an
                                earlier release from starting, written in db, the session build_row was
                                given, which writes the row.

The row's id is set before the first hook runs, so a hook may bind something to it; SQLAlchemy would
otherwise give the row its id only when it is flushed. A hook changes the row in place and returns
nothing. It must not raise: build_row runs inside the transaction of the change the row records, so an
exception here fails that change. raw_details is a copy, and the caller's own dict is never changed.

In this release privacy applies the recording levels (app/core/audit_privacy.py), case puts the id of the
compliance case the code acts under on the row, seal_nonce gives the row its nonce, and kept_records keeps the
compliance records' marker (app/core/compliance_marker.py); provenance leaves the row as it is, so its column
stays NULL.
"""


def provenance(row) -> None:
    """How row.ip_address was learned. Not recorded yet: row.ip_via stays NULL."""


def case(row) -> None:
    """The compliance case the code acts under (app/core/case_context.py, acting_for), or NULL outside one."""
    try:
        from app.core.case_context import current
        case_id = current()
    except Exception:  # noqa: BLE001 -- a hook never fails the change its row records
        return
    if case_id is not None:
        row.case_id = case_id


def privacy(row, raw_details) -> None:
    """What is recorded of the row's personal values: the recording levels decide its username, address,
    user agent and details, and stamp row.privacy_version and row.recorded (app/core/audit_privacy.py).
    Never raises: a failure writes the row without personal values."""
    from app.core import audit_privacy
    audit_privacy.apply(row, raw_details)


def seal_nonce(row) -> None:
    """The row's integrity-chain nonce: 16 random bytes (app/core/audit_integrity.py), under which the chain
    commits to the row's personal values, so an erase that later destroys it leaves nothing that can be tested
    against a guess of the old values."""
    import secrets
    row.seal_nonce = secrets.token_bytes(16)


_compliance_actions = None


def kept_records(row, db=None) -> None:
    """A row of the compliance category (app/core/audit_catalog.py) is kept COMPLIANCE_RECORD_MIN_DAYS, which an
    earlier release would not do. When the row records a step of compliance access taken (compliance_marker.counts:
    not a refusal, not a vault owner's own step), the marker that stops one from starting is written in ``db``'s
    transaction, the one that writes the row (app/core/compliance_marker.py, ensure). Any other row: nothing. Never
    raises."""
    global _compliance_actions
    try:
        if _compliance_actions is None:
            from app.core import audit_catalog
            _compliance_actions = frozenset(audit_catalog.stored_names(["compliance"]))
        if row.action not in _compliance_actions or db is None:
            return
        from app.core import compliance_marker
        if not compliance_marker.counts(row.action, row.status):
            return
        compliance_marker.ensure(db)
    except Exception:  # noqa: BLE001 -- a hook never fails the change its row records; the pruner writes it
        return
