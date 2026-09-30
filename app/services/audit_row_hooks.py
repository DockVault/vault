"""What AuditLogger.build_row asks of other modules about a row before the row is written.

build_row makes every audit row, for the web app and the SFTP server alike (nothing else constructs an
AuditLog). Once it has filled a row from its arguments and from the request, it calls these hooks, in
this order, once each:

    provenance(row)             how the recorded address was learned (row.ip_via);
    case(row)                   the compliance case the request acts under (row.case_id);
    privacy(row, raw_details)   what is recorded of the row's personal values (row.privacy_version,
                                row.recorded, and what stays in the row's own fields); raw_details is
                                the caller's details before build_row took the name keys out;
    seal_nonce(row)             the value per row under which the log's integrity chain commits to the
                                row's personal values (row.seal_nonce).

The row's id is set before the first hook runs, so a hook may bind something to it; SQLAlchemy would
otherwise give the row its id only when it is flushed. A hook changes the row in place and returns
nothing. It must not raise: build_row runs inside the transaction of the change the row records, so an
exception here fails that change. raw_details is a copy, and the caller's own dict is never changed.

In this release every hook leaves the row as it is, so these columns stay NULL.
"""


def provenance(row) -> None:
    """How row.ip_address was learned. Not recorded yet: row.ip_via stays NULL."""


def case(row) -> None:
    """The compliance case the request acts under. None yet: row.case_id stays NULL."""


def privacy(row, raw_details) -> None:
    """What is recorded of the row's personal values. The row keeps what build_row put in it, with the
    name keys already taken out of its details; row.privacy_version and row.recorded stay NULL."""


def seal_nonce(row) -> None:
    """The row's integrity-chain nonce. Not set yet: row.seal_nonce stays NULL."""
