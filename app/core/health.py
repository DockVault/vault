"""Subsystem checks behind the unauthenticated ``/health`` endpoint.

``/health`` answers before anyone logs in — a container healthcheck and any monitoring in front
of the app both read it. So every check here returns a short, fixed vocabulary and nothing else:
no paths, no capacity figures, no host details, no exception text. Knowing that storage is
writable is operationally useful; knowing *where* it is, or how full, tells an anonymous caller
about the machine.

This mirrors ``check_db_connection`` / ``check_redis_connection`` in ``database.py``, which
already answer as bare booleans "without leaking connection details".
"""
import os
import socket
import uuid

from app.core.config import settings


# Set by run_combined.py on the children it starts, and ONLY there: it is the one launcher that
# serves the web and SFTP halves from a single container. Its absence means SFTP, if this
# deployment runs it at all, is in another container — see check_sftp_status.
SFTP_IN_CONTAINER_ENV = "VAULT_SFTP_IN_CONTAINER"


def _truthy(value) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def check_sftp_status() -> str:
    """``disabled`` | ``external`` | ``listening`` | ``unreachable``.

    SFTP is opt-in: a deployment runs web only unless ``RUN_SFTP`` is set, and the two halves
    are separate processes. The API process therefore cannot inspect the SFTP process directly
    — it asks the only question that matters to a client, which is whether something is
    accepting connections on the port.

    ``disabled`` is deliberately distinct from ``unreachable``: a vault that was never meant to
    serve SFTP is healthy, while one that was and is not, is broken. Collapsing the two would
    make every web-only deployment look degraded.

    ``external`` exists because ``RUN_SFTP`` and the loopback probe answer different questions.
    ``RUN_SFTP`` says the DEPLOYMENT serves SFTP; the probe says THIS CONTAINER does. In the
    split profile those diverge: ``vault-api`` is started with an explicit api-only command and
    SFTP lives in its own ``vault-sftp`` container, yet ``RUN_SFTP`` still arrives from the
    shared ``.env``. Probing loopback there finds nothing and reports a subsystem this process
    was never asked to run as broken — which made every split deployment permanently
    ``degraded``. ``run_combined.py`` is the only launcher that serves both halves from one
    container, so it marks the processes it starts; without that marker SFTP is somebody else's
    container and this one declines to answer for it.
    """
    if not _truthy(os.environ.get("RUN_SFTP")):
        return "disabled"
    if not _truthy(os.environ.get(SFTP_IN_CONTAINER_ENV)):
        return "external"
    try:
        with socket.create_connection(("127.0.0.1", int(settings.sftp_port)), timeout=2):
            return "listening"
    except Exception:
        return "unreachable"


def check_storage_status() -> str:
    """``writable`` | ``unwritable``.

    Actually writes, rather than asking the OS for permission bits: the interesting failures
    here are a full disk and a volume that mounted read-only, and neither shows up in a
    permission check. The probe file is uniquely named and removed in a ``finally``, so two
    concurrent checks cannot collide and a mid-check crash leaves at most one stray zero-byte
    file inside the storage root.
    """
    probe = os.path.join(settings.file_storage_path, f".health-{uuid.uuid4().hex}")
    try:
        os.makedirs(settings.file_storage_path, exist_ok=True)
        with open(probe, "wb") as fh:
            fh.write(b"")
        return "writable"
    except Exception:
        return "unwritable"
    finally:
        try:
            os.remove(probe)
        except OSError:
            pass


# Computed once, after the boot-time replay has run, and never again while the process lives.
#
# The value cannot change: the replay only happens in the lifespan handler, before the app serves
# anything. Re-reading it would put a database round trip in the container healthcheck's path
# every thirty seconds for the life of the deployment, to re-derive a constant -- and that cost is
# measurable, not theoretical. It showed up as a memory rise during a large download that happened
# to overlap a healthcheck.
_SCHEMA_STATE: str | None = None


def refresh_schema_state() -> str:
    """Read the recorded schema state and remember it. Called once at startup."""
    global _SCHEMA_STATE
    _SCHEMA_STATE = _read_schema_state()
    return _SCHEMA_STATE


def check_schema_state() -> str:
    """The schema state as of this process's boot.

    Falls back to reading when nothing has been remembered yet, so a caller that arrives before
    startup finished -- or a test exercising this directly -- still gets a real answer rather than
    a default.
    """
    if _SCHEMA_STATE is not None:
        return _SCHEMA_STATE
    return _read_schema_state()


def _read_schema_state() -> str:
    """``complete`` | ``incomplete`` | ``partial`` | ``unknown``.

    Reads what the boot-time DDL replay recorded about itself. The four answers are distinct on
    purpose, because they call for different things from whoever reads them:

    * ``complete`` -- every declared step applied.
    * ``incomplete`` -- at least one step FAILED. The deployment is missing schema it believes it
      has, and requests that need it will error. This is the state that makes ``/health`` answer
      non-2xx.
    * ``partial`` -- a step was deliberately skipped because the data made it inapplicable, which
      today means the case-insensitive email index on a deployment holding two addresses differing
      only in case. The code chose to boot rather than refuse, and that choice stands; reporting it
      as a failure would restart a container that is working as designed. It is surfaced so the
      operator can see a difference from a fresh install that used to be invisible.
    * ``unknown`` -- the record could not be read. Reported honestly rather than as ``complete``:
      "cannot tell" and "fine" are different answers, and defaulting to the reassuring one is the
      habit this whole surface exists to break. A deployment whose database is unreachable is
      already reporting that separately.
    """
    try:
        from sqlalchemy import func, select

        from app.core.database import get_db_context
        from app.core.models import SchemaStep

        with get_db_context() as db:
            counts = dict(
                db.execute(
                    select(SchemaStep.outcome, func.count()).group_by(SchemaStep.outcome)
                ).all()
            )
    except Exception:
        return "unknown"

    if counts.get(SchemaStep.OUTCOME_FAILED):
        return "incomplete"
    if counts.get(SchemaStep.OUTCOME_SKIPPED):
        return "partial"
    if not counts:
        # No rows at all. Either the replay has never run here, or it could not record -- both mean
        # the question has not been answered, and neither is evidence that the schema is right.
        return "unknown"
    return "complete"
