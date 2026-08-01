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


def _truthy(value) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def check_sftp_status() -> str:
    """``disabled`` | ``listening`` | ``unreachable``.

    SFTP is opt-in: a deployment runs web only unless ``RUN_SFTP`` is set, and the two halves
    are separate processes in one container. The API process therefore cannot inspect the SFTP
    process directly — it asks the only question that matters to a client, which is whether
    something is accepting connections on the port.

    ``disabled`` is deliberately distinct from ``unreachable``: a vault that was never meant to
    serve SFTP is healthy, while one that was and is not, is broken. Collapsing the two would
    make every web-only deployment look degraded.
    """
    if not _truthy(os.environ.get("RUN_SFTP")):
        return "disabled"
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
