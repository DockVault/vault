"""The free space the storage volume keeps: uploads, SFTP writes and copies stop before it is used up.

Nothing else bounds the disk on the shipped defaults: MAX_STORAGE_GB is unlimited, an administrator need not save a
limit in the panel, and what legal holds keep after a deletion is in no vault's size. A member of a held vault could
upload and delete in turn until the disk was full, and a full disk stops more than uploads: the database shares it
on most installs, and a database that cannot write its log stops.

So every write of a file's bytes to the storage volume keeps at least ``floor_bytes`` of it free:

- before a transfer starts, when its size is known (an upload's declared length, a chunked upload's declared size,
  a chunk's, a copy's): refused when storing it would leave less than the floor;
- while its bytes are written (app/services/streaming_upload.py): every ``CHECK_EVERY_BYTES`` written, refused once
  less than the floor is left, so one transfer of unknown size cannot run the disk to the end;
- as its row is written (VaultService._claim_room): refused when less than the floor is left with its bytes on
  the disk.

A refused file is removed. The floor is MIN_FREE_SPACE_GB: by default (-1) the larger of 2 GB and 5% of the volume,
but never more than half of it (on a volume of less than 4 GB, 2 GB would leave little or nothing to store) nor more
than 20 GB (5% of a 400 GB volume; 5% of a larger one holds back far more than the server and its database need, a
terabyte of a 20 TB volume), 0 turns it off, any other value is that many GB, more than 20 GB too. A value that is
not a finite number reads as the default. A volume that reports no size (some network filesystems) cannot be judged
and is not checked; a volume whose free space cannot be read is not checked either, and the server's log says so
once.
"""
from __future__ import annotations

import math
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

GIB = 1024 ** 3
# The automatic floor: the larger of these, but never more than AUTO_MAX_SHARE of the volume nor AUTO_MAX_BYTES.
AUTO_MIN_BYTES = 2 * GIB
AUTO_FRACTION = 0.05
AUTO_MAX_SHARE = 0.5
AUTO_MAX_BYTES = 20 * GIB
# A configured floor larger than this (4 EiB, more than any volume) is held at it.
MAX_FLOOR_BYTES = 2 ** 62
# How many bytes a transfer writes between two looks at the free space (a look costs one statvfs call).
CHECK_EVERY_BYTES = 8 * 1024 * 1024

_said = threading.Event()


@dataclass(frozen=True)
class Room:
    free: int
    floor: int
    total: int


def configured_gb():
    from app.core.config import settings
    return getattr(settings, "min_free_space_gb", -1)


def floor_bytes(total: int, configured=None) -> int:
    """The bytes the volume keeps free, for a volume of ``total`` bytes: 0 when the floor is off."""
    value = configured_gb() if configured is None else configured
    try:
        value = float(value)
    except (TypeError, ValueError):
        value = -1.0
    # Negative, NaN or infinite: automatic. ('inf' is a float the settings accept, and int() of it raises, which
    # would turn every upload into a 500.)
    if not math.isfinite(value) or value < 0:
        return min(max(AUTO_MIN_BYTES, int(total * AUTO_FRACTION)), int(total * AUTO_MAX_SHARE), AUTO_MAX_BYTES)
    # A value so large its bytes are no longer a finite float still means "more than any volume".
    return int(min(value * GIB, float(MAX_FLOOR_BYTES)))


def storage_path():
    from app.core.config import settings
    return settings.file_storage_path


def room(path=None) -> Optional[Room]:
    """The volume's free space and floor at ``path`` (the storage path by default), or None when it cannot be
    judged: the floor is off, the volume reports no size, or its free space cannot be read."""
    where = Path(path or storage_path())
    try:
        usage = shutil.disk_usage(str(where))
    except OSError as exc:
        if not _said.is_set():
            _said.set()
            print(f"Warning: the free space of the storage volume could not be read ({type(exc).__name__}); "
                  "uploads are not held to MIN_FREE_SPACE_GB while it cannot", flush=True)
        return None
    if not usage.total:
        return None
    floor = floor_bytes(usage.total)
    if floor <= 0:
        return None
    return Room(free=int(usage.free), floor=floor, total=int(usage.total))


def short_of(additional: int = 0, path=None) -> Optional[Room]:
    """The volume's room when writing ``additional`` more bytes would leave less than its floor free; None when
    there is room, or the floor is off or cannot be judged."""
    found = room(path)
    if found is None:
        return None
    if found.free - max(0, int(additional or 0)) < found.floor:
        return found
    return None


def _size(n: int) -> str:
    from app.core import storage_quota
    return storage_quota.format_bytes(n)


def refusal_text(found: Room) -> str:
    """What a refused transfer is told."""
    return (f"The server's storage is nearly full: {_size(found.free)} is free, and it keeps at least "
            f"{_size(found.floor)} free so that the server and its database keep working. Free up space, or ask "
            f"an administrator to add space or change MIN_FREE_SPACE_GB.")


class WriteGuard:
    """Asks short_of() as a transfer's bytes are written: at its first write and then every CHECK_EVERY_BYTES. The
    caller's ``refuse(room)`` raises."""

    def __init__(self, path, refuse):
        self._path = path
        self._refuse = refuse
        self._since = None

    def wrote(self, n: int) -> None:
        if self._since is not None and self._since + n < CHECK_EVERY_BYTES:
            self._since += n
            return
        self._since = 0
        found = short_of(0, self._path)
        if found is not None:
            self._refuse(found)
