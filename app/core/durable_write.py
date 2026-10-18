"""Stored bytes reach the disk before anything says they exist.

A file's bytes and the row that lists it are written by two systems with two ideas of "written". The
database forces each commit to the disk before it answers. A file that is only closed sits in the
kernel's page cache, which writes it out some seconds later. A host that loses power in between comes
back with the row and without the bytes: the file is listed, and its download fails. So every writer of
stored bytes calls these before a row, or an answer to the client, says the bytes are there:

- :func:`sync_file` on the open file, after its last write and before it is closed, or renamed into
  place: the file's content and size are on the disk;
- :func:`sync_directory` on the directory the file was created or renamed into: its name is on the disk;
- :func:`make_directories` for a directory the file needs: each directory it creates is synced into its
  parent, so the path down to the file is on the disk too.

None of them is called on an error path that removes the file. There is nothing there to keep.

What this cannot do: survive a disk that reports a write it has not made. And it changes nothing for a
process that is killed: its writes are already in the kernel, which keeps them. Only a power cut or a
kernel crash loses what was never synced.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path

# Windows cannot open a directory to sync it. The vault runs on Linux; this lets a development
# checkout and the offline tests run on Windows, where only the directory step is skipped.
DIRECTORY_SYNC = os.name != "nt"

# What a filesystem that cannot sync a directory at all answers. PostgreSQL ignores these two for a
# directory for the same reason. Every other error, EIO above all, means the name may not be on the
# disk, and is raised.
_CANNOT_SYNC_DIRECTORY = frozenset({errno.EINVAL, errno.EBADF})

# A directory this process may create entries in but not read (write and search permission, no read)
# cannot be opened, so it cannot be synced from here; PostgreSQL skips it too. That is a parent the
# vault does not own, as the one a custom storage path is first created in can be: an upload or a
# start there must not fail for a sync it cannot do, as neither did before directories were synced.
_CANNOT_OPEN_DIRECTORY = frozenset({errno.EACCES})


def sync_file(handle) -> None:
    """Force a file's content to the disk: an open file object (its buffer is flushed first) or a
    descriptor from ``os.open``."""
    if isinstance(handle, int):
        os.fsync(handle)
        return
    handle.flush()
    os.fsync(handle.fileno())


def sync_directory(path) -> None:
    """Force the names in directory ``path`` to the disk: a file just created in it or renamed into
    it is then found there after a power cut."""
    if not DIRECTORY_SYNC:
        return
    try:
        fd = os.open(os.fspath(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        if exc.errno in _CANNOT_OPEN_DIRECTORY:
            return
        raise
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in _CANNOT_SYNC_DIRECTORY:
            raise
    finally:
        os.close(fd)


def make_directories(path) -> None:
    """Create ``path`` and any missing directory above it, like ``mkdir -p``, syncing each directory
    it creates into its parent, from the top down.

    A directory another process creates in the same moment is synced as well, since this one cannot
    know whether its creator got that far. A directory that was already there is left as it is.
    """
    path = Path(path)
    missing = []
    current = path
    while not current.is_dir():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    for directory in reversed(missing):
        try:
            directory.mkdir()
        except FileExistsError:
            if not directory.is_dir():
                raise
        sync_directory(directory.parent)
