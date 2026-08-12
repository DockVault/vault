"""
Streaming upload context for handling chunked file uploads.
"""
import hashlib
from pathlib import Path


class StreamingUploadContext:
    """
    Context manager for streaming file uploads with chunked encryption.

    The `codec` plugs in the at-rest format. It must expose:
      - ``header() -> bytes``: written once when the file is opened (may be empty).
      - ``encrypt(chunk: bytes, index: int) -> bytes``: the on-disk bytes for one
        chunk; ``index`` is the monotonic 0-based position (used by the AES-GCM codec
        as part of each chunk's AAD, so reorders are detectable on read).
    See ``security.GcmChunkStreamCodec`` (Standard vaults) and
    ``security.IdentityChunkCodec`` (zero-knowledge passthrough).
    """

    def __init__(self, file_id, storage_path: Path, codec):
        self.file_id = file_id
        self.storage_path = storage_path
        self.codec = codec
        self.file_handle = None
        self.total_bytes = 0
        self.hasher = hashlib.sha256()
        self.chunks_written = 0

    def __enter__(self):
        """Open file for writing encrypted chunks and emit the format header."""
        self.file_handle = open(self.storage_path, 'wb')
        header = self.codec.header()
        if header:
            self.file_handle.write(header)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close the stream -- writing its terminal first, if the format has one.

        Only on a clean exit. A failed upload must NOT be terminated: a terminal says "this file is
        complete", and writing one over a partial upload would turn a detectable truncation into an
        object that authenticates as whole. On the error path the file is removed below anyway, but
        the ordering matters more than the cleanup does, because the cleanup is best-effort.
        """
        terminal_failed = None
        if self.file_handle:
            try:
                if exc_type is None and hasattr(self.codec, 'terminal'):
                    self.file_handle.write(self.codec.terminal())
            except Exception as e:      # noqa: BLE001 - out of disk, I/O error
                # Must not escape before the close below, or the handle leaks and the cleanup
                # never runs -- `exc_type` is still None on this path, so the error branch would
                # not fire either. The partial blob is unreadable regardless (no terminal), but
                # leaking a descriptor and a file is not a good way to express that.
                terminal_failed = e
            finally:
                self.file_handle.close()

        # If there was an error, clean up the file
        if (exc_type is not None or terminal_failed is not None) and self.storage_path.exists():
            try:
                self.storage_path.unlink()
            except:
                pass

        if terminal_failed is not None:
            raise terminal_failed
        return False

    def write_chunk(self, chunk: bytes) -> int:
        """
        Write and encrypt a chunk of data.

        Args:
            chunk: Raw chunk data

        Returns:
            Number of bytes written (raw, before encryption)
        """
        if not chunk:
            return 0

        # Update checksum with raw data
        self.hasher.update(chunk)

        # Encrypt chunk (bound to its 0-based position for the AEAD AAD)
        encrypted_chunk = self.codec.encrypt(chunk, self.chunks_written)

        # Write to file
        self.file_handle.write(encrypted_chunk)

        # Update counters
        chunk_size = len(chunk)
        self.total_bytes += chunk_size
        self.chunks_written += 1

        return chunk_size
    
    def get_checksum(self) -> str:
        """Get SHA256 checksum of original (unencrypted) data."""
        return self.hasher.hexdigest()
    
    def get_total_size(self) -> int:
        """Get total bytes written (original size, not encrypted size)."""
        return self.total_bytes
