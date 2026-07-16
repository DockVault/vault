"""
Encrypted File Storage — secure-deletion helper.

The whole-file AES-256-GCM writer that used to live here has been removed. Every
upload now goes through the AES-GCM chunked at-rest stream (see
``VaultService.upload_file_streaming``), which binds each chunk's AAD to
``vault_id`` + ``file_id``. Only the secure-delete overwrite helper below is used
by the live code (``VaultService`` calls it when destroying a blob).
"""

import os
from pathlib import Path
import secrets


class EncryptedFileStorage:
    """Filesystem helper for securely destroying stored vault blobs."""

    def __init__(self, base_storage_path: Path):
        """
        Args:
            base_storage_path: Base directory for file storage
        """
        self.storage_path = Path(base_storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def secure_delete(self, storage_path: Path) -> None:
        """
        Securely delete a stored file by overwriting it with random data before
        removal (single pass), for compliance with data-protection regulations.

        Args:
            storage_path: Path to file to delete
        """
        if not storage_path.exists():
            return

        try:
            # Get file size
            file_size = storage_path.stat().st_size

            # Overwrite with random data
            with open(storage_path, 'wb') as f:
                # Write random data in 1MB chunks to avoid memory issues
                chunk_size = 1024 * 1024
                remaining = file_size
                while remaining > 0:
                    chunk = secrets.token_bytes(min(chunk_size, remaining))
                    f.write(chunk)
                    remaining -= len(chunk)

            # Flush to disk
            with open(storage_path, 'rb') as f:
                os.fsync(f.fileno())

            # Finally, delete the file
            storage_path.unlink()

        except Exception as e:
            # If secure deletion fails, still try to delete normally
            print(f"Warning: Secure deletion failed: {e}")
            try:
                storage_path.unlink()
            except Exception:
                pass
