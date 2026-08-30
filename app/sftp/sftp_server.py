"""
Custom SFTP server implementation using Paramiko.

Implements secure SFTP with vault support and hierarchical access control.

Standard-vault SFTP security model:
  * The SFTP client IS the UI; we expose a *virtual* tree — the principal's
    accessible vaults as top-level folders, their folders/files inside
    (``/Finance-Vault/report.pdf``). There is no real on-disk directory the
    client sees; every path is resolved against the database for THIS principal.
  * The authenticated principal is ``self.server.user`` (set by
    ``check_auth_password``). Every authorization decision uses it.
  * All file I/O is routed through ``VaultService`` so each path is re-authorized
    exactly like the web handlers: ``get_vault`` re-checks membership + the
    temp-credential vault scope (``enforce_vault``), and the data layer re-checks
    the file's REAL vault (blocks file-ID IDOR). Temp-credential per-vault
    capabilities (``vault.see_files`` / ``file.download`` / ``file.upload`` / …)
    are enforced here before the operation runs.
  * At-rest format is the SAME canonical format the web path uses: SFTP uploads
    go through ``VaultService.upload_file_streaming`` / ``finalize_streaming_upload``
    (the live chunked-Fernet writer) and downloads through
    ``VaultService.download_file`` (which auto-detects format). Web↔SFTP files are
    therefore byte-format identical and mutually decryptable. The per-vault
    AES-256-GCM upgrade is tracked separately as part of the zero-knowledge work
    (assessment #5/#6) and is intentionally NOT changed here.

NOTE on the per-vault *password*: in DockVault the vault password is a web-only
second factor (an access gate; file content is encrypted with the server key, not
the password — see security assessment). SFTP has no prompt channel for it, and
the documented SFTP auth model is {account password, SSH key, temp credential}.
So SFTP access is gated by account/temp-cred auth + vault membership + temp-cred
scope; the per-vault password is not (and cannot be) re-prompted over SFTP. This
matches the design doc, which lists Standard (incl. password-protected) vaults as
SFTP-capable.
"""
import os
import signal
import socket
import threading
import posixpath
import tempfile
import mimetypes
import time
import paramiko
from pathlib import Path
from typing import Optional, Dict, List
import uuid
import redis
import json

if __name__ == "__main__":
    from app.core.config import bootstrap_entrypoint
    bootstrap_entrypoint("SFTP")

from app.core.database import get_db_context
from app.core.models import User, ActiveSession, Vault, Folder, File
from app.services.auth_service import AuthService
from app.core.authorization import PermissionService, PermissionDeniedError
from app.services.vault_service import (
    VaultService,
    VaultNotFoundError,
    FolderNotFoundError,
    PasswordRequiredError,
    InvalidPasswordError,
    require_file_scope,
    require_folder_scope,
    require_item_scope,
    filter_listing_for_scope,
    folder_is_navigable,
)
from app.services.vault_service import FileNotFoundError as VaultFileNotFoundError
from app.services.audit_logger import AuditLogger
from app.core.config import settings
from app.sftp.host_key import generate_ed25519_host_key, load_host_key
from app.core.session_hash_utils import hash_session_token
from app.core.safe_log import safe_event
from app.core.temp_scope import is_scoped, effective_vault_caps, scope_ids
from app.core.security import name_blind_index
from sqlalchemy import or_

# Global registry of active transports: session_token -> transport
active_transports: Dict[str, paramiko.Transport] = {}
transport_lock = threading.Lock()

# Pre-auth connection admission (the SSH MaxStartups equivalent; see settings.sftp_max_connections*).
# The accept loop builds a worker thread + a paramiko Transport per accepted TCP connection, and the
# auth throttles only fire once a credential is OFFERED -- so a flood of connections that complete the
# handshake but never authenticate would otherwise tie up threads and Transports through the grace
# window with nothing metering raw connections. These gate at accept() time, before a thread or
# Transport is created, and drop the connection when a limit is hit.
class _ConnectionAdmission:
    """Non-blocking pre-auth admission for SFTP connections (the SSH MaxStartups equivalent).

    ``max_total`` caps live connections overall; ``max_per_ip`` caps one source IP's in-flight share.
    Either being <= 0 disables that limit. :meth:`admit` reserves a slot (False when a ceiling is
    reached); every True MUST be paired with exactly one :meth:`release`, so callers release in a
    ``finally``. Thread-safe: the accept loop and every worker thread share one instance.
    """

    def __init__(self, max_total: int, max_per_ip: int):
        self._max_per_ip = max_per_ip
        self._sem = (threading.BoundedSemaphore(max_total)
                     if max_total and max_total > 0 else None)
        self._per_ip: Dict[str, int] = {}
        self._lock = threading.Lock()

    def admit(self, ip: str) -> bool:
        if self._sem is not None and not self._sem.acquire(blocking=False):
            return False
        if self._max_per_ip and self._max_per_ip > 0:
            with self._lock:
                if self._per_ip.get(ip, 0) >= self._max_per_ip:
                    if self._sem is not None:
                        self._sem.release()  # give back the total slot we just took
                    return False
                self._per_ip[ip] = self._per_ip.get(ip, 0) + 1
        return True

    def release(self, ip: str) -> None:
        if self._max_per_ip and self._max_per_ip > 0:
            with self._lock:
                remaining = self._per_ip.get(ip, 0) - 1
                if remaining <= 0:
                    self._per_ip.pop(ip, None)
                else:
                    self._per_ip[ip] = remaining
        if self._sem is not None:
            self._sem.release()


_connection_admission = _ConnectionAdmission(
    settings.sftp_max_connections, settings.sftp_max_connections_per_ip)

# Where incoming uploads are buffered (plaintext) before being pushed through the
# encryption pipeline at handle close. The path sits inside the storage volume, but the compose
# files mount a size-capped tmpfs (RAM) over this subdirectory, so the plaintext buffer never
# reaches persistent disk. A deployment whose compose does not mount that tmpfs keeps buffering on
# the volume as before (and should set SFTP_STAGING_TMPFS_MB=0 so uploads are not size-clamped).
_SFTP_TMP_DIR = Path(settings.file_storage_path) / ".sftp_tmp"


def _staging_capped_max(eff_max_bytes: int, tmpfs_mb: int) -> int:
    """The per-upload byte cap, clamped to the SFTP staging tmpfs budget.

    A buffered SFTP upload cannot be larger than the tmpfs it is staged in, so the per-file limit
    is capped there and an oversized upload is refused in-stream -- a clean failure -- rather than
    filling the tmpfs mid-write. ``tmpfs_mb <= 0`` disables the clamp (staging is on the volume, not
    a tmpfs); an ``eff_max_bytes`` of 0 means "no configured per-file limit", so the budget itself
    becomes the limit.
    """
    if tmpfs_mb and tmpfs_mb > 0:
        budget = tmpfs_mb * 1024 * 1024
        return budget if eff_max_bytes <= 0 else min(eff_max_bytes, budget)
    return eff_max_bytes

# POSIX open-flag access mode mask (app/sftp/sftp_server.py only runs inside the Linux
# container, but be defensive if os lacks the constant).
_O_ACCMODE = getattr(os, "O_ACCMODE", 0o3)
_O_CREAT = getattr(os, "O_CREAT", 0o100)


def _strip_ctrl(name: str) -> str:
    """Drop C0 control characters (incl. CR/LF) and DEL from an SFTP-supplied filename.

    An SFTP path segment may hold any byte except '/', so a client can put/rename to a name
    with embedded control chars; persisted verbatim into File.original_name, they later inject
    into a web download's Content-Disposition header (that download sink is also hardened — this
    is the SFTP source guard). Mirrors security.sanitize_filename's control-char rule but keeps
    everything else, so a legitimate name (spaces, unicode) is preserved for display/download."""
    return ''.join(c for c in (name or '') if ord(c) >= 32 and ord(c) != 127)


def _group_requires_temp_cred_for_sftp(db, user) -> bool:
    """Org SFTP-auth policy: a user in any group listed under the global setting
    ``sftp_require_temp_cred_groups`` may ONLY use a temporary credential for SFTP — direct password and
    SSH-key auth are refused. Per-group by design (a global force would break SSH-key automation). Reads
    the admin Settings store (SystemSetting 'global'); fails OPEN (no extra restriction) on any error."""
    try:
        from app.core.models import SystemSetting, user_groups
        from sqlalchemy import select
        row = db.query(SystemSetting).filter(SystemSetting.key == "global").first()
        groups = (row.value or {}).get("sftp_require_temp_cred_groups") if (row and row.value) else None
        if not groups:
            return False
        required = {str(g) for g in groups}
        user_gids = {
            str(r[0]) for r in db.execute(
                select(user_groups.c.group_id).where(user_groups.c.user_id == user.id)
            ).fetchall()
        }
        return bool(required & user_gids)
    except Exception:  # noqa: BLE001
        return False


def _mfa_sftp_requires_temp_cred(db, user) -> bool:
    """MFA SFTP-auth policy: when the org sets ``mfa_sftp_policy=temp_credential_only``, a user whose
    second factor is IN EFFECT (enrolled, or required by mode / department / user) may reach SFTP ONLY
    through a temporary credential — direct password / SSH-key auth is refused, so SFTP cannot become a
    single-factor back door around MFA. Reuses the exact per-group temp-cred mechanism. Reads the admin
    Settings store; fails OPEN (no extra restriction) on any error."""
    try:
        from app.core.models import SystemSetting, SecondFactorEnrollment, user_groups
        from app.core import second_factor_policy as pol
        from sqlalchemy import select
        row = db.query(SystemSetting).filter(SystemSetting.key == "global").first()
        blob = (row.value or {}) if (row and row.value) else {}
        p = pol.effective_policy(blob)
        if p.get("mfa_sftp_policy") != "temp_credential_only":
            return False
        has_active = db.query(SecondFactorEnrollment.id).filter(
            SecondFactorEnrollment.user_id == user.id,
            SecondFactorEnrollment.status == "active").first() is not None
        user_gids = [
            str(r[0]) for r in db.execute(
                select(user_groups.c.group_id).where(user_groups.c.user_id == user.id)
            ).fetchall()
        ]
        eff = pol.effective_second_factor(
            mode=p["mfa_mode"], required_group_ids=p["mfa_required_group_ids"],
            required_user_ids=p["mfa_required_user_ids"], user_group_ids=user_gids,
            user_id=user.id, has_active_enrollment=has_active)
        return bool(eff["in_effect"])
    except Exception:  # noqa: BLE001
        return False


def _user_requires_temp_cred_for_sftp(db, user) -> bool:
    """A non-temp session must use a temporary credential for SFTP when EITHER the per-group rule
    (``sftp_require_temp_cred_groups``) OR the MFA SFTP policy (``mfa_sftp_policy=temp_credential_only``,
    for a user whose second factor is in effect) applies. Both fail OPEN independently."""
    return _group_requires_temp_cred_for_sftp(db, user) or _mfa_sftp_requires_temp_cred(db, user)


class _PathNotFound(Exception):
    """Internal: a path segment did not resolve to a real vault/folder/file."""
    pass


class VaultSFTPHandle(paramiko.SFTPHandle):
    """
    A single open-file handle.

    Read mode: ``reader`` answers ranges from the stored file, decrypting only the records a
    request touches. It used to hold the entire decrypted file instead -- for the life of the
    handle, not the length of a transfer, so a client that opened a large file and walked away
    held all of it until it closed.

    Write mode: incoming bytes are buffered to a temp file; on ``close`` the
    assembled plaintext is pushed through the real encryption pipeline via the
    ``finalizer`` callback. Authorization already happened in ``open()`` (so
    permission errors are reported to the client there); ``close`` only performs
    the encrypt-and-persist, which the SFTP protocol cannot fail cleanly anyway.
    """

    def __init__(self, flags: int = 0):
        super().__init__(flags)
        # Read mode. `reader` answers ranges without holding the file; the whole plaintext used to
        # sit here instead, for as long as the client left the handle open.
        self.reader = None
        self.file_id = None
        # write mode
        self.writepath: Optional[str] = None
        self.writefile = None
        self.finalizer = None  # callable(temp_path) -> None
        # In-stream upload bound: cap the plaintext buffered to the shared volume so a
        # client can't fill it before the close-time size check. 0 = no bound. overlimit
        # marks the upload for discard at close (an SFTP close can't signal failure).
        self.max_bytes = 0
        self.overlimit = False
        # A write raised (e.g. the staging tmpfs ran out of space under concurrent uploads). Like
        # overlimit, this marks the upload for discard at close so a truncated buffer is never
        # finalized -- an SFTP close cannot report failure, so the discard is the only signal.
        self.write_failed = False
        # Back-reference to the paramiko SFTP protocol handler, set on an upload handle in open().
        # A raw int status return (e.g. SFTP_FAILURE) carries only paramiko's default word "Failure";
        # setting a pending description here lets _send_status attach a message that names the actual
        # cause (over the size limit / staging buffer full) so the SFTP client is not left guessing.
        self._sftp_server = None
        # shared
        self.attrs: Optional[paramiko.SFTPAttributes] = None

    # A single read is answered in at most this much. The protocol allows a server to return fewer
    # bytes than asked for, and clients loop; real ones ask for 32 KB at a time and never reach
    # this. What it stops is a client asking for the whole file in one request, which would
    # assemble all of it in memory -- about five times over, once the response is framed -- and
    # hold the session for the duration. Without it the per-handle bound is only a convention the
    # client is trusted to keep.
    MAX_READ = 1024 * 1024

    def read(self, offset: int, length: int):
        if self.reader is None:
            return paramiko.SFTP_OP_UNSUPPORTED
        if offset >= self.reader.size:
            return paramiko.SFTP_EOF
        try:
            return self.reader.read(offset, min(length, self.MAX_READ))
        except Exception as e:  # noqa: BLE001 - a read failure must not drop the connection
            # Reaching here means a record would not authenticate, or the blob moved underneath
            # the handle. Either way the client gets a failure for this read rather than bytes
            # that were not verified.
            safe_event('read.failed', e, file=self.file_id)
            return paramiko.SFTP_FAILURE

    def write(self, offset: int, data: bytes):
        if self.writefile is None:
            return paramiko.SFTP_OP_UNSUPPORTED
        # In-stream size bound: reject any write that would push the buffered file past the
        # per-file max, BEFORE it lands on the shared storage volume — so an SFTP client can't
        # stream unbounded plaintext into .sftp_tmp (filling the volume shared by every vault)
        # before the close-time size check runs. Mark the handle so close() discards the upload.
        if self.max_bytes and (offset + len(data)) > self.max_bytes:
            self.overlimit = True
            self._set_status_desc(
                "upload rejected: file exceeds the %d MB SFTP limit (raise SFTP_STAGING_TMPFS_MB, "
                "which uses that much RAM, or lower MAX_FILE_SIZE_MB to match)"
                % (self.max_bytes // (1024 * 1024)))
            return paramiko.SFTP_FAILURE
        try:
            self.writefile.seek(offset)
            self.writefile.write(data)
            return paramiko.SFTP_OK
        except Exception as e:  # noqa: BLE001
            # The buffer write failed (a full staging tmpfs is the expected cause). Mark the
            # upload for discard so close() does not finalize the partial bytes already written.
            self.write_failed = True
            self._set_status_desc(
                "upload failed: the SFTP staging buffer is full (raise SFTP_STAGING_TMPFS_MB)")
            safe_event('write.failed', e)
            return paramiko.SFTP_FAILURE

    def _set_status_desc(self, desc: str):
        """Attach a human description to the status paramiko is about to send for THIS request.
        Consumed and cleared by _MessageSFTPServer._send_status, which runs synchronously right after
        this write() returns (paramiko processes one request at a time per connection)."""
        srv = self._sftp_server
        if srv is not None:
            srv._pending_status_desc = desc

    def stat(self):
        if self.attrs is not None:
            return self.attrs
        return paramiko.SFTP_OP_UNSUPPORTED

    def close(self):
        # Read mode: release the blob. Held for the life of the handle, so a client that opens a
        # file and leaves is the case this matters for.
        if self.reader is not None:
            try:
                self.reader.close()
            except Exception:  # noqa: BLE001 - closing is best effort
                pass
            self.reader = None

        # Write mode: assemble + encrypt + persist.
        if self.writefile is not None:
            # Flush and close are SEPARATE: the buffer is a BufferedWriter, so the final
            # sub-buffer-size tail of the upload only reaches the staging file here, at flush().
            # If the tmpfs filled between the last write() and this flush (concurrent uploads),
            # flush() raises and the buffer is TRUNCATED -- mark it for discard so close() below
            # does not finalize partial bytes. close() itself is best-effort.
            try:
                self.writefile.flush()
            except Exception as e:  # noqa: BLE001
                self.write_failed = True
                safe_event('upload.flush.failed', e)
            try:
                self.writefile.close()
            except Exception:  # noqa: BLE001
                pass
            self.writefile = None
            if self.overlimit:
                # The upload exceeded the per-file max mid-stream: discard it (don't persist),
                # leaving any existing same-name file intact. The temp buffer is removed below.
                safe_event('upload.discarded.too-large', limit=self.max_bytes)
            elif self.write_failed:
                # A buffer write failed mid-stream (e.g. the staging tmpfs filled): the buffer is
                # truncated, so discard it rather than finalize partial bytes. Any existing
                # same-name file is left intact.
                safe_event('upload.discarded.write-failed')
            elif self.finalizer is not None and self.writepath:
                try:
                    self.finalizer(self.writepath)
                except Exception as e:  # noqa: BLE001
                    safe_event('upload.finalize.failed', e)
            # Always clean up the plaintext temp buffer.
            try:
                if self.writepath and os.path.exists(self.writepath):
                    os.remove(self.writepath)
            except Exception:  # noqa: BLE001
                pass


class SFTPServerInterface(paramiko.SFTPServerInterface):
    """
    Custom SFTP server interface that integrates with our vault system.

    The authenticated principal is ``self.server.user`` — it MUST be used for
    every authorization decision (never a stale ``self.user``).
    """

    def __init__(self, server: 'SFTPServer', *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.server = server

    # -- principal / scope helpers ------------------------------------------
    # Temp-credential scope attributes (plain, non-ORM-mapped) attached at auth.
    _SCOPE_ATTRS = (
        "_is_temp_session", "_temp_cred_id", "_temp_scope",
        "_temp_vault_mode", "_temp_can_create", "_temp_vault_caps",
        "_temp_vault_pw_fp",
        # Per-vault ID-based file/folder restriction ({files, folders} | None). Without re-applying
        # this to the freshly-loaded principal, scope_ids() reads None (whole vault) and every SFTP
        # per-file/folder scope check silently degrades to no-op.
        "_temp_vault_scope",
    )

    def _load_principal(self, db) -> Optional[User]:
        """Load the authenticated principal FRESH in the given session.

        The object produced at auth time is detached AND expired (auth commits,
        then its session closes), so its mapped columns can't be read later
        (DetachedInstanceError). We therefore re-fetch the user by id in the
        caller's live session and re-apply the temp-credential scope, which lives
        on plain (non-mapped) attributes that survive the auth session closing."""
        uid = getattr(self.server, "user_id", None)
        if uid is None:
            return None
        user = db.query(User).filter(User.id == uid).first()
        # Parity with the web get_current_user: a deactivated or locked account is
        # rejected on EVERY operation, so an admin lock/disable revokes an already
        # -open SFTP connection at its next op (not just at the next login). Also
        # honour sftp_enabled here so turning SFTP off cuts a live session next op.
        # account_locked() honours the auto-unlock TTL (an expired failed-login lock = open).
        from app.services.auth_service import account_locked
        if user is None or not user.is_active or account_locked(user) or not user.sftp_enabled:
            return None
        src = getattr(self.server, "user", None)
        if src is not None and getattr(src, "_is_temp_session", False):
            for attr in self._SCOPE_ATTRS:
                if hasattr(src, attr):
                    setattr(user, attr, getattr(src, attr))
        else:
            user._is_temp_session = False
        # Org policy (require temp cred for SFTP) re-evaluated per op, not just at auth entry:
        # if the user's group(s) now mandate a temp credential and this is a DIRECT (non-temp)
        # session, cut it on the next op — so adding a user to a require-temp-cred group takes
        # effect on an already-live direct session (parity with lock/deactivate/sftp_enabled).
        # _user_requires_temp_cred_for_sftp fails OPEN, so it never wrongly severs a session.
        if not getattr(user, "_is_temp_session", False) and _user_requires_temp_cred_for_sftp(db, user):
            return None
        # Carry the connection's client address on the principal so a scope-denial audit (which fires
        # deep in the data layer, with no ASGI request and thus no ClientIPMiddleware contextvar) can
        # still record WHERE an out-of-scope SFTP act came from -- matching the IP the success-path
        # _audit already logs from self.server.client_address.
        user._client_ip = getattr(self.server, "client_address", None)
        return user

    def _has_cap(self, user, vault_id, cap: str) -> bool:
        """Per-vault temp-credential capability check (non-raising).

        Mirrors temp_scope.require_cap but returns a bool so SFTP can map it to a
        protocol status. No-op (True) for normal users / legacy creds."""
        if not is_scoped(user):
            return True
        scope = getattr(user, "_temp_scope", None) or {}
        allowed = set(effective_vault_caps(user, vault_id)) | set(scope.get("caps", []))
        return cap in allowed

    # -- per-file/folder scope (non-raising; a scoped credential sees a virtual filesystem
    #    containing ONLY its in-scope subtree, so anything outside it reads as "not found") ------
    def _scope_ok_file(self, db, user, vault_id, file_id) -> bool:
        """True if the credential may act on this FILE (in scope). No-op True for non-scoped."""
        try:
            require_file_scope(db, user, vault_id, file_id)
            return True
        except PermissionDeniedError:
            return False

    def _scope_ok_folder(self, db, user, vault_id, folder_id) -> bool:
        """True if the credential may write INTO / delete this FOLDER (strictly in scope). Root
        (None) is denied for a scoped credential. No-op True for non-scoped."""
        try:
            require_folder_scope(db, user, vault_id, folder_id)
            return True
        except PermissionDeniedError:
            return False

    def _scope_ok_item(self, db, user, vault_id, item_id) -> bool:
        """True if the credential may act on this FILE-or-FOLDER (in-place rename). No-op True for
        non-scoped."""
        try:
            require_item_scope(db, user, vault_id, item_id)
            return True
        except PermissionDeniedError:
            return False

    def _check_session_valid(self) -> bool:
        """Check the connection's session is still active (immediate revocation)."""
        token = getattr(self.server, "session_token", None)
        if not token:
            return False
        try:
            with get_db_context() as db:
                session = db.query(ActiveSession).filter(
                    ActiveSession.session_token == hash_session_token(token),
                    ActiveSession.is_active == True  # noqa: E712
                ).first()
                if not session:
                    safe_event('session.terminated', session=token[:8])
                    return False
                # Enforce the session's HARD expiry on every op, not just at login. A regular
                # PASSWORD account session now carries an absolute 31-day expires_at (set in
                # authenticate_user); a KEY-based SFTP session still carries NULL (no hard bound →
                # skipped); a temp-credential session carries the credential's expires_at, so a cred
                # with a short total lifetime can't keep operating over SFTP past it (the web path
                # rejects per request; nothing on the SFTP path did). Stored naive (UTC).
                from datetime import datetime, timezone
                if session.expires_at is not None:
                    _exp = session.expires_at
                    if _exp.tzinfo is None:
                        _exp = _exp.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) > _exp:
                        safe_event('session.expired', session=token[:8])
                        return False
                # A deactivated temporary credential must not keep a live SFTP
                # session alive (deactivate revokes access immediately, like the
                # web path). Covers the case where deactivation flips only the
                # credential, not the session row.
                if session.temp_credential_id is not None:
                    from app.core.models import TemporaryCredential
                    tc = db.query(TemporaryCredential).filter(
                        TemporaryCredential.id == session.temp_credential_id
                    ).first()
                    if tc is None or not tc.is_active:
                        safe_event('session.credential-deactivated', session=token[:8])
                        return False
                    # The credential's VALIDITY WINDOW (deactivate_at) is tighter than the hard
                    # expiry enforced at the session level above; enforce it too so a
                    # short-validity cred stops on the next SFTP op (else it stayed usable ~65m
                    # until the inactivity reaper). deactivate_at is stored naive (UTC).
                    _da = tc.deactivate_at
                    if _da is not None:
                        if _da.tzinfo is None:
                            _da = _da.replace(tzinfo=timezone.utc)
                        if datetime.now(timezone.utc) > _da:
                            safe_event('session.credential-expired', session=token[:8])
                            return False
                return True
        except Exception as e:  # noqa: BLE001
            safe_event('session.check.failed', e)
            return False

    # -- path helpers -------------------------------------------------------
    def _normalize_path(self, path: str) -> str:
        """Canonicalize to an absolute, ``..``/``.``-collapsed path confined to
        the virtual root. posixpath.normpath cannot climb above '/'."""
        if not path or not path.startswith('/'):
            path = '/' + (path or '')
        return posixpath.normpath(path)

    @staticmethod
    def _segments(path: str) -> List[str]:
        return [s for s in path.split('/') if s]

    @staticmethod
    def _vault_display_name(vault: Vault) -> str:
        return vault.name or f"vault_{vault.id}"

    def _vault_password_proven(self, user, vault) -> bool:
        """Whether THIS principal has proven the vault's CURRENT password.

        SFTP has no per-vault prompt channel, so the only carrier of that proof is a
        'selected'-scope temporary credential that explicitly includes the vault — minting
        such a credential verifies the vault password (see auth_service) and records a
        fingerprint of the password hash it proved. Here we require that the vault is in the
        credential's selected set AND that the recorded fingerprint still matches the
        vault's live password hash: if the password was later added, changed, or rotated,
        the hash (and fingerprint) differ and the standing proof is void — so SFTP tracks
        the live password exactly as the web's per-request check does. Direct account/
        SSH-key principals, and 'all'-scope or legacy temp credentials, carry no per-vault
        proof, so password-protected vaults stay hidden from them (parity with the
        zero-knowledge exclusion)."""
        from app.core.security import vault_password_fingerprint
        if not getattr(user, "_is_temp_session", False):
            return False
        if getattr(user, "_temp_vault_mode", None) != "selected":
            return False
        if str(vault.id) not in (getattr(user, "_temp_vault_caps", {}) or {}):
            return False
        stored = (getattr(user, "_temp_vault_pw_fp", {}) or {}).get(str(vault.id))
        return bool(stored) and stored == vault_password_fingerprint(vault.password_hash)

    def _resolve_vault(self, vault_service: VaultService, user, segment: str) -> Optional[Vault]:
        """Resolve a top-level path segment to a vault the principal may reach.

        Matches by display name (the friendly tree the design doc wants), and also
        accepts the unambiguous ``vault_<uuid>`` / raw-uuid machine forms. Returns
        None if it doesn't resolve or access is denied. Re-authorizes via
        ``get_vault`` (membership + temp-cred vault scope)."""
        try:
            vaults = vault_service.list_vaults(user)  # already scope-filtered
        except Exception:  # noqa: BLE001
            return None

        candidates = [v for v in vaults if self._vault_display_name(v) == segment]
        if not candidates:
            # machine forms
            raw = segment[len("vault_"):] if segment.startswith("vault_") else segment
            try:
                wanted = uuid.UUID(raw)
                candidates = [v for v in vaults if v.id == wanted]
            except (ValueError, AttributeError):
                candidates = []
        if not candidates:
            return None
        # Deterministic on the (rare) duplicate-name case (names aren't unique in
        # the data model). Sort by id so resolution is stable across calls.
        candidates.sort(key=lambda v: str(v.id))
        vault = candidates[0]
        try:
            # Re-authorize for THIS principal (membership + temp-cred scope).
            resolved = vault_service.get_vault(vault.id, user, require_password=False)
        except (PermissionDeniedError, VaultNotFoundError):
            return None
        # SFTP serves ONLY Standard vaults. Zero-knowledge vaults have no
        # server-side key — the server can neither decrypt downloads nor encrypt
        # uploads for them — so they are not exposed over SFTP (web app only).
        if getattr(resolved, 'type', 'standard') != 'standard':
            return None
        # Password-protected vaults are reachable over SFTP only with proof of the vault
        # password, which only a vault-scoped temp credential carries (see
        # _vault_password_proven). Otherwise they are hidden, same as on the web where the
        # password is a hard gate — SFTP must not let account auth alone bypass it.
        if resolved.password_hash is not None and not self._vault_password_proven(user, resolved):
            return None
        return resolved

    def _resolve_folder(self, db, vault_id, segments: List[str]) -> Optional[uuid.UUID]:
        """Walk folder names from the vault root. '' / [] => vault root (None).
        Raises _PathNotFound if any segment doesn't name a real sub-folder."""
        parent: Optional[uuid.UUID] = None
        for seg in segments:
            folder = db.query(Folder).filter(
                Folder.vault_id == vault_id,
                Folder.parent_folder_id == parent,
                # Names are encrypted at rest (Standard vaults); match the per-vault
                # blind index, OR plaintext for any not-yet-backfilled legacy row.
                or_(Folder.name_bi == name_blind_index(vault_id, seg), Folder.name == seg),
            ).first()
            if not folder:
                raise _PathNotFound(seg)
            parent = folder.id
        return parent

    def _resolve_file(self, db, vault_id, folder_id, name: str) -> Optional[File]:
        """Find a file by its display name within a vault+folder. Matches the
        human ``original_name`` first, then the sanitized stored ``name``."""
        q = db.query(File).filter(
            File.vault_id == vault_id,
            File.folder_id == folder_id,
        )
        # Newest-first: if a name somehow has duplicate rows (the data model
        # doesn't enforce per-folder name uniqueness), SFTP reads/removes should
        # act on the MOST RECENT upload, never silently serve a stale copy.
        # Names are encrypted at rest (Standard vaults): match the per-vault blind index,
        # OR the plaintext columns for any not-yet-backfilled legacy row.
        bi = name_blind_index(vault_id, name)
        f = q.filter(
            or_(File.name_bi == bi, File.original_name == name, File.name == name)
        ).order_by(File.created_at.desc()).first()
        return f

    @staticmethod
    def _dir_attr(name: Optional[str] = None, mtime: int = 0, size: int = 0) -> paramiko.SFTPAttributes:
        attr = paramiko.SFTPAttributes()
        if name is not None:
            attr.filename = name
        attr.st_mode = 0o40755
        attr.st_size = size
        attr.st_uid = 0
        attr.st_gid = 0
        attr.st_atime = mtime
        attr.st_mtime = mtime
        return attr

    @staticmethod
    def _file_attr(name: str, size: int, mtime: int) -> paramiko.SFTPAttributes:
        attr = paramiko.SFTPAttributes()
        attr.filename = name
        attr.st_mode = 0o100644
        attr.st_size = size
        attr.st_uid = 0
        attr.st_gid = 0
        attr.st_atime = mtime
        attr.st_mtime = mtime
        return attr

    @staticmethod
    def _ts(dt) -> int:
        try:
            return int(dt.timestamp()) if dt else 0
        except Exception:  # noqa: BLE001
            return 0

    # -- session lifecycle --------------------------------------------------
    def session_started(self):
        pass

    def session_ended(self):
        pass

    # -- directory listing --------------------------------------------------
    def list_folder(self, path: str):
        if not self._check_session_valid():
            return paramiko.SFTP_PERMISSION_DENIED

        path = self._normalize_path(path)
        segments = self._segments(path)

        with get_db_context() as db:
            user = self._load_principal(db)
            if user is None:
                return paramiko.SFTP_PERMISSION_DENIED
            vault_service = VaultService(db, PermissionService(db))

            # Root: the principal's accessible vaults as top-level folders.
            if not segments:
                result = []
                try:
                    vaults = vault_service.list_vaults(user)
                except Exception as e:  # noqa: BLE001
                    safe_event('list-vaults.failed', e)
                    return paramiko.SFTP_FAILURE
                for vault in vaults:
                    # SFTP exposes only Standard vaults; zero-knowledge vaults have
                    # no server-side key and are web-app only.
                    if getattr(vault, 'type', 'standard') != 'standard':
                        continue
                    # Password-protected vaults are hidden unless this principal proved the
                    # vault password (only a vault-scoped temp credential can) — same gate
                    # as the web; account auth alone must not list/reach them.
                    if vault.password_hash is not None and not self._vault_password_proven(user, vault):
                        continue
                    # A scoped temp credential only sees a vault it may "see_info".
                    if not self._has_cap(user, vault.id, "vault.see_info"):
                        continue
                    # A per-file/folder-scoped credential must not learn the whole-vault size OR
                    # mtime from the vault directory entry: the size covers files outside its scope,
                    # and vault.updated_at is bumped by any file activity anywhere in the vault, so it
                    # would be a coarse "something changed" oracle over out-of-scope files. Report 0/0.
                    _scoped_here = scope_ids(user, vault.id) is not None
                    _sz = 0 if _scoped_here else (vault.total_size_bytes or 0)
                    _mt = 0 if _scoped_here else self._ts(vault.updated_at)
                    result.append(self._dir_attr(
                        self._vault_display_name(vault),
                        mtime=_mt,
                        size=_sz,
                    ))
                return result

            # /<vault>[/<folder>...] : list a vault or one of its folders.
            vault = self._resolve_vault(vault_service, user, segments[0])
            if vault is None:
                return paramiko.SFTP_NO_SUCH_FILE

            # Listing file contents requires the see_files capability.
            if not self._has_cap(user, vault.id, "vault.see_files"):
                return paramiko.SFTP_PERMISSION_DENIED

            try:
                folder_id = self._resolve_folder(db, vault.id, segments[1:])
            except _PathNotFound:
                return paramiko.SFTP_NO_SUCH_FILE

            # A scoped credential can only list a folder it may navigate (in scope, or an ancestor
            # of its scope). A folder outside its scope reads as non-existent — never an empty dir,
            # which would confirm the folder exists.
            if not folder_is_navigable(db, user, vault.id, folder_id):
                return paramiko.SFTP_NO_SUCH_FILE

            folders = db.query(Folder).filter(
                Folder.vault_id == vault.id,
                Folder.parent_folder_id == folder_id,
            ).all()
            files = db.query(File).filter(
                File.vault_id == vault.id,
                File.folder_id == folder_id,
            ).all()
            # Filter to in-scope children + the ancestor folders needed to reach the scope.
            folders, files = filter_listing_for_scope(db, user, vault.id, folder_id, folders, files)

            result = []
            for folder in folders:
                result.append(self._dir_attr(folder.name, mtime=self._ts(folder.updated_at)))
            for f in files:
                result.append(self._file_attr(
                    f.original_name or f.name,
                    size=f.size_bytes or 0,
                    mtime=self._ts(f.created_at),
                ))
            return result

    # -- stat ---------------------------------------------------------------
    def stat(self, path: str):
        if not self._check_session_valid():
            return paramiko.SFTP_PERMISSION_DENIED

        path = self._normalize_path(path)
        segments = self._segments(path)

        if not segments:
            return self._dir_attr()

        with get_db_context() as db:
            user = self._load_principal(db)
            if user is None:
                return paramiko.SFTP_PERMISSION_DENIED
            vault_service = VaultService(db, PermissionService(db))
            vault = self._resolve_vault(vault_service, user, segments[0])
            if vault is None:
                return paramiko.SFTP_NO_SUCH_FILE

            # The vault root directory itself. Confirming its existence/mtime requires
            # visibility into the vault — see_info (the gate the root LISTING enforces) OR
            # see_files (which already lets the cred list the vault's contents, so it
            # inherently reveals existence; gating on both keeps `stat`/`cd` working for a
            # see_files cred without opening an oracle to one with neither). Return
            # NO_SUCH_FILE (not PERMISSION_DENIED) so absence is indistinguishable from
            # non-existence for a credential granted no visibility at all.
            if len(segments) == 1:
                if not (self._has_cap(user, vault.id, "vault.see_info")
                        or self._has_cap(user, vault.id, "vault.see_files")):
                    return paramiko.SFTP_NO_SUCH_FILE
                # Suppress the vault mtime for a scoped credential (see the root listing) — it is a
                # whole-vault activity oracle otherwise.
                _mt = 0 if scope_ids(user, vault.id) is not None else self._ts(vault.updated_at)
                return self._dir_attr(self._vault_display_name(vault), mtime=_mt)

            # Metadata for a KNOWN path inside the vault. Directory ENUMERATION stays gated on
            # vault.see_files (see list_folder / the web list path), but confirming ONE
            # already-known path reveals no more than the per-file capability already does — a
            # download/rename/delete credential can already open/act on that exact path, so
            # stat/lstat of it is not extra disclosure. Any of those caps (or see_files) therefore
            # satisfies stat: this lets `sftp get <known-file>` work for a download-only credential
            # (paramiko stats a file before opening it) without letting a credential holding NONE of
            # these confirm a file/folder's existence, size or mtime. Return NO_SUCH_FILE (not
            # PERMISSION_DENIED) so such a credential can't use stat as an existence oracle.
            if not any(self._has_cap(user, vault.id, c) for c in (
                    "vault.see_files", "file.download", "file.rename", "file.delete", "folder.delete")):
                return paramiko.SFTP_NO_SUCH_FILE

            # Try the full path as a folder first.
            try:
                folder_id = self._resolve_folder(db, vault.id, segments[1:])
                # A scoped credential may stat a folder it can navigate to (in scope or an ancestor
                # of its scope); anything else reads as non-existent (no existence oracle).
                if not folder_is_navigable(db, user, vault.id, folder_id):
                    return paramiko.SFTP_NO_SUCH_FILE
                folder = db.query(Folder).filter(Folder.id == folder_id).first()
                return self._dir_attr(segments[-1], mtime=self._ts(folder.updated_at) if folder else 0)
            except _PathNotFound:
                pass

            # Otherwise the last segment is a file inside the parent folder path.
            try:
                folder_id = self._resolve_folder(db, vault.id, segments[1:-1])
            except _PathNotFound:
                return paramiko.SFTP_NO_SUCH_FILE
            f = self._resolve_file(db, vault.id, folder_id, segments[-1])
            if f is None:
                return paramiko.SFTP_NO_SUCH_FILE
            # A scoped credential may stat only an in-scope file; else it reads as non-existent.
            if not self._scope_ok_file(db, user, vault.id, f.id):
                return paramiko.SFTP_NO_SUCH_FILE
            return self._file_attr(f.original_name or f.name,
                                   size=f.size_bytes or 0, mtime=self._ts(f.created_at))

    def lstat(self, path: str):
        return self.stat(path)

    # -- open (download / upload) ------------------------------------------
    def open(self, path: str, flags: int, attr: Optional[paramiko.SFTPAttributes] = None):
        if not self._check_session_valid():
            return paramiko.SFTP_PERMISSION_DENIED

        path = self._normalize_path(path)
        segments = self._segments(path)
        # A file must live under a vault: at least /<vault>/<file>.
        if len(segments) < 2:
            return paramiko.SFTP_PERMISSION_DENIED

        is_write = bool(flags & (os.O_WRONLY | os.O_RDWR)) or bool(flags & _O_CREAT)
        if is_write:
            return self._open_write(segments)
        return self._open_read(segments)

    def _open_read(self, segments: List[str]):
        filename = segments[-1]
        with get_db_context() as db:
            user = self._load_principal(db)
            if user is None:
                return paramiko.SFTP_PERMISSION_DENIED
            vault_service = VaultService(db, PermissionService(db))
            vault = self._resolve_vault(vault_service, user, segments[0])
            if vault is None:
                return paramiko.SFTP_NO_SUCH_FILE
            if not self._has_cap(user, vault.id, "file.download"):
                return paramiko.SFTP_PERMISSION_DENIED
            try:
                folder_id = self._resolve_folder(db, vault.id, segments[1:-1])
            except _PathNotFound:
                return paramiko.SFTP_NO_SUCH_FILE
            f = self._resolve_file(db, vault.id, folder_id, filename)
            if f is None:
                return paramiko.SFTP_NO_SUCH_FILE
            # A scoped credential may download only an in-scope file; else it reads as non-existent.
            if not self._scope_ok_file(db, user, vault.id, f.id):
                return paramiko.SFTP_NO_SUCH_FILE
            try:
                # Re-resolves the file's REAL vault and re-checks READ permission + any per-file
                # password, through the same function the web path uses. Opens the blob and reads
                # its framing; it does not read the file.
                reader = vault_service.open_random_reader(f.id, user)
            except (PermissionDeniedError, PasswordRequiredError, InvalidPasswordError):
                return paramiko.SFTP_PERMISSION_DENIED
            except VaultFileNotFoundError:
                return paramiko.SFTP_NO_SUCH_FILE
            except Exception as e:  # noqa: BLE001
                safe_event('download.failed', e, file=f.id)
                return paramiko.SFTP_FAILURE

            name = reader.name
            self._audit(user, "file_download", str(f.id),
                        {"vault_id": str(vault.id), "file_name": name, "via": "sftp"})

            handle = VaultSFTPHandle(flags=os.O_RDONLY)
            handle.reader = reader
            handle.file_id = str(f.id)
            # The size the format itself reports, which for the current format is authenticated by
            # its terminal -- unlike the directory listing's, which comes from the database row.
            handle.attrs = self._file_attr(name, size=reader.size, mtime=self._ts(f.created_at))
            return handle

    def _open_write(self, segments: List[str]):
        # Strip control chars at the write sink so they never reach File.original_name.
        filename = _strip_ctrl(segments[-1])
        with get_db_context() as db:
            user = self._load_principal(db)
            if user is None:
                return paramiko.SFTP_PERMISSION_DENIED
            vault_service = VaultService(db, PermissionService(db))
            vault = self._resolve_vault(vault_service, user, segments[0])
            if vault is None:
                return paramiko.SFTP_NO_SUCH_FILE
            if not self._has_cap(user, vault.id, "file.upload"):
                return paramiko.SFTP_PERMISSION_DENIED
            # Admin file-type allowlist + effective max size. SFTP serves only standard vaults, so
            # the plaintext extension is always visible and the allowlist always applies.
            from app.core import upload_policy as _up
            from app.core.models import SystemSetting as _SS
            _srow = db.query(_SS).filter(_SS.key == "global").first()
            _sblob = (_srow.value or {}) if (_srow and _srow.value) else {}
            if not _up.file_type_allowed(filename, _up.parse_allowed_exts(_sblob.get("allowed_file_types"))):
                return paramiko.SFTP_PERMISSION_DENIED
            _eff_max = _up.effective_max_file_bytes((settings.max_file_size_mb or 0) * 1024 * 1024, _sblob.get("max_file_size"))
            # A buffered upload can't exceed the staging tmpfs; refuse an oversized one in-stream
            # rather than filling the tmpfs mid-write.
            _eff_max = _staging_capped_max(_eff_max, settings.sftp_staging_tmpfs_mb)
            try:
                folder_id = self._resolve_folder(db, vault.id, segments[1:-1])
            except _PathNotFound:
                return paramiko.SFTP_NO_SUCH_FILE
            # A scoped credential may upload only INTO an in-scope folder (the vault root is denied);
            # an out-of-scope destination reads as non-existent.
            if not self._scope_ok_folder(db, user, vault.id, folder_id):
                return paramiko.SFTP_NO_SUCH_FILE
            vault_id = vault.id
            # Replacing an existing file deletes it, so overwrite requires real DELETE
            # authority: the file.delete temp-cred capability AND vault DELETE permission
            # (RBAC). _has_cap alone is True for every non-scoped user (scope layer only), so
            # without the RBAC check a write-but-no-delete member could destroy files via an
            # SFTP put — mirror the web _principal_can_replace_file gate.
            from app.core.models import VaultPermissionEnum
            can_overwrite = (self._has_cap(user, vault_id, "file.delete")
                             and vault_service.permission_service.can_access_vault(
                                 user, vault_id, VaultPermissionEnum.DELETE))
            # No-clobber: a principal lacking DELETE may CREATE files but may not replace an
            # existing one. Reject at open() (a visible error) rather than silently inserting
            # a hidden duplicate that shadows the original. (Normal members with DELETE
            # overwrite as before.)
            if not can_overwrite:
                clash = db.query(File).filter(
                    File.vault_id == vault_id,
                    File.folder_id == folder_id,
                    or_(File.name_bi == name_blind_index(vault_id, filename),
                        File.original_name == filename),
                ).first()
                if clash is not None:
                    return paramiko.SFTP_PERMISSION_DENIED

        # Buffer the plaintext to a temp file; encrypt + persist at close().
        try:
            _SFTP_TMP_DIR.mkdir(parents=True, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(prefix="up_", dir=str(_SFTP_TMP_DIR))
            os.close(fd)
            wf = open(tmp_path, "wb")
        except Exception as e:  # noqa: BLE001
            safe_event('upload.buffer-open.failed', e)
            return paramiko.SFTP_FAILURE

        handle = VaultSFTPHandle(flags=os.O_WRONLY)
        handle.writepath = tmp_path
        handle.writefile = wf
        # Bound the buffered plaintext in-stream at the configured per-file max, so the write
        # can't fill the shared .sftp_tmp volume before the close-time size check runs.
        handle.max_bytes = _eff_max
        # Let an in-stream refusal (over-limit / staging-full) carry a descriptive status instead of
        # paramiko's bare "Failure". _sftp_server is the protocol handler, wired by _MessageSFTPServer.
        handle._sftp_server = getattr(self, "_sftp_server", None)
        handle.finalizer = self._make_upload_finalizer(
            vault_id, folder_id, filename, can_overwrite
        )
        return handle

    def _make_upload_finalizer(self, vault_id, folder_id, filename, can_overwrite):
        """Build the close-time callback that pushes a buffered plaintext file
        through the canonical (web-identical) encryption pipeline and creates the
        File row + vault stats."""
        interface = self

        def _finalize(tmp_path: str):
            # The plaintext is fully buffered, so validate size UP FRONT — before
            # writing any encrypted blob or deleting the existing file. An SFTP
            # close can't report failure to the client, so the contract here is:
            # a rejected upload must leave NO orphan blob AND must NOT destroy the
            # file it was meant to replace (no silent data loss).
            try:
                buffered_size = os.path.getsize(tmp_path)
            except OSError:
                buffered_size = 0
            max_bytes = settings.max_file_size_mb * 1024 * 1024
            if max_bytes and buffered_size > max_bytes:
                safe_event('upload.rejected.too-large',
                            bytes=buffered_size, limit=max_bytes)
                return

            with get_db_context() as db:
                user = interface._load_principal(db)
                # Re-validate principal AND session at persist time: an account
                # locked/deactivated or a session revoked mid-transfer must not
                # land the write (TOCTOU between open() and close()).
                if user is None or not interface._check_session_valid():
                    safe_event('upload.aborted.principal-invalid')
                    return
                vault_service = VaultService(db, PermissionService(db))
                # Re-authorize at persist time (fresh session): membership +
                # temp-cred vault scope. upload re-checks the real vault.
                vault = vault_service.get_vault(vault_id, user, require_password=False)
                # Re-check the destination folder's ID-scope too (parity with the session/password/
                # quota re-checks): a scoped credential whose scope was narrowed between open() and
                # close() must not land a write into a now-out-of-scope folder.
                if not interface._scope_ok_folder(db, user, vault_id, folder_id):
                    safe_event('upload.aborted.folder-out-of-scope')
                    return
                # Re-gate the per-vault password proof too: a password ADDED or rotated
                # between open() and close() must not let an in-flight write land without
                # current proof (TOCTOU) — same gate _resolve_vault applies at open().
                if vault.password_hash is not None and not interface._vault_password_proven(user, vault):
                    safe_event('upload.aborted.password-proof-invalid')
                    return

                # Vault quota pre-check (mirror the web upload path) — again before
                # we write or delete anything.
                if vault.size_limit and (vault.total_size_bytes or 0) + buffered_size > vault.size_limit:
                    safe_event('upload.rejected.vault-limit',
                                vault=vault.id, bytes=buffered_size, limit=vault.size_limit)
                    return
                # Deployment-wide plan storage ceiling (aggregate across all vaults) —
                # same gate the web upload path enforces, so SFTP can't bypass the plan.
                from app.services.vault_service import would_exceed_deployment_storage
                exceeds, _used, _cap = would_exceed_deployment_storage(db, buffered_size)
                if exceeds:
                    safe_event('upload.rejected.plan-limit', bytes=buffered_size)
                    return

                mime_type, _ = mimetypes.guess_type(filename)
                file_info, stream_ctx = vault_service.upload_file_streaming(
                    vault_id=vault_id,
                    file_name=filename,
                    user=user,
                    folder_id=folder_id,
                    mime_type=mime_type,
                )
                try:
                    with stream_ctx as ctx:
                        with open(tmp_path, "rb") as tf:
                            while True:
                                buf = tf.read(1024 * 1024)
                                if not buf:
                                    break
                                ctx.write_chunk(buf)
                        checksum = ctx.get_checksum()
                        total_size = ctx.get_total_size()
                    # ATOMIC OVERWRITE: replace-on-clash is done inside finalize, in the
                    # SAME transaction as the new insert (old same-name row deleted before
                    # the new one commits) — so a failed/oversize upload never destroys the
                    # existing file, and the two never coexist under the name unique index.
                    # Still gated by file.delete (no silent capability bypass): when the
                    # principal can't overwrite, replace_same_name=False and a clash that
                    # slipped past the open() no-clobber check fails the put (DuplicateName).
                    new_file = vault_service.finalize_streaming_upload(
                        file_info=file_info, total_size=total_size, checksum=checksum,
                        replace_same_name=can_overwrite,
                    )
                except Exception:
                    # The streaming context only unlinks the blob on an in-block
                    # error; a failure in finalize_streaming_upload (after the
                    # block) would otherwise strand the encrypted blob with no
                    # File row. Remove it so a failed put leaves no orphan.
                    try:
                        orphan = vault_service.storage_path / file_info["storage_path"]
                        if orphan.exists():
                            orphan.unlink()
                    except Exception:  # noqa: BLE001
                        pass
                    raise

                interface._audit(user, "file_upload", str(new_file.id),
                                 {"vault_id": str(vault_id), "file_name": filename, "via": "sftp"})
                safe_event('upload.stored',
                            file=new_file.id, vault=vault_id, bytes=total_size)

        return _finalize

    # -- remove / rename ----------------------------------------------------
    def remove(self, path: str):
        if not self._check_session_valid():
            return paramiko.SFTP_PERMISSION_DENIED
        segments = self._segments(self._normalize_path(path))
        if len(segments) < 2:
            return paramiko.SFTP_PERMISSION_DENIED

        with get_db_context() as db:
            user = self._load_principal(db)
            if user is None:
                return paramiko.SFTP_PERMISSION_DENIED
            vault_service = VaultService(db, PermissionService(db))
            vault = self._resolve_vault(vault_service, user, segments[0])
            if vault is None:
                return paramiko.SFTP_NO_SUCH_FILE
            if not self._has_cap(user, vault.id, "file.delete"):
                return paramiko.SFTP_PERMISSION_DENIED
            try:
                folder_id = self._resolve_folder(db, vault.id, segments[1:-1])
            except _PathNotFound:
                return paramiko.SFTP_NO_SUCH_FILE
            f = self._resolve_file(db, vault.id, folder_id, segments[-1])
            if f is None:
                return paramiko.SFTP_NO_SUCH_FILE
            # A scoped credential may delete only an in-scope file; else it reads as non-existent.
            if not self._scope_ok_file(db, user, vault.id, f.id):
                return paramiko.SFTP_NO_SUCH_FILE
            fid = f.id
            try:
                vault_service.delete_file(fid, user)
            except PermissionDeniedError:
                return paramiko.SFTP_PERMISSION_DENIED
            except VaultFileNotFoundError:
                return paramiko.SFTP_NO_SUCH_FILE
            except Exception as e:  # noqa: BLE001
                safe_event('remove.failed', e, file=fid, vault=vault.id)
                return paramiko.SFTP_FAILURE
            self._audit(user, "file_delete", str(fid),
                        {"vault_id": str(vault.id), "via": "sftp"})
            # Feed the bulk-deletion detector (best-effort; must never fail the delete).
            try:
                from app.services.security_monitor import get_security_monitor
                get_security_monitor(db).record_file_deletion(str(user.id), str(vault.id), file_count=1)
            except Exception:
                pass
            return paramiko.SFTP_OK

    def rename(self, oldpath: str, newpath: str):
        if not self._check_session_valid():
            return paramiko.SFTP_PERMISSION_DENIED
        old_seg = self._segments(self._normalize_path(oldpath))
        new_seg = self._segments(self._normalize_path(newpath))
        if len(old_seg) < 2 or len(new_seg) < 2:
            return paramiko.SFTP_PERMISSION_DENIED
        # Only in-place rename is supported (same vault + same parent folder);
        # moving across folders/vaults is not a VaultService.rename operation.
        if old_seg[0] != new_seg[0] or old_seg[:-1] != new_seg[:-1]:
            return paramiko.SFTP_OP_UNSUPPORTED

        with get_db_context() as db:
            user = self._load_principal(db)
            if user is None:
                return paramiko.SFTP_PERMISSION_DENIED
            vault_service = VaultService(db, PermissionService(db))
            vault = self._resolve_vault(vault_service, user, old_seg[0])
            if vault is None:
                return paramiko.SFTP_NO_SUCH_FILE
            if not self._has_cap(user, vault.id, "file.rename"):
                return paramiko.SFTP_PERMISSION_DENIED
            try:
                folder_id = self._resolve_folder(db, vault.id, old_seg[1:-1])
            except _PathNotFound:
                return paramiko.SFTP_NO_SUCH_FILE
            f = self._resolve_file(db, vault.id, folder_id, old_seg[-1])
            target_id = f.id if f is not None else None
            if target_id is None:
                # Maybe it's a folder being renamed.
                folder = db.query(Folder).filter(
                    Folder.vault_id == vault.id,
                    Folder.parent_folder_id == folder_id,
                    or_(Folder.name_bi == name_blind_index(vault.id, old_seg[-1]),
                        Folder.name == old_seg[-1]),
                ).first()
                if folder is None:
                    return paramiko.SFTP_NO_SUCH_FILE
                target_id = folder.id
            # A scoped credential may rename only an in-scope file/folder (rename is in-place — same
            # parent — so the item's own scope covers both source and destination); else non-existent.
            if not self._scope_ok_item(db, user, vault.id, target_id):
                return paramiko.SFTP_NO_SUCH_FILE
            # Renaming a FILE enforces the admin file-type allowlist on the new name (SFTP serves
            # only standard vaults, so the extension is visible); folders have no file-type. Parity
            # with the web rename + the upload sinks.
            if f is not None:
                from app.core import upload_policy as _up
                from app.core.models import SystemSetting as _SS
                _srow2 = db.query(_SS).filter(_SS.key == "global").first()
                _sblob2 = (_srow2.value or {}) if (_srow2 and _srow2.value) else {}
                if not _up.file_type_allowed(_strip_ctrl(new_seg[-1]), _up.parse_allowed_exts(_sblob2.get("allowed_file_types"))):
                    return paramiko.SFTP_PERMISSION_DENIED
            try:
                # vault_id pins the rename to the resolved vault (cross-vault guard).
                # Strip control chars at the rename sink (parity with the upload sink) so a
                # CRLF-laden new name can't be persisted into original_name.
                vault_service.rename_file(target_id, _strip_ctrl(new_seg[-1]), user, vault_id=vault.id)
            except PermissionDeniedError:
                return paramiko.SFTP_PERMISSION_DENIED
            except (VaultFileNotFoundError, FileNotFoundError):
                return paramiko.SFTP_NO_SUCH_FILE
            except ValueError:
                return paramiko.SFTP_FAILURE
            except Exception as e:  # noqa: BLE001
                safe_event('rename.failed', e, vault=vault.id)
                return paramiko.SFTP_FAILURE
            # Attribute the rename like every other SFTP mutation (download/upload/delete/mkdir/
            # rmdir) and the REST rename twin. Without it a temp credential holding file.rename
            # could rename in-scope items untracked over SFTP -- the contractor-facing surface the
            # audit trail exists to cover. Names are omitted, matching the sibling SFTP audits (the
            # logger redacts old_name/new_name from stored details anyway).
            self._audit(user, "file_rename" if f is not None else "folder_rename",
                        str(target_id), {"vault_id": str(vault.id), "via": "sftp"})
            return paramiko.SFTP_OK

    # -- mkdir / rmdir ------------------------------------------------------
    def mkdir(self, path: str, attr: Optional[paramiko.SFTPAttributes] = None):
        if not self._check_session_valid():
            return paramiko.SFTP_PERMISSION_DENIED
        segments = self._segments(self._normalize_path(path))
        # Need a vault + at least one folder name; you can't mkdir a vault.
        if len(segments) < 2:
            return paramiko.SFTP_PERMISSION_DENIED

        with get_db_context() as db:
            user = self._load_principal(db)
            if user is None:
                return paramiko.SFTP_PERMISSION_DENIED
            vault_service = VaultService(db, PermissionService(db))
            vault = self._resolve_vault(vault_service, user, segments[0])
            if vault is None:
                return paramiko.SFTP_NO_SUCH_FILE
            if not self._has_cap(user, vault.id, "folder.create"):
                return paramiko.SFTP_PERMISSION_DENIED
            try:
                parent_id = self._resolve_folder(db, vault.id, segments[1:-1])
            except _PathNotFound:
                return paramiko.SFTP_NO_SUCH_FILE
            # A scoped credential may create a folder only INSIDE an in-scope folder (not at the
            # vault root); an out-of-scope parent reads as non-existent.
            if not self._scope_ok_folder(db, user, vault.id, parent_id):
                return paramiko.SFTP_NO_SUCH_FILE
            try:
                new_folder = vault_service.create_folder(
                    vault_id=vault.id, name=segments[-1], user=user, parent_folder_id=parent_id
                )
            except PermissionDeniedError:
                return paramiko.SFTP_PERMISSION_DENIED
            except Exception as e:  # noqa: BLE001
                safe_event('mkdir.failed', e, vault=vault.id)
                return paramiko.SFTP_FAILURE
            # Audit by folder id, not the (now at-rest-encrypted) plaintext name.
            self._audit(user, "folder_create", str(getattr(new_folder, "id", "")),
                        {"vault_id": str(vault.id), "via": "sftp"})
            return paramiko.SFTP_OK

    def rmdir(self, path: str):
        if not self._check_session_valid():
            return paramiko.SFTP_PERMISSION_DENIED
        segments = self._segments(self._normalize_path(path))
        if len(segments) < 2:  # can't remove a vault over SFTP
            return paramiko.SFTP_PERMISSION_DENIED

        with get_db_context() as db:
            user = self._load_principal(db)
            if user is None:
                return paramiko.SFTP_PERMISSION_DENIED
            vault_service = VaultService(db, PermissionService(db))
            vault = self._resolve_vault(vault_service, user, segments[0])
            if vault is None:
                return paramiko.SFTP_NO_SUCH_FILE
            # rmdir recursively wipes every file in the subtree, so it needs DELETE authority
            # for FILES, not merely WRITE. The old gate (folder.delete cap + WRITE RBAC) let a
            # write-but-no-delete member — or a folder.delete-only temp cred WITHOUT file.delete
            # — destroy the owner's DELETE-protected files, because the per-file delete_file
            # check below was swallowed. Mirror the web delete_folder handler: require DELETE
            # RBAC + the file.delete cap UP FRONT, and never swallow a per-file PermissionDenied.
            if not (self._has_cap(user, vault.id, "folder.delete")
                    and self._has_cap(user, vault.id, "file.delete")):
                return paramiko.SFTP_PERMISSION_DENIED
            try:
                from app.core.models import VaultPermissionEnum
                vault_service.permission_service.require_vault_permission(
                    user, vault.id, VaultPermissionEnum.DELETE
                )
            except PermissionDeniedError:
                return paramiko.SFTP_PERMISSION_DENIED
            try:
                folder_id = self._resolve_folder(db, vault.id, segments[1:])
            except _PathNotFound:
                return paramiko.SFTP_NO_SUCH_FILE
            if folder_id is None:
                return paramiko.SFTP_PERMISSION_DENIED
            # A scoped credential may remove only an in-scope folder (its own subtree); an
            # out-of-scope folder reads as non-existent.
            if not self._scope_ok_folder(db, user, vault.id, folder_id):
                return paramiko.SFTP_NO_SUCH_FILE

            # Recursively wipe contained files (storage + rows + stats), then
            # sub-folders, then the folder — mirrors the web delete_folder handler.
            def _purge(fid):
                n = 0
                for child in db.query(File).filter(File.folder_id == fid).all():
                    try:
                        vault_service.delete_file(child.id, user)
                        n += 1
                    except PermissionDeniedError:
                        # Never destroy a file the caller can't delete — abort the whole
                        # rmdir (defense-in-depth behind the vault-level DELETE gate above).
                        raise
                    except Exception as ex:  # noqa: BLE001
                        safe_event('rmdir.child-delete.failed', ex, file=child.id)
                for sub in db.query(Folder).filter(Folder.parent_folder_id == fid).all():
                    n += _purge(sub.id)
                    db.delete(sub)
                return n
            try:
                _rmdir_deleted = _purge(folder_id)
                folder = db.query(Folder).filter(Folder.id == folder_id).first()
                if folder is not None:
                    db.delete(folder)
                db.commit()
                # Feed the whole subtree to the bulk-deletion detector as ONE record (SFTP rmdir is a
                # high-throughput deletion vector). Best-effort: monitoring must never fail the rmdir.
                if _rmdir_deleted:
                    try:
                        from app.services.security_monitor import get_security_monitor
                        get_security_monitor(db).record_file_deletion(str(user.id), str(vault.id), file_count=_rmdir_deleted)
                    except Exception:
                        pass
            except PermissionDeniedError:
                db.rollback()
                return paramiko.SFTP_PERMISSION_DENIED
            except Exception as e:  # noqa: BLE001
                db.rollback()
                safe_event('rmdir.failed', e, vault=vault.id)
                return paramiko.SFTP_FAILURE
            self._audit(user, "folder_delete", str(folder_id),
                        {"vault_id": str(vault.id), "via": "sftp"})
            return paramiko.SFTP_OK

    def chattr(self, path: str, attr: paramiko.SFTPAttributes):
        # No mutable POSIX attributes in the vault model.
        return paramiko.SFTP_OP_UNSUPPORTED

    # -- audit --------------------------------------------------------------
    def _audit(self, user, action: str, resource_id: str, details: dict):
        try:
            with get_db_context() as db:
                AuditLogger(db).log_action(
                    action=action,
                    status="success",
                    user=user,
                    resource_type=("folder" if "folder" in action else "file"),
                    resource_id=resource_id,
                    details=details,
                    ip_address=getattr(self.server, "client_address", None),
                )
        except Exception:  # noqa: BLE001
            pass  # auditing must never break the operation


# --- SSH-key auth throttle (per source IP + username) ----------------------
# SSH public-key auth is not password-guessable (you can't brute-force a private key), so
# unlike check_auth_password it had NO throttle. The real risks it leaves open are a flood of
# key offers (CPU/connection exhaustion) and authorized-key / username enumeration. We bound
# both with a sliding window over key OFFERS keyed by (source IP, username), cleared on a
# successful auth so a healthy (frequently reconnecting) client never accumulates. Keying on
# (ip, username) — not ip alone — means many users behind one NAT/bastion/CGNAT egress IP don't
# share a single counter (which would false-positive-lock unrelated clients), and a success
# only clears that principal's budget. It rides the rate-limiter's circuit breaker and fails
# CLOSED to a durable DB fallback on a Redis outage (a successful auth clears both counters), so
# the bound survives an outage without locking out a healthy client — the account lockout +
# is_active/is_locked checks stay the primary controls; this is a DoS/enumeration bound, not a
# credential control.
def _sftp_key_id(ip: str, username: str) -> str:
    return f"sftp_pk:{ip}:{username}"


def _sftp_key_throttled(ip: str, username: str) -> bool:
    """True if (ip, username) has exceeded its SSH-key offer budget in the current window.

    Fails CLOSED to a durable DB fallback on a Redis outage (mirroring the password login throttle
    in AuthService): a Redis outage must not silently lift the flood / username-enumeration bound on
    key offers, which is exactly what returning "not throttled" here used to do."""
    from app.core.rate_limiter import rate_limiter, RateLimiterUnavailable
    from app.core import rate_limit_settings
    # Resolved through the rate-limit registry so an admin override applies (bounded + fail-safe to the
    # deployment default); the SFTP key throttle shares the login window.
    limit = rate_limit_settings.effective("rate_limit_sftp_key_attempts")
    window = rate_limit_settings.effective("rate_limit_login_window_seconds")
    try:
        allowed, _, _ = rate_limiter.check_rate_limit(
            _sftp_key_id(ip, username), limit, window, fail_open=False,
        )
        return not allowed
    except RateLimiterUnavailable:
        # Redis down / breaker open -> the same durable DB throttle the password path uses.
        allowed, _ = AuthService._db_throttle_hit(f"{ip}:{username}", "sftp_pk", limit, window)
        return not allowed
    except Exception:
        # Any other unexpected error: fail CLOSED (treat as throttled) rather than lift the bound.
        return True


class _MessageSFTPServer(paramiko.SFTPServer):
    """paramiko SFTP protocol handler that can attach a human-readable description to a status.

    A handle method (e.g. VaultSFTPHandle.write) returns a bare int status code, which paramiko
    turns into its default word for that code ("Failure"). When an upload is refused in-stream for a
    reason the operator can act on (over the SFTP size limit, or a full staging buffer), the handle
    records a description via _set_status_desc; this override sends it in place of the default. Only
    the tiny _send_status method is overridden, so it is robust across paramiko point releases.

    Paramiko processes one request at a time per connection, so a description set inside a handle
    method is consumed by exactly the status that method's return produces; it is cleared on every
    send so it can never attach to an unrelated status.
    """

    def __init__(self, channel, name, server, sftp_si=SFTPServerInterface, *largs, **kwargs):
        super().__init__(channel, name, server, sftp_si, *largs, **kwargs)
        self._pending_status_desc = None
        # Give the request handler (self.server is the SFTPServerInterface) a back-reference so
        # open() can wire each upload handle to this protocol handler.
        try:
            self.server._sftp_server = self
        except Exception:  # noqa: BLE001 - never let wiring break a connection
            pass

    def _send_status(self, request_number, code, desc=None):
        pending = self._pending_status_desc
        self._pending_status_desc = None
        if desc is None and pending:
            desc = pending
        return super()._send_status(request_number, code, desc)


def _sftp_key_clear(ip: str, username: str) -> None:
    """Reset this principal's key-offer counter after a successful key auth -- BOTH the Redis counter
    and the durable DB-fallback row -- so a healthy (frequently reconnecting, multi-key) client never
    trips the throttle, including while Redis is down and the DB fallback is doing the counting."""
    try:
        from app.core.database import redis_client
        redis_client.delete(f"rate_limit:{_sftp_key_id(ip, username)}")
    except Exception:
        pass
    # The Redis-outage fallback (_sftp_key_throttled) counts offers in a durable RateLimitRecord row;
    # clear it on success too, or a legitimate client that keeps authenticating would accumulate offers
    # it never resets and eventually lock itself out mid-window. Best-effort, own short-lived session.
    try:
        from app.core.database import get_db_context
        from app.core.models import RateLimitRecord
        with get_db_context() as db:
            db.query(RateLimitRecord).filter(
                RateLimitRecord.identifier == f"{ip}:{username}",
                RateLimitRecord.action == "sftp_pk",
            ).delete(synchronize_session=False)
    except Exception:
        pass


class SFTPServer(paramiko.ServerInterface):
    """
    Custom SSH server interface for authentication.
    """

    def __init__(self, client_address: str):
        self.client_address = client_address
        self.user: Optional[User] = None
        self.user_id: Optional[uuid.UUID] = None
        self.session_token: Optional[str] = None
        self._key_id: Optional[uuid.UUID] = None  # matched UserSSHKey id (key auth)

    def check_auth_password(self, username: str, password: str) -> int:
        """
        Authenticate user with username and password.
        Supports both regular users and temporary credentials.
        """
        try:
            with get_db_context() as db:
                auth_service = AuthService(db)
                audit_logger = AuditLogger(db)

                try:
                    # Check if this is a temporary credential (starts with "temp_")
                    if username.startswith("temp_"):
                        # Authenticate as temporary credential
                        user, session_token = auth_service.authenticate_temporary_credential(
                            temp_username=username,
                            credential=password,
                            ip_address=self.client_address
                        )

                        self.user = user
                        self.user_id = user.id  # capture while the session is open
                        self.session_token = session_token

                        audit_logger.log_login_success(
                            user, self.client_address, is_temporary=True
                        )

                        return paramiko.AUTH_SUCCESSFUL
                    else:
                        # Regular user authentication
                        user, session_token = auth_service.authenticate_user(
                            username, password, self.client_address
                        )

                        # Per-account SFTP gate: the user may disable SFTP entirely,
                        # or disable password SFTP (key-only); and the org may require
                        # a temp credential for SFTP for this user's group(s).
                        # authenticate_user already created a session, so revoke it.
                        deny = None
                        if not user.sftp_enabled:
                            deny = "SFTP disabled for this account"
                        elif not user.sftp_password_auth:
                            deny = "SFTP password auth disabled (use an SSH key)"
                        elif _user_requires_temp_cred_for_sftp(db, user):
                            deny = "SFTP requires a temporary credential for this account"
                        if deny is not None:
                            db.query(ActiveSession).filter(
                                ActiveSession.session_token == hash_session_token(session_token)
                            ).update({"is_active": False})
                            db.commit()
                            audit_logger.log_login_failure(username, self.client_address, deny)
                            return paramiko.AUTH_FAILED

                        self.user = user
                        self.user_id = user.id  # capture while the session is open
                        self.session_token = session_token

                        audit_logger.log_login_success(
                            user, self.client_address, is_temporary=False
                        )

                        return paramiko.AUTH_SUCCESSFUL

                except Exception as e:
                    # The exception CLASS, not its text. This lands in the audit row's reason and
                    # error_message, so a driver message carrying a query fragment or a value from
                    # the row it choked on would persist in the database -- the same hazard the
                    # operational log rule addresses, one table over. The class is what an
                    # investigator can act on.
                    audit_logger.log_login_failure(
                        username, self.client_address, type(e).__name__
                    )
                    return paramiko.AUTH_FAILED

        except Exception:
            return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        """SSH public-key authentication.

        The key authenticates the USER; vault access then flows from the user's
        membership/scope, exactly like password auth. We only VALIDATE here and
        remember the principal — the ActiveSession is created post-auth in
        handle_sftp_client, because paramiko also calls this in a no-signature
        'query' phase, and a session must not exist until the signature is verified
        (a real channel opens). Temp credentials do not use keys.
        """
        if username.startswith("temp_"):
            return paramiko.AUTH_FAILED
        # Per-(IP, username) throttle: bound a flood of key offers / key-and-username
        # enumeration. Each offer counts; a successful auth clears this principal's counter
        # (below) so a healthy client never trips it. Fails CLOSED to a durable DB fallback on a
        # Redis outage.
        if _sftp_key_throttled(self.client_address, username):
            return paramiko.AUTH_FAILED
        try:
            offered_b64 = key.get_base64()
            with get_db_context() as db:
                from app.services.auth_service import account_locked
                user = db.query(User).filter(User.username == username).first()
                if user is None or not user.is_active or account_locked(user) or not user.sftp_enabled:
                    return paramiko.AUTH_FAILED
                # Org policy: this user's group(s) may require a temp credential for
                # SFTP, which refuses SSH-key (and password) auth.
                if _user_requires_temp_cred_for_sftp(db, user):
                    return paramiko.AUTH_FAILED
                from app.core.models import UserSSHKey
                matched = None
                for k in db.query(UserSSHKey).filter(UserSSHKey.user_id == user.id).all():
                    parts = (k.public_key or "").split()
                    stored_b64 = parts[1] if len(parts) >= 2 else (parts[0] if parts else "")
                    if stored_b64 and stored_b64 == offered_b64:  # public blobs; plain compare
                        matched = k
                        break
                if matched is None:
                    return paramiko.AUTH_FAILED
                # Validated. Defer session creation + audit to post-auth.
                self.user = user
                self.user_id = user.id
                self._key_id = matched.id
                _sftp_key_clear(self.client_address, username)  # healthy client — reset its counter
                return paramiko.AUTH_SUCCESSFUL
        except Exception:
            return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        """
        Check if a channel request is allowed.

        Key-authenticated logins create their ActiveSession HERE: this fires AFTER
        authentication (signature verified) and BEFORE the SFTP subsystem can issue
        any operation, which avoids both paramiko's no-signature publickey 'query'
        phase and a race with the subsystem handler reading session_token.
        """
        if kind != 'session':
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        if self.session_token is None and self.user_id is not None:
            try:
                from datetime import datetime as _dt, timezone as _tz
                from app.services.auth_service import account_locked
                with get_db_context() as db:
                    u = db.query(User).filter(User.id == self.user_id).first()
                    if u is None or not u.is_active or account_locked(u) or not u.sftp_enabled:
                        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
                    self.session_token = AuthService(db).create_sftp_key_session(
                        u, self.client_address)
                    if self._key_id is not None:
                        from app.core.models import UserSSHKey
                        k = db.query(UserSSHKey).filter(UserSSHKey.id == self._key_id).first()
                        if k is not None:
                            k.last_used = _dt.now(_tz.utc)
                    AuditLogger(db).log_login_success(u, self.client_address, is_temporary=False)
                safe_event('session.key-auth.created', user=self.user_id)
            except Exception as e:  # noqa: BLE001
                safe_event('session.key-auth.failed', e)
                return paramiko.OPEN_FAILED_CONNECT_FAILED

        return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username: str) -> str:
        """
        Return allowed authentication methods. Both are offered; the per-account
        sftp_enabled / sftp_password_auth flags and key matching are enforced in the
        check_auth_* methods.
        """
        return 'password,publickey'


def listen_for_terminations():
    """
    Listen for session termination signals from Redis and close transports.

    Force-closing a live SFTP transport on lock/deactivate is a SECURITY control
    (immediate session revocation). Redis pub/sub connections die on a Redis
    restart/blip, and pubsub.listen() then raises and never resubscribes — which
    would silently disable revocation until the SFTP process is restarted. So we
    run the subscribe+listen inside a reconnect loop with a short backoff: a Redis
    outage degrades revocation only for the duration of the outage, then it
    self-heals.
    """
    while True:
        try:
            r = redis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                db=settings.redis_db,
                password=settings.redis_password if settings.redis_password else None,
                decode_responses=True,
                # Match the shared client settings (app/core/database.py) so a HALF-OPEN socket — a Redis blip
                # that drops the TCP connection WITHOUT a clean close — is detected instead of blocking
                # forever, which would silently disable live SFTP revocation until the process restarts.
                # socket_keepalive + health_check_interval actively probe an idle pub/sub connection;
                # socket_timeout bounds every read (incl. the health-check PONG) and socket_connect_timeout
                # bounds reconnects.
                socket_connect_timeout=settings.redis_connect_timeout,
                socket_timeout=settings.redis_socket_timeout,
                socket_keepalive=True,
                health_check_interval=30,
            )
            pubsub = r.pubsub()
            pubsub.subscribe('session_terminations')

            safe_event('termination-listener.listening')

            while True:
                # Bounded poll, never an unbounded listen(): returns None on an idle tick, so
                # health_check_interval can fire a PING and surface a dead/half-open socket promptly
                # (raising into the reconnect loop below) instead of hanging.
                message = pubsub.get_message(timeout=1.0)
                if message is None:
                    continue
                if message.get('type') == 'message':
                    try:
                        data = json.loads(message['data'])
                        session_token = data.get('session_token')

                        if session_token:
                            with transport_lock:
                                transport = active_transports.get(session_token)
                                if transport:
                                    safe_event('session.terminating', session=session_token[:8])
                                    transport.close()
                                    active_transports.pop(session_token, None)
                                    safe_event('session.terminated.ok', session=session_token[:8])
                                else:
                                    safe_event('session.terminate.not-found', session=session_token[:8])
                    except Exception as e:
                        safe_event('termination-signal.failed', e)

        except Exception as e:
            # Connection lost / health-check failed (Redis restarted, or a half-open socket surfaced
            # by health_check_interval) — back off briefly, then reconnect + resubscribe so revocation
            # self-heals after the outage.
            safe_event('termination-listener.reconnecting', e)
            time.sleep(5)


def _sweep_sftp_tmp():
    """Delete orphaned plaintext upload buffers from a previous run.

    SFTP uploads buffer the client's plaintext to .sftp_tmp/up_* before encrypting at close.
    A crash, kill, or dropped connection mid-transfer skips the finalizer's cleanup and
    leaves that plaintext on the persisted volume indefinitely. A freshly-started server has
    no in-flight uploads, so every up_* file here is an orphan — safe to remove. (The
    finalizer also cleans its own buffer on the normal/failure paths; this catches the rest.)"""
    try:
        if not _SFTP_TMP_DIR.exists():
            return
        removed = 0
        for f in _SFTP_TMP_DIR.glob("up_*"):
            try:
                f.unlink()
                removed += 1
            except OSError:
                pass
        if removed:
            # The directory is a deployment path; the COUNT is the operational fact.
            safe_event('tmp-sweep.completed', removed=removed)
    except Exception as e:  # noqa: BLE001 — best-effort housekeeping, never block startup
        safe_event('tmp-sweep.failed', e)


def start_sftp_server():
    """
    Start the SFTP server.
    """
    # Generate or load host key
    host_key_path = Path(settings.sftp_host_key_path)

    if not host_key_path.exists():
        # New install: generate a modern Ed25519 key. Where it is written is a host path and stays
        # out of the log. An existing deployment already has its key here and skips this branch, so
        # its fingerprint never changes on upgrade.
        safe_event('host-key.generating')
        generate_ed25519_host_key(host_key_path)

    # Load whatever is present -- Ed25519 on new installs, RSA on ones that predate this.
    host_key = load_host_key(str(host_key_path))

    # Remove any plaintext upload buffers orphaned by a previous crash/kill (no uploads can
    # be in flight at startup, so all are stale).
    _sweep_sftp_tmp()

    # Start Redis termination listener in background
    termination_thread = threading.Thread(target=listen_for_terminations, daemon=True)
    termination_thread.start()
    safe_event('termination-listener.started')

    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((settings.sftp_host, settings.sftp_port))
    server_socket.listen(10)

    safe_event('server.listening', port=settings.sftp_port)

    # Graceful shutdown: SIGTERM (docker stop / run_combined forwarding it) and SIGINT both
    # close the listening socket so accept() unblocks and the loop exits cleanly, instead of
    # the process being hard-killed. Handlers run only in the main thread, which is where
    # start_sftp_server() runs.
    _stop = threading.Event()

    def _shutdown(signum, _frame):
        safe_event('server.signal', signal=signum)
        _stop.set()
        try:
            server_socket.close()
        except Exception:  # noqa: BLE001
            pass

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    while not _stop.is_set():
        try:
            client_socket, client_address = server_socket.accept()

            # Pre-auth admission: refuse the connection here -- before a thread or Transport exists --
            # when the total or per-IP ceiling is reached, so a no-credential flood cannot exhaust
            # threads/Transports through the handshake window.
            if not _connection_admission.admit(client_address[0]):
                safe_event('connection.rejected.overcap', peer=client_address)
                try:
                    client_socket.close()
                except Exception:  # noqa: BLE001
                    pass
                continue

            # Handle client in a new thread (the handler releases the admission slot in its finally).
            # Everything after a successful admit() lives in this try, so ANY failure before the
            # handler thread owns the slot -- including a logging error on a broken stdout pipe --
            # still releases the slot and closes the socket instead of leaking them.
            try:
                safe_event('connection.accepted', peer=client_address)
                client_thread = threading.Thread(
                    target=handle_sftp_client,
                    args=(client_socket, client_address, host_key)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:  # noqa: BLE001
                # Failed after admission (spawn, or the log above) -- release the slot and close, so
                # neither the slot nor the socket FD is leaked.
                _connection_admission.release(client_address[0])
                try:
                    client_socket.close()
                except Exception:  # noqa: BLE001
                    pass
                safe_event('connection.thread.spawn.failed', e, peer=client_address)
                continue

        except KeyboardInterrupt:
            safe_event('server.shutting-down')
            break
        except OSError:
            # accept() on a socket closed by the signal handler — exit if we're stopping.
            if _stop.is_set():
                break
            continue
        except Exception as e:
            safe_event('connection.accept.failed', e)
            continue

    try:
        server_socket.close()
    except Exception:  # noqa: BLE001
        pass
    safe_event('server.stopped')


def handle_sftp_client(
    client_socket: socket.socket,
    client_address: tuple,
    host_key: paramiko.PKey
):
    """
    Handle an SFTP client connection.
    """
    transport = None
    server = None

    try:
        # Create SSH transport. Refuse SWEET32-vulnerable 3DES-CBC, all CBC ciphers, and
        # MD5/SHA1 (incl. truncated -96) MACs so an active downgrade or a hostile/misconfigured
        # client can't weaken the file-transfer channel; the strong defaults (aes-ctr/gcm +
        # hmac-sha2) are untouched, so conformant clients are unaffected.
        transport = paramiko.Transport(
            client_socket,
            disabled_algorithms={
                'ciphers': ['3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc',
                            'blowfish-cbc', 'cast128-cbc'],
                'macs': ['hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96'],
            },
        )
        # Neutral version banner — don't leak the exact paramiko library + version pre-auth.
        transport.local_version = "SSH-2.0-DockVault"
        # Bound how long a connection is held before it authenticates (the SSH LoginGraceTime
        # equivalent), so a stalled or silent pre-auth connection is dropped instead of occupying a
        # thread + Transport for paramiko's longer defaults.
        grace = settings.sftp_auth_grace_seconds
        if grace and grace > 0:
            transport.banner_timeout = grace
            transport.auth_timeout = grace
        transport.add_server_key(host_key)
        transport.set_subsystem_handler(
            'sftp',
            _MessageSFTPServer,
            SFTPServerInterface
        )

        # Create server instance
        server = SFTPServer(client_address[0])

        # Start SSH server
        transport.start_server(server=server)

        # Wait for authentication
        channel = transport.accept(20)

        if channel is None:
            safe_event('channel.open.failed', peer=client_address)
            return

        # Register transport in global registry if authenticated (key-auth sessions
        # are created in check_channel_request, so session_token is set by now). Keyed by the
        # token's hash — the same value the DB stores and the termination signal carries — so a
        # revocation published by the API (which sends the stored hash) finds this transport.
        if server.session_token:
            with transport_lock:
                active_transports[hash_session_token(server.session_token)] = transport
            safe_event('transport.registered', session=server.session_token[:8])

        # Keep connection alive
        while transport.is_active():
            transport.accept(1)

    except Exception as e:
        safe_event('client.handling.failed', e, peer=client_address)

    finally:
        # Unregister transport (same hashed key it was registered under).
        if transport and server and server.session_token:
            with transport_lock:
                active_transports.pop(hash_session_token(server.session_token), None)
            safe_event('transport.unregistered', session=server.session_token[:8])

        if transport:
            transport.close()

        # Release the pre-auth admission slot reserved for this connection in the accept loop. In
        # the finally so it frees on every path -- normal close, exception, or an early return.
        _connection_admission.release(client_address[0])


if __name__ == '__main__':
    start_sftp_server()
