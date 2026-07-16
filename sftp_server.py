"""
Custom SFTP server implementation using Paramiko.

Implements secure SFTP with vault support and hierarchical access control.

Design (Standard-vault SFTP, see docs/vault-zero-trust-and-sftp-design.md §1):
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

from app.core.database import get_db_context
from app.core.models import User, ActiveSession, Vault, Folder, File
from auth_service import AuthService
from app.core.authorization import PermissionService, PermissionDeniedError
from vault_service import (
    VaultService,
    VaultNotFoundError,
    FolderNotFoundError,
    PasswordRequiredError,
    InvalidPasswordError,
)
from vault_service import FileNotFoundError as VaultFileNotFoundError
from app.services.audit_logger import AuditLogger
from app.core.config import settings
from app.core.temp_scope import is_scoped, effective_vault_caps
from app.core.security import name_blind_index
from sqlalchemy import or_

# Global registry of active transports: session_token -> transport
active_transports: Dict[str, paramiko.Transport] = {}
transport_lock = threading.Lock()

# Where incoming uploads are buffered (plaintext) before being pushed through the
# encryption pipeline at handle close. Lives inside the storage volume so it is on
# the same filesystem as the final encrypted file.
_SFTP_TMP_DIR = Path(settings.file_storage_path) / ".sftp_tmp"

# POSIX open-flag access mode mask (sftp_server.py only runs inside the Linux
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


def _user_requires_temp_cred_for_sftp(db, user) -> bool:
    """Org SFTP-auth policy (design §5): a user in any group listed under the global
    setting ``sftp_require_temp_cred_groups`` may ONLY use a temporary credential for
    SFTP — direct password and SSH-key auth are refused. Per-group by design (a
    global force would break SSH-key automation). Reads the admin Settings store
    (SystemSetting 'global'); fails OPEN (no extra restriction) on any error."""
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


class _PathNotFound(Exception):
    """Internal: a path segment did not resolve to a real vault/folder/file."""
    pass


class VaultSFTPHandle(paramiko.SFTPHandle):
    """
    A single open-file handle.

    Read mode: the (decrypted) file content is loaded into ``readbuf`` up front
    (mirrors the web download, which also materialises the whole file) and served
    by offset.

    Write mode: incoming bytes are buffered to a temp file; on ``close`` the
    assembled plaintext is pushed through the real encryption pipeline via the
    ``finalizer`` callback. Authorization already happened in ``open()`` (so
    permission errors are reported to the client there); ``close`` only performs
    the encrypt-and-persist, which the SFTP protocol cannot fail cleanly anyway.
    """

    def __init__(self, flags: int = 0):
        super().__init__(flags)
        # read mode
        self.readbuf: Optional[bytes] = None
        # write mode
        self.writepath: Optional[str] = None
        self.writefile = None
        self.finalizer = None  # callable(temp_path) -> None
        # In-stream upload bound: cap the plaintext buffered to the shared volume so a
        # client can't fill it before the close-time size check. 0 = no bound. overlimit
        # marks the upload for discard at close (an SFTP close can't signal failure).
        self.max_bytes = 0
        self.overlimit = False
        # shared
        self.attrs: Optional[paramiko.SFTPAttributes] = None

    def read(self, offset: int, length: int):
        if self.readbuf is None:
            return paramiko.SFTP_OP_UNSUPPORTED
        if offset >= len(self.readbuf):
            return paramiko.SFTP_EOF
        return self.readbuf[offset:offset + length]

    def write(self, offset: int, data: bytes):
        if self.writefile is None:
            return paramiko.SFTP_OP_UNSUPPORTED
        # In-stream size bound: reject any write that would push the buffered file past the
        # per-file max, BEFORE it lands on the shared storage volume — so an SFTP client can't
        # stream unbounded plaintext into .sftp_tmp (filling the volume shared by every vault)
        # before the close-time size check runs. Mark the handle so close() discards the upload.
        if self.max_bytes and (offset + len(data)) > self.max_bytes:
            self.overlimit = True
            return paramiko.SFTP_FAILURE
        try:
            self.writefile.seek(offset)
            self.writefile.write(data)
            return paramiko.SFTP_OK
        except Exception as e:  # noqa: BLE001
            print(f"❌ SFTP write error: {e}")
            return paramiko.SFTP_FAILURE

    def stat(self):
        if self.attrs is not None:
            return self.attrs
        return paramiko.SFTP_OP_UNSUPPORTED

    def close(self):
        # Write mode: assemble + encrypt + persist.
        if self.writefile is not None:
            try:
                self.writefile.flush()
                self.writefile.close()
            except Exception:  # noqa: BLE001
                pass
            self.writefile = None
            if self.overlimit:
                # The upload exceeded the per-file max mid-stream: discard it (don't persist),
                # leaving any existing same-name file intact. The temp buffer is removed below.
                print(f"⚠️ SFTP upload discarded: exceeded max file size ({self.max_bytes}B)")
            elif self.finalizer is not None and self.writepath:
                try:
                    self.finalizer(self.writepath)
                except Exception as e:  # noqa: BLE001
                    print(f"❌ SFTP upload finalize failed: {e}")
            # Always clean up the plaintext temp buffer.
            try:
                if self.writepath and os.path.exists(self.writepath):
                    os.remove(self.writepath)
            except Exception:  # noqa: BLE001
                pass
        self.readbuf = None


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
        from auth_service import account_locked
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

    def _check_session_valid(self) -> bool:
        """Check the connection's session is still active (immediate revocation)."""
        token = getattr(self.server, "session_token", None)
        if not token:
            return False
        try:
            with get_db_context() as db:
                session = db.query(ActiveSession).filter(
                    ActiveSession.session_token == token,
                    ActiveSession.is_active == True  # noqa: E712
                ).first()
                if not session:
                    print(f"⛔ Session {token[:8]}... has been terminated")
                    return False
                # Enforce the session's HARD expiry on every op, not just at login. Regular
                # account sessions carry a NULL expires_at (no hard bound → skipped); a
                # temp-credential session carries the credential's expires_at, so a cred with a
                # short total lifetime can't keep operating over SFTP past it (the web path
                # rejects per request; nothing on the SFTP path did). Stored naive (UTC).
                from datetime import datetime, timezone
                if session.expires_at is not None:
                    _exp = session.expires_at
                    if _exp.tzinfo is None:
                        _exp = _exp.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) > _exp:
                        print(f"⛔ Session {token[:8]}... past its hard expiry")
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
                        print(f"⛔ Session {token[:8]}... temp credential deactivated")
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
                            print(f"⛔ Session {token[:8]}... temp credential past its validity window")
                            return False
                return True
        except Exception as e:  # noqa: BLE001
            print(f"❌ Error checking session validity: {e}")
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
                    print(f"❌ SFTP list_vaults failed: {e}")
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
                    result.append(self._dir_attr(
                        self._vault_display_name(vault),
                        mtime=self._ts(vault.updated_at),
                        size=vault.total_size_bytes or 0,
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

            result = []
            folders = db.query(Folder).filter(
                Folder.vault_id == vault.id,
                Folder.parent_folder_id == folder_id,
            ).all()
            for folder in folders:
                result.append(self._dir_attr(folder.name, mtime=self._ts(folder.updated_at)))

            files = db.query(File).filter(
                File.vault_id == vault.id,
                File.folder_id == folder_id,
            ).all()
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
                return self._dir_attr(self._vault_display_name(vault),
                                      mtime=self._ts(vault.updated_at))

            # Metadata for anything INSIDE the vault requires see_files — same
            # gate as list_folder and the web list path. Return NO_SUCH_FILE (not
            # PERMISSION_DENIED) so a see_info-only credential can't confirm a
            # file/folder's existence, size, or mtime via stat/lstat.
            if not self._has_cap(user, vault.id, "vault.see_files"):
                return paramiko.SFTP_NO_SUCH_FILE

            # Try the full path as a folder first.
            try:
                folder_id = self._resolve_folder(db, vault.id, segments[1:])
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
            try:
                # download_file re-resolves the file's REAL vault and re-checks
                # READ permission + any per-file password — same as the web path.
                content, name, _mime = vault_service.download_file(f.id, user)
            except (PermissionDeniedError, PasswordRequiredError, InvalidPasswordError):
                return paramiko.SFTP_PERMISSION_DENIED
            except VaultFileNotFoundError:
                return paramiko.SFTP_NO_SUCH_FILE
            except Exception as e:  # noqa: BLE001
                print(f"❌ SFTP download failed for {f.id}: {e}")
                return paramiko.SFTP_FAILURE

            self._audit(user, "file_download", str(f.id),
                        {"vault_id": str(vault.id), "file_name": name, "via": "sftp"})

            handle = VaultSFTPHandle(flags=os.O_RDONLY)
            handle.readbuf = content
            handle.attrs = self._file_attr(name, size=len(content), mtime=self._ts(f.created_at))
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
            try:
                folder_id = self._resolve_folder(db, vault.id, segments[1:-1])
            except _PathNotFound:
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
            print(f"❌ SFTP could not open upload buffer: {e}")
            return paramiko.SFTP_FAILURE

        handle = VaultSFTPHandle(flags=os.O_WRONLY)
        handle.writepath = tmp_path
        handle.writefile = wf
        # Bound the buffered plaintext in-stream at the configured per-file max, so the write
        # can't fill the shared .sftp_tmp volume before the close-time size check runs.
        handle.max_bytes = (settings.max_file_size_mb or 0) * 1024 * 1024
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
                print(f"⚠️ SFTP upload rejected: {filename} ({buffered_size}B) exceeds "
                      f"max {max_bytes}B — existing file left intact")
                return

            with get_db_context() as db:
                user = interface._load_principal(db)
                # Re-validate principal AND session at persist time: an account
                # locked/deactivated or a session revoked mid-transfer must not
                # land the write (TOCTOU between open() and close()).
                if user is None or not interface._check_session_valid():
                    print("⚠️ SFTP upload aborted: principal/session no longer valid")
                    return
                vault_service = VaultService(db, PermissionService(db))
                # Re-authorize at persist time (fresh session): membership +
                # temp-cred vault scope. upload re-checks the real vault.
                vault = vault_service.get_vault(vault_id, user, require_password=False)
                # Re-gate the per-vault password proof too: a password ADDED or rotated
                # between open() and close() must not let an in-flight write land without
                # current proof (TOCTOU) — same gate _resolve_vault applies at open().
                if vault.password_hash is not None and not interface._vault_password_proven(user, vault):
                    print("⚠️ SFTP upload aborted: vault password proof no longer valid")
                    return

                # Vault quota pre-check (mirror the web upload path) — again before
                # we write or delete anything.
                if vault.size_limit and (vault.total_size_bytes or 0) + buffered_size > vault.size_limit:
                    print(f"⚠️ SFTP upload rejected: would exceed vault size limit — "
                          f"existing file left intact")
                    return
                # Deployment-wide plan storage ceiling (aggregate across all vaults) —
                # same gate the web upload path enforces, so SFTP can't bypass the plan.
                from vault_service import would_exceed_deployment_storage
                exceeds, _used, _cap = would_exceed_deployment_storage(db, buffered_size)
                if exceeds:
                    print("⚠️ SFTP upload rejected: would exceed the plan storage limit — "
                          "existing file left intact")
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
                print(f"✅ SFTP upload stored {filename} ({total_size} bytes) in vault {vault_id}")

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
            fid = f.id
            try:
                vault_service.delete_file(fid, user)
            except PermissionDeniedError:
                return paramiko.SFTP_PERMISSION_DENIED
            except VaultFileNotFoundError:
                return paramiko.SFTP_NO_SUCH_FILE
            except Exception as e:  # noqa: BLE001
                print(f"❌ SFTP remove failed: {e}")
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
                print(f"❌ SFTP rename failed: {e}")
                return paramiko.SFTP_FAILURE
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
            try:
                new_folder = vault_service.create_folder(
                    vault_id=vault.id, name=segments[-1], user=user, parent_folder_id=parent_id
                )
            except PermissionDeniedError:
                return paramiko.SFTP_PERMISSION_DENIED
            except Exception as e:  # noqa: BLE001
                print(f"❌ SFTP mkdir failed: {e}")
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
                        print(f"⚠️ rmdir: failed to delete file {child.id}: {ex}")
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
                print(f"❌ SFTP rmdir failed: {e}")
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
    limit = settings.rate_limit_sftp_key_attempts
    window = settings.rate_limit_login_window_seconds
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
                                ActiveSession.session_token == session_token
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
                    audit_logger.log_login_failure(
                        username, self.client_address, str(e)
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
                from auth_service import account_locked
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
                from auth_service import account_locked
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
                print(f"🔑 SSH-key SFTP session created for {self.user_id}")
            except Exception as e:  # noqa: BLE001
                print(f"❌ Failed to create key-auth session: {e}")
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

            print("👂 Listening for session termination signals...")

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
                                    print(f"⚠️ Terminating session {session_token[:8]}...")
                                    transport.close()
                                    active_transports.pop(session_token, None)
                                    print(f"✅ Session {session_token[:8]}... terminated")
                                else:
                                    print(f"ℹ️ Session {session_token[:8]}... not found in active transports")
                    except Exception as e:
                        print(f"❌ Error processing termination signal: {e}")

        except Exception as e:
            # Connection lost / health-check failed (Redis restarted, or a half-open socket surfaced
            # by health_check_interval) — back off briefly, then reconnect + resubscribe so revocation
            # self-heals after the outage.
            print(f"❌ Termination listener connection lost; reconnecting in 5s: {e}")
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
            print(f"🧹 Swept {removed} orphaned SFTP upload buffer(s) from {_SFTP_TMP_DIR}")
    except Exception as e:  # noqa: BLE001 — best-effort housekeeping, never block startup
        print(f"⚠️ SFTP tmp sweep failed: {e}")


def start_sftp_server():
    """
    Start the SFTP server.
    """
    # Generate or load host key
    host_key_path = Path(settings.sftp_host_key_path)

    if not host_key_path.exists():
        print(f"Generating new RSA host key at {host_key_path}")
        host_key_path.parent.mkdir(parents=True, exist_ok=True)
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(host_key_path))

    host_key = paramiko.RSAKey.from_private_key_file(str(host_key_path))

    # Remove any plaintext upload buffers orphaned by a previous crash/kill (no uploads can
    # be in flight at startup, so all are stale).
    _sweep_sftp_tmp()

    # Start Redis termination listener in background
    termination_thread = threading.Thread(target=listen_for_terminations, daemon=True)
    termination_thread.start()
    print("✅ Session termination listener started")

    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((settings.sftp_host, settings.sftp_port))
    server_socket.listen(10)

    print(f"SFTP Server listening on {settings.sftp_host}:{settings.sftp_port}")

    # Graceful shutdown: SIGTERM (docker stop / run_combined forwarding it) and SIGINT both
    # close the listening socket so accept() unblocks and the loop exits cleanly, instead of
    # the process being hard-killed. Handlers run only in the main thread, which is where
    # start_sftp_server() runs.
    _stop = threading.Event()

    def _shutdown(signum, _frame):
        print(f"\nSFTP server received signal {signum}; shutting down...")
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
            print(f"Connection from {client_address}")

            # Handle client in a new thread
            client_thread = threading.Thread(
                target=handle_sftp_client,
                args=(client_socket, client_address, host_key)
            )
            client_thread.daemon = True
            client_thread.start()

        except KeyboardInterrupt:
            print("\nShutting down SFTP server...")
            break
        except OSError:
            # accept() on a socket closed by the signal handler — exit if we're stopping.
            if _stop.is_set():
                break
            continue
        except Exception as e:
            print(f"Error accepting connection: {e}")
            continue

    try:
        server_socket.close()
    except Exception:  # noqa: BLE001
        pass
    print("SFTP server stopped.")


def handle_sftp_client(
    client_socket: socket.socket,
    client_address: tuple,
    host_key: paramiko.RSAKey
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
        transport.add_server_key(host_key)
        transport.set_subsystem_handler(
            'sftp',
            paramiko.SFTPServer,
            SFTPServerInterface
        )

        # Create server instance
        server = SFTPServer(client_address[0])

        # Start SSH server
        transport.start_server(server=server)

        # Wait for authentication
        channel = transport.accept(20)

        if channel is None:
            print(f"Client {client_address} failed to open channel")
            return

        # Register transport in global registry if authenticated (key-auth sessions
        # are created in check_channel_request, so session_token is set by now).
        if server.session_token:
            with transport_lock:
                active_transports[server.session_token] = transport
            print(f"✅ Registered transport for session {server.session_token[:8]}...")

        # Keep connection alive
        while transport.is_active():
            transport.accept(1)

    except Exception as e:
        print(f"Error handling client {client_address}: {e}")

    finally:
        # Unregister transport
        if transport and server and server.session_token:
            with transport_lock:
                active_transports.pop(server.session_token, None)
            print(f"🔌 Unregistered transport for session {server.session_token[:8]}...")

        if transport:
            transport.close()


if __name__ == '__main__':
    start_sftp_server()
