#!/usr/bin/env python3
"""Convert one plaintext dotenv file to encrypted credentials without data loss."""

import argparse
import base64
import ctypes
import errno
import getpass
from io import StringIO
import os
from dataclasses import dataclass, field
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Mapping, Sequence

import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv.parser import Binding, parse_stream

# Run as ``python scripts/setup_master_password.py``. Keep the runtime bcrypt limit
# and compatibility clamp as the single shared implementation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.core.startup_security import (  # noqa: E402
    BCRYPT_MAX_PASSWORD_BYTES,
    bcrypt_password_bytes,
)


SECRET_KEYS = (
    "ENCRYPTION_KEY",
    "DATABASE_URL",
    "REDIS_PASSWORD",
    "JWT_SECRET_KEY",
    "ADMIN_PASSWORD",
)
GENERATED_KEYS = (
    "MASTER_PASSWORD_HASH",
    "MASTER_KEY_SALT",
    *(f"ENCRYPTED_{key}" for key in SECRET_KEYS),
)
_ASSIGNMENT_RE = re.compile(
    r"^(?P<prefix>[ \t]*(?:export[ \t]+)?)"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<separator>[ \t]*=)(?P<leading>[ \t]*)(?P<rhs>.*)$"
)
_INTERPOLATION_RE = re.compile(r"\$\{[^}]+\}")


class ConversionError(RuntimeError):
    """A typed conversion failure whose text is safe for operator output."""

    def __init__(self, code: str, safe_message: str):
        self.code = code
        self.safe_message = safe_message
        super().__init__(safe_message)


@dataclass(frozen=True)
class SourceDocument:
    path: Path
    backup_path: Path
    original_bytes: bytes = field(repr=False)
    source_identity: tuple[int, int]
    original_text: str = field(repr=False)
    bindings: tuple[Binding, ...] = field(repr=False)
    secrets: Mapping[str, str] = field(repr=False)
    newline: str = field(repr=False)


@dataclass(frozen=True)
class ConversionResult:
    source_path: Path
    backup_path: Path


def generate_salt() -> str:
    """Generate a random salt for PBKDF2."""
    return base64.urlsafe_b64encode(os.urandom(16)).decode()


def derive_key_from_password(password: str, salt: str) -> bytes:
    """Derive the credential-wrapping key used by the runtime unlocker."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=600000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_value(value: str, fernet: Fernet) -> str:
    """Encrypt one decoded dotenv value."""
    return fernet.encrypt(value.encode()).decode()


def get_master_password() -> str:
    """Prompt for a new master password with confirmation."""
    print("=" * 60)
    print("DockVault Master Password Setup")
    print("=" * 60)
    print("\nThis password will protect all sensitive credentials.")
    print("If you forget it, the encrypted credentials cannot be recovered.")
    print("\nRequirements:")
    print("  - Minimum 16 characters")
    print(f"  - Maximum {BCRYPT_MAX_PASSWORD_BYTES} UTF-8 bytes")
    print("  - Store it in a password manager")
    print()

    while True:
        password = getpass.getpass("Enter master password: ")
        if len(password) < 16:
            print("Password must be at least 16 characters.\n")
            continue

        encoded_length = len(password.encode("utf-8"))
        if encoded_length > BCRYPT_MAX_PASSWORD_BYTES:
            print(
                f"Password is {encoded_length} bytes; the maximum is "
                f"{BCRYPT_MAX_PASSWORD_BYTES} bytes."
            )
            print(
                "This limit counts BYTES, not characters; non-ASCII characters "
                "can use multiple bytes.\n"
            )
            continue

        password_confirm = getpass.getpass("Confirm master password: ")
        if password != password_confirm:
            print("Passwords do not match.\n")
            continue

        strength = sum(
            [
                any(c.isupper() for c in password),
                any(c.islower() for c in password),
                any(c.isdigit() for c in password),
                any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password),
            ]
        )
        if strength < 3:
            print("Weak password: a mix of character classes is recommended.")
            if input("Continue anyway? (yes/no): ").strip().lower() != "yes":
                continue
        return password


def _select_newline(text: str) -> str:
    endings = re.findall(r"\r\n|\n|\r", text)
    return endings[0] if endings else "\n"


def _split_line_ending(raw: str) -> tuple[str, str]:
    for ending in ("\r\n", "\n", "\r"):
        if raw.endswith(ending):
            return raw[: -len(ending)], ending
    return raw, ""


def _quoted_value_end(rhs: str, quote: str) -> int:
    escaped = False
    for index in range(1, len(rhs)):
        char = rhs[index]
        if char == quote and not escaped:
            return index
        if char == "\\" and not escaped:
            escaped = True
        else:
            escaped = False
    return -1


def _rewrite_secret_binding(binding: Binding, encrypted_value: str) -> str:
    body, ending = _split_line_ending(binding.original.string)
    if "\n" in body or "\r" in body:
        raise ConversionError(
            "required-secret-ambiguous",
            "A required secret uses an unsupported multiline assignment.",
        )

    match = _ASSIGNMENT_RE.fullmatch(body)
    if not match or match.group("key") != binding.key:
        raise ConversionError(
            "required-secret-ambiguous",
            "A required secret assignment could not be transformed safely.",
        )

    rhs = match.group("rhs")
    suffix = ""
    if rhs.startswith(("'", '"')):
        quote = rhs[0]
        end = _quoted_value_end(rhs, quote)
        if end < 0:
            raise ConversionError(
                "required-secret-ambiguous",
                "A required secret has an unterminated quoted value.",
            )
        suffix = rhs[end + 1 :]
        if suffix.strip() and not suffix.lstrip().startswith("#"):
            raise ConversionError(
                "required-secret-ambiguous",
                "A required secret has ambiguous trailing content.",
            )
        replacement_rhs = f"{quote}{encrypted_value}{quote}{suffix}"
    else:
        if rhs.startswith("#") and match.group("leading"):
            suffix = match.group("leading") + rhs
        elif comment := re.search(r"(?P<suffix>[ \t]+#.*)$", rhs):
            suffix = comment.group("suffix")
        replacement_rhs = encrypted_value + suffix

    return (
        f"{match.group('prefix')}ENCRYPTED_{binding.key}"
        f"{match.group('separator')}{match.group('leading')}"
        f"{replacement_rhs}{ending}"
    )

def _file_identity(file_stat: os.stat_result) -> tuple[int, int]:
    return file_stat.st_dev, file_stat.st_ino


def _read_regular_file(path: Path) -> tuple[bytes, tuple[int, int]]:
    """Read one unchanged regular-file entry without following a final symlink."""
    try:
        entry_stat = path.lstat()
    except OSError:
        raise ConversionError(
            "source-unavailable",
            "The selected environment file is unavailable.",
        ) from None
    if not stat.S_ISREG(entry_stat.st_mode):
        raise ConversionError(
            "source-unsafe",
            "The selected environment path must remain a regular file.",
        )

    flags = os.O_RDONLY
    for optional_flag in ("O_BINARY", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, optional_flag, 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        opened_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_stat.st_mode)
            or _file_identity(opened_stat) != _file_identity(entry_stat)
        ):
            raise ConversionError(
                "source-changed",
                "The selected environment file changed during conversion.",
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            content = handle.read()
        final_stat = path.lstat()
    except ConversionError:
        raise
    except OSError:
        raise ConversionError(
            "source-unavailable",
            "The selected environment file became unavailable.",
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)

    if (
        not stat.S_ISREG(final_stat.st_mode)
        or _file_identity(final_stat) != _file_identity(opened_stat)
    ):
        raise ConversionError(
            "source-changed",
            "The selected environment file changed during conversion.",
        )
    return content, _file_identity(opened_stat)


def prepare_source_document(source_path: os.PathLike | str) -> SourceDocument:
    """Read and validate one explicitly selected source file without mutating it."""
    requested = Path(source_path)
    if requested.is_symlink():
        raise ConversionError(
            "source-unsafe",
            "The selected environment file must not be a symbolic link.",
        )
    try:
        path = requested.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ConversionError(
            "source-unavailable",
            "The selected environment file is unavailable.",
        ) from None
    backup_path = path.with_name(path.name + ".backup")
    if os.path.lexists(backup_path):
        raise ConversionError(
            "backup-exists",
            "The non-clobbering backup path already exists.",
        )

    original_bytes, source_identity = _read_regular_file(path)
    try:
        original_text = original_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ConversionError(
            "source-invalid",
            "The selected environment file must be readable UTF-8 text.",
        ) from None
    if original_text.startswith("\ufeff"):
        raise ConversionError(
            "source-invalid",
            "The selected environment file must not contain a UTF-8 BOM.",
        )

    bindings = tuple(parse_stream(StringIO(original_text)))
    if any(binding.error for binding in bindings):
        raise ConversionError(
            "source-invalid",
            "The selected environment file contains invalid dotenv syntax.",
        )
    if "".join(binding.original.string for binding in bindings) != original_text:
        raise ConversionError(
            "source-invalid",
            "The selected environment file could not be parsed losslessly.",
        )

    occurrences: dict[str, list[Binding]] = {key: [] for key in SECRET_KEYS}
    generated_present = set()
    for binding in bindings:
        if binding.key in occurrences:
            occurrences[binding.key].append(binding)
        if binding.key in GENERATED_KEYS:
            generated_present.add(binding.key)
    if generated_present:
        raise ConversionError(
            "credential-state-ambiguous",
            "The selected file already contains encrypted credential metadata.",
        )

    secrets: dict[str, str] = {}
    for key, matches in occurrences.items():
        if len(matches) != 1:
            code = "required-secret-missing" if not matches else "required-secret-duplicate"
            raise ConversionError(
                code,
                "Each required plaintext secret must appear exactly once.",
            )
        value = matches[0].value
        raw_body, _ending = _split_line_ending(matches[0].original.string)
        raw_match = _ASSIGNMENT_RE.fullmatch(raw_body)
        comment_only = bool(
            raw_match
            and raw_match.group("leading")
            and raw_match.group("rhs").startswith("#")
        )
        if value is None or not value.strip() or comment_only:
            raise ConversionError(
                "required-secret-missing",
                "Each required plaintext secret must have a value.",
            )
        if _INTERPOLATION_RE.search(value):
            raise ConversionError(
                "required-secret-ambiguous",
                "Required secrets must not depend on dotenv interpolation.",
            )
        secrets[key] = value

    return SourceDocument(
        path=path,
        backup_path=backup_path,
        original_bytes=original_bytes,
        source_identity=source_identity,
        original_text=original_text,
        bindings=bindings,
        secrets=secrets,
        newline=_select_newline(original_text),
    )


def _encrypted_material(
    password: str,
    secrets: Mapping[str, str],
) -> tuple[str, str, dict[str, str]]:
    salt = generate_salt()
    wrapping_fernet = Fernet(derive_key_from_password(password, salt))
    password_hash = bcrypt.hashpw(
        bcrypt_password_bytes(password),
        bcrypt.gensalt(),
    ).decode()

    encrypted = {
        key: encrypt_value(value, wrapping_fernet)
        for key, value in secrets.items()
    }
    for key, token in encrypted.items():
        try:
            round_trip = wrapping_fernet.decrypt(token.encode()).decode()
        except Exception:
            raise ConversionError(
                "credential-roundtrip-failed",
                "Encrypted credentials failed verification before file mutation.",
            ) from None
        if round_trip != secrets[key]:
            raise ConversionError(
                "credential-roundtrip-failed",
                "Encrypted credentials failed verification before file mutation.",
            )
    return salt, password_hash, encrypted


def create_secure_env(
    password: str,
    secrets: Mapping[str, str],
) -> tuple[str, str, str]:
    """Compatibility helper that serializes only values supplied by the caller."""
    salt, password_hash, encrypted = _encrypted_material(password, secrets)
    lines = [
        f"MASTER_PASSWORD_HASH={password_hash}",
        f"MASTER_KEY_SALT={salt}",
        *(f"ENCRYPTED_{key}={value}" for key, value in encrypted.items()),
    ]
    return "\n".join(lines), salt, password_hash


def _build_transformed_text(document: SourceDocument, password: str) -> str:
    encoded_length = len(password.encode("utf-8"))
    if len(password) < 16:
        raise ConversionError(
            "master-password-weak",
            "The master password must be at least 16 characters.",
        )
    if encoded_length > BCRYPT_MAX_PASSWORD_BYTES:
        raise ConversionError(
            "master-password-too-long",
            "The master password exceeds bcrypt's UTF-8 byte limit.",
        )

    salt, password_hash, encrypted = _encrypted_material(
        password,
        document.secrets,
    )
    metadata = (
        f"MASTER_PASSWORD_HASH={password_hash}{document.newline}"
        f"MASTER_KEY_SALT={salt}{document.newline}"
    )
    output = []
    inserted_metadata = False
    for binding in document.bindings:
        if binding.key in SECRET_KEYS:
            if not inserted_metadata:
                output.append(metadata)
                inserted_metadata = True
            output.append(
                _rewrite_secret_binding(binding, encrypted[binding.key])
            )
        else:
            output.append(binding.original.string)
    if not inserted_metadata:
        raise ConversionError(
            "required-secret-missing",
            "The required plaintext secrets could not be located.",
        )
    return "".join(output)


def _windows_current_sid() -> str:
    from ctypes import wintypes

    token_query = 0x0008
    token_user_class = 1
    error_insufficient_buffer = 122

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]

    class TokenUser(ctypes.Structure):
        _fields_ = [("user", SidAndAttributes)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        token_query,
        ctypes.byref(token),
    ):
        error = ctypes.get_last_error()
        raise OSError(error, ctypes.FormatError(error))
    try:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            token_user_class,
            None,
            0,
            ctypes.byref(required),
        )
        error = ctypes.get_last_error()
        if error != error_insufficient_buffer or not required.value:
            raise OSError(error, ctypes.FormatError(error))
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            token_user_class,
            buffer,
            required,
            ctypes.byref(required),
        ):
            error = ctypes.get_last_error()
            raise OSError(error, ctypes.FormatError(error))
        user = ctypes.cast(buffer, ctypes.POINTER(TokenUser)).contents
        sid_pointer = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(
            user.user.sid,
            ctypes.byref(sid_pointer),
        ):
            error = ctypes.get_last_error()
            raise OSError(error, ctypes.FormatError(error))
        try:
            return sid_pointer.value
        finally:
            kernel32.LocalFree(sid_pointer)
    finally:
        kernel32.CloseHandle(token)


def _windows_acl_semantics_are_owner_only(
    *,
    protected: bool,
    ace_count: int,
    ace_type: int,
    ace_flags: int,
    access_mask: int,
    sid_matches: bool,
) -> bool:
    return (
        protected
        and ace_count == 1
        and ace_type == 0
        and ace_flags == 0
        and access_mask == 0x001F01FF
        and sid_matches
    )


def _windows_acl_is_owner_only(path: Path) -> bool:
    from ctypes import wintypes

    se_file_object = 1
    dacl_security_information = 0x00000004
    se_dacl_protected = 0x1000
    acl_size_information = 2

    class AclSizeInformation(ctypes.Structure):
        _fields_ = [
            ("ace_count", wintypes.DWORD),
            ("acl_bytes_in_use", wintypes.DWORD),
            ("acl_bytes_free", wintypes.DWORD),
        ]

    class AceHeader(ctypes.Structure):
        _fields_ = [
            ("ace_type", wintypes.BYTE),
            ("ace_flags", wintypes.BYTE),
            ("ace_size", wintypes.WORD),
        ]

    class AccessAllowedAce(ctypes.Structure):
        _fields_ = [
            ("header", AceHeader),
            ("mask", wintypes.DWORD),
            ("sid_start", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    void_pointer_pointer = ctypes.POINTER(ctypes.c_void_p)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        void_pointer_pointer,
        void_pointer_pointer,
        void_pointer_pointer,
        void_pointer_pointer,
        void_pointer_pointer,
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.IsValidAcl.argtypes = [ctypes.c_void_p]
    advapi32.IsValidAcl.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        void_pointer_pointer,
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        void_pointer_pointer,
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.IsValidSid.argtypes = [ctypes.c_void_p]
    advapi32.IsValidSid.restype = wintypes.BOOL
    advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi32.EqualSid.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    security_descriptor = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    status = advapi32.GetNamedSecurityInfoW(
        str(path),
        se_file_object,
        dacl_security_information,
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(security_descriptor),
    )
    if status:
        raise OSError(status, ctypes.FormatError(status))
    try:
        if not dacl or not advapi32.IsValidAcl(dacl):
            return False
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            security_descriptor,
            ctypes.byref(control),
            ctypes.byref(revision),
        ):
            error = ctypes.get_last_error()
            raise OSError(error, ctypes.FormatError(error))

        size_information = AclSizeInformation()
        if not advapi32.GetAclInformation(
            dacl,
            ctypes.byref(size_information),
            ctypes.sizeof(size_information),
            acl_size_information,
        ):
            error = ctypes.get_last_error()
            raise OSError(error, ctypes.FormatError(error))
        if size_information.ace_count != 1:
            return False

        ace_pointer = ctypes.c_void_p()
        if not advapi32.GetAce(dacl, 0, ctypes.byref(ace_pointer)):
            error = ctypes.get_last_error()
            raise OSError(error, ctypes.FormatError(error))
        ace = ctypes.cast(
            ace_pointer,
            ctypes.POINTER(AccessAllowedAce),
        ).contents
        sid_offset = AccessAllowedAce.sid_start.offset
        ace_offset = ace_pointer.value - dacl.value
        if (
            ace.header.ace_size < sid_offset + 8
            or ace_offset < 0
            or ace_offset + ace.header.ace_size
            > size_information.acl_bytes_in_use
        ):
            return False

        ace_sid = ctypes.c_void_p(ace_pointer.value + sid_offset)
        if not advapi32.IsValidSid(ace_sid):
            return False
        if sid_offset + advapi32.GetLengthSid(ace_sid) > ace.header.ace_size:
            return False

        expected_sid = ctypes.c_void_p()
        if not advapi32.ConvertStringSidToSidW(
            _windows_current_sid(),
            ctypes.byref(expected_sid),
        ):
            error = ctypes.get_last_error()
            raise OSError(error, ctypes.FormatError(error))
        try:
            return _windows_acl_semantics_are_owner_only(
                protected=bool(control.value & se_dacl_protected),
                ace_count=size_information.ace_count,
                ace_type=ace.header.ace_type,
                ace_flags=ace.header.ace_flags,
                access_mask=ace.mask,
                sid_matches=bool(advapi32.EqualSid(ace_sid, expected_sid)),
            )
        finally:
            kernel32.LocalFree(expected_sid)
    finally:
        kernel32.LocalFree(security_descriptor)


def _restrict_file(path: Path) -> None:
    """Apply and verify owner-only permissions on the current platform."""
    if os.name != "nt":
        os.chmod(path, 0o600)
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise OSError(errno.EACCES, "owner-only mode could not be verified")
        return

    from ctypes import wintypes

    se_file_object = 1
    dacl_security_information = 0x00000004
    protected_dacl_security_information = 0x80000000
    sid = _windows_current_sid()
    expected_sddl = f"D:P(A;;FA;;;{sid})"
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    void_pointer_pointer = ctypes.POINTER(ctypes.c_void_p)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        void_pointer_pointer,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        void_pointer_pointer,
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    security_descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        expected_sddl,
        1,
        ctypes.byref(security_descriptor),
        None,
    ):
        error = ctypes.get_last_error()
        raise OSError(error, ctypes.FormatError(error))
    try:
        dacl_present = wintypes.BOOL()
        dacl_defaulted = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(
            security_descriptor,
            ctypes.byref(dacl_present),
            ctypes.byref(dacl),
            ctypes.byref(dacl_defaulted),
        ) or not dacl_present:
            error = ctypes.get_last_error() or errno.EACCES
            raise OSError(error, "owner-only DACL could not be constructed")
        status = advapi32.SetNamedSecurityInfoW(
            str(path),
            se_file_object,
            dacl_security_information | protected_dacl_security_information,
            None,
            None,
            dacl,
            None,
        )
        if status:
            raise OSError(status, ctypes.FormatError(status))
    finally:
        kernel32.LocalFree(security_descriptor)
    if not _windows_acl_is_owner_only(path):
        raise OSError(errno.EACCES, "owner-only DACL could not be verified")


def _write_exclusive_backup(
    path: Path,
    content: bytes,
) -> tuple[int, int]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = None
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _restrict_file(path)
        backup_stat = path.lstat()
        if not stat.S_ISREG(backup_stat.st_mode):
            raise OSError(errno.EINVAL, "backup is not a regular file")
        return _file_identity(backup_stat)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise


def _write_restricted_temp(path: Path, content: bytes) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _restrict_file(temporary_path)
        return temporary_path
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary_path.unlink()
        except OSError:
            pass
        raise


def _exchange_paths(left: Path, right: Path) -> None:
    """Atomically exchange two directory entries without losing either one."""
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise OSError(errno.ENOTSUP, "atomic exchange is unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100,
            os.fsencode(left),
            -100,
            os.fsencode(right),
            0x2,
        )
    elif sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        renamex_np = getattr(libc, "renamex_np", None)
        if renamex_np is None:
            raise OSError(errno.ENOTSUP, "atomic exchange is unavailable")
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        result = renamex_np(os.fsencode(left), os.fsencode(right), 0x2)
    else:
        raise OSError(errno.ENOTSUP, "atomic exchange is unavailable")
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _windows_replace_file(
    source: Path,
    replacement: Path,
    backup: Path | None,
) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    replace_file = kernel32.ReplaceFileW
    replace_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    replace_file.restype = ctypes.c_int
    if not replace_file(
        str(source),
        str(replacement),
        str(backup) if backup is not None else None,
        0,
        None,
        None,
    ):
        error = ctypes.get_last_error()
        raise OSError(error, ctypes.FormatError(error))


def _restore_displaced_source(displaced: Path, source: Path) -> None:
    os.rename(displaced, source)


def _atomic_swap_source(source: Path, replacement: Path) -> Path:
    """Install replacement atomically and return the displaced source path."""
    if os.name != "nt":
        _exchange_paths(source, replacement)
        return replacement

    descriptor, displaced_name = tempfile.mkstemp(
        prefix=f".{source.name}.plaintext.",
        suffix=".recovery",
        dir=source.parent,
    )
    os.close(descriptor)
    displaced_path = Path(displaced_name)
    displaced_path.unlink()
    try:
        _windows_replace_file(source, replacement, displaced_path)
    except Exception as original_error:
        # ReplaceFileW normally leaves all names unchanged on failure, but its
        # documented partial state can move the original to the backup name.
        if displaced_path.exists():
            try:
                _restore_displaced_source(displaced_path, source)
            except OSError:
                raise ConversionError(
                    "recovery-required",
                    "Atomic replacement failed; the original remains recoverable.",
                ) from None
        raise original_error
    return displaced_path

def _rollback_source_swap(
    source: Path,
    displaced: Path,
    expected_content: bytes,
    expected_identity: tuple[int, int],
) -> None:
    if os.name == "nt":
        captured_path = _unused_recovery_path(source, "rollback-current")
        try:
            _windows_replace_file(source, displaced, captured_path)
        except Exception:
            raise ConversionError(
                "recovery-required",
                "Source rollback failed; recoverable files remain.",
            ) from None
    else:
        _exchange_paths(source, displaced)
        captured_path = displaced

    try:
        captured_content, captured_identity = _read_regular_file(captured_path)
    except ConversionError:
        captured_content = None
        captured_identity = None
    if captured_content != expected_content or captured_identity != expected_identity:
        try:
            if os.name == "nt":
                _windows_replace_file(source, captured_path, displaced)
            else:
                _exchange_paths(source, captured_path)
        except Exception:
            raise ConversionError(
                "recovery-required",
                "Source rollback failed; recoverable files remain.",
            ) from None
        raise ConversionError(
            "recovery-required",
            "The source changed before rollback; recoverable files remain.",
        )

    try:
        captured_path.unlink()
    except OSError:
        raise ConversionError(
            "recovery-required",
            "Source rollback left a recoverable encrypted file.",
        ) from None

def _unused_recovery_path(anchor: Path, purpose: str) -> Path:
    descriptor, recovery_name = tempfile.mkstemp(
        prefix=f".{anchor.name}.{purpose}.",
        suffix=".recovery",
        dir=anchor.parent,
    )
    os.close(descriptor)
    recovery_path = Path(recovery_name)
    recovery_path.unlink()
    return recovery_path


def _atomic_finalize_backup(displaced: Path, backup: Path) -> Path:
    """Install the displaced source and return the prior backup reservation."""
    if os.name != "nt":
        _exchange_paths(displaced, backup)
        return displaced

    reservation_path = _unused_recovery_path(backup, "reservation")
    try:
        _windows_replace_file(backup, displaced, reservation_path)
    except Exception:
        if reservation_path.exists():
            raise ConversionError(
                "recovery-required",
                "Backup finalization failed; recoverable files remain.",
            ) from None
        raise
    return reservation_path


def _rollback_backup_finalize(backup: Path, reservation: Path) -> Path:
    """Restore the prior reservation and return the displaced original source."""
    if os.name != "nt":
        _exchange_paths(backup, reservation)
        return reservation

    displaced_path = _unused_recovery_path(backup, "rollback")
    try:
        _windows_replace_file(backup, reservation, displaced_path)
    except Exception:
        raise ConversionError(
            "recovery-required",
            "Backup rollback failed; recoverable files remain.",
        ) from None
    return displaced_path

def _sync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        try:
            os.fsync(descriptor)
        except OSError:
            pass
    finally:
        os.close(descriptor)


def _snapshot_matches(
    document: SourceDocument,
    content: bytes,
    identity: tuple[int, int],
) -> bool:
    return content == document.original_bytes and identity == document.source_identity


def _atomic_replace_source(
    document: SourceDocument,
    content: bytes,
    backup_identity: tuple[int, int],
) -> None:
    temporary_path = _write_restricted_temp(document.path, content)
    displaced_path: Path | None = None
    reservation_path: Path | None = None
    source_swapped = False
    backup_finalized = False
    reservation_verified = False
    try:
        current_bytes, current_identity = _read_regular_file(document.path)
        if not _snapshot_matches(document, current_bytes, current_identity):
            raise ConversionError(
                "source-changed",
                "The selected environment file changed during conversion.",
            )

        # Tighten the source before the native swap so both the installed file and
        # the atomically displaced plaintext inherit owner-only protection.
        _restrict_file(document.path)
        current_bytes, current_identity = _read_regular_file(document.path)
        if not _snapshot_matches(document, current_bytes, current_identity):
            raise ConversionError(
                "source-changed",
                "The selected environment file changed during conversion.",
            )

        displaced_path = _atomic_swap_source(document.path, temporary_path)
        source_swapped = True
        installed_bytes, installed_identity = _read_regular_file(document.path)
        if installed_bytes != content:
            raise ConversionError(
                "atomic-replace-failed",
                "The encrypted environment file failed commit verification.",
            )
        displaced_bytes, displaced_identity = _read_regular_file(displaced_path)
        if not _snapshot_matches(document, displaced_bytes, displaced_identity):
            raise ConversionError(
                "source-changed",
                "The selected environment file changed at the atomic commit boundary.",
            )

        try:
            current_backup, current_backup_identity = _read_regular_file(
                document.backup_path
            )
        except ConversionError:
            raise ConversionError(
                "backup-changed",
                "The reserved backup changed during conversion.",
            ) from None
        if (
            current_backup_identity != backup_identity
            or current_backup != document.original_bytes
        ):
            raise ConversionError(
                "backup-changed",
                "The reserved backup changed during conversion.",
            )

        _restrict_file(document.path)
        _restrict_file(displaced_path)
        reservation_path = _atomic_finalize_backup(
            displaced_path,
            document.backup_path,
        )
        displaced_path = None
        backup_finalized = True

        try:
            reserved_bytes, reserved_identity = _read_regular_file(reservation_path)
        except ConversionError:
            raise ConversionError(
                "backup-changed",
                "The backup changed at the atomic commit boundary.",
            ) from None
        if (
            reserved_identity != backup_identity
            or reserved_bytes != document.original_bytes
        ):
            raise ConversionError(
                "backup-changed",
                "The backup changed at the atomic commit boundary.",
            )
        reservation_verified = True

        try:
            committed_backup, _committed_backup_identity = _read_regular_file(
                document.backup_path
            )
        except ConversionError:
            raise ConversionError(
                "backup-changed",
                "The backup changed at the atomic commit boundary.",
            ) from None
        if committed_backup != document.original_bytes:
            raise ConversionError(
                "backup-changed",
                "The backup changed at the atomic commit boundary.",
            )

        _restrict_file(document.backup_path)
        reservation_path.unlink()
        reservation_path = None
        backup_finalized = False
        source_swapped = False
        _sync_directory(document.path.parent)
    except Exception as original_error:
        if backup_finalized and reservation_path is not None:
            if reservation_verified:
                # The captured reservation is a verified original copy. Use it
                # to restore the source without touching a backup name that may
                # have been changed after finalization.
                displaced_path = reservation_path
                reservation_path = None
                backup_finalized = False
            else:
                try:
                    displaced_path = _rollback_backup_finalize(
                        document.backup_path,
                        reservation_path,
                    )
                    reservation_path = None
                    backup_finalized = False
                except Exception:
                    raise ConversionError(
                        "recovery-required",
                        "Atomic conversion could not be rolled back; recoverable files remain.",
                    ) from None
        if source_swapped and displaced_path is not None:
            try:
                _rollback_source_swap(
                    document.path,
                    displaced_path,
                    content,
                    installed_identity,
                )
                source_swapped = False
                displaced_path = None
            except Exception:
                raise ConversionError(
                    "recovery-required",
                    "Atomic conversion could not be rolled back; recoverable files remain.",
                ) from None
        raise original_error
    finally:
        if not source_swapped and temporary_path.exists():
            try:
                temporary_path.unlink()
            except OSError:
                pass

def convert_prepared_document(
    document: SourceDocument,
    password: str,
) -> ConversionResult:
    """Verify, back up, and atomically replace a previously validated source."""
    transformed = _build_transformed_text(document, password).encode("utf-8")
    current_bytes, current_identity = _read_regular_file(document.path)
    if not _snapshot_matches(document, current_bytes, current_identity):
        raise ConversionError(
            "source-changed",
            "The selected environment file changed during conversion.",
        )
    if os.path.lexists(document.backup_path):
        raise ConversionError(
            "backup-exists",
            "The non-clobbering backup path already exists.",
        )

    try:
        backup_identity = _write_exclusive_backup(
            document.backup_path,
            document.original_bytes,
        )
    except FileExistsError:
        raise ConversionError(
            "backup-exists",
            "The non-clobbering backup path already exists.",
        ) from None
    except OSError:
        raise ConversionError(
            "backup-write-failed",
            "The restricted backup could not be written.",
        ) from None

    try:
        _atomic_replace_source(document, transformed, backup_identity)
    except ConversionError:
        raise
    except OSError:
        raise ConversionError(
            "atomic-replace-failed",
            "The encrypted environment file could not be installed atomically.",
        ) from None

    return ConversionResult(
        source_path=document.path,
        backup_path=document.backup_path,
    )

def convert_env_file(
    source_path: os.PathLike | str,
    password: str,
) -> ConversionResult:
    """Convert one source path without consulting process environment values."""
    document = prepare_source_document(source_path)
    return convert_prepared_document(document, password)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypt credentials in one dotenv file without rebuilding it.",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="source dotenv file to transform in place (default: .env)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    try:
        document = prepare_source_document(args.env_file)
    except ConversionError as exc:
        print(f"Conversion failed [{exc.code}]: {exc.safe_message}", file=sys.stderr)
        return 1

    password = get_master_password()
    try:
        result = convert_prepared_document(document, password)
    except ConversionError as exc:
        print(f"Conversion failed [{exc.code}]: {exc.safe_message}", file=sys.stderr)
        return 1

    print("Credential conversion complete.")
    print(f"Encrypted source: {result.source_path}")
    print(f"Restricted backup: {result.backup_path}")
    print("Verify the application unlocks, then securely remove the plaintext backup.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nConversion cancelled.", file=sys.stderr)
        raise SystemExit(1) from None
