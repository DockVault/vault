"""Lossless and atomic plaintext-to-encrypted dotenv conversion."""

import importlib.util
import os
from pathlib import Path
import stat
import sys

from cryptography.fernet import Fernet
from dotenv import dotenv_values
import pytest

from app.core.startup_security import CredentialManager


pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parent.parent
GOOD_PASSWORD = "Correct-Horse-Batt9!!"
FERNET_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
FILE_SECRETS = {
    "ENCRYPTION_KEY": FERNET_KEY,
    "DATABASE_URL": "postgresql://file-user:file-pass@db:5432/vault",
    "REDIS_PASSWORD": "redis-file-secret",
    "JWT_SECRET_KEY": "file-jwt-secret-" + ("j" * 48),
    "ADMIN_PASSWORD": "Admin-File-Secret-27",
}


@pytest.fixture(scope="module")
def setup_module():
    path = ROOT / "scripts" / "setup_master_password.py"
    spec = importlib.util.spec_from_file_location(
        "_master_password_conversion",
        path,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _source_text(newline="\n", final_newline=True):
    lines = [
        "# operator comment",
        'FUTURE_FLAG="keep me exactly"',
        f"ENCRYPTION_KEY = '{FILE_SECRETS['ENCRYPTION_KEY']}' # key comment",
        f'DATABASE_URL="{FILE_SECRETS["DATABASE_URL"]}"',
        f"REDIS_PASSWORD={FILE_SECRETS['REDIS_PASSWORD']} # redis comment",
        f"JWT_SECRET_KEY='{FILE_SECRETS['JWT_SECRET_KEY']}'",
        f'ADMIN_PASSWORD = "{FILE_SECRETS["ADMIN_PASSWORD"]}"',
        "RATE_LIMIT_API_DEFAULT=77",
        "# trailing comment",
    ]
    text = newline.join(lines)
    return text + (newline if final_newline else "")


def _write_source(path, text):
    path.write_bytes(text.encode("utf-8"))
    return path.read_bytes()


def _decrypted_values(setup, path):
    values = dotenv_values(path, interpolate=False)
    wrapping_key = setup.derive_key_from_password(
        GOOD_PASSWORD,
        values["MASTER_KEY_SALT"],
    )
    fernet = Fernet(wrapping_key)
    return {
        key: fernet.decrypt(values[f"ENCRYPTED_{key}"].encode()).decode()
        for key in FILE_SECRETS
    }


def test_windows_owner_only_acl_semantics_reject_permission_drift(setup_module):
    expected = {
        "protected": True,
        "ace_count": 1,
        "ace_type": 0,
        "ace_flags": 0,
        "access_mask": 0x001F01FF,
        "sid_matches": True,
    }
    assert setup_module._windows_acl_semantics_are_owner_only(**expected)

    for field, invalid_value in (
        ("protected", False),
        ("ace_count", 0),
        ("ace_count", 2),
        ("ace_type", 1),
        ("ace_flags", 0x10),
        ("access_mask", 0x00120089),
        ("sid_matches", False),
    ):
        candidate = {**expected, field: invalid_value}
        assert not setup_module._windows_acl_semantics_are_owner_only(**candidate)


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL")
def test_windows_owner_only_acl_verification_is_sddl_independent(
    setup_module,
    tmp_path,
    monkeypatch,
):
    restricted = tmp_path / "restricted.tmp"
    restricted.write_bytes(b"")
    setup_module._restrict_file(restricted)
    monkeypatch.setattr(
        setup_module.re,
        "fullmatch",
        lambda *_args: pytest.fail("semantic ACL verification used SDDL text"),
    )

    assert setup_module._windows_acl_is_owner_only(restricted)


def test_selected_source_is_transformed_without_ambient_or_unknown_key_loss(
    setup_module,
    tmp_path,
    monkeypatch,
):
    decoy = tmp_path / ".env"
    decoy_bytes = _write_source(decoy, "DECOY=unchanged\n")
    selected = tmp_path / "selected.env"
    original = _write_source(selected, _source_text())
    monkeypatch.chdir(tmp_path)
    for key in FILE_SECRETS:
        monkeypatch.setenv(key, f"ambient-conflict-{key}")
    monkeypatch.setenv("FUTURE_FLAG", "ambient-future-conflict")

    result = setup_module.convert_env_file(selected, GOOD_PASSWORD)

    assert result.source_path == selected.resolve()
    assert result.backup_path == selected.with_name("selected.env.backup")
    assert decoy.read_bytes() == decoy_bytes
    assert result.backup_path.read_bytes() == original
    assert not (tmp_path / ".env.secure").exists()

    output = selected.read_text(encoding="utf-8")
    assert '# operator comment\nFUTURE_FLAG="keep me exactly"\n' in output
    assert "RATE_LIMIT_API_DEFAULT=77\n# trailing comment\n" in output
    assert "ENCRYPTED_ENCRYPTION_KEY = '" in output
    assert "' # key comment" in output
    assert 'ENCRYPTED_DATABASE_URL="' in output
    assert "ENCRYPTED_REDIS_PASSWORD=" in output
    assert " # redis comment" in output
    assert "ENCRYPTED_JWT_SECRET_KEY='" in output
    assert 'ENCRYPTED_ADMIN_PASSWORD = "' in output
    for key, value in FILE_SECRETS.items():
        assert f"\n{key}=" not in output
        assert value not in output
    assert _decrypted_values(setup_module, selected) == FILE_SECRETS

    converted = dotenv_values(selected, interpolate=False)
    for key in FILE_SECRETS:
        monkeypatch.delenv(key, raising=False)
    for key in setup_module.GENERATED_KEYS:
        monkeypatch.setenv(key, converted[key])
    manager = CredentialManager()
    manager.unlock_or_raise(master_password=GOOD_PASSWORD, interactive=False)
    assert manager.credentials == FILE_SECRETS


@pytest.mark.parametrize(
    ("newline", "final_newline"),
    [("\r\n", True), ("\n", False)],
)
def test_newline_style_and_final_newline_are_preserved(
    setup_module,
    tmp_path,
    newline,
    final_newline,
):
    source = tmp_path / "style.env"
    original_text = _source_text(newline, final_newline)
    _write_source(source, original_text)

    setup_module.convert_env_file(source, GOOD_PASSWORD)

    output = source.read_bytes()
    if newline == "\r\n":
        assert b"\n" not in output.replace(b"\r\n", b"")
    assert output.endswith(newline.encode()) is final_newline
    assert _decrypted_values(setup_module, source) == FILE_SECRETS


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (
            lambda text: text.replace(
                f'ADMIN_PASSWORD = "{FILE_SECRETS["ADMIN_PASSWORD"]}"\n',
                "",
            ),
            "required-secret-missing",
        ),
        (
            lambda text: text.replace(
                f"REDIS_PASSWORD={FILE_SECRETS['REDIS_PASSWORD']} # redis comment",
                "REDIS_PASSWORD= # redis comment",
            ),
            "required-secret-missing",
        ),
        (
            lambda text: text.replace(
                f'DATABASE_URL="{FILE_SECRETS["DATABASE_URL"]}"',
                "DATABASE_URL='   '",
            ),
            "required-secret-missing",
        ),
        (
            lambda text: text.replace(
                f"JWT_SECRET_KEY='{FILE_SECRETS['JWT_SECRET_KEY']}'",
                "JWT_SECRET_KEY=   ",
            ),
            "required-secret-missing",
        ),
        (
            lambda text: text
            + f"DATABASE_URL={FILE_SECRETS['DATABASE_URL']}\n",
            "required-secret-duplicate",
        ),
        (
            lambda text: text.replace(
                f"REDIS_PASSWORD={FILE_SECRETS['REDIS_PASSWORD']} # redis comment",
                "REDIS_PASSWORD=${AMBIENT_REDIS_PASSWORD}",
            ),
            "required-secret-ambiguous",
        ),
    ],
)
def test_invalid_required_secrets_fail_before_mutation(
    setup_module,
    tmp_path,
    mutate,
    expected_code,
):
    source = tmp_path / "invalid.env"
    original = _write_source(source, mutate(_source_text()))

    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    assert exc_info.value.code == expected_code
    assert source.read_bytes() == original
    assert not source.with_name("invalid.env.backup").exists()
    for secret in FILE_SECRETS.values():
        assert secret not in str(exc_info.value)


@pytest.mark.parametrize(
    "metadata_line",
    [
        "MASTER_PASSWORD_HASH=already-present",
        "MASTER_KEY_SALT=already-present",
        "ENCRYPTED_DATABASE_URL=already-present",
    ],
)
def test_existing_encrypted_metadata_fails_before_mutation(
    setup_module,
    tmp_path,
    metadata_line,
):
    source = tmp_path / "metadata.env"
    original = _write_source(source, metadata_line + "\n" + _source_text())

    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    assert exc_info.value.code == "credential-state-ambiguous"
    assert source.read_bytes() == original
    assert not source.with_name("metadata.env.backup").exists()


def test_symlink_and_non_regular_sources_are_rejected(setup_module, tmp_path):
    directory = tmp_path / "directory.env"
    directory.mkdir()
    with pytest.raises(setup_module.ConversionError) as directory_error:
        setup_module.prepare_source_document(directory)
    assert directory_error.value.code == "source-unsafe"

    target = tmp_path / "target.env"
    _write_source(target, _source_text())
    link = tmp_path / "link.env"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    with pytest.raises(setup_module.ConversionError) as symlink_error:
        setup_module.prepare_source_document(link)
    assert symlink_error.value.code == "source-unsafe"
    assert not link.with_name("link.env.backup").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO")
def test_fifo_source_is_rejected_without_opening_it(setup_module, tmp_path):
    source = tmp_path / "fifo.env"
    os.mkfifo(source)

    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.prepare_source_document(source)

    assert exc_info.value.code == "source-unsafe"


def test_encryption_roundtrip_failure_precedes_mutation(
    setup_module,
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "roundtrip.env"
    original = _write_source(source, _source_text())
    monkeypatch.setattr(
        setup_module,
        "encrypt_value",
        lambda _value, _fernet: "not-a-valid-fernet-token",
    )

    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    assert exc_info.value.code == "credential-roundtrip-failed"
    assert source.read_bytes() == original
    assert not source.with_name("roundtrip.env.backup").exists()


def test_existing_backup_is_never_clobbered(setup_module, tmp_path):
    source = tmp_path / "existing.env"
    original = _write_source(source, _source_text())
    backup = source.with_name("existing.env.backup")
    backup.write_bytes(b"operator-backup")

    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    assert exc_info.value.code == "backup-exists"
    assert source.read_bytes() == original
    assert backup.read_bytes() == b"operator-backup"


def test_source_change_between_validation_and_write_fails_closed(
    setup_module,
    tmp_path,
):
    source = tmp_path / "changed.env"
    _write_source(source, _source_text())
    document = setup_module.prepare_source_document(source)
    source.write_text("CHANGED=1\n", encoding="utf-8")

    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_prepared_document(document, GOOD_PASSWORD)

    assert exc_info.value.code == "source-changed"
    assert source.read_text(encoding="utf-8") == "CHANGED=1\n"
    assert not document.backup_path.exists()


def test_change_during_backup_is_preserved_and_not_overwritten(
    setup_module,
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "backup-race.env"
    original = _write_source(source, _source_text())
    real_write_backup = setup_module._write_exclusive_backup

    def backup_then_edit(path, content):
        identity = real_write_backup(path, content)
        source.write_text("CONCURRENT_BACKUP_EDIT=1\n", encoding="utf-8")
        return identity

    monkeypatch.setattr(setup_module, "_write_exclusive_backup", backup_then_edit)
    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    assert exc_info.value.code == "source-changed"
    assert source.read_text(encoding="utf-8") == "CONCURRENT_BACKUP_EDIT=1\n"
    assert source.with_name("backup-race.env.backup").read_bytes() == original


def test_change_at_atomic_commit_boundary_is_rolled_back(
    setup_module,
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "commit-race.env"
    original = _write_source(source, _source_text())
    real_swap = setup_module._atomic_swap_source

    def edit_then_swap(path, replacement):
        path.write_text("CONCURRENT_COMMIT_EDIT=1\n", encoding="utf-8")
        return real_swap(path, replacement)

    monkeypatch.setattr(setup_module, "_atomic_swap_source", edit_then_swap)
    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    assert exc_info.value.code == "source-changed"
    assert source.read_text(encoding="utf-8") == "CONCURRENT_COMMIT_EDIT=1\n"
    assert source.with_name("commit-race.env.backup").read_bytes() == original
    assert not list(tmp_path.glob(".commit-race.env.*.tmp"))
    assert not list(tmp_path.glob(".commit-race.env.*.recovery"))


def test_reserved_backup_tampering_is_not_clobbered_and_rolls_back(
    setup_module,
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "backup-tamper.env"
    original = _write_source(source, _source_text())
    backup = source.with_name("backup-tamper.env.backup")
    real_swap = setup_module._atomic_swap_source

    def swap_then_tamper(path, replacement):
        displaced = real_swap(path, replacement)
        backup.unlink()
        backup.write_bytes(b"operator-replacement-backup")
        return displaced

    monkeypatch.setattr(setup_module, "_atomic_swap_source", swap_then_tamper)
    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    assert exc_info.value.code == "backup-changed"
    assert source.read_bytes() == original
    assert backup.read_bytes() == b"operator-replacement-backup"
    assert not list(tmp_path.glob(".backup-tamper.env.*.tmp"))
    assert not list(tmp_path.glob(".backup-tamper.env.*.recovery"))


def test_backup_replacement_at_finalize_boundary_is_captured_and_rolled_back(
    setup_module,
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "backup-finalize-race.env"
    original = _write_source(source, _source_text())
    backup = source.with_name("backup-finalize-race.env.backup")
    real_finalize = setup_module._atomic_finalize_backup

    def replace_then_finalize(displaced, backup_path):
        backup_path.unlink()
        backup_path.write_bytes(b"operator-late-backup")
        return real_finalize(displaced, backup_path)

    monkeypatch.setattr(
        setup_module,
        "_atomic_finalize_backup",
        replace_then_finalize,
    )
    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    assert exc_info.value.code == "backup-changed"
    assert source.read_bytes() == original
    assert backup.read_bytes() == b"operator-late-backup"
    assert not list(tmp_path.glob(".backup-finalize-race.env.*.tmp"))
    assert not list(tmp_path.glob(".backup-finalize-race.env.*.recovery"))

def test_backup_replacement_after_finalize_is_preserved_during_source_rollback(
    setup_module,
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "backup-post-finalize-race.env"
    original = _write_source(source, _source_text())
    backup = source.with_name("backup-post-finalize-race.env.backup")
    real_finalize = setup_module._atomic_finalize_backup

    def finalize_then_replace(displaced, backup_path):
        reservation = real_finalize(displaced, backup_path)
        backup_path.unlink()
        backup_path.write_bytes(b"operator-post-finalize-backup")
        return reservation

    monkeypatch.setattr(
        setup_module,
        "_atomic_finalize_backup",
        finalize_then_replace,
    )
    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    assert exc_info.value.code == "backup-changed"
    assert source.read_bytes() == original
    assert backup.read_bytes() == b"operator-post-finalize-backup"
    assert not list(tmp_path.glob(".backup-post-finalize-race.env.*.tmp"))
    assert not list(tmp_path.glob(".backup-post-finalize-race.env.*.recovery"))


def test_source_replacement_before_rollback_is_preserved_with_original_recovery(
    setup_module,
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "source-rollback-race.env"
    original = _write_source(source, _source_text())
    backup = source.with_name("source-rollback-race.env.backup")
    real_swap = setup_module._atomic_swap_source
    real_rollback = setup_module._rollback_source_swap

    def swap_then_tamper_backup(path, replacement):
        displaced = real_swap(path, replacement)
        backup.unlink()
        backup.write_bytes(b"operator-backup")
        return displaced

    def replace_then_rollback(
        source_path,
        displaced,
        expected_content,
        expected_identity,
    ):
        operator_entry = tmp_path / "operator-source"
        operator_entry.write_bytes(b"operator-source")
        os.replace(operator_entry, source_path)
        return real_rollback(
            source_path,
            displaced,
            expected_content,
            expected_identity,
        )

    monkeypatch.setattr(setup_module, "_atomic_swap_source", swap_then_tamper_backup)
    monkeypatch.setattr(setup_module, "_rollback_source_swap", replace_then_rollback)
    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    recovery_entries = [
        path
        for path in tmp_path.glob(".source-rollback-race.env.*")
        if path.is_file()
    ]
    assert exc_info.value.code == "recovery-required"
    assert source.read_bytes() == b"operator-source"
    assert backup.read_bytes() == b"operator-backup"
    assert any(path.read_bytes() == original for path in recovery_entries)

def test_backup_write_failure_does_not_touch_source(
    setup_module,
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "backup-failure.env"
    original = _write_source(source, _source_text())

    def fail_backup(*_args, **_kwargs):
        raise OSError("secret-bearing low-level detail")

    monkeypatch.setattr(setup_module, "_write_exclusive_backup", fail_backup)
    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    assert exc_info.value.code == "backup-write-failed"
    assert "secret-bearing" not in str(exc_info.value)
    assert source.read_bytes() == original
    assert not source.with_name("backup-failure.env.backup").exists()


def test_atomic_replace_failure_leaves_source_and_backup_recoverable(
    setup_module,
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "replace-failure.env"
    original = _write_source(source, _source_text())

    def fail_replace(*_args, **_kwargs):
        raise OSError("secret-bearing replace detail")

    monkeypatch.setattr(setup_module, "_atomic_swap_source", fail_replace)
    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    backup = source.with_name("replace-failure.env.backup")
    assert exc_info.value.code == "atomic-replace-failed"
    assert "secret-bearing" not in str(exc_info.value)
    assert source.read_bytes() == original
    assert backup.read_bytes() == original
    assert not list(tmp_path.glob(".replace-failure.env.*.tmp"))


def test_backup_finalize_failure_rolls_source_back(
    setup_module,
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "finalize-failure.env"
    original = _write_source(source, _source_text())

    def fail_finalize(*_args, **_kwargs):
        raise OSError("secret-bearing finalize detail")

    monkeypatch.setattr(setup_module, "_atomic_finalize_backup", fail_finalize)
    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    backup = source.with_name("finalize-failure.env.backup")
    assert exc_info.value.code == "atomic-replace-failed"
    assert "secret-bearing" not in str(exc_info.value)
    assert source.read_bytes() == original
    assert backup.read_bytes() == original
    assert not list(tmp_path.glob(".finalize-failure.env.*.tmp"))
    assert not list(tmp_path.glob(".finalize-failure.env.*.recovery"))


@pytest.mark.skipif(os.name != "nt", reason="Windows ReplaceFileW partial state")
def test_windows_partial_replace_restore_failure_preserves_recovery(
    setup_module,
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "partial-replace.env"
    original = _write_source(source, _source_text())

    def partial_replace(source_path, _replacement, recovery_path):
        assert recovery_path is not None
        os.replace(source_path, recovery_path)
        raise OSError(1177, "secret-bearing partial replacement detail")

    def fail_restore(_displaced, _source):
        raise OSError("secret-bearing restore detail")

    monkeypatch.setattr(setup_module, "_windows_replace_file", partial_replace)
    monkeypatch.setattr(setup_module, "_restore_displaced_source", fail_restore)
    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    backup = source.with_name("partial-replace.env.backup")
    recovery_paths = list(tmp_path.glob(".partial-replace.env.*.recovery"))
    assert exc_info.value.code == "recovery-required"
    assert "secret-bearing" not in str(exc_info.value)
    assert not source.exists()
    assert backup.read_bytes() == original
    assert len(recovery_paths) == 1
    assert recovery_paths[0].read_bytes() == original
    assert not list(tmp_path.glob(".partial-replace.env.*.tmp"))

@pytest.mark.skipif(os.name != "nt", reason="Windows non-clobbering restore")
def test_windows_partial_replace_does_not_clobber_recreated_source(
    setup_module,
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "partial-recreated.env"
    original = _write_source(source, _source_text())

    def partial_replace(source_path, _replacement, recovery_path):
        assert recovery_path is not None
        os.replace(source_path, recovery_path)
        source_path.write_bytes(b"operator-recreated-source")
        raise OSError(1177, "secret-bearing partial replacement detail")

    monkeypatch.setattr(setup_module, "_windows_replace_file", partial_replace)
    with pytest.raises(setup_module.ConversionError) as exc_info:
        setup_module.convert_env_file(source, GOOD_PASSWORD)

    backup = source.with_name("partial-recreated.env.backup")
    recovery_paths = list(tmp_path.glob(".partial-recreated.env.*.recovery"))
    assert exc_info.value.code == "recovery-required"
    assert "secret-bearing" not in str(exc_info.value)
    assert source.read_bytes() == b"operator-recreated-source"
    assert backup.read_bytes() == original
    assert len(recovery_paths) == 1
    assert recovery_paths[0].read_bytes() == original
    assert not list(tmp_path.glob(".partial-recreated.env.*.tmp"))

@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_source_and_backup_are_owner_only(setup_module, tmp_path):
    source = tmp_path / "permissions.env"
    _write_source(source, _source_text())

    result = setup_module.convert_env_file(source, GOOD_PASSWORD)

    assert stat.S_IMODE(source.stat().st_mode) == 0o600
    assert stat.S_IMODE(result.backup_path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL")
def test_source_and_backup_have_verified_owner_only_dacls(setup_module, tmp_path):
    source = tmp_path / "windows-permissions.env"
    _write_source(source, _source_text())

    result = setup_module.convert_env_file(source, GOOD_PASSWORD)

    for path in (source, result.backup_path):
        assert setup_module._windows_acl_is_owner_only(path)
