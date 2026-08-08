"""Executable compatibility boundary for DockVault's published crypto formats.

The fixture bytes are immutable public test data.  Independent Python codecs
reproduce them; the current Python implementation and the real shipped browser
library must continue to read them, and current writers must emit the same bytes
when their randomness is deterministically supplied by the test.
"""

from __future__ import annotations

import io
import json
import shutil
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap
from cryptography.fernet import Fernet, InvalidToken

import crypto_reference_vectors as reference


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "crypto" / "v0.10.0"
NODE_HARNESS = Path(__file__).parent / "js" / "crypto_compatibility_vectors.js"
VECTOR_FILENAMES = (
    "standard-0x10.json",
    "standard-fernet-chunk-stream.json",
    "zk-content-unversioned.json",
    "zk-direct-dek-wrap-legacy.json",
    "zk-name-zk1.json",
    "zk-name-zk2.json",
    "zk-private-envelope-legacy.json",
    "zk-team-private-wrap-v1.json",
)

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]


def vector(name: str) -> dict:
    return reference.load_vector(FIXTURE_DIR / name)


def mutate_last(value: bytes) -> bytes:
    changed = bytearray(value)
    changed[-1] ^= 1
    return bytes(changed)


def framed_records(
    encoded: bytes, *, header_size: int = 0
) -> tuple[bytes, list[bytes]]:
    header = encoded[:header_size]
    offset = header_size
    records: list[bytes] = []
    while offset < len(encoded):
        if len(encoded) - offset < 4:
            raise ValueError("partial length header")
        size = struct.unpack(">I", encoded[offset : offset + 4])[0]
        end = offset + 4 + size
        if end > len(encoded):
            raise ValueError("partial framed record")
        records.append(encoded[offset:end])
        offset = end
    return header, records


def test_manifest_pins_the_exact_reviewed_fixture_set() -> None:
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert manifest == {
        "schema": "dockvault-crypto-manifest-v1",
        "test_only": True,
        "notice": reference.NOTICE,
        "release": reference.RELEASE,
        "commit": reference.COMMIT,
        "vectors": manifest["vectors"],
    }
    listed = [entry["path"] for entry in manifest["vectors"]]
    assert listed == list(VECTOR_FILENAMES)
    assert {path.name for path in FIXTURE_DIR.glob("*.json")} == {
        "manifest.json",
        *VECTOR_FILENAMES,
    }
    for entry in manifest["vectors"]:
        assert set(entry) == {"path", "sha256"}
        assert reference.sha256_file(FIXTURE_DIR / entry["path"]) == entry["sha256"]


@pytest.mark.parametrize("name", VECTOR_FILENAMES)
def test_every_vector_is_pinned_public_test_material(name: str) -> None:
    path = FIXTURE_DIR / name
    value = reference.load_vector(path)
    assert value["test_only"] is True
    assert value["notice"] == reference.NOTICE
    assert value["source_paths"]
    assert "-----" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("name", "encoder", "result_field"),
    (
        ("standard-0x10.json", reference.encode_standard_0x10, None),
        (
            "standard-fernet-chunk-stream.json",
            reference.encode_fernet_chunk_stream,
            None,
        ),
        ("zk-content-unversioned.json", reference.encode_zk_content, None),
        (
            "zk-private-envelope-legacy.json",
            reference.encode_private_envelope,
            "encrypted",
        ),
        (
            "zk-direct-dek-wrap-legacy.json",
            reference.encode_direct_dek_wrap,
            "wrapped_dek_b64",
        ),
        (
            "zk-team-private-wrap-v1.json",
            reference.encode_team_private_wrap,
            "wrapped_key_b64",
        ),
        ("zk-name-zk1.json", reference.encode_zk_name, "token"),
        ("zk-name-zk2.json", reference.encode_zk_name, "token"),
    ),
)
def test_independent_writer_reproduces_exact_vector_bytes(
    name, encoder, result_field
) -> None:
    value = vector(name)
    encoded = encoder(value)
    if result_field is None:
        actual = reference.b64e(encoded)
    else:
        actual = encoded[result_field]
        if result_field == "token":
            actual = actual[4:]
    assert actual == value["encoded_b64"]


def test_independent_readers_recover_all_pinned_plaintexts_and_keys() -> None:
    standard = vector("standard-0x10.json")
    si = standard["inputs"]
    assert reference.decode_standard_0x10(
        reference.b64d(standard["encoded_b64"]),
        encryption_key=si["encryption_key"],
        vault_id=si["vault_id"],
        file_id=si["file_id"],
    ) == reference.b64d(standard["expected"]["plaintext_b64"])

    legacy = vector("standard-fernet-chunk-stream.json")
    assert reference.decode_fernet_chunk_stream(
        reference.b64d(legacy["encoded_b64"]),
        encryption_key=legacy["inputs"]["encryption_key"],
    ) == reference.b64d(legacy["expected"]["plaintext_b64"])

    content = vector("zk-content-unversioned.json")
    assert reference.decode_zk_content(
        reference.b64d(content["encoded_b64"]), dek_hex=content["inputs"]["dek_hex"]
    ) == reference.b64d(content["expected"]["plaintext_b64"])

    private = vector("zk-private-envelope-legacy.json")
    private_plaintext = reference.decode_private_envelope(
        private["expected"]["envelope"], password=private["inputs"]["password"]
    )
    assert private_plaintext == reference.p384_private_pem(
        private["inputs"]["identity_private_scalar_hex"]
    )
    assert not private_plaintext.endswith("\n")

    direct = vector("zk-direct-dek-wrap-legacy.json")
    assert (
        reference.decode_direct_dek_wrap(
            direct["expected"]["wrapped_dek_b64"],
            ephemeral_public_key_b64=direct["expected"]["ephemeral_public_key_b64"],
            recipient_private_scalar_hex=direct["inputs"][
                "recipient_private_scalar_hex"
            ],
        ).hex()
        == direct["inputs"]["dek_hex"]
    )

    team = vector("zk-team-private-wrap-v1.json")
    team_key = reference.decode_team_private_wrap(
        team["expected"]["wrapped_key_b64"],
        ephemeral_public_key_b64=team["expected"]["ephemeral_public_key_b64"],
        member_private_scalar_hex=team["inputs"]["member_private_scalar_hex"],
    )
    assert team_key.private_numbers().private_value == int(
        team["inputs"]["team_private_scalar_hex"], 16
    )

    for name in ("zk-name-zk1.json", "zk-name-zk2.json"):
        sealed = vector(name)
        ni = sealed["inputs"]
        assert (
            reference.decode_zk_name(
                sealed["expected"]["token"],
                dek_hex=ni["dek_hex"],
                vault_id=ni["vault_id"],
                field=ni["field"],
                epoch=ni["epoch"],
                object_id=ni.get("object_id"),
            )
            == ni["plaintext"]
        )


def test_current_python_standard_reader_and_writer_match_pinned_bytes(
    monkeypatch,
) -> None:
    from app.core import security

    value = vector("standard-0x10.json")
    inputs = value["inputs"]
    encoded = reference.b64d(value["encoded_b64"])
    monkeypatch.setattr(
        security,
        "_runtime_settings",
        lambda: SimpleNamespace(encryption_key=inputs["encryption_key"]),
    )
    assert security.decrypt_gcm_chunk_stream(
        io.BytesIO(encoded), inputs["vault_id"], inputs["file_id"]
    ) == reference.b64d(value["expected"]["plaintext_b64"])

    nonces = iter(bytes.fromhex(item) for item in inputs["nonces_hex"])
    monkeypatch.setattr(security.secrets, "token_bytes", lambda size: next(nonces))
    codec = security.GcmChunkStreamCodec(inputs["vault_id"], inputs["file_id"])
    written = codec.header() + b"".join(
        codec.encrypt(reference.b64d(chunk), index)
        for index, chunk in enumerate(inputs["chunks_b64"])
    )
    assert written == encoded


def test_current_python_legacy_fernet_reader_and_writer_match_pinned_bytes(
    monkeypatch,
) -> None:
    import cryptography.fernet as fernet_module
    from app.core import security

    value = vector("standard-fernet-chunk-stream.json")
    inputs = value["inputs"]
    encoded = reference.b64d(value["encoded_b64"])
    fernet = Fernet(inputs["encryption_key"].encode("ascii"))
    monkeypatch.setattr(security, "_fernet", lambda: fernet)
    assert b"".join(
        security.decrypt_chunk_stream(io.BytesIO(encoded))
    ) == reference.b64d(value["expected"]["plaintext_b64"])

    ivs = iter(bytes.fromhex(item) for item in inputs["ivs_hex"])
    timestamps = iter(inputs["timestamps"])
    monkeypatch.setattr(fernet_module.os, "urandom", lambda size: next(ivs))
    monkeypatch.setattr(fernet_module.time, "time", lambda: next(timestamps))
    written = b"".join(
        security.encrypt_chunk(reference.b64d(chunk)) for chunk in inputs["chunks_b64"]
    )
    assert written == encoded


def test_standard_stream_rejects_wrong_context_tamper_and_partial_record() -> None:
    value = vector("standard-0x10.json")
    inputs = value["inputs"]
    encoded = reference.b64d(value["encoded_b64"])
    kwargs = {
        "encryption_key": inputs["encryption_key"],
        "vault_id": inputs["vault_id"],
        "file_id": inputs["file_id"],
    }
    with pytest.raises(InvalidTag):
        reference.decode_standard_0x10(
            encoded,
            **{**kwargs, "vault_id": "33333333-3333-4333-8333-333333333333"},
        )
    with pytest.raises(InvalidTag):
        reference.decode_standard_0x10(
            encoded,
            **{**kwargs, "file_id": "33333333-3333-4333-8333-333333333333"},
        )
    with pytest.raises(InvalidTag):
        reference.decode_standard_0x10(mutate_last(encoded), **kwargs)
    with pytest.raises(ValueError, match="record size"):
        reference.decode_standard_0x10(encoded[:-1], **kwargs)
    with pytest.raises(ValueError, match="record length"):
        reference.decode_standard_0x10(encoded + b"\x00", **kwargs)

    header, records = framed_records(
        encoded, header_size=len(reference.STANDARD_HEADER)
    )
    with pytest.raises(InvalidTag):
        reference.decode_standard_0x10(
            header + records[1] + records[0] + records[2], **kwargs
        )
    with pytest.raises(InvalidTag):
        reference.decode_standard_0x10(
            header + records[0] + records[0] + records[2], **kwargs
        )


def test_current_readers_reject_unknown_standard_version_and_cross_format_confusion(
    monkeypatch, tmp_path
) -> None:
    from app.core import security

    standard = vector("standard-0x10.json")
    legacy = vector("standard-fernet-chunk-stream.json")
    inputs = standard["inputs"]
    standard_bytes = reference.b64d(standard["encoded_b64"])
    legacy_bytes = reference.b64d(legacy["encoded_b64"])
    context = {
        "encryption_key": inputs["encryption_key"],
        "vault_id": inputs["vault_id"],
        "file_id": inputs["file_id"],
    }
    monkeypatch.setattr(
        security,
        "_runtime_settings",
        lambda: SimpleNamespace(encryption_key=inputs["encryption_key"]),
    )
    monkeypatch.setattr(
        security,
        "_fernet",
        lambda: Fernet(legacy["inputs"]["encryption_key"].encode("ascii")),
    )

    unknown_version = bytearray(standard_bytes)
    unknown_version[len(reference.STANDARD_MAGIC)] = reference.STANDARD_VERSION + 1
    with pytest.raises(ValueError, match="header"):
        reference.decode_standard_0x10(bytes(unknown_version), **context)
    with pytest.raises(security.EncryptionError, match="valid AES-GCM"):
        security.decrypt_gcm_chunk_stream(
            io.BytesIO(unknown_version), inputs["vault_id"], inputs["file_id"]
        )

    unknown_path = tmp_path / "unknown-standard-version.bin"
    unknown_path.write_bytes(unknown_version)
    assert security.is_gcm_chunk_stream(unknown_path) is False

    with pytest.raises(ValueError, match="header"):
        reference.decode_standard_0x10(legacy_bytes, **context)
    with pytest.raises(ValueError, match="Fernet record size"):
        reference.decode_fernet_chunk_stream(
            standard_bytes, encryption_key=legacy["inputs"]["encryption_key"]
        )
    with pytest.raises(security.EncryptionError, match="valid AES-GCM"):
        security.decrypt_gcm_chunk_stream(
            io.BytesIO(legacy_bytes), inputs["vault_id"], inputs["file_id"]
        )
    with pytest.raises(security.EncryptionError, match="Incomplete chunk"):
        b"".join(security.decrypt_chunk_stream(io.BytesIO(standard_bytes)))


@pytest.mark.characterization
def test_current_standard_reader_characterizes_reserved_bytes_and_clean_boundary_truncation(
    monkeypatch,
) -> None:
    from app.core import security

    value = vector("standard-0x10.json")
    inputs = value["inputs"]
    encoded = reference.b64d(value["encoded_b64"])
    monkeypatch.setattr(
        security,
        "_runtime_settings",
        lambda: SimpleNamespace(encryption_key=inputs["encryption_key"]),
    )
    changed_reserved = bytearray(encoded)
    changed_reserved[
        len(reference.STANDARD_MAGIC) + 1 : len(reference.STANDARD_HEADER)
    ] = b"\xaa\xbb"
    assert security.decrypt_gcm_chunk_stream(
        io.BytesIO(changed_reserved), inputs["vault_id"], inputs["file_id"]
    ) == reference.b64d(value["expected"]["plaintext_b64"])

    header, records = framed_records(
        encoded, header_size=len(reference.STANDARD_HEADER)
    )
    assert security.decrypt_gcm_chunk_stream(
        io.BytesIO(header + b"".join(records[:-1])),
        inputs["vault_id"],
        inputs["file_id"],
    ) == b"".join(reference.b64d(chunk) for chunk in inputs["chunks_b64"][:-1])
    assert security.decrypt_gcm_chunk_stream(
        io.BytesIO(encoded + b"\x00\x01"), inputs["vault_id"], inputs["file_id"]
    ) == reference.b64d(value["expected"]["plaintext_b64"])


def test_legacy_fernet_stream_rejects_wrong_key_tamper_and_partial_record() -> None:
    value = vector("standard-fernet-chunk-stream.json")
    inputs = value["inputs"]
    encoded = reference.b64d(value["encoded_b64"])
    with pytest.raises(InvalidToken):
        reference.decode_fernet_chunk_stream(
            encoded,
            encryption_key=Fernet.generate_key().decode("ascii"),
        )
    with pytest.raises(InvalidToken):
        reference.decode_fernet_chunk_stream(
            mutate_last(encoded), encryption_key=inputs["encryption_key"]
        )
    with pytest.raises(ValueError, match="record size"):
        reference.decode_fernet_chunk_stream(
            encoded[:-1], encryption_key=inputs["encryption_key"]
        )
    with pytest.raises(ValueError, match="record length"):
        reference.decode_fernet_chunk_stream(
            encoded + b"\x00", encryption_key=inputs["encryption_key"]
        )


@pytest.mark.characterization
def test_current_legacy_fernet_reader_characterizes_unbound_records_and_boundary_truncation(
    monkeypatch,
) -> None:
    from app.core import security

    value = vector("standard-fernet-chunk-stream.json")
    inputs = value["inputs"]
    encoded = reference.b64d(value["encoded_b64"])
    monkeypatch.setattr(
        security,
        "_fernet",
        lambda: Fernet(inputs["encryption_key"].encode("ascii")),
    )
    _, records = framed_records(encoded)
    chunks = [reference.b64d(item) for item in inputs["chunks_b64"]]
    assert b"".join(
        security.decrypt_chunk_stream(io.BytesIO(records[2] + records[0]))
    ) == (chunks[2] + chunks[0])
    assert (
        b"".join(security.decrypt_chunk_stream(io.BytesIO(records[0] * 2)))
        == chunks[0] * 2
    )
    assert b"".join(
        security.decrypt_chunk_stream(io.BytesIO(b"".join(records[:-1])))
    ) == b"".join(chunks[:-1])
    assert b"".join(
        security.decrypt_chunk_stream(io.BytesIO(encoded + b"\x00\x01"))
    ) == b"".join(chunks)


def test_zero_knowledge_content_and_private_envelope_reject_modified_inputs() -> None:
    content = vector("zk-content-unversioned.json")
    raw_content = reference.b64d(content["encoded_b64"])
    with pytest.raises(InvalidTag):
        reference.decode_zk_content(raw_content, dek_hex="ff" * 32)
    for changed in (mutate_last(raw_content), raw_content[:-1], raw_content + b"\x00"):
        with pytest.raises(InvalidTag):
            reference.decode_zk_content(changed, dek_hex=content["inputs"]["dek_hex"])

    private = vector("zk-private-envelope-legacy.json")
    envelope = private["expected"]["envelope"]
    with pytest.raises(InvalidTag):
        reference.decode_private_envelope(envelope, password="PUBLIC-WRONG-PASSPHRASE")
    for encrypted in (
        reference.b64e(mutate_last(reference.b64d(envelope["encrypted"]))),
        reference.b64e(reference.b64d(envelope["encrypted"])[:-1]),
        reference.b64e(reference.b64d(envelope["encrypted"]) + b"\x00"),
    ):
        with pytest.raises(InvalidTag):
            reference.decode_private_envelope(
                {**envelope, "encrypted": encrypted},
                password=private["inputs"]["password"],
            )


def test_direct_and_team_wraps_reject_wrong_keys_tamper_truncation_and_cross_use() -> (
    None
):
    direct = vector("zk-direct-dek-wrap-legacy.json")
    team = vector("zk-team-private-wrap-v1.json")
    direct_args = {
        "ephemeral_public_key_b64": direct["expected"]["ephemeral_public_key_b64"],
        "recipient_private_scalar_hex": direct["inputs"][
            "recipient_private_scalar_hex"
        ],
    }
    with pytest.raises(InvalidUnwrap):
        reference.decode_direct_dek_wrap(
            direct["expected"]["wrapped_dek_b64"],
            **{**direct_args, "recipient_private_scalar_hex": "23"},
        )
    for wrapped in (
        reference.b64e(
            mutate_last(reference.b64d(direct["expected"]["wrapped_dek_b64"]))
        ),
        reference.b64e(reference.b64d(direct["expected"]["wrapped_dek_b64"])[:-1]),
        team["expected"]["wrapped_key_b64"],
    ):
        with pytest.raises((InvalidUnwrap, ValueError)):
            reference.decode_direct_dek_wrap(wrapped, **direct_args)
    with pytest.raises(ValueError):
        reference.decode_direct_dek_wrap(
            direct["expected"]["wrapped_dek_b64"],
            **{**direct_args, "ephemeral_public_key_b64": reference.b64e(bytes(97))},
        )

    team_args = {
        "ephemeral_public_key_b64": team["expected"]["ephemeral_public_key_b64"],
        "member_private_scalar_hex": team["inputs"]["member_private_scalar_hex"],
    }
    with pytest.raises(InvalidTag):
        reference.decode_team_private_wrap(
            team["expected"]["wrapped_key_b64"],
            **{**team_args, "member_private_scalar_hex": "56"},
        )
    for wrapped in (
        reference.b64e(
            mutate_last(reference.b64d(team["expected"]["wrapped_key_b64"]))
        ),
        reference.b64e(reference.b64d(team["expected"]["wrapped_key_b64"])[:-1]),
        direct["expected"]["wrapped_dek_b64"],
    ):
        with pytest.raises((InvalidTag, ValueError)):
            reference.decode_team_private_wrap(wrapped, **team_args)
    with pytest.raises(ValueError):
        reference.decode_team_private_wrap(
            team["expected"]["wrapped_key_b64"],
            **{**team_args, "ephemeral_public_key_b64": reference.b64e(bytes(97))},
        )


def test_object_bound_name_rejects_every_changed_context_and_modified_blob() -> None:
    value = vector("zk-name-zk2.json")
    inputs = value["inputs"]
    kwargs = {
        "dek_hex": inputs["dek_hex"],
        "vault_id": inputs["vault_id"],
        "field": inputs["field"],
        "epoch": inputs["epoch"],
        "object_id": inputs["object_id"],
    }
    for changed in (
        {**kwargs, "dek_hex": "ff" * 32},
        {**kwargs, "vault_id": "33333333-3333-4333-8333-333333333333"},
        {**kwargs, "field": "mime"},
        {**kwargs, "epoch": inputs["epoch"] + 1},
        {**kwargs, "object_id": "33333333-3333-4333-8333-333333333333"},
    ):
        with pytest.raises(InvalidTag):
            reference.decode_zk_name(value["expected"]["token"], **changed)
    raw = reference.b64d(value["encoded_b64"])
    for changed in (mutate_last(raw), raw[:-1], raw + b"\x00"):
        with pytest.raises(InvalidTag):
            reference.decode_zk_name(f"zk2:{reference.b64e(changed)}", **kwargs)


@pytest.mark.characterization
def test_legacy_name_reader_characterizes_prefixless_and_object_unbound_reads() -> None:
    value = vector("zk-name-zk1.json")
    inputs = value["inputs"]
    common = {
        "dek_hex": inputs["dek_hex"],
        "vault_id": inputs["vault_id"],
        "field": inputs["field"],
        "epoch": inputs["epoch"],
    }
    assert (
        reference.decode_zk_name(
            value["expected"]["token"],
            **common,
            object_id="22222222-2222-4222-8222-222222222222",
        )
        == inputs["plaintext"]
    )
    assert (
        reference.decode_zk_name(
            value["encoded_b64"],
            **common,
            object_id="33333333-3333-4333-8333-333333333333",
        )
        == inputs["plaintext"]
    )


@pytest.fixture(scope="module")
def browser_results() -> dict:
    node = shutil.which("node")
    assert node, "Node is required: browser crypto compatibility must not be skipped"
    completed = subprocess.run(
        [node, str(NODE_HARNESS), str(FIXTURE_DIR)],
        cwd=Path(__file__).parent.parent,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout)
    assert "fatal" not in result, result.get("fatal")
    assert result["runtime"]["webcrypto"] is True
    return result


@pytest.mark.parametrize(
    "phase_case",
    (
        "content.reader_matches",
        "private_envelope.reader_matches",
        "direct_wrap.reader_matches",
        "team_private_wrap.reader_matches",
        "team_private_wrap.default_non_extractable",
        "names.zk1_reader_matches",
        "names.zk1_prefixless_reader_matches",
        "names.zk2_reader_matches",
        "names.blind_index_matches",
    ),
)
def test_browser_read_phase_accepts_published_vectors(
    browser_results, phase_case
) -> None:
    group, case = phase_case.split(".")
    assert browser_results[group][case] is True


@pytest.mark.parametrize(
    "phase_case",
    (
        "content.writer_matches",
        "private_envelope.writer_matches",
        "direct_wrap.writer_matches",
        "team_private_wrap.writer_matches",
        "names.zk2_writer_matches",
    ),
)
def test_browser_write_phase_emits_exact_published_bytes(
    browser_results, phase_case
) -> None:
    group, case = phase_case.split(".")
    assert browser_results[group][case] is True


@pytest.mark.parametrize(
    "phase_case",
    (
        "content.wrong_key_rejected",
        "content.tamper_rejected",
        "content.truncation_rejected",
        "content.append_rejected",
        "private_envelope.wrong_password_rejected",
        "private_envelope.tamper_rejected",
        "private_envelope.truncation_rejected",
        "private_envelope.append_rejected",
        "private_envelope.malformed_encrypted_base64_rejected",
        "private_envelope.malformed_salt_base64_rejected",
        "direct_wrap.wrong_private_key_rejected",
        "direct_wrap.tamper_rejected",
        "direct_wrap.truncation_rejected",
        "direct_wrap.malformed_point_rejected",
        "direct_wrap.malformed_wrapped_base64_rejected",
        "direct_wrap.malformed_point_base64_rejected",
        "direct_wrap.team_blob_cross_use_rejected",
        "team_private_wrap.wrong_private_key_rejected",
        "team_private_wrap.tamper_rejected",
        "team_private_wrap.truncation_rejected",
        "team_private_wrap.malformed_point_rejected",
        "team_private_wrap.malformed_wrapped_base64_rejected",
        "team_private_wrap.malformed_point_base64_rejected",
        "team_private_wrap.direct_blob_cross_use_rejected",
        "names.blind_index_context_separated",
        "names.missing_object_writer_rejected",
        "names.wrong_object_rejected",
        "names.wrong_vault_rejected",
        "names.wrong_field_rejected",
        "names.wrong_epoch_rejected",
        "names.tamper_rejected",
        "names.truncation_rejected",
        "names.append_rejected",
        "names.unknown_prefix_rejected",
        "names.malformed_base64_rejected",
    ),
)
def test_browser_adversarial_phase_fails_closed(browser_results, phase_case) -> None:
    group, case = phase_case.split(".")
    assert browser_results[group][case] is True


@pytest.mark.characterization
@pytest.mark.parametrize(
    "phase_case",
    (
        "private_envelope.valid_different_p384_key_unlock_characterized",
        "names.zk1_object_transposition_characterized",
    ),
)
def test_browser_legacy_characterization_phase(browser_results, phase_case) -> None:
    group, case = phase_case.split(".")
    assert browser_results[group][case] is True
