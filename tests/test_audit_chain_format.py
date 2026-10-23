"""The audit integrity chain's format 1, offline: the fixed vectors, and the rules they pin checked against
independent forms (the definition of the Merkle tree, the standard library's JSON writer, struct packing).

A changed vector means a changed format: rows sealed by one release would no longer verify under the other.
"""
import hashlib
import json
import struct
import sys
import threading
import uuid
from datetime import datetime

import pytest

import audit_chain_vectors as vectors
from app.core import audit_chain_format as f

pytestmark = pytest.mark.unit


def test_the_vectors_are_what_the_format_gives():
    pinned = json.loads(vectors.PATH.read_text(encoding="utf-8"))
    assert vectors.build() == pinned


# --------------------------------------------------------------------------- E()

def test_each_type_has_its_tag_and_length():
    assert f.e_null() == b"\x00"
    assert f.e_text(None) == f.e_bytes(None) == f.e_int(None) == f.e_uuid(None) == f.e_ts(None) == b"\x00"
    assert f.e_text("hé") == b"\x01" + struct.pack(">I", 3) + "hé".encode()
    assert f.e_bytes(b"\x00\xff") == b"\x02\x00\x00\x00\x02\x00\xff"
    assert f.e_int(-2) == b"\x03" + struct.pack(">q", -2)
    u = uuid.uuid4()
    assert f.e_uuid(u) == b"\x04" + u.bytes
    assert f.e_uuid(str(u)) == f.e_uuid(u)
    assert f.e_ts(datetime(1970, 1, 1, 0, 0, 1, 5)) == b"\x05" + struct.pack(">q", 1_000_005)


def test_json_null_and_sql_null_encode_alike():
    assert f.e_json_text(None) == f.e_json_text("null") == b"\x00"


def test_text_is_not_normalised():
    composed, decomposed = "é", "é"
    assert f.e_text(composed) != f.e_text(decomposed)


# --------------------------------------------------------------------------- canonical JSON

def recipe(text):
    """The standard library's recipe for the canonical form, which the format's own writer must equal wherever
    the interpreter's limits allow it."""
    value = json.loads(text)
    out = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    out = "".join("\\u%04x" % ord(ch) if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in out)
    return out.encode("utf-8")


@pytest.mark.parametrize("text", [c for c in vectors.CANONICAL_CASES if c not in ("1e400", "[NaN]", "[Infinity]")])
def test_the_writer_equals_the_standard_library_recipe(text):
    assert f.canonical_json(f.parse_json(text)) == recipe(text)


def test_floats_are_written_shortest():
    got = f.canonical_json(f.parse_json("[1e+16, 1000000000000000.0, 0.0001, 1e-05, -0.0, 5e-324, "
                                        "1.7976931348623157e+308]"))
    assert got == b"[1e+16,1000000000000000.0,0.0001,1e-05,-0.0,5e-324,1.7976931348623157e+308]"


def test_integers_stay_exact():
    assert f.canonical_json(f.parse_json("18446744073709551616")) == b"18446744073709551616"
    assert f.canonical_json(f.parse_json("[1E2, 100.0]")) == b"[100.0,100.0]"


def test_keys_sort_by_code_point_not_utf16():
    got = f.canonical_json({"\U00010000": 1, "￿": 2, "": 3})
    assert got == '{"":3,"￿":2,"\U00010000":1}'.encode()


def test_escapes_and_lone_surrogates():
    assert f.canonical_json("\x01\x1f\x7f ") == b'"\\u0001\\u001f\x7f\xe2\x80\xa8"'
    assert f.canonical_json(f.parse_json('"\\ud800"')) == b'"\\ud800"'
    assert f.canonical_json(f.parse_json('"\\ud83d\\ude00"')) == "\"\U0001F600\"".encode()


@pytest.mark.parametrize("text", ["1e400", "[NaN]", "[Infinity]", "[-Infinity]"])
def test_values_no_release_writes_fall_back_to_tag_07(text):
    e = f.e_json_text(text)
    assert e[:1] == b"\x07" and e[5:] == text.encode()
    assert not f.json_text_writable(text)


def test_equal_values_spelled_differently_encode_alike():
    a = f.e_json_text('{"a": 1, "b": [1.0, "x"]}')
    assert a == f.e_json_text('{"b":[1.0,"\\u0078"],"a":1}') == f.e_json_text('{"a":0,"a":1,"b":[1.0,"x"]}')


@pytest.mark.parametrize("limit", [640, 0, 100000])
def test_the_digit_limit_is_the_formats_whatever_the_interpreters(limit):
    if not hasattr(sys, "set_int_max_str_digits"):
        pytest.skip("this Python has no digit limit")
    before = sys.get_int_max_str_digits()
    ok, too_long = "9" * f.MAX_INT_DIGITS, "9" * (f.MAX_INT_DIGITS + 1)
    try:
        sys.set_int_max_str_digits(limit)
        assert f.e_json_text(ok)[:1] == b"\x06"
        assert f.e_json_text(ok)[5:] == ok.encode()
        assert f.e_json_text("-" + ok)[:1] == b"\x06"
        assert f.e_json_text(too_long)[:1] == b"\x07"
    finally:
        sys.set_int_max_str_digits(before)


def _deep(n):
    return "[" * n + "]" * n


def test_nesting_limit_in_the_main_thread_and_a_worker():
    results = {}

    def run(tag):
        results[tag] = (f.e_json_text(_deep(f.MAX_DEPTH))[:1], f.e_json_text(_deep(f.MAX_DEPTH + 1))[:1],
                        f.e_json_text(_deep(20000))[:1])

    run("main")
    worker = threading.Thread(target=run, args=("worker",))
    worker.start()
    worker.join()
    assert results["main"] == results["worker"] == (b"\x06", b"\x07", b"\x07")


def test_the_parser_itself_refuses_nesting_past_the_limit():
    f.parse_json(_deep(f.MAX_DEPTH))
    with pytest.raises(f.NotCanonical):
        f.parse_json(_deep(f.MAX_DEPTH + 1))


def test_a_scalar_is_depth_zero():
    assert f._depth(1) == 0 and f._depth([]) == 1 and f._depth({"a": [{}]}) == 3


# --------------------------------------------------------------------------- rows

def _full():
    return vectors._row(vectors.ROW_FULL)


def test_leaves_take_the_columns_in_order():
    row = _full()
    expected = f.LABEL_LEAF_S + b"".join((
        f.e_uuid(row["id"]), f.e_ts(row["timestamp"]), f.e_text(row["action"]), f.e_text(row["status"]),
        f.e_text(row["resource_type"]), f.e_text(row["resource_id"]), f.e_uuid(row["temp_credential_id"]),
        f.e_text(row["channel"]), f.e_text(row["method"]), f.e_uuid(row["case_id"]),
        f.e_int(row["privacy_version"]), f.e_text(row["ip_via"])))
    assert f.leaf_s(row) == expected
    c = hashlib.sha256(f.LABEL_COMMIT + f.e_bytes(vectors.NONCE) + b"".join((
        f.e_text(row["username"]), f.e_text(row["ip_address"]), f.e_text(row["user_agent"]),
        f.e_text(row["endpoint"]), f.e_text(row["temp_credential_name"]), f.e_text(row["error_message"]),
        f.e_json_text(row["recorded"]), f.e_json_text(row["details"])))).digest()
    assert f.commitment(vectors.NONCE, row) == c
    assert f.leaf_c(row["id"], c) == f.LABEL_LEAF_C + f.e_uuid(row["id"]) + f.e_bytes(c)


@pytest.mark.parametrize("column", f.STABLE_COLUMNS)
def test_every_stable_column_changes_the_stable_leaf_and_not_the_commitment(column):
    row, other = _full(), _full()
    other[column] = None
    assert f.leaf_s(row) != f.leaf_s(other)
    assert f.commitment(vectors.NONCE, row) == f.commitment(vectors.NONCE, other)


@pytest.mark.parametrize("column", f.COMMITTED_COLUMNS)
def test_every_committed_column_changes_the_commitment_and_not_the_stable_leaf(column):
    row, other = _full(), _full()
    other[column] = None
    assert f.leaf_s(row) == f.leaf_s(other)
    assert f.commitment(vectors.NONCE, row) != f.commitment(vectors.NONCE, other)


def test_the_nonce_changes_the_commitment_and_the_labels_keep_trees_apart():
    row = _full()
    assert f.commitment(vectors.NONCE, row) != f.commitment(bytes(16), row)
    c = f.commitment(vectors.NONCE, row)
    assert f.leaf_c(row["id"], c)[:len(f.LABEL_LEAF_C)] != f.leaf_s(row)[:len(f.LABEL_LEAF_S)]


def test_a_legacy_nonce_is_hmac_of_the_raw_id():
    import hmac
    rid = uuid.UUID(vectors.ROW_FULL["id"])
    want = hmac.new(vectors.SALT, b"dvaudit-legacy-nonce-v1\x00" + rid.bytes, hashlib.sha256).digest()[:16]
    assert f.legacy_nonce(vectors.SALT, rid) == want


# --------------------------------------------------------------------------- trees

@pytest.mark.parametrize("n", [0, 1, 2, 3, 4, 5, 7, 8, 9, 1000, 1023, 1024, 1025])
def test_the_streaming_tree_equals_the_definition(n):
    leaves = [hashlib.sha256(str(i).encode()).digest() for i in range(n)]
    builder = f.TreeBuilder()
    for leaf in leaves:
        builder.push(leaf)
    assert builder.root() == f.mth(leaves)
    assert builder.count == n


def test_rfc6962_shapes():
    a, b, c = b"a", b"b", b"c"
    assert f.mth([]) == hashlib.sha256(b"").digest()
    assert f.mth([a]) == hashlib.sha256(b"\x00a").digest()
    ha, hb, hc = (hashlib.sha256(b"\x00" + x).digest() for x in (a, b, c))
    ab = hashlib.sha256(b"\x01" + ha + hb).digest()
    assert f.mth([a, b]) == ab
    assert f.mth([a, b, c]) == hashlib.sha256(b"\x01" + ab + hc).digest()


# --------------------------------------------------------------------------- seals and keys

def test_the_chain_of_vector_seals_links_and_macs():
    data = vectors.build()
    key = bytes.fromhex(data["keys"]["key"])
    old = f.chain_key(vectors.OLD_KEY_TEXT)
    prev = f.LINK_0
    for seal in data["seals"]:
        body = bytes.fromhex(seal["body"])
        ln = hashlib.sha256(b"dvaudit-link-v1\x00" + prev + hashlib.sha256(body).digest()).digest()
        assert ln.hex() == seal["link"]
        assert seal["head"] == "dvchain1:%d:%s" % (seal["seq"], ln.hex())
        assert body[:len(f.LABEL_SEAL)] == f.LABEL_SEAL
        assert struct.unpack(">Q", body[len(f.LABEL_SEAL):len(f.LABEL_SEAL) + 8])[0] == seal["seq"]
        signing = old if seal["seq"] < 3 else key
        assert f.mac(signing, ln).hex() == seal["mac"]
        prev = ln
    proof = data["seals"][2]["detail"]["old_key_proof"]
    second = bytes.fromhex(data["seals"][1]["link"])
    assert f.old_key_proof(old, second, data["keys"]["key_id"]).hex() == proof


def test_key_derivation_is_rfc5869_hkdf():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    want = HKDF(algorithm=hashes.SHA256(), length=32, salt=f.KEY_SALT, info=f.KEY_INFO).derive(b"x" * 64)
    assert f.chain_key("x" * 64) == want
    kid = f.key_id(want)
    assert kid.startswith("kc1:") and len(kid) == 20 and kid != f.key_id(f.chain_key("y" * 64))


def test_a_head_reads_back():
    ln = bytes(range(32))
    text = f.head(42, ln)
    assert f.parse_head(text) == (42, ln)
    with pytest.raises(ValueError):
        f.parse_head("dvchain2:1:" + "00" * 32)


def test_times_in_details():
    assert f.hour_text(datetime(2026, 1, 2, 3)) == "2026-01-02T03:00:00Z"
    assert f.time_text(datetime(2026, 1, 2, 3, 4, 5, 6)) == "2026-01-02T03:04:05.000006Z"
    assert f.parse_time_text("2026-01-02T03:04:05.000006Z") == datetime(2026, 1, 2, 3, 4, 5, 6)


def test_int_to_decimal_handles_long_values():
    v = 7 * 10 ** 4299 + 12345
    assert f.int_to_decimal(v) == "7" + "0" * 4294 + "12345"
    assert f.int_to_decimal(-v) == "-" + f.int_to_decimal(v)
