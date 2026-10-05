"""The audit log's integrity chain, format 1: how rows, hours and seals are turned into bytes and hashes.

Everything here is a pure function of its arguments, uses the standard library only, and is pinned by the
fixed vectors in tests/fixtures/audit-chain-v1/. A second implementation follows the rules below and the
vectors; nothing here may change without a new format number.

Values. E(v) is a tag byte and the value:

    00  SQL NULL or JSON null              01  text: u32be(byte length) + UTF-8
    02  bytes: u32be(length) + bytes       03  integer: i64be
    04  UUID: its 16 bytes                 05  timestamp: i64be(microseconds since 1970-01-01, as UTC)
    06  JSON: u32be(length) + canonical JSON bytes
    07  JSON text that cannot be canonicalised: u32be(length) + the stored text as UTF-8

Each column has a fixed type, and every hash input fixes its column order.

Canonical JSON. A stored JSON text is parsed here, never by the database driver: a duplicate key's last
value wins; a number with no fraction and no exponent is an exact integer of at most 4,300 decimal digits
(the sign not counted), any other number a binary64; nesting is at most 128 deep; NaN and the infinities are
refused; a lone surrogate escape stays a lone surrogate. Both limits belong to the format: they hold whatever
the interpreter's own limits are. It is written back with keys sorted by code point, no whitespace, the
escapes of JSON (control characters and lone surrogates as lowercase \\u escapes), every other code point as
UTF-8, integers exactly, and binary64 values as the shortest digit string that reads back as the same value.
A value that cannot be written back (a number that overflows binary64) or parsed within the limits is
encoded with tag 07, over the stored text itself.

Rows give two leaves: the stable leaf (fields that never change, in clear) and the commitment leaf (the
row's id and a commitment to its personal values under the row's nonce). Each closed hour gives two Merkle
roots (RFC 6962), over the rows in (timestamp, id) order. Seals are chained by an unkeyed link, and each
link carries an HMAC under the chain's key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import struct
import uuid
from datetime import date, datetime, timezone
from typing import Any, Iterable, Optional, Sequence

FORMAT = 1
MAX_INT_DIGITS = 4300
MAX_DEPTH = 128
# A seal whose sealed_at steps back by more than this, along seq, is reported.
BACKWARDS_TOLERANCE_SECONDS = 300

LABEL_COMMIT = b"dvaudit-commit-v1\x00"
LABEL_LEAF_S = b"dvaudit-leaf-s-v1\x00"
LABEL_LEAF_C = b"dvaudit-leaf-c-v1\x00"
LABEL_LEGACY_NONCE = b"dvaudit-legacy-nonce-v1\x00"
LABEL_SEAL = b"dvaudit-seal-v1\x00"
LABEL_IDS = b"dvaudit-ids-v1\x00"
LABEL_LINK = b"dvaudit-link-v1\x00"
LABEL_MAC = b"dvaudit-mac-v1\x00"
LABEL_KEY_ID = b"dvaudit-key-id-v1\x00"
LABEL_KEY_CHANGE = b"dvaudit-key-change-v1\x00"
LABEL_DAY = b"dvaudit-day-v1\x00"

KEY_SALT = b"dockvault-audit-chain-key-v1"
KEY_INFO = b"audit-chain-v1"

LINK_0 = bytes(32)
ZERO_NONCE = bytes(16)
_EPOCH = datetime(1970, 1, 1)


class NotCanonical(ValueError):
    """A JSON text the format cannot canonicalise."""


# --------------------------------------------------------------------------- integers without the interpreter's limit

_CHUNK = 600   # below the smallest digit limit Python allows (640), so every conversion here is allowed


def _int_from_digits(text: str) -> int:
    neg = text.startswith("-")
    digits = text[1:] if neg else text
    value = 0
    for i in range(0, len(digits), _CHUNK):
        part = digits[i:i + _CHUNK]
        value = value * (10 ** len(part)) + int(part)
    return -value if neg else value


def int_to_decimal(value: int) -> str:
    """``value`` in decimal, whatever the interpreter's digit limit."""
    if -(10 ** _CHUNK) < value < 10 ** _CHUNK:
        return str(value)
    neg = value < 0
    value = -value if neg else value
    base = 10 ** _CHUNK
    parts = []
    while value:
        value, rest = divmod(value, base)
        parts.append(rest)
    out = str(parts[-1]) + "".join(str(p).rjust(_CHUNK, "0") for p in reversed(parts[:-1]))
    return "-" + out if neg else out


# --------------------------------------------------------------------------- canonical JSON

def _parse_int(text: str) -> int:
    if len(text.lstrip("-")) > MAX_INT_DIGITS:
        raise NotCanonical("integer too long")
    return _int_from_digits(text)


def _refuse_constant(name: str):
    raise NotCanonical(f"{name} is not JSON")


def _depth(value: Any) -> int:
    """The nesting depth of ``value``: a scalar is 0, an empty list or object 1. Iterative."""
    deepest = 0
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, (list, dict)):
            depth += 1
            if depth > deepest:
                deepest = depth
                if deepest > MAX_DEPTH:
                    return deepest
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, depth) for child in children)
    return deepest


def parse_json(text: str) -> Any:
    """``text`` parsed under the format's rules. Raises NotCanonical for anything outside them."""
    try:
        value = json.loads(text, parse_int=_parse_int, parse_constant=_refuse_constant)
    except NotCanonical:
        raise
    except (ValueError, RecursionError, TypeError) as exc:
        raise NotCanonical(type(exc).__name__) from None
    if _depth(value) > MAX_DEPTH:
        raise NotCanonical("nested too deep")
    return value


_SHORT_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        code = ord(ch)
        esc = _SHORT_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif code < 0x20 or 0xD800 <= code <= 0xDFFF:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _float(x: float) -> str:
    if x != x or x in (float("inf"), float("-inf")):
        raise NotCanonical("not a finite number")
    return repr(x)


def _dump(value: Any, out: list) -> None:
    # Iterative over containers would be needed only past MAX_DEPTH, which parse_json refuses.
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        out.append(int_to_decimal(value))
    elif isinstance(value, float):
        out.append(_float(value))
    elif isinstance(value, str):
        out.append(_string(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _dump(item, out)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        for i, key in enumerate(sorted(value)):
            if not isinstance(key, str):
                raise NotCanonical("object key is not text")
            if i:
                out.append(",")
            out.append(_string(key))
            out.append(":")
            _dump(value[key], out)
        out.append("}")
    else:
        raise NotCanonical(f"{type(value).__name__} is not JSON")


def canonical_json(value: Any) -> bytes:
    """``value`` (already parsed) in canonical form, as UTF-8 bytes. Raises NotCanonical."""
    if _depth(value) > MAX_DEPTH:
        raise NotCanonical("nested too deep")
    out: list = []
    _dump(value, out)
    return "".join(out).encode("utf-8")


# --------------------------------------------------------------------------- E()

def _u32(n: int) -> bytes:
    return struct.pack(">I", n)


def _utf8(s: str) -> bytes:
    return s.encode("utf-8", "surrogatepass")


def e_null() -> bytes:
    return b"\x00"


def e_text(s: Optional[str]) -> bytes:
    if s is None:
        return b"\x00"
    data = _utf8(s)
    return b"\x01" + _u32(len(data)) + data


def e_bytes(b: Optional[bytes]) -> bytes:
    if b is None:
        return b"\x00"
    b = bytes(b)
    return b"\x02" + _u32(len(b)) + b


def e_int(i: Optional[int]) -> bytes:
    if i is None:
        return b"\x00"
    return b"\x03" + struct.pack(">q", int(i))


def as_uuid(u) -> Optional[uuid.UUID]:
    if u is None:
        return None
    if isinstance(u, uuid.UUID):
        return u
    if isinstance(u, (bytes, bytearray)) and len(u) == 16:
        return uuid.UUID(bytes=bytes(u))
    return uuid.UUID(str(u))


def e_uuid(u) -> bytes:
    u = as_uuid(u)
    if u is None:
        return b"\x00"
    return b"\x04" + u.bytes


def micros(ts: datetime) -> int:
    """Microseconds since 1970-01-01T00:00:00, the stored value read as UTC."""
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    delta = ts - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def from_micros(us: int) -> datetime:
    from datetime import timedelta
    return _EPOCH + timedelta(microseconds=us)


def e_ts(ts: Optional[datetime]) -> bytes:
    if ts is None:
        return b"\x00"
    return b"\x05" + struct.pack(">q", micros(ts))


def e_json_text(text: Optional[str]) -> bytes:
    """A JSON column, from its stored text (SQL NULL is None). JSON null encodes as SQL NULL does."""
    if text is None:
        return b"\x00"
    try:
        value = parse_json(text)
        if value is None:
            return b"\x00"
        data = canonical_json(value)
    except NotCanonical:
        raw = _utf8(text)
        return b"\x07" + _u32(len(raw)) + raw
    return b"\x06" + _u32(len(data)) + data


def json_text_writable(text: Optional[str]) -> bool:
    """Whether a stored JSON text canonicalises (False: it encodes with tag 07)."""
    if text is None:
        return True
    try:
        canonical_json(parse_json(text))
        return True
    except NotCanonical:
        return False


# --------------------------------------------------------------------------- rows

# The columns, in the order the hashes take them. Moving one between the two needs a new format.
STABLE_COLUMNS = ("id", "timestamp", "action", "status", "resource_type", "resource_id", "temp_credential_id",
                  "channel", "method", "case_id", "privacy_version", "ip_via")
COMMITTED_COLUMNS = ("username", "ip_address", "user_agent", "endpoint", "temp_credential_name",
                     "error_message", "recorded", "details")
_UUID_COLUMNS = {"id", "temp_credential_id", "case_id"}
_INT_COLUMNS = {"privacy_version"}
_JSON_COLUMNS = {"recorded", "details"}


def _e_column(name: str, value) -> bytes:
    if name in _UUID_COLUMNS:
        return e_uuid(value)
    if name == "timestamp":
        return e_ts(value)
    if name in _INT_COLUMNS:
        return e_int(value)
    if name in _JSON_COLUMNS:
        return e_json_text(value)
    return e_text(value)


def commitment(nonce: Optional[bytes], row) -> bytes:
    """C over the row's personal values under ``nonce``. ``row`` maps the committed columns (JSON columns as
    their stored text)."""
    parts = [LABEL_COMMIT, e_bytes(nonce)]
    parts.extend(_e_column(name, row[name]) for name in COMMITTED_COLUMNS)
    return hashlib.sha256(b"".join(parts)).digest()


def leaf_s(row) -> bytes:
    return LABEL_LEAF_S + b"".join(_e_column(name, row[name]) for name in STABLE_COLUMNS)


def leaf_c(row_id, c: bytes) -> bytes:
    return LABEL_LEAF_C + e_uuid(row_id) + e_bytes(c)


def legacy_nonce(salt: bytes, row_id) -> bytes:
    return hmac.new(salt, LABEL_LEGACY_NONCE + as_uuid(row_id).bytes, hashlib.sha256).digest()[:16]


def ids_digest(ids: Iterable) -> bytes:
    h = hashlib.sha256(LABEL_IDS)
    for i in ids:
        h.update(i if isinstance(i, (bytes, bytearray)) else as_uuid(i).bytes)
    return h.digest()


def ids_digest_of_blob(blob: Optional[bytes]) -> bytes:
    return hashlib.sha256(LABEL_IDS + (bytes(blob) if blob else b"")).digest()


# --------------------------------------------------------------------------- Merkle trees (RFC 6962)

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(d: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + d).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


class TreeBuilder:
    """MTH over leaves pushed in order, in O(log n) memory: merge the top two while they cover equal
    numbers of leaves, and at the end fold the stack from the top down."""

    __slots__ = ("_stack", "count")

    def __init__(self):
        self._stack: list = []   # [(hash, number of leaves)]
        self.count = 0

    def push(self, d: bytes) -> None:
        self.push_hash(leaf_hash(d))

    def push_hash(self, h: bytes) -> None:
        self.count += 1
        size = 1
        stack = self._stack
        while stack and stack[-1][1] == size:
            left, _ = stack.pop()
            h = node_hash(left, h)
            size *= 2
        stack.append((h, size))

    def root(self) -> bytes:
        if not self._stack:
            return EMPTY_ROOT
        h = self._stack[-1][0]
        for left, _ in reversed(self._stack[:-1]):
            h = node_hash(left, h)
        return h


def mth(leaves: Sequence[bytes]) -> bytes:
    """MTH by its definition (the vectors check the builder against it)."""
    n = len(leaves)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaf_hash(leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


# --------------------------------------------------------------------------- seals

def detail_digest(detail: Any) -> bytes:
    return hashlib.sha256(canonical_json(detail)).digest()


def body(seq: int, kind: str, period_start: Optional[datetime], period_end: Optional[datetime], fmt: int,
         row_count: int, row_bytes: int, root_s: Optional[bytes], root_c: Optional[bytes],
         ids_dig: Optional[bytes], detail_dig: bytes, key_id: str, sealed_at: datetime) -> bytes:
    return b"".join((
        LABEL_SEAL, struct.pack(">Q", seq), e_text(kind), e_ts(period_start), e_ts(period_end),
        struct.pack(">H", fmt), struct.pack(">Q", row_count), struct.pack(">Q", row_bytes), e_bytes(root_s),
        e_bytes(root_c), e_bytes(ids_dig), e_bytes(detail_dig), e_text(key_id), e_ts(sealed_at)))


def link(prev_link: bytes, body_bytes: bytes) -> bytes:
    return hashlib.sha256(LABEL_LINK + prev_link + hashlib.sha256(body_bytes).digest()).digest()


def mac(key: bytes, link_bytes: bytes) -> bytes:
    return hmac.new(key, LABEL_MAC + link_bytes, hashlib.sha256).digest()


def head(seq: int, link_bytes: bytes) -> str:
    return "dvchain1:%d:%s" % (seq, link_bytes.hex())


def parse_head(text: str) -> tuple:
    """(seq, link) from a head string. Raises ValueError."""
    prefix, seq, hexlink = text.strip().split(":")
    if prefix != "dvchain1" or len(hexlink) != 64:
        raise ValueError("not a chain head")
    return int(seq), bytes.fromhex(hexlink)


# --------------------------------------------------------------------------- keys

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def chain_key(ikm_text: str) -> bytes:
    return hkdf_sha256(ikm_text.encode("utf-8"), KEY_SALT, KEY_INFO, 32)


def key_id(key: bytes) -> str:
    return "kc1:" + hmac.new(key, LABEL_KEY_ID, hashlib.sha256).hexdigest()[:16]


def old_key_proof(old_key: bytes, prev_link: bytes, new_key_id: str) -> bytes:
    return hmac.new(old_key, LABEL_KEY_CHANGE + prev_link + e_text(new_key_id), hashlib.sha256).digest()


# --------------------------------------------------------------------------- times in details

def hour_text(h: datetime) -> str:
    return h.strftime("%Y-%m-%dT%H:00:00Z")


def time_text(t: datetime) -> str:
    if t.tzinfo is not None:
        t = t.astimezone(timezone.utc).replace(tzinfo=None)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_time_text(text: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    raise ValueError(f"not a chain time: {text!r}")


def day_digest(summaries: Iterable[Sequence]) -> bytes:
    """The digest of a day's hour summaries, in order: each (period_start, period_end, count, root_s, root_c,
    ids_digest)."""
    h = hashlib.sha256(LABEL_DAY)
    for start, end, count, rs, rc, idd in summaries:
        h.update(e_ts(start) + e_ts(end) + e_int(count) + e_bytes(rs) + e_bytes(rc) + e_bytes(idd))
    return h.digest()


def utc_date(t: datetime) -> date:
    return t.date()
