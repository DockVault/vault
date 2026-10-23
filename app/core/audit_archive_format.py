"""The format of an audit archive block (app/core/audit_archive.py): every column of every row of a part of a
UTC day, as NDJSON, compressed with the standard library's zstd at level 9.

The first line is a header::

    {"format": 1, "day": "YYYY-MM-DD", "part": n, "columns": [...], "salts": {"YYYY-MM-DDTHH:00:00Z": hex}}

``columns`` names every column of ``audit_logs`` in the model's order (COLUMNS, generated from the model and
pinned by a test, so a column added to the model cannot be left out of the archive unnoticed). ``salts`` holds,
for each hour whose rows include some written without a nonce, the hour's salt from its seal (the block keeps
the salt instead of the derived nonces, 32 bytes an hour rather than 16 a row).

Every other line is one row, in (timestamp, id) order: a JSON array of the columns' values, then the size
Postgres stored the row in (``pg_column_size`` when it was archived, which the size cap and the prune seals
count). A value is written by its column's type: a UUID as 32 hex digits, a time as microseconds since
1970-01-01 (the stored value read as UTC), bytes as hex, a JSON column as the text the database stored (so
the row comes back exactly), anything else as itself; NULL as null.

The per-block dictionary: in DICT_COLUMNS (the browser description and the endpoint, the long values that
repeat), a value seen before in the block is written as its index (an integer, from 0 in order of first
appearance), and a value seen for the first time as itself, a string, which takes the next index. Encoding
and decoding then each read the rows once, in order, and hold only the dictionary.

``identity`` is a SHA-256 over each row's values in their written form, before the dictionary: computed while
encoding from the rows the database gave and again while decoding, it shows that every column of every row
came back unchanged.

``aggregates`` (kept in the block's row, beside the payload, and checked against the rows whenever the payload
is read): ``{"by": [[action, status, channel, rows, line bytes, stored bytes], ...], "hours": [[hour, rows,
stored bytes], ...], "by_hour": [[hour, action, status, channel, rows], ...]}``, sorted. The line bytes are the
NDJSON lines' (with the dictionary); the stored bytes the sizes Postgres stored the rows in. The Activity page's
summary band counts archived hours from ``by_hour`` (app/services/activity_archive.py), and the size cap takes from
``by`` and ``hours`` no more of an archived part as never to be deleted than the chain binds for its hours.
"""
from __future__ import annotations

import hashlib
import io
import json
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Dict, Iterator, List, Optional, Tuple

import sqlalchemy as sa

from app.core import audit_chain_format as fmt

FORMAT = 1
CODEC = "zstd"
LEVEL = 9
DICT_COLUMNS = ("user_agent", "endpoint")


def _kind_of(column) -> str:
    t = column.type
    if isinstance(t, sa.Uuid):
        return "uuid"
    if isinstance(t, sa.DateTime):
        return "time"
    if isinstance(t, sa.LargeBinary):
        return "bytes"
    if isinstance(t, sa.JSON):
        return "json"
    if isinstance(t, sa.Integer):
        return "int"
    if isinstance(t, (sa.String, sa.Text)):
        return "text"
    raise TypeError(f"audit_logs.{column.name}: the archive does not know how to write a {type(t).__name__}")


def _columns() -> Tuple[Tuple[str, str], ...]:
    from app.core.models import AuditLog
    return tuple((c.name, _kind_of(c)) for c in AuditLog.__table__.columns)


COLUMNS: Tuple[Tuple[str, str], ...] = _columns()
NAMES: Tuple[str, ...] = tuple(name for name, _kind in COLUMNS)
JSON_NAMES: Tuple[str, ...] = tuple(name for name, kind in COLUMNS if kind == "json")


class BlockError(ValueError):
    """A payload that is not a block this release wrote."""


class LaterFormat(BlockError):
    """A block whose header names a block format newer than this release's: a later release wrote it (one that adds
    a column to audit_logs changes the format), and this release neither reads its rows nor changes it."""


def _write(kind: str, value):
    if value is None:
        return None
    if kind == "uuid":
        return fmt.as_uuid(value).hex
    if kind == "time":
        return fmt.micros(value)
    if kind == "bytes":
        return bytes(value).hex()
    if kind == "int":
        return int(value)
    if kind == "json":
        if not isinstance(value, str):
            raise TypeError("a JSON column must be read as its stored text")
        return value
    return str(value)


def _read(kind: str, value):
    if value is None:
        return None
    if kind == "uuid":
        return uuid.UUID(hex=value)
    if kind == "time":
        return fmt.from_micros(int(value))
    if kind == "bytes":
        return bytes.fromhex(value)
    if kind == "int":
        return int(value)
    return value


def _line(values) -> bytes:
    return json.dumps(values, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sort_key(key: tuple) -> tuple:
    return tuple(("", "") if x is None else ("x", x) for x in key)


class _Aggregates:
    """Rows, line bytes and stored bytes by (action, status, channel), rows and stored bytes by hour, and rows by
    (hour, action, status, channel)."""

    def __init__(self):
        self.by: Dict[tuple, list] = {}
        self.hours: Dict[datetime, list] = {}
        self.by_hour: Dict[tuple, int] = {}

    def add(self, row: dict, line_bytes: int) -> None:
        stored = int(row.get("_bytes") or 0)
        agg = self.by.setdefault((row.get("action"), row.get("status"), row.get("channel")), [0, 0, 0])
        agg[0] += 1
        agg[1] += line_bytes
        agg[2] += stored
        ts = row.get("timestamp")
        if isinstance(ts, datetime):
            hour = ts.replace(minute=0, second=0, microsecond=0)
            h = self.hours.setdefault(hour, [0, 0])
            h[0] += 1
            h[1] += stored
            key = (hour, row.get("action"), row.get("status"), row.get("channel"))
            self.by_hour[key] = self.by_hour.get(key, 0) + 1

    def stored_form(self) -> dict:
        return {"by": [list(k) + list(v) for k, v in sorted(self.by.items(), key=lambda kv: _sort_key(kv[0]))],
                "hours": [[fmt.hour_text(h)] + list(v) for h, v in sorted(self.hours.items())],
                "by_hour": [[fmt.hour_text(k[0]), k[1], k[2], k[3], n] for k, n in
                            sorted(self.by_hour.items(), key=lambda kv: (kv[0][0], _sort_key(kv[0][1:])))]}


class BlockWriter:
    """Encodes one part, a row at a time. ``salts`` maps an hour to its salt (bytes)."""

    def __init__(self, day: date, part: int, salts: Optional[Dict[datetime, bytes]] = None):
        from compression import zstd
        self._c = zstd.ZstdCompressor(level=LEVEL)
        self._chunks: List[bytes] = []
        self.raw_bytes = 0
        self.rows = 0
        self.identity = hashlib.sha256()
        self._dicts: Dict[str, Dict[str, int]] = {name: {} for name in DICT_COLUMNS}
        self._aggregates = _Aggregates()
        header = {"format": FORMAT, "day": day.isoformat(), "part": int(part), "columns": list(NAMES),
                  "salts": {fmt.hour_text(h): s.hex() for h, s in sorted((salts or {}).items())}}
        self._put(_line(header))

    def _put(self, line: bytes) -> None:
        self.raw_bytes += len(line) + 1
        self._chunks.append(self._c.compress(line + b"\n"))

    def add(self, row: dict) -> None:
        """``row`` holds every column (a JSON column as its stored text) and ``_bytes``."""
        values = [_write(kind, row.get(name)) for name, kind in COLUMNS]
        self.identity.update(_line(values) + b"\n")
        out = list(values)
        for i, (name, _kind) in enumerate(COLUMNS):
            if name in self._dicts and values[i] is not None:
                d = self._dicts[name]
                if values[i] in d:
                    out[i] = d[values[i]]
                else:
                    d[values[i]] = len(d)
        line = _line(out + [int(row.get("_bytes") or 0)])
        self._put(line)
        self.rows += 1
        self._aggregates.add(row, len(line) + 1)

    @property
    def aggregates(self) -> dict:
        return self._aggregates.stored_form()

    def finish(self) -> bytes:
        from compression import zstd
        self._chunks.append(self._c.flush(zstd.ZstdCompressor.FLUSH_FRAME))
        return b"".join(self._chunks)


@dataclass
class Block:
    """A decoded block: its header, and its rows read one at a time (``rows()``, once)."""
    header: dict
    _lines: Iterator[bytes] = None
    identity: object = field(default_factory=hashlib.sha256)
    raw_bytes: int = 0
    _aggregates: _Aggregates = field(default_factory=_Aggregates)
    count: int = 0

    @property
    def salts(self) -> Dict[datetime, bytes]:
        return {fmt.parse_time_text(h): bytes.fromhex(s) for h, s in (self.header.get("salts") or {}).items()}

    @property
    def aggregates(self) -> dict:
        return self._aggregates.stored_form()

    def rows(self) -> Iterator[dict]:
        names = self.header["columns"]
        kinds = dict(COLUMNS)
        dicts: Dict[str, List[str]] = {name: [] for name in DICT_COLUMNS}
        width = len(names)
        for raw in self._lines:
            line = raw.rstrip(b"\n")
            if not line:
                continue
            self.raw_bytes += len(line) + 1
            try:
                values = json.loads(line)
            except ValueError as exc:
                raise BlockError(f"a row is not JSON ({exc})") from None
            if not isinstance(values, list) or len(values) != width + 1:
                raise BlockError("a row has the wrong number of values")
            plain = list(values[:width])
            for i, name in enumerate(names):
                if name in dicts and plain[i] is not None:
                    d = dicts[name]
                    v = plain[i]
                    if isinstance(v, int) and not isinstance(v, bool):
                        if not 0 <= v < len(d):
                            raise BlockError(f"a {name} refers to no earlier value")
                        plain[i] = d[v]
                    elif isinstance(v, str):
                        d.append(v)
                    else:
                        raise BlockError(f"a {name} is neither a value nor a reference")
            self.identity.update(_line(plain) + b"\n")
            stored = values[width]
            if stored is not None and (not isinstance(stored, int) or isinstance(stored, bool)):
                raise BlockError("a row's stored size is not a number")
            try:
                row = {name: _read(kinds[name], plain[i]) for i, name in enumerate(names)}
                row["id"] = fmt.as_uuid(row["id"])
            except (TypeError, ValueError, AttributeError) as exc:
                raise BlockError(f"a row's value cannot be read ({type(exc).__name__})") from None
            row["_bytes"] = int(stored or 0)
            self.count += 1
            self._aggregates.add(row, len(line) + 1)
            yield row


def open_block(payload: bytes) -> Block:
    """The block in ``payload``: its header now, its rows as they are read. Raises BlockError."""
    from compression import zstd
    try:
        stream = zstd.ZstdFile(io.BytesIO(bytes(payload)), mode="rb")
        first = stream.readline()
    except (zstd.ZstdError, OSError, EOFError) as exc:
        raise BlockError(f"the payload does not decompress ({type(exc).__name__})") from None
    try:
        header = json.loads(first)
    except ValueError:
        raise BlockError("the header is not JSON") from None
    later = header.get("format") if isinstance(header, dict) else None
    if isinstance(later, int) and not isinstance(later, bool) and later > FORMAT:
        raise LaterFormat(f"block format {later}, which a later release writes")
    if not isinstance(header, dict) or header.get("format") != FORMAT:
        raise BlockError(f"format {header.get('format') if isinstance(header, dict) else '?'}")
    if list(header.get("columns") or []) != list(NAMES):
        raise BlockError("the block's columns are not this release's")

    def lines():
        try:
            for line in stream:
                yield line
        except (zstd.ZstdError, OSError, EOFError) as exc:
            raise BlockError(f"the payload does not decompress ({type(exc).__name__})") from None

    block = Block(header, lines())
    block.raw_bytes = len(first.rstrip(b"\n")) + 1
    return block


# How much of a payload header_format() reads, and the most it decompresses of it: the header is one line of a
# few kilobytes (the columns' names and at most a day's salts).
HEADER_BYTES = 65536
HEADER_MAX = 1 << 20


def header_format(prefix: bytes) -> Optional[int]:
    """The block format the header names, read from ``prefix``, the first bytes of a payload (at most HEADER_BYTES):
    None when they do not hold the whole header line, or are not the start of a block."""
    from compression import zstd
    try:
        out = zstd.ZstdDecompressor().decompress(bytes(prefix), max_length=HEADER_MAX)
    except (zstd.ZstdError, EOFError, ValueError, TypeError):
        return None
    line, newline, _rest = out.partition(b"\n")
    if not newline:
        return None
    try:
        header = json.loads(line)
    except ValueError:
        return None
    named = header.get("format") if isinstance(header, dict) else None
    return named if isinstance(named, int) and not isinstance(named, bool) else None


def digest(payload: bytes) -> str:
    """The SHA-256 of the payload as stored, as an archive seal binds it."""
    return hashlib.sha256(bytes(payload)).hexdigest()
