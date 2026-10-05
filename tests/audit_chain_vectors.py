"""Builds the fixed vectors of the audit integrity chain, format 1 (tests/fixtures/audit-chain-v1/vectors.json).

The test compares a fresh build with the committed file, so a change to the format shows as a changed vector.
Run this file to write the vectors again, only for a new format:

    python tests/audit_chain_vectors.py --write
"""
from __future__ import annotations

import hashlib
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core import audit_chain_format as f  # noqa: E402

PATH = Path(__file__).resolve().parent / "fixtures" / "audit-chain-v1" / "vectors.json"

FIXED_KEY_TEXT = "a" * 64
OLD_KEY_TEXT = "b" * 64

ROW_FULL = {
    "id": "6f1c1d5e-9a43-4c1e-8f53-3b0b2d2a7c11",
    "timestamp": "2026-10-05T13:14:15.123456",
    "action": "file_uploaded",
    "status": "success",
    "resource_type": "file",
    "resource_id": "c1d2e3f4-0000-4000-8000-000000000001",
    "temp_credential_id": "0b8f4a3e-1111-4222-8333-444455556666",
    "channel": "web",
    "method": "POST",
    "case_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    "privacy_version": 3,
    "ip_via": "direct",
    "username": "Zoë \U0001F600",
    "ip_address": "203.0.113.7",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
    "endpoint": "/api/vaults/{vault_id}/files",
    "temp_credential_name": "temp_contractor",
    "error_message": "line one\nline two",
    "recorded": "{\"ip\": \"full\", \"names\": \"fingerprint\"}",
    "details": "{\"size\": 1048576, \"name\": \"résumé.pdf\", \"nested\": {\"b\": [1, 2.5, null, true]}}",
}
ROW_NULL = {name: None for name in ROW_FULL}
ROW_NULL["id"] = "00000000-0000-4000-8000-000000000000"

NONCE = bytes(range(16))
SALT = bytes(range(32, 64))

CANONICAL_CASES = [
    '{"b":1,"a":2}',
    '{"\U00010000":1,"￿":2,"":3}',
    '"quote \\" backslash \\\\ controls \\b\\t\\n\\f\\r \\u0001 \\u001f del \\u007f ls \\u2028 ps \\u2029"',
    '"lone \\ud800 and pair \\ud83d\\ude00 and low \\udc00"',
    '[1e+16, 1000000000000000.0, 0.0001, 1e-05, -0.0, 5e-324, 1.7976931348623157e+308]',
    '[1E2, 100.0, 0.1, 123456789012345678901234567890]',
    '18446744073709551616',
    '-18446744073709551616',
    '"café 中文"',
    '{"a":1,"a":2}',
    '[true,false,null]',
    'null',
    '1e400',
    '[NaN]',
    '[Infinity]',
    '{ "spaced" : [ 1 , 2 ] }',
]


def _row(spec: dict) -> dict:
    row = dict(spec)
    for name in ("id", "temp_credential_id", "case_id"):
        if row[name] is not None:
            row[name] = uuid.UUID(row[name])
    if row["timestamp"] is not None:
        row["timestamp"] = datetime.fromisoformat(row["timestamp"])
    return row


def _hex(b) -> str:
    return b.hex() if b is not None else None


def build() -> dict:
    out: dict = {"format": f.FORMAT}

    # E() of each type.
    out["e"] = {
        "null": f.e_null().hex(),
        "text": f.e_text("héllo \U0001F600").hex(),
        "text_empty": f.e_text("").hex(),
        "bytes": f.e_bytes(b"\x00\x01\xff").hex(),
        "int": f.e_int(-2).hex(),
        "int_max": f.e_int(2 ** 63 - 1).hex(),
        "uuid": f.e_uuid(uuid.UUID(ROW_FULL["id"])).hex(),
        "timestamp": f.e_ts(datetime(2026, 10, 5, 13, 14, 15, 123456)).hex(),
        "timestamp_epoch": f.e_ts(datetime(1970, 1, 1)).hex(),
        "timestamp_before_epoch": f.e_ts(datetime(1969, 12, 31, 23, 59, 59, 999999)).hex(),
        "json": f.e_json_text('{"b":[1,2],"a":"x"}').hex(),
        "json_null": f.e_json_text("null").hex(),
        "json_tag07": f.e_json_text("1e400").hex(),
    }

    canon = []
    for text in CANONICAL_CASES:
        canon.append({"text": text, "e": f.e_json_text(text).hex()})
    big = "9" * f.MAX_INT_DIGITS
    canon.append({"text": "<4300 nines>", "e_sha256": hashlib.sha256(f.e_json_text(big)).hexdigest(),
                  "tag": f.e_json_text(big)[:1].hex()})
    canon.append({"text": "<4301 nines>", "e_sha256": hashlib.sha256(f.e_json_text(big + "9")).hexdigest(),
                  "tag": f.e_json_text(big + "9")[:1].hex()})
    deep_ok = "[" * f.MAX_DEPTH + "]" * f.MAX_DEPTH
    deep_bad = "[" * (f.MAX_DEPTH + 1) + "]" * (f.MAX_DEPTH + 1)
    canon.append({"text": "<128 deep>", "e": f.e_json_text(deep_ok).hex()})
    canon.append({"text": "<129 deep>", "e": f.e_json_text(deep_bad).hex()})
    out["canonical"] = canon

    rows = []
    for name, spec, nonce in (("full", ROW_FULL, NONCE), ("null", ROW_NULL, None)):
        row = _row(spec)
        c = f.commitment(nonce, row)
        rows.append({"name": name, "nonce": _hex(nonce), "C": c.hex(), "leaf_s": f.leaf_s(row).hex(),
                     "leaf_c": f.leaf_c(row["id"], c).hex()})
    out["rows"] = rows

    leaves = [hashlib.sha256(str(i).encode()).digest() for i in range(1025)]
    out["mth"] = {str(n): f.mth(leaves[:n]).hex() for n in (0, 1, 2, 3, 5, 8, 1000, 1023, 1025)}

    out["legacy_nonce"] = {"salt": SALT.hex(), "id": ROW_FULL["id"],
                           "nonce": f.legacy_nonce(SALT, uuid.UUID(ROW_FULL["id"])).hex()}
    ids = [uuid.UUID(ROW_FULL["id"]), uuid.UUID(ROW_NULL["id"])]
    out["ids_digest"] = {"ids": [str(i) for i in ids], "digest": f.ids_digest(ids).hex(),
                         "empty": f.ids_digest([]).hex()}

    key = f.chain_key(FIXED_KEY_TEXT)
    old = f.chain_key(OLD_KEY_TEXT)
    kid, old_kid = f.key_id(key), f.key_id(old)
    out["keys"] = {"ikm": FIXED_KEY_TEXT, "key": key.hex(), "key_id": kid, "old_ikm": OLD_KEY_TEXT,
                   "old_key_id": old_kid}

    # A chain with one seal of each kind under the fixed key (the key seal moves it from the old key).
    full = _row(ROW_FULL)
    c_full = f.commitment(NONCE, full)
    hour_root_s = f.mth([f.leaf_s(full)])
    hour_root_c = f.mth([f.leaf_c(full["id"], c_full)])
    hour_ids = f.ids_digest([full["id"]])
    h13 = datetime(2026, 10, 5, 13)
    h14 = datetime(2026, 10, 5, 14)
    t = lambda m: datetime(2026, 10, 5, 15, m, 0, 250000)  # noqa: E731
    specs = [
        ("genesis", None, None, 0, 0, f.EMPTY_ROOT, f.EMPTY_ROOT, f.ids_digest([]),
         {"format": 1, "release": "0.34.0", "first_row_hour": f.hour_text(h13), "backlog_through": f.hour_text(h13),
          "backlog_rows": 1, "undated_rows": 0, "replaces": None, "grace_until": None}, old_kid),
        ("policy", None, None, 0, 0, None, None, None,
         {"state": {"audit_max_days": {"value": 0, "source": "default", "setting": None, "request_seq": None,
                                       "set_by": 2}},
          "inputs": {"AUDIT_LOG_RETENTION_DAYS": None}, "cause": "genesis", "request_seq": None, "request": None,
          "audit_row": None, "by": "server", "user_id": None}, old_kid),
        ("key", None, None, 0, 0, None, None, None, None, kid),
        ("hour", h13, h14, 1, 412, hour_root_s, hour_root_c, hour_ids, {}, kid),
        ("hour", h14, datetime(2026, 10, 5, 20), 0, 0, f.EMPTY_ROOT, f.EMPTY_ROOT, f.ids_digest([]), {}, kid),
        ("late", h13, h14, 1, 412, hour_root_s, hour_root_c, hour_ids,
         {"hour": f.hour_text(h13), "prev_seq": 4, "added": [], "by": "sealer"}, kid),
        ("prune", None, None, 0, 0, None, None, None,
         {"reason": "retention", "policy_seq": 2, "request_seq": None,
          "hours": [[f.hour_text(h13), 6, 0, 0, f.EMPTY_ROOT.hex(), f.EMPTY_ROOT.hex(), f.ids_digest([]).hex()]]}, kid),
        ("erase", None, None, 0, 0, None, None, None,
         {"hour": None, "request_seq": 2, "request_id": ROW_NULL["id"], "placeholder": "erased-0a1b2c3d",
          "bytes_now": 0, "through": f.hour_text(h13), "final": True, "rows": []}, kid),
        ("archive", None, None, 0, 0, None, None, None,
         {"day": "2026-10-05", "cause": "archive", "after_seq": None, "complete": False,
          "parts": [[0, f.hour_text(h13), f.hour_text(h13), 1, 300, hashlib.sha256(b"block").hexdigest()]]}, kid),
        ("ack", None, None, 0, 0, None, None, None,
         {"acknowledges": [6], "failures": [], "rows": [], "discarded": [], "by": "host", "user_id": None,
          "request": None}, kid),
    ]
    seals = []
    prev = f.LINK_0
    for i, (kind, ps, pe, count, nbytes, rs, rc, idd, detail, k_id) in enumerate(specs, 1):
        if kind == "key":
            proof = f.old_key_proof(old, prev, kid)
            detail = {"old_key_id": old_kid, "new_key_id": kid, "old_key_proof": proof.hex(),
                      "accepted_unverified": False, "by": "sealer"}
        dd = f.detail_digest(detail)
        b = f.body(i, kind, ps, pe, f.FORMAT, count, nbytes, rs, rc, idd, dd, k_id, t(i))
        ln = f.link(prev, b)
        signing = key if k_id == kid else old
        seals.append({"seq": i, "kind": kind, "detail": detail, "body": b.hex(), "link": ln.hex(),
                      "mac": f.mac(signing, ln).hex(), "head": f.head(i, ln)})
        prev = ln
    out["seals"] = seals
    out["day_digest"] = f.day_digest([(h13, h14, 1, hour_root_s, hour_root_c, hour_ids)]).hex()
    return out


def main(argv) -> int:
    data = build()
    if "--write" in argv:
        PATH.parent.mkdir(parents=True, exist_ok=True)
        PATH.write_text(json.dumps(data, indent=1, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8",
                        newline="\n")
        print(f"wrote {PATH}")
    else:
        print(json.dumps(data, indent=1, sort_keys=True)[:2000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
