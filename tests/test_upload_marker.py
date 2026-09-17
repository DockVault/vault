"""Unit contract for the in-flight upload marker + same-name lock, offline with a fake Redis.

Proves the crypto (the final name round-trips, is BOUND to its (vault, folder) so a marker cannot be
replayed into another folder, and never appears in cleartext at rest), the lock (a deterministic
KEYED hash, folder-sensitive; a second same-name upload is refused with the holder's member), and
the outage posture (breaker open => place SKIPS and fails OPEN, listing empty, remove is inert).
The live behaviour (a real SFTP upload publishes/removes the marker) is a live-lane test.
"""
import json
import uuid

import pytest

pytestmark = pytest.mark.unit

import _bare_api_env  # noqa: E402
_bare_api_env.set_bare_api_env()

from app.core import upload_marker as um  # noqa: E402
from app.core import security  # noqa: E402
from app.core import redis_guard  # noqa: E402


class _FakeRedis:
    """A dict-backed stand-in with just the ops the marker module uses, honouring SET NX + EX."""
    def __init__(self):
        self.store = {}

    def set(self, key, val, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = val
        return True

    def get(self, key):
        return self.store.get(key)

    def delete(self, *keys):
        n = 0
        for k in keys:
            if k in self.store:
                del self.store[k]
                n += 1
        return n

    def expire(self, key, ttl):
        return key in self.store

    def scan_iter(self, match=None, count=None):
        import fnmatch
        return [k for k in list(self.store) if match is None or fnmatch.fnmatch(k, match)]

    def mget(self, keys):
        return [self.store.get(k) for k in keys]


@pytest.fixture
def fake_redis(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr(um, "redis_client", r)
    # Guard closed by default (no breaker, no private-memory failure), so best_effort runs the op.
    monkeypatch.setattr(redis_guard, "guard_is_open", lambda _now: False)
    return r


def test_marker_name_round_trips_and_is_bound_to_its_vault_and_folder():
    v1, v2 = uuid.uuid4(), uuid.uuid4()
    f1, f2 = uuid.uuid4(), uuid.uuid4()
    name = "Quarterly Report.xlsx"
    token = security.encrypt_upload_marker_name(v1, f1, name)

    assert security.decrypt_upload_marker_name(v1, f1, token) == name   # round-trips in its own slot
    assert name not in token                                            # ciphertext, not the name
    for wrong in ((v1, f2), (v2, f1), (v2, f2)):
        with pytest.raises(Exception):
            security.decrypt_upload_marker_name(wrong[0], wrong[1], token)   # AAD binds (vault, folder)


def test_root_folder_none_round_trips_as_its_own_slot():
    v = uuid.uuid4()
    name = "root-file.bin"
    token = security.encrypt_upload_marker_name(v, None, name)
    assert security.decrypt_upload_marker_name(v, None, token) == name
    # A real folder is a DIFFERENT slot than the root, so a root marker never decrypts under one.
    with pytest.raises(Exception):
        security.decrypt_upload_marker_name(v, uuid.uuid4(), token)


def test_lock_index_is_deterministic_keyed_and_folder_and_name_sensitive():
    import hashlib
    v, f, f2 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    name = "同名.pdf"
    idx = security.upload_marker_lock_index(v, f, name)

    assert idx == security.upload_marker_lock_index(v, f, name)          # deterministic
    assert len(idx) == 64 and int(idx, 16) >= 0                          # hex sha256 digest
    assert idx != name and idx != hashlib.sha256(name.encode()).hexdigest()  # KEYED, not the plaintext/unkeyed
    assert idx != security.upload_marker_lock_index(v, f, name + "x")    # name-sensitive
    assert idx != security.upload_marker_lock_index(v, f2, name)         # folder-sensitive
    assert idx != security.upload_marker_lock_index(uuid.uuid4(), f, name)  # vault-sensitive


def test_place_acquires_then_a_second_same_name_is_refused_with_the_holder(fake_redis):
    v, f = uuid.uuid4(), uuid.uuid4()
    alice, bob = uuid.uuid4(), uuid.uuid4()

    assert um.place(v, f, "report.pdf", alice) is None          # first upload acquires the lock
    assert um.place(v, f, "report.pdf", bob) == str(alice)      # second is refused, names the holder
    assert um.place(v, f, "other.pdf", bob) is None             # a different name is free
    # A different folder with the same name is a different slot -> free.
    assert um.place(v, uuid.uuid4(), "report.pdf", bob) is None


def test_the_final_name_is_never_stored_in_cleartext_with_a_positive_control(fake_redis):
    v, f = uuid.uuid4(), uuid.uuid4()
    member = uuid.uuid4()
    name = "SECRET-payroll-2026.csv"
    assert um.place(v, f, name, member) is None

    def _appears_in_store(needle):
        for k, val in fake_redis.store.items():
            if needle in str(k) or needle in str(val):
                return True
        return False

    assert not _appears_in_store(name), "the cleartext final name leaked into Redis"
    # (The member ID may appear -- it is an opaque id, not a name; the brief forbids the cleartext
    # filename and the member USERNAME at rest, not the member id.)
    # Positive control: the scanner is not vacuously passing -- a value known present IS found.
    fake_redis.store["__control__"] = name
    assert _appears_in_store(name)

    # And the listing recovers the correct final name for an authorized viewer.
    del fake_redis.store["__control__"]
    rows = um.list_folder(v, f)
    assert len(rows) == 1
    assert security.decrypt_upload_marker_name(v, f, rows[0]["enc_name"]) == name
    assert rows[0]["member_id"] == str(member)


def test_listing_is_scoped_to_its_folder(fake_redis):
    v = uuid.uuid4()
    f1, f2 = uuid.uuid4(), uuid.uuid4()
    um.place(v, f1, "a.txt", uuid.uuid4())
    um.place(v, f1, "b.txt", uuid.uuid4())
    um.place(v, f2, "c.txt", uuid.uuid4())
    assert len(um.list_folder(v, f1)) == 2
    assert len(um.list_folder(v, f2)) == 1
    assert um.list_folder(v, uuid.uuid4()) == []


def test_remove_clears_the_marker_and_frees_the_lock(fake_redis):
    v, f = uuid.uuid4(), uuid.uuid4()
    a, b = uuid.uuid4(), uuid.uuid4()
    assert um.place(v, f, "x.bin", a) is None
    um.remove(v, f, "x.bin")
    assert um.list_folder(v, f) == []
    assert um.place(v, f, "x.bin", b) is None      # freed: the next upload may claim it


def test_holder_reads_the_lock_without_taking_it(fake_redis):
    v, f = uuid.uuid4(), uuid.uuid4()
    m = uuid.uuid4()
    assert um.holder(v, f, "x.pdf") is None             # free
    assert um.place(v, f, "x.pdf", m) is None
    assert um.holder(v, f, "x.pdf") == str(m)           # held -> names the member
    # holder() must NOT acquire: a free name it read stays claimable.
    assert um.holder(v, f, "y.pdf") is None
    assert um.place(v, f, "y.pdf", uuid.uuid4()) is None


def test_holder_fails_open_on_an_outage(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr(um, "redis_client", r)
    monkeypatch.setattr(redis_guard, "guard_is_open", lambda _now: True)
    # SKIPPED, not None: a caller must be able to tell "Redis down" (fail open) from "name free".
    assert um.holder(uuid.uuid4(), uuid.uuid4(), "x") is um.SKIPPED


def test_breaker_open_skips_place_fails_open_listing_empty_remove_inert(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr(um, "redis_client", r)
    monkeypatch.setattr(redis_guard, "guard_is_open", lambda _now: True)   # outage: guard open

    v, f = uuid.uuid4(), uuid.uuid4()
    assert um.place(v, f, "x.bin", uuid.uuid4()) is um.SKIPPED   # fail OPEN, no marker written
    assert r.store == {}                                          # nothing touched Redis
    assert um.list_folder(v, f) == []                             # listing shows no rows during outage
    um.remove(v, f, "x.bin")                                      # inert, never raises
    um.refresh_key(um.marker_key(v, f, "x.bin"))                  # inert, never raises


def test_marker_ttl_is_readable_and_positive():
    assert um.marker_ttl_seconds() > 0
