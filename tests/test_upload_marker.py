"""Unit contract for the in-flight upload marker + same-name lock, offline with a fake Redis.

Proves the crypto (the final name round-trips, is BOUND to its (vault, folder) so a marker cannot be
replayed into another folder, and never appears in cleartext at rest), the lock (a deterministic
KEYED hash, folder-sensitive; a second same-name upload is refused with the holder's member),
enumeration by a per-folder INDEX SET (not a keyspace SCAN), the OWNERSHIP TOKEN (a stale close can
never delete or extend a marker that has become another holder's), and the outage posture (breaker
open => place SKIPS and fails OPEN, listing empty, remove/refresh inert). The live behaviour is a
live-lane test.
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
    """A dict-backed stand-in with the ops the marker module uses: string keys (SET NX/EX, GET, MGET),
    the per-folder index SET (SADD/SREM/SMEMBERS/EXPIRE), and a script runner for the token-checked
    compare-and-delete / compare-and-refresh scripts (emulated in Python)."""
    def __init__(self):
        self.store = {}
        self.sets = {}

    def set(self, key, val, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = val
        return True

    def get(self, key):
        return self.store.get(key)

    def mget(self, keys):
        return [self.store.get(k) for k in keys]

    def expire(self, key, ttl):
        return key in self.store or key in self.sets

    def sadd(self, key, *vals):
        self.sets.setdefault(key, set()).update(vals)
        return len(vals)

    def srem(self, key, *vals):
        s = self.sets.get(key, set())
        n = 0
        for v in vals:
            if v in s:
                s.discard(v)
                n += 1
        return n

    def smembers(self, key):
        return set(self.sets.get(key, set()))

    def eval(self, script, numkeys, *args):
        keys, argv = list(args[:numkeys]), list(args[numkeys:])
        mkey, ikey, token = keys[0], (keys[1] if len(keys) > 1 else None), argv[0]
        v = self.store.get(mkey)
        if not v:
            return 0
        try:
            if json.loads(v).get("t") != token:      # not our marker any more -> no-op
                return 0
        except Exception:
            return 0
        if "DEL" in script:                           # compare-and-delete
            self.store.pop(mkey, None)
            if ikey in self.sets:
                self.sets[ikey].discard(mkey)
        return 1                                      # (EXPIRE branch: no real TTL to move in the fake)


@pytest.fixture
def fake_redis(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr(um, "redis_client", r)
    monkeypatch.setattr(redis_guard, "guard_is_open", lambda _now: False)
    return r


def _appears_anywhere(r, needle):
    for k, val in r.store.items():
        if needle in str(k) or needle in str(val):
            return True
    for k, members in r.sets.items():
        if needle in str(k) or any(needle in str(m) for m in members):
            return True
    return False


def test_marker_name_round_trips_and_is_bound_to_its_vault_and_folder():
    v1, v2 = uuid.uuid4(), uuid.uuid4()
    f1, f2 = uuid.uuid4(), uuid.uuid4()
    name = "Quarterly Report.xlsx"
    token = security.encrypt_upload_marker_name(v1, f1, name)
    assert security.decrypt_upload_marker_name(v1, f1, token) == name
    assert name not in token
    for wrong in ((v1, f2), (v2, f1), (v2, f2)):
        with pytest.raises(Exception):
            security.decrypt_upload_marker_name(wrong[0], wrong[1], token)


def test_root_folder_none_round_trips_as_its_own_slot():
    v = uuid.uuid4()
    name = "root-file.bin"
    token = security.encrypt_upload_marker_name(v, None, name)
    assert security.decrypt_upload_marker_name(v, None, token) == name
    with pytest.raises(Exception):
        security.decrypt_upload_marker_name(v, uuid.uuid4(), token)


def test_lock_index_is_deterministic_keyed_and_folder_and_name_sensitive():
    import hashlib
    v, f, f2 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    name = "同名.pdf"
    idx = security.upload_marker_lock_index(v, f, name)
    assert idx == security.upload_marker_lock_index(v, f, name)
    assert len(idx) == 64 and int(idx, 16) >= 0
    assert idx != name and idx != hashlib.sha256(name.encode()).hexdigest()
    assert idx != security.upload_marker_lock_index(v, f, name + "x")
    assert idx != security.upload_marker_lock_index(v, f2, name)
    assert idx != security.upload_marker_lock_index(uuid.uuid4(), f, name)


def test_place_acquires_then_a_second_same_name_is_refused_with_the_holder(fake_redis):
    v, f = uuid.uuid4(), uuid.uuid4()
    alice, bob = uuid.uuid4(), uuid.uuid4()
    outcome, token = um.place(v, f, "report.pdf", alice)
    assert outcome is None and token                     # acquired, with an ownership token
    assert um.place(v, f, "report.pdf", bob)[0] == str(alice)   # second refused, names the holder
    assert um.place(v, f, "other.pdf", bob)[0] is None          # a different name is free
    assert um.place(v, uuid.uuid4(), "report.pdf", bob)[0] is None  # a different folder is a different slot


def test_the_final_name_is_never_stored_in_cleartext_with_a_positive_control(fake_redis):
    v, f = uuid.uuid4(), uuid.uuid4()
    member = uuid.uuid4()
    name = "SECRET-payroll-2026.csv"
    assert um.place(v, f, name, member)[0] is None
    assert not _appears_anywhere(fake_redis, name), "the cleartext final name leaked into Redis"
    fake_redis.store["__control__"] = name
    assert _appears_anywhere(fake_redis, name)           # positive control: the scanner works
    del fake_redis.store["__control__"]
    rows = um.list_folder(v, f)
    assert len(rows) == 1
    assert security.decrypt_upload_marker_name(v, f, rows[0]["enc_name"]) == name
    assert rows[0]["member_id"] == str(member)


def test_listing_reads_the_folder_index_not_a_keyspace_scan(fake_redis):
    v = uuid.uuid4()
    f1, f2 = uuid.uuid4(), uuid.uuid4()
    um.place(v, f1, "a.txt", uuid.uuid4())
    um.place(v, f1, "b.txt", uuid.uuid4())
    um.place(v, f2, "c.txt", uuid.uuid4())
    assert um.index_key(v, f1) in fake_redis.sets and len(fake_redis.sets[um.index_key(v, f1)]) == 2
    assert len(um.list_folder(v, f1)) == 2
    assert len(um.list_folder(v, f2)) == 1
    assert um.list_folder(v, uuid.uuid4()) == []


def test_listing_prunes_a_stale_index_entry_whose_marker_expired(fake_redis):
    v, f = uuid.uuid4(), uuid.uuid4()
    um.place(v, f, "gone.txt", uuid.uuid4())
    mkey = um.marker_key(v, f, "gone.txt")
    del fake_redis.store[mkey]                    # the marker expired but its index entry lingers
    assert um.list_folder(v, f) == []             # MGET None -> dropped from the listing
    assert mkey not in fake_redis.sets[um.index_key(v, f)]   # ...and pruned from the index lazily


def test_the_holders_own_close_removes_the_marker_and_index_and_frees_the_lock(fake_redis):
    v, f = uuid.uuid4(), uuid.uuid4()
    a, b = uuid.uuid4(), uuid.uuid4()
    _, token = um.place(v, f, "x.bin", a)
    um.remove(v, f, "x.bin", token)
    assert um.list_folder(v, f) == []
    assert um.marker_key(v, f, "x.bin") not in fake_redis.sets.get(um.index_key(v, f), set())
    assert um.place(v, f, "x.bin", b)[0] is None   # freed: the next upload may claim it


def test_a_stale_close_never_removes_a_new_holders_marker(fake_redis):
    # The stale-close scenario: A places, A's marker expires (a client stalled past the TTL with no
    # heartbeat), B places the SAME name and now owns the marker, then A's LATE close() fires. The
    # ownership token makes A's remove a no-op, so B's marker and index entry survive.
    v, f = uuid.uuid4(), uuid.uuid4()
    a, b = uuid.uuid4(), uuid.uuid4()
    _, tok_a = um.place(v, f, "same.bin", a)
    mkey = um.marker_key(v, f, "same.bin")
    fake_redis.store.pop(mkey)                                  # A's marker expires (TTL)
    fake_redis.sets.get(um.index_key(v, f), set()).discard(mkey)
    outcome_b, tok_b = um.place(v, f, "same.bin", b)            # B re-claims the freed name
    assert outcome_b is None and tok_b != tok_a

    um.remove(v, f, "same.bin", tok_a)                          # A's stale close -> must be a no-op
    rows = um.list_folder(v, f)
    assert len(rows) == 1 and rows[0]["member_id"] == str(b), "a stale close deleted the new holder's marker"

    um.remove(v, f, "same.bin", tok_b)                          # B's own close removes it
    assert um.list_folder(v, f) == []


def test_remove_is_atomic_not_a_get_then_delete_race(monkeypatch):
    # Pins ATOMICITY, not just the token check (test_a_stale_close_... passes even for a GET-then-DEL
    # remove, because the plain fake is single-threaded). Here get() and the script runner fire a
    # one-shot hook that expires A's marker and lets B claim the SAME name mid-operation. The shipped
    # one-script remove() reads-and-deletes in ONE atomic step, so it sees B's token and no-ops -> B's
    # marker and index entry survive. A GET-then-DEL remove() reads A's stale value and then deletes
    # the key unconditionally on the match -> it destroys B's marker.
    # (mutation: rewrite remove() as redis_client.get(...) then redis_client.delete(...) -> red.)
    import json as _json
    from app.core import security as _sec

    v, f = uuid.uuid4(), uuid.uuid4()
    a, b = uuid.uuid4(), uuid.uuid4()
    name = "raced.bin"
    tok_b = "bbbbbbbbbbbbbbbb"

    class _Interleaving(_FakeRedis):
        def __init__(self):
            super().__init__()
            self._hook = None

        def _fire(self):
            if self._hook:
                h, self._hook = self._hook, None
                h()

        def get(self, key):
            v_ = super().get(key)
            self._fire()          # the window a two-call (GET-then-DEL) shape opens is right here
            return v_

        def eval(self, script, numkeys, *args):
            self._fire()          # an atomic script sees B's concurrent claim serialized before its read
            return super().eval(script, numkeys, *args)

    r = _Interleaving()
    monkeypatch.setattr(um, "redis_client", r)
    monkeypatch.setattr(redis_guard, "guard_is_open", lambda _now: False)
    _, tok_a = um.place(v, f, name, a)
    mkey, ikey = um.marker_key(v, f, name), um.index_key(v, f)

    def _b_claims():
        # A's marker expired; B claims the same name (same key, B's token) mid-operation.
        r.store[mkey] = _json.dumps({"n": _sec.encrypt_upload_marker_name(v, f, name), "m": str(b), "t": tok_b})
        r.sets.setdefault(ikey, set()).add(mkey)
    r._hook = _b_claims

    um.remove(v, f, name, tok_a)   # A's close, racing B's claim

    # The atomic remove saw B's token and no-oped: B's marker and its index entry survive.
    assert mkey in r.store and _json.loads(r.store[mkey])["t"] == tok_b, \
        "the atomic remove deleted the new holder's marker (a GET-then-DEL race)"
    assert mkey in r.sets.get(ikey, set())


def test_a_stale_refresh_never_extends_a_new_holders_marker(fake_redis):
    # The refresh twin: a stale holder's heartbeat must not touch the new holder's marker. (The fake
    # has no real TTL, so we assert the token-checked script reports a no-op for the wrong token and a
    # match for the right one.)
    v, f = uuid.uuid4(), uuid.uuid4()
    _, tok = um.place(v, f, "hb.bin", uuid.uuid4())
    mkey, ikey = um.marker_key(v, f, "hb.bin"), um.index_key(v, f)
    assert fake_redis.eval(um._CAD_REFRESH, 2, mkey, ikey, "wrong-token", "900") == 0
    assert fake_redis.eval(um._CAD_REFRESH, 2, mkey, ikey, tok, "900") == 1


def test_holder_reads_the_lock_without_taking_it(fake_redis):
    v, f = uuid.uuid4(), uuid.uuid4()
    m = uuid.uuid4()
    assert um.holder(v, f, "x.pdf") is None
    assert um.place(v, f, "x.pdf", m)[0] is None
    assert um.holder(v, f, "x.pdf") == str(m)
    assert um.holder(v, f, "y.pdf") is None
    assert um.place(v, f, "y.pdf", uuid.uuid4())[0] is None


def test_holder_fails_open_on_an_outage(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr(um, "redis_client", r)
    monkeypatch.setattr(redis_guard, "guard_is_open", lambda _now: True)
    assert um.holder(uuid.uuid4(), uuid.uuid4(), "x") is um.SKIPPED


def test_place_retries_the_claim_when_the_marker_expires_between_setnx_and_holder_read(monkeypatch):
    # SET NX loses but the holder GET then misses (the marker expired in between): place must retry
    # the claim once rather than proceed markerless. Emulate by losing the first SET NX while the key
    # is absent (so GET misses), then winning the retry.
    r = _FakeRedis()
    monkeypatch.setattr(um, "redis_client", r)
    monkeypatch.setattr(redis_guard, "guard_is_open", lambda _now: False)
    calls = {"n": 0}
    real_set = r.set

    def _flaky_set(key, val, nx=False, ex=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return None          # lose the first SET NX, key absent -> GET misses
        return real_set(key, val, nx=nx, ex=ex)

    r.set = _flaky_set
    v, f = uuid.uuid4(), uuid.uuid4()
    outcome, token = um.place(v, f, "retry.bin", uuid.uuid4())
    assert outcome is None and token          # the retry claimed it
    assert calls["n"] == 2                     # exactly one retry


def test_breaker_open_skips_place_fails_open_listing_empty_remove_inert(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr(um, "redis_client", r)
    monkeypatch.setattr(redis_guard, "guard_is_open", lambda _now: True)   # outage: guard open
    v, f = uuid.uuid4(), uuid.uuid4()
    outcome, token = um.place(v, f, "x.bin", uuid.uuid4())
    assert outcome is um.SKIPPED and token is None    # fail OPEN, no marker
    assert r.store == {} and r.sets == {}
    assert um.list_folder(v, f) == []
    um.remove(v, f, "x.bin", "any-token")             # inert, never raises
    um.refresh(v, f, "x.bin", "any-token")            # inert, never raises


def test_marker_ttl_is_readable_and_positive():
    assert um.marker_ttl_seconds() > 0


def test_the_default_ttl_is_one_number_wherever_it_is_written():
    # It is 300 now that a stalled upload's marker is removed by the write-progress watchdog, and
    # the TTL only reaps a marker nothing was left alive to remove. The number lives in the
    # settings, in this module's own fallback, and in the example environment file.
    from pathlib import Path
    from app.core.config import Settings
    fields = Settings.model_fields
    assert fields["upload_marker_ttl_seconds"].default == 300
    assert um._DEFAULT_TTL_SECONDS == 300
    example = (Path(__file__).resolve().parent.parent / ".env.example").read_text(encoding="utf-8")
    lines = [ln for ln in example.splitlines() if ln.startswith("UPLOAD_MARKER_TTL_SECONDS=")]
    assert lines == ["UPLOAD_MARKER_TTL_SECONDS=300"]


def test_a_stalled_upload_keeps_its_name_until_the_watchdog_has_failed_it():
    # Both sides, from the shipped constants. The marker is refreshed by writes, at most once per
    # TTL/divisor, so it is GUARANTEED only TTL - TTL/divisor past the last write. The watchdog
    # works in fixed windows, so from the last write it can take: the rest of a window that has
    # already cleared (up to a whole one), then a whole empty window, then one sweep interval.
    # If the first is shorter than the second, there are seconds in which a stalled upload has
    # lost its name but is not yet failed, and a second upload of that name is admitted -- to
    # lose at the unique index, instead of being refused at open with the holder named.
    #
    # At the defaults this is 270 s against 245 s -- 241.8 s MEASURED on a live stack (one record,
    # then silence, product defaults). The 25 s between is for a loaded server whose sweep arrives
    # late: this test cannot see that, only a changed setting. It was 250 s (divisor 6) once,
    # and 8 s of real margin was judged too little. A longer window has to come with a longer
    # TTL (or a larger divisor), and this is the test that says so.
    from app.core.config import Settings
    from app.sftp import sftp_server as srv
    ttl = Settings.model_fields["upload_marker_ttl_seconds"].default
    window = Settings.model_fields["sftp_write_progress_timeout_seconds"].default
    guaranteed = ttl - ttl // srv._MARKER_REFRESH_DIVISOR
    slowest_verdict = 2 * window + srv._WriteProgressWatchdog.MAX_SWEEP_SECONDS
    assert guaranteed >= slowest_verdict, (guaranteed, slowest_verdict)


def test_the_fallback_ttl_is_used_when_the_setting_is_unusable(monkeypatch):
    monkeypatch.setattr(um.settings, "upload_marker_ttl_seconds", 0)
    assert um.marker_ttl_seconds() == 300
    monkeypatch.setattr(um.settings, "upload_marker_ttl_seconds", 45)
    assert um.marker_ttl_seconds() == 45


# ---- how a refusal names the holder: one rule, both doors -----------------------------------------------------

class _NameDB:
    def __init__(self, user=None, raise_=False):
        self._user, self._raise = user, raise_

    def query(self, *a):
        if self._raise:
            raise RuntimeError("the lookup failed")
        return self

    def filter(self, *a):
        return self

    def first(self):
        return self._user


def test_a_same_name_refusal_names_the_holder_only_to_a_member_grade_viewer():
    # The web refusal used to name the holder's username to ANY caller -- a scoped credential
    # could learn a member's username from a file name it was refused -- while the SFTP refusal
    # gated it. Both doors now ask this one function. (mutation: drop the is_scoped gate -> the
    # scoped case names alice -> red. mutation: fall back to the email -> red.)
    from types import SimpleNamespace
    member = SimpleNamespace(_is_temp_session=False, _temp_scope=None)                   # interactive member
    scoped = SimpleNamespace(_is_temp_session=True, _temp_scope={"pages": ["vaults"]})   # scoped credential
    alice = SimpleNamespace(username="alice", email="alice@example.com")
    assert um.holder_display_name(_NameDB(alice), "id", member) == "alice"
    assert um.holder_display_name(_NameDB(alice), "id", scoped) == "another member"
    assert um.holder_display_name(_NameDB(SimpleNamespace(username=None, email="b@x")), "id", member) == "another member"
    assert um.holder_display_name(_NameDB(None), "id", member) == "another member"
    assert um.holder_display_name(_NameDB(raise_=True), "id", member) == "another member"   # never a 500


def test_both_doors_ask_the_one_rule_and_neither_looks_the_name_up_itself():
    # Smoke alarm on comment-free code: the web upload-init refusal and the SFTP refusal both call
    # holder_display_name, and no `.username` lookup for a marker holder remains inline at either.
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    api = "\n".join(ln for ln in (root / "app/api/api_server.py").read_text(encoding="utf-8").splitlines()
                    if not ln.lstrip().startswith("#"))
    site = api[api.index("_holder = _um.holder(vault_id, folder_uuid, body.file_name)"):]
    site = site[:site.index("raise HTTPException(")]
    assert "_who = _um.holder_display_name(db, _holder, current_user)" in site
    assert "username" not in site and "User).filter" not in site, site
    sftp = "\n".join(ln for ln in (root / "app/sftp/sftp_server.py").read_text(encoding="utf-8").splitlines()
                     if not ln.lstrip().startswith("#"))
    body = sftp[sftp.index("def _resolve_member_name(db, member_id, viewer):"):]
    body = body[:body.index("\n    def ", 10)]
    assert "return upload_marker.holder_display_name(db, member_id, viewer)" in body
    assert "is_scoped" not in body and "username" not in body.split('"""')[-1]
