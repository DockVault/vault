"""The challenges of key registration and envelope replacement keep their one-time key sealed.

Registering an encryption key and replacing the passphrase envelope each answer a one-time challenge: an
ECDH key confirmation against a server key that lives in the challenge row for five minutes. ECDH is
symmetric, so whoever reads a live row's key in the clear can compute the MAC the server expects, for
any public key -- with a session for the account (and its second factor, where it has one), that is enough
to have a garbage envelope accepted, which destroys the account's zero-knowledge vaults unless it holds a
recovery kit. The key-proof challenges were sealed from the start; these two tables stored it in the clear.

Now both seal it with the deployment key and read it back only through the strict decrypt, so a row
holding a key in the clear -- written by an older release before an upgrade, or by anyone who can write
the table -- is refused like a challenge that does not exist. The client asks for a fresh challenge once.
And the pruner deletes rows past their lifetime, which used to stay until the account's next
issuance. test_possession_challenges_sealed_live.py checks the same on a running deployment.
"""
import base64
import hashlib
import hmac
import inspect
import os
import re
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import sqltypes

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import ecc_router as E  # noqa: E402
from app.core import retention  # noqa: E402
from app.core.models import (AuditLog, ECCKeyUpdateChallenge, ECCRegistrationChallenge, User,  # noqa: E402
                             UserKeyPair)
from app.core.security import decrypt_secret_strict, encrypt_secret  # noqa: E402
from app.services import ecc_pop, ecc_update_pop  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
ROUTER = (ROOT / "app" / "api" / "ecc_router.py").read_text(encoding="utf-8")

REGISTER_CHALLENGE = inspect.unwrap(E.register_challenge)
UPDATE_CHALLENGE = inspect.unwrap(E.key_update_challenge)
UPDATE = inspect.unwrap(E.update_private_key)


@pytest.fixture
def world(monkeypatch):
    original = sqltypes.Uuid.bind_processor

    def bind_processor(self, dialect):
        inner = original(self, dialect)
        if inner is None:
            return None

        def process(value):
            return inner(uuid.UUID(value) if isinstance(value, str) else value)
        return process

    monkeypatch.setattr(sqltypes.Uuid, "bind_processor", bind_processor)
    monkeypatch.setattr(E, "_ecc_rate_limit", lambda *a, **k: None)
    audit = []
    monkeypatch.setattr(E, "_audit_zk", lambda db, actor, action, **kw: audit.append((action, kw.get("details"))))
    import app.api.api_server as S
    monkeypatch.setattr(S, "_enforce_step_up", lambda *a, **k: None)
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'pop.db'}", connect_args={"check_same_thread": False})
        for table in (User.__table__, UserKeyPair.__table__, ECCRegistrationChallenge.__table__,
                      ECCKeyUpdateChallenge.__table__):
            table.create(engine)
        maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        opened = []

        def session():
            opened.append(maker())
            return opened[-1]
        yield SimpleNamespace(Session=session, audit=audit)
        for s in opened:
            s.close()
        engine.dispose()


def _pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _account(world, *, with_key=False):
    s = world.Session()
    user = User(id=uuid.uuid4(), username=f"u_{uuid.uuid4().hex[:8]}", password_hash="x")
    s.add(user)
    key = ec.generate_private_key(ec.SECP384R1())
    if with_key:
        s.add(UserKeyPair(user_id=user.id, public_key=_pem(key), fingerprint="f", encrypted_private_key="old"))
    s.commit()
    return s, user, key


def _registration_mac(user_key, server_public_pem, nonce_b64, public_pem):
    shared = user_key.exchange(ec.ECDH(), serialization.load_pem_public_key(server_public_pem.encode()))
    mac_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"dv-ecc-pop-v1",
                   info=b"registration-pop").derive(shared)
    return base64.b64encode(hmac.new(mac_key, base64.b64decode(nonce_b64) + public_pem.encode(),
                                     hashlib.sha256).digest()).decode()


def _register_request(user_key, challenge_id, mac):
    return SimpleNamespace(public_key=_pem(user_key), pop=SimpleNamespace(challenge_id=challenge_id, mac=mac))


# ------------------------------------------------------------------------------------ registration

def test_a_registration_challenge_is_stored_sealed_and_answers(world):
    s, user, key = _account(world)
    out = run_coroutine(REGISTER_CHALLENGE(current_user=user, db=s))
    row = s.query(ECCRegistrationChallenge).one()
    assert "BEGIN" not in row.server_private_key
    assert decrypt_secret_strict(row.server_private_key).startswith("-----BEGIN PRIVATE KEY-----")
    mac = _registration_mac(key, out["server_ephemeral_public_key"], out["nonce"], _pem(key))
    E._verify_registration_pop(s, user, _register_request(key, out["challenge_id"], mac))
    assert s.query(ECCRegistrationChallenge).count() == 0


def test_a_registration_challenge_holding_its_key_in_the_clear_is_refused_and_used_up(world):
    """A row written in the clear -- by an older release, or by anyone who can write the table -- cannot be
    answered, even with the MAC the key in it gives."""
    s, user, key = _account(world)
    server = ec.generate_private_key(ec.SECP384R1())
    nonce = base64.b64encode(os.urandom(32)).decode()
    row = ECCRegistrationChallenge(user_id=user.id, server_private_key=_private_pem(server), nonce=nonce)
    s.add(row)
    s.commit()
    mac = _registration_mac(key, _pem(server), nonce, _pem(key))
    assert ecc_pop.verify_pop(_private_pem(server), _pem(key), nonce, mac), "the MAC itself is right"
    with pytest.raises(HTTPException) as exc:
        E._verify_registration_pop(s, user, _register_request(key, str(row.id), mac))
    assert exc.value.status_code == 400
    assert exc.value.detail == "Invalid or expired proof-of-possession challenge."
    assert s.query(ECCRegistrationChallenge).count() == 0


# ------------------------------------------------------------------------------ envelope replacement

def _update_request(world, user, key, challenge, envelope="new-envelope"):
    mac = base64.b64encode(ecc_update_pop.expected_mac(
        challenge["server_private_pem"], _pem(key), challenge["challenge_id"], challenge["nonce"],
        str(user.id), envelope)).decode()
    return E.PrivateKeyUpdateRequest(encrypted_private_key=envelope,
                                     pop=E.KeyUpdatePoP(challenge_id=challenge["challenge_id"], mac=mac))


def test_an_envelope_replacement_challenge_is_stored_sealed_and_answers(world):
    s, user, key = _account(world, with_key=True)
    out = run_coroutine(UPDATE_CHALLENGE(current_user=user, db=s))
    row = s.query(ECCKeyUpdateChallenge).one()
    assert "BEGIN" not in row.server_private_key
    challenge = dict(out, server_private_pem=decrypt_secret_strict(row.server_private_key))
    result = run_coroutine(UPDATE(request=_update_request(world, user, key, challenge), current_user=user, db=s))
    assert result["ok"] is True
    assert s.query(UserKeyPair).filter(UserKeyPair.user_id == user.id).one().encrypted_private_key == "new-envelope"


def test_an_envelope_replacement_challenge_holding_its_key_in_the_clear_is_refused(world):
    s, user, key = _account(world, with_key=True)
    server = ec.generate_private_key(ec.SECP384R1())
    nonce = base64.b64encode(os.urandom(32)).decode()
    row = ECCKeyUpdateChallenge(user_id=user.id, server_private_key=_private_pem(server), nonce=nonce)
    s.add(row)
    s.commit()
    challenge = {"challenge_id": str(row.id), "nonce": nonce, "server_private_pem": _private_pem(server)}
    with pytest.raises(HTTPException) as exc:
        run_coroutine(UPDATE(request=_update_request(world, user, key, challenge), current_user=user, db=s))
    assert exc.value.status_code == 400 and exc.value.detail == E._UPDATE_POP_FAILED
    assert world.audit[-1] == ("zk_key_update_pop_failed", {"reason": "no_live_challenge"})
    assert s.query(ECCKeyUpdateChallenge).count() == 0
    assert s.query(UserKeyPair).filter(UserKeyPair.user_id == user.id).one().encrypted_private_key == "old"


def _call_text(src, at):
    """The text of the call that starts at `at`, up to its closing parenthesis."""
    depth = 0
    for i in range(src.index("(", at), len(src)):
        depth += {"(": 1, ")": -1}.get(src[i], 0)
        if depth == 0:
            return src[at:i + 1]
    raise AssertionError("unbalanced call")


def test_every_write_of_either_table_seals_its_key():
    for model in ("ECCRegistrationChallenge(", "ECCKeyUpdateChallenge("):
        sites = [m.start() for m in re.finditer(r"(?<![\w.])" + re.escape(model), ROUTER)]
        assert len(sites) == 1, model
        call = _call_text(ROUTER, sites[0])
        assert "server_private_key=encrypt_secret(priv_pem)" in call, call
    assert ROUTER.count("server_priv = _unseal_pop_challenge_key(sealed)") == 2


# ------------------------------------------------------------------------------------------ sweep

def test_expired_challenges_of_both_tables_are_swept_and_live_ones_kept(world):
    s, user, _ = _account(world)
    now = datetime.utcnow()
    ttl = timedelta(seconds=ecc_update_pop.CHALLENGE_TTL_SECONDS)
    for model in (ECCRegistrationChallenge, ECCKeyUpdateChallenge):
        for created in (now - ttl - timedelta(seconds=1), now - ttl + timedelta(seconds=1), now):
            s.add(model(user_id=user.id, server_private_key=encrypt_secret("k"), nonce="n", created_at=created))
    s.commit()
    AuditLog.__table__.create(s.get_bind(), checkfirst=True)     # the pruner's records
    made = []

    def factory():
        made.append(sessionmaker(bind=s.get_bind(), autocommit=False, autoflush=False)())
        return made[-1]

    try:
        done = retention.prune_possession_challenges(retention.Pass(factory, now=now, batch_rows=10))
    finally:
        for other in made:
            other.close()
    s.expire_all()
    assert done.deleted == 2
    assert s.query(ECCRegistrationChallenge).count() == 2 and s.query(ECCKeyUpdateChallenge).count() == 2
    tables = {r.details["table"] for r in s.query(AuditLog).filter(AuditLog.action == "retention_pruned")}
    assert tables == {"ecc_registration_challenges", "ecc_key_update_challenges"}


def test_the_sweep_never_cuts_a_challenge_short():
    """One lifetime serves both tables: neither kind of challenge may live longer than what the sweep keeps."""
    assert E._POP_CHALLENGE_TTL_SECONDS == ecc_update_pop.CHALLENGE_TTL_SECONDS


def test_the_pruner_sweeps_them_and_the_periodic_loop_does_not():
    job = next(j for j in retention.JOBS if j.name == "possession_challenges")
    # A working record: the hold switch, which stops the jobs over logs, does not stop it.
    assert job.run is retention.prune_possession_challenges and job.held is False
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    reaper = src[src.index("async def cleanup_expired_sessions"):]
    reaper = reaper[:reaper.index("\ndef ")]
    for name in ("ECCRegistrationChallenge", "ECCKeyUpdateChallenge", "possession_challenge"):
        assert name not in reaper, name


def _function(name):
    decl = re.search(r"^(async )?function " + re.escape(name) + r"\(", APP, re.M)
    assert decl, name
    rest = APP[decl.end():]
    nxt = re.search(r"^(async )?function |^(const|let|var) |^// =====", rest, re.M)
    return APP[decl.start():decl.end() + (nxt.start() if nxt else len(rest))]


def test_the_client_asks_for_a_fresh_challenge_once_and_only_once():
    for name, route in (("zkRegisterNewKeypair", "'/ecc/keys/register'"),
                        ("zkPutPrivateEnvelope", "'/ecc/keys/private'")):
        fn = _function(name)
        loop = fn[fn.index("for (let attempt = 0; ; attempt++) {"):]
        assert loop.index("/challenge'") < loop.index(route + ", {"), name
        assert "if (attempt === 0 && zkIsPossessionChallengeRefusal(e)) continue;" in loop, name
        assert "throw e;" in loop[loop.index("zkIsPossessionChallengeRefusal(e)"):], name


def test_the_refusals_the_client_retries_are_the_servers_challenge_refusals():
    """Every text the retry matches is one the server (this release or an older one) gives for a
    challenge, and nothing else it gives for these routes."""
    fn = _function("zkIsPossessionChallengeRefusal")
    prefixes = re.findall(r"err\.message\.startsWith\('([^']+)'\)", fn)
    assert len(prefixes) == 3 and "err.status !== 400" in fn
    server_texts = [
        "Invalid or expired proof-of-possession challenge.",
        "Proof-of-possession challenge has expired; request a new one.",
        "Proof of possession failed for this public key.",
        E._UPDATE_POP_FAILED,
    ]
    for text in server_texts:
        assert text in ROUTER, text
        assert any(text.startswith(p) for p in prefixes), text
    others = ["Proof of possession is required to register a key.", "Invalid proof-of-possession challenge.",
              "pop.challenge_id and pop.mac are required", "encrypted_private_key is too large"]
    for text in others:
        assert not any(text.startswith(p) for p in prefixes), text
