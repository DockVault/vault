"""Two hardening invariants for the device sync credential path.

1. The per-device credential cap must count only OUTSTANDING credentials — active, unspent, and
   unexpired. A single-use cred is spent by its one SFTP auth, which flips is_used True but leaves
   is_active True until the lazy expiry sweep; if the cap counted spent creds, a device that mints
   and uses credentials in the normal way would false-hit the cap (a 409 stall) within the hour
   despite holding nothing live. And the client may request a SHORTER validity, clamped so it can
   only shorten and never extend past the server default.

2. A secret rotation may be driven only from the CURRENT device secret. A refresh authenticated
   with the PREVIOUS (in-grace) secret is refused with a DISTINCT typed reason, so two holders of
   one secret cannot leapfrog by each rotating inside the grace window (which would keep the
   past-grace reuse check from ever seeing a stale secret), and a device that lost a rotation
   response is routed to the owner-restore path rather than read as an unknown secret.

Style follows the rest of the suite (see test_locked_reread_is_fresh / test_device_secret): a small
in-process behaviour probe pins the mechanism the fix rests on, and a source rule pins that the
live code actually uses it — because the full DB-backed route (register -> grant -> mint -> spend ->
cap, and rotate -> refresh-in-grace) can only run against the live throwaway stack at verify time.
"""
import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
AUTH_SERVICE = ROOT / "app" / "services" / "auth_service.py"
API_SERVER = ROOT / "app" / "api" / "api_server.py"


def _flat(path: Path) -> str:
    """The file as one whitespace-collapsed line, so a multi-line expression reads as one."""
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


# ---- Cap: only outstanding (active + unspent + unexpired) credentials count ----------------------
def test_cap_filter_counts_only_active_unspent_unexpired():
    """The behaviour the per-device cap rests on: a spent (is_used) credential drops out of the
    count, so a device that mints-and-uses does not stall against the cap.

    A throwaway table mirrors the columns the cap query touches (device_id, is_active, is_used,
    expires_at); the assertion runs the EXACT filter predicate the mint uses. The source rule below
    pins that the live query is that predicate.
    """
    sa = pytest.importorskip("sqlalchemy")
    from sqlalchemy.orm import declarative_base, sessionmaker

    Base = declarative_base()

    class TempCred(Base):
        __tablename__ = "device_cap_probe"
        id = sa.Column(sa.Integer, primary_key=True)
        device_id = sa.Column(sa.String)
        is_active = sa.Column(sa.Boolean)
        is_used = sa.Column(sa.Boolean)
        expires_at = sa.Column(sa.DateTime)

    engine = sa.create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    s = Session()

    now = datetime.utcnow()
    future = now + timedelta(hours=1)
    past = now - timedelta(hours=1)
    DEV, OTHER = "dev-1", "dev-2"
    s.add_all([
        TempCred(id=1, device_id=DEV, is_active=True, is_used=False, expires_at=future),   # outstanding -> counts
        TempCred(id=2, device_id=DEV, is_active=True, is_used=True, expires_at=future),     # SPENT -> must NOT count
        TempCred(id=3, device_id=DEV, is_active=True, is_used=False, expires_at=past),      # expired -> must NOT count
        TempCred(id=4, device_id=DEV, is_active=False, is_used=False, expires_at=future),   # revoked -> must NOT count
        TempCred(id=5, device_id=OTHER, is_active=True, is_used=False, expires_at=future),  # another device -> isolated
    ])
    s.commit()

    def outstanding_for(dev):
        return s.query(TempCred).filter(
            TempCred.device_id == dev,
            TempCred.is_active == True,   # noqa: E712
            TempCred.is_used == False,    # noqa: E712
            TempCred.expires_at > datetime.utcnow(),
        ).count()

    # Only the single outstanding row counts for this device — the spent, expired, revoked, and
    # other-device rows are all excluded.
    assert outstanding_for(DEV) == 1
    assert outstanding_for(OTHER) == 1  # device isolation: one path never counts another's creds

    # Spend the last outstanding cred: the count drops to zero, so a fresh mint is NOT blocked —
    # this is the regression the is_used filter closes (a spent cred was stalling the cap for its TTL).
    s.query(TempCred).filter(TempCred.id == 1).update({"is_used": True})
    s.commit()
    assert outstanding_for(DEV) == 0

    s.close()
    engine.dispose()


def test_cap_query_in_source_filters_on_is_used():
    """The live per-device cap query must filter is_active AND is_used == False AND expires_at.

    Pinned as a source rule because the count runs in a method that needs the full application to
    import; a refactor that dropped the is_used clause would silently reopen the 409-stall and pass
    every pure test otherwise.
    """
    flat = _flat(AUTH_SERVICE)
    device_cap_queries = [
        q for q in re.findall(r"query\(TemporaryCredential\)\.filter\([^;]{0,400}?\.count\(\)", flat)
        if "device_id == device.id" in q
    ]
    assert device_cap_queries, "did not find the per-device cap count query (rule matched nothing)"
    for q in device_cap_queries:
        assert "is_used == False" in q, f"per-device cap count no longer excludes spent creds:\n  {q}"
        assert "is_active == True" in q, f"per-device cap count no longer requires active:\n  {q}"
        assert "expires_at >" in q, f"per-device cap count no longer excludes expired:\n  {q}"


# ---- Validity: a client may only SHORTEN the TTL, never extend it --------------------------------
def _clamp(requested, server_default):
    """Mirrors the one-line clamp in mint_device_sync_credential (pinned in source by the rule
    below). Kept here so the arithmetic the source line must implement is asserted directly."""
    if requested is not None:
        return max(1, min(int(requested), server_default))
    return server_default


def test_validity_clamp_shortens_but_never_extends():
    DEFAULT = 60
    assert _clamp(None, DEFAULT) == DEFAULT     # unset -> the server value, unchanged
    assert _clamp(5, DEFAULT) == 5              # a shorter request is honoured
    assert _clamp(60, DEFAULT) == DEFAULT       # equal to the ceiling stays
    assert _clamp(600, DEFAULT) == DEFAULT      # a LONGER request is clamped down, never extends
    assert _clamp(1, DEFAULT) == 1              # the floor
    assert _clamp(10 ** 9, DEFAULT) == DEFAULT  # an absurd request is still clamped to the ceiling


def test_mint_clamps_validity_shorten_only_in_source():
    """The mint must clamp a client validity to [1, server default] — shorten-only."""
    flat = _flat(AUTH_SERVICE)
    assert "server_validity = settings.temp_cred_validity_minutes" in flat, (
        "the mint no longer reads the server validity ceiling"
    )
    assert "max(1, min(int(validity_minutes), server_validity))" in flat, (
        "the mint no longer clamps a client validity_minutes to [1, server default] (shorten-only)"
    )


def test_mint_route_threads_validity_and_model_accepts_it():
    """The route must pass the client's validity_minutes into the mint, and the request model accept it."""
    flat = _flat(API_SERVER)
    assert "validity_minutes=body.validity_minutes" in flat, (
        "the mint route no longer forwards the client's validity_minutes"
    )
    assert re.search(r"class DeviceSyncCredentialRequest\(BaseModel\):.{0,400}?validity_minutes", flat), (
        "the mint request model no longer accepts validity_minutes"
    )


# ---- Refresh: rotation requires the CURRENT secret; an in-grace secret is refused, distinctly -----
def test_refresh_refuses_in_grace_with_distinct_reason_in_source():
    """The refresh route must refuse an in-grace principal with a DISTINCT typed reason.

    Distinct from 'invalid-device-credential' so the desktop can tell a stale-but-ours secret (catch
    up / owner-restore) from a secret that was never ours. Pinned as a source rule because a real
    in-grace principal reaching the route needs the live DB-backed resolver (verified against the
    live stack); the guard's presence and its typed reason are what a refactor could quietly drop.
    """
    flat = _flat(API_SERVER)
    # The guard sits in the refresh route and rejects on principal.in_grace with the stale reason.
    assert re.search(
        r"if principal\.in_grace:\s*raise _device_auth_401\(\"device-secret-stale\"\)",
        flat,
    ), "the refresh route no longer refuses an in-grace (previous-secret) principal"
    # And that refusal must NOT collapse into the generic invalid-credential reason.
    assert 'if principal.in_grace: raise _device_auth_401("invalid-device-credential")' not in flat, (
        "the in-grace refresh refusal must carry its own reason, not the generic invalid-credential one"
    )


# ---- Restore: rotate-always, unconditional (no preserve option) ----------------------------------
def test_restore_always_rotates_and_kills_the_outgoing_secret_in_source():
    """Restore must ALWAYS rotate: mint a fresh secret and no-grace-kill the outgoing one.

    The no-preserve default is what makes restore safe against a suspend provoked by an attacker who
    captured the CURRENT secret and rotated first — a preserve-restore would hand that live secret
    back. The end-to-end capture-and-rotate scenario (attacker captures the current secret and
    rotates first → the legitimate desktop is suspended → the owner rotate-restores → the captured
    secret is dead and the desktop gets the fresh secret) runs against the live stack; here we pin
    that the code has no preserve path left and performs the rotation unconditionally.
    """
    flat = _flat(API_SERVER)
    body = _fn_body(API_SERVER.read_text(encoding="utf-8"), r"async def restore_device_endpoint\(")

    # No toggle remains — neither the request model/field nor a conditional rotate branch.
    assert "rotate_secret" not in flat, "the rotate_secret toggle must be gone (rotate is unconditional)"
    assert "DeviceRestoreRequest" not in flat, "the DeviceRestoreRequest toggle model must be removed"
    assert "if rotate" not in body, "restore must rotate unconditionally, not behind an if"

    # The unconditional rotation: fresh secret, no-grace kill of the outgoing one, epoch bump, secret
    # returned once.
    assert "new_secret = generate_device_secret()" in body, "restore no longer mints a fresh secret"
    assert "device.prev_secret_hash = device.secret_hash" in body, "restore no longer retires the outgoing secret"
    assert "device.prev_secret_retired_at = None" in body, (
        "restore must retire with retired_at=None (no grace) so the outgoing secret is never grace-valid"
    )
    assert "device.secret_hash = hash_device_secret(new_secret)" in body, "restore no longer installs the fresh secret"
    assert '"secret": new_secret' in body, "restore no longer returns the fresh secret once"


def test_no_restore_rotate_toggle_config_remains():
    """Rotate-always is unconditional, so no restore-rotate toggle should linger in config/.env.

    (The separate device_secret_reuse_hard_revoke posture — suspend vs revoke on replay detection —
    is a DIFFERENT axis and is intentionally retained; this rule only forbids a restore-rotate toggle.)
    """
    config_txt = (ROOT / "app" / "core" / "config.py").read_text(encoding="utf-8")
    env_txt = (ROOT / ".env.example").read_text(encoding="utf-8")
    for hay, where in ((config_txt, "config.py"), (env_txt, ".env.example")):
        low = hay.lower()
        assert "restore_rotate" not in low and "rotate_secret" not in low and "restore_secret_rotate" not in low, (
            f"a restore-rotate toggle lingers in {where}; rotate-always is unconditional"
        )


# ---- last_seen: written on sync activity (mint/refresh), never at register ------------------------
MODELS = ROOT / "app" / "core" / "models.py"


def _fn_body(raw: str, signature_re: str) -> str:
    """Isolate one function's source — from its signature to the next top-level def/route, newlines
    intact so the boundary is real — then flatten just that slice for substring checks."""
    m = re.search(signature_re, raw)
    assert m, f"could not find a function matching {signature_re!r}"
    rest = raw[m.end():]
    nxt = re.search(r"\n@app\.|\nasync def |\ndef ", rest)
    body = raw[m.start(): m.end() + (nxt.start() if nxt else len(rest))]
    return re.sub(r"\s+", " ", body)


def test_mint_and_refresh_write_last_seen():
    """Both meaningful device-principal operations record activity, so a synced device has a time."""
    mint = _fn_body(AUTH_SERVICE.read_text(encoding="utf-8"), r"def mint_device_sync_credential\(")
    assert "device.last_seen = datetime.utcnow()" in mint, (
        "the mint no longer records device.last_seen on a successful mint"
    )
    refresh = _fn_body(API_SERVER.read_text(encoding="utf-8"), r"async def refresh_device_secret_endpoint\(")
    assert "device.last_seen = datetime.utcnow()" in refresh, (
        "the refresh route no longer records device.last_seen"
    )


def test_register_does_not_write_last_seen():
    """A registered-but-never-synced device must stay NULL — register must not stamp last_seen, so the
    devices list can honestly show 'not synced yet' instead of a fabricated time."""
    register = _fn_body(API_SERVER.read_text(encoding="utf-8"), r"async def register_device_endpoint\(")
    assert "last_seen" not in register, (
        "register must not set last_seen (a never-synced device stays NULL)"
    )


def test_last_seen_column_present_and_nullable():
    """The column exists and is nullable — a device with no recorded activity reads back NULL.

    (No ALTER migration is needed: last_seen has been in the Device model since the devices table was
    first introduced, so every devices table is created with it — unlike the later-added suspended.)
    """
    models_flat = _flat(MODELS)
    assert re.search(r"last_seen = Column\(DateTime, nullable=True\)", models_flat), (
        "the Device.last_seen column (nullable) is missing"
    )


def test_devices_list_renders_last_seen_honest_null():
    """The devices list surfaces last_seen but never fabricates one — NULL renders as null, not now()."""
    api_flat = _flat(API_SERVER)
    assert re.search(r'"last_seen":\s*\(d\.last_seen\.isoformat\(\)\s*\+\s*"Z"\)\s*if d\.last_seen else None', api_flat), (
        "the devices list no longer renders last_seen as an honest null"
    )
