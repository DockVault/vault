"""
Shared pytest fixtures for the DockVault vault-service integration suite.

These tests run on the HOST and exercise the live container at
http://localhost:8200 (bring it up with `docker compose up -d`). Nothing here
imports the application code — everything goes
over HTTP, so the suite tests the real, deployed surface.

Config (all optional, sensible defaults):
  VAULT_BASE_URL   default http://localhost:8200
  VAULT_ADMIN_USER / VAULT_ADMIN_PASS
        default: read from ../.env (ADMIN_USERNAME / ADMIN_PASSWORD)
"""
import base64
import json
import os
import random
import socket
import time
import uuid
from pathlib import Path

import pytest
import requests


def _random_ip() -> str:
    """A unique-ish source IP so each client lands in its own login
    rate-limit bucket (the server honours X-Forwarded-For)."""
    return "10.%d.%d.%d" % (
        random.randint(1, 254), random.randint(1, 254), random.randint(1, 254)
    )

BASE_URL = os.environ.get("VAULT_BASE_URL", "http://localhost:8200").rstrip("/")
ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


def _read_env_file(path: Path) -> dict:
    """Parse a simple KEY=VALUE .env file (no external deps)."""
    values = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip().strip('"').strip("'")
    return values


_ENV = _read_env_file(ENV_FILE)
ADMIN_USER = os.environ.get("VAULT_ADMIN_USER") or _ENV.get("ADMIN_USERNAME", "admin")
ADMIN_PASS = os.environ.get("VAULT_ADMIN_PASS") or _ENV.get("ADMIN_PASSWORD", "")


class _GenerateEmail:
    """Sentinel meaning "no email argument was given, so make one up".

    Exists so that ``None`` can mean what a reader expects it to mean -- genuinely no email --
    rather than being indistinguishable from "not specified". See ApiClient.create_user.
    """
    def __repr__(self):
        return "GENERATE_EMAIL"


GENERATE_EMAIL = _GenerateEmail()


def unique(prefix: str = "t") -> str:
    """A short unique token for names/emails that won't collide across runs."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def skip_for_older_deployment(reason: str) -> None:
    """Keep compatibility skips local-only; same-commit CI must test the new image."""
    if os.environ.get("VAULT_SAME_COMMIT_CI", "").lower() in {"1", "true", "yes"}:
        pytest.fail(f"{reason}; the newly built image must advertise this endpoint")
    pytest.skip(reason)


def compute_registration_pop(client, priv, public_key_pem: str) -> dict:
    """Client-side registration proof-of-possession — a faithful Python mirror of
    app/services/ecc_pop.py / ecc_crypto.js.computeRegistrationPoP. Fetches a challenge, does
    ECDH(priv, server_ephemeral_pub) -> HKDF -> HMAC over (nonce || public_key_pem), and
    returns the {challenge_id, mac} dict to send with POST /ecc/keys/register. `priv` is the
    EC private key matching public_key_pem (proving possession). Salt/info/hash MUST match
    the server + browser, or a real browser's PoP won't verify."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    ch = client.post("/ecc/keys/register/challenge").json()
    server_pub = serialization.load_pem_public_key(ch["server_ephemeral_public_key"].encode())
    shared = priv.exchange(ec.ECDH(), server_pub)
    mac_key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=b"dv-ecc-pop-v1", info=b"registration-pop").derive(shared)
    msg = _base64.b64decode(ch["nonce"]) + public_key_pem.encode()
    mac = _base64.b64encode(_hmac.new(mac_key, msg, _hashlib.sha256).digest()).decode()
    return {"challenge_id": ch["challenge_id"], "mac": mac}


def compute_key_update_pop(client, priv, public_key_pem: str, user_id: str, envelope: str) -> dict:
    """Client-side proof for REPLACING the private-key envelope -- a faithful Python mirror of
    app/services/ecc_update_pop.py and ecc_crypto.js.computeKeyUpdatePoP.

    Fetches an update challenge, derives the MAC key under the UPDATE domain (deliberately
    different salt and info from registration, so the two protocols cannot be cross-used), and
    MACs the transcript that binds the exact replacement bytes. `priv` must be the key matching
    the account's REGISTERED public key. Returns {challenge_id, mac} for PUT /ecc/keys/private.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    ch = client.post("/ecc/keys/private/challenge").json()
    server_pub = serialization.load_pem_public_key(ch["server_ephemeral_public_key"].encode())
    shared = priv.exchange(ec.ECDH(), server_pub)
    mac_key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=b"dv-ecc-update-pop-v1", info=b"private-key-update-pop").derive(shared)
    point = serialization.load_pem_public_key(public_key_pem.encode()).public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    transcript = _hashlib.sha256(b"\x00".join([
        b"dockvault-private-key-update-pop-v1",
        str(ch["challenge_id"]).lower().encode(),
        _base64.b64decode(ch["nonce"]),
        str(user_id).lower().encode(),
        _hashlib.sha256(point).digest(),
        _hashlib.sha256(envelope.encode("utf-8")).digest(),
    ])).digest()
    mac = _base64.b64encode(_hmac.new(mac_key, transcript, _hashlib.sha256).digest()).decode()
    return {"challenge_id": ch["challenge_id"], "mac": mac}


def ensure_ecc_keypair(client) -> None:
    """Ensure the logged-in user has a registered ECC keypair (idempotent).

    Zero-knowledge vault creation now requires the owner to have one — the server
    wraps a fresh vault DEK to their public key at creation time. Registers a real
    P-384 public key with an OPAQUE encrypted-private-key blob (the server stores
    the blob but can't read it, so this doesn't weaken the zero-knowledge model),
    with a valid proof-of-possession (the server now requires one)."""
    import json as _json
    if client.get("/ecc/keys/public").json().get("has_keypair"):
        return
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    priv = ec.generate_private_key(ec.SECP384R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    client.post("/ecc/keys/register", json={
        "public_key": pub_pem,
        "encrypted_private_key": _json.dumps(
            {"encrypted": "opaque", "salt": "opaque", "iterations": 600000}
        ),
        "pop": compute_registration_pop(client, priv, pub_pem),
    })


# Opaque stand-ins for a browser-wrapped DEK. The server stores these verbatim and
# cannot read them, so API tests (which never decrypt) can use fixed blobs; the real
# ECDH wrap/unwrap round-trip is covered by the Playwright E2E.
import base64 as _base64  # noqa: E402
ZK_WRAPPED_DEK_STUB = _base64.b64encode(b"wrapped-dek-stub" * 4).decode()
ZK_EPHEMERAL_STUB = _base64.b64encode(b"ephemeral-pubkey-stub" * 5).decode()


# ---------------------------------------------------------------------------
# Zero-knowledge name crypto — a faithful Python mirror of static/js/ecc_crypto.js
# (encryptName / decryptName / nameBlindIndex). Lets the HTTP suite encrypt a name the
# exact way the browser does, prove the server stores only opaque ciphertext + a blind
# index it can't reverse, and round-trip-decrypt it. Formats here MUST match ecc_crypto.js
# and security.ZK_NAME_PREFIX — if any of them drift, real browser names won't decrypt.
import hmac as _hmac  # noqa: E402
import hashlib as _hashlib  # noqa: E402

ZK_NAME_PREFIX = "zk1:"
ZK_NAME_PREFIX_V2 = "zk2:"


def _zk_name_aad(vault_id, field, epoch) -> bytes:
    return f"dv-zk-name-v1|{vault_id}|{field}|{epoch}".encode()


def _zk_name_aad_v2(vault_id, field, epoch, obj_id) -> bytes:
    return f"dv-zk-name-v2|{vault_id}|{field}|{epoch}|{obj_id}".encode()


def zk_encrypt_name(plaintext: str, dek: bytes, vault_id, field, epoch, obj_id=None) -> str:
    """AES-256-GCM(name) under the vault DEK. Mirrors ecc_crypto.js: v1 (zk1:, AAD vault|field|
    epoch) when obj_id is None (legacy/backward-compat); v2 (zk2:, AAD also binds obj_id) when an
    obj_id is given, so a v2 blob can't be transposed to a different object."""
    import os as _os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv = _os.urandom(12)
    if obj_id is None:
        aad, prefix = _zk_name_aad(vault_id, field, epoch), ZK_NAME_PREFIX
    else:
        aad, prefix = _zk_name_aad_v2(vault_id, field, epoch, obj_id), ZK_NAME_PREFIX_V2
    ct = AESGCM(dek).encrypt(iv, str(plaintext).encode(), aad)
    return prefix + _base64.b64encode(iv + ct).decode()


def zk_decrypt_name(token: str, dek: bytes, vault_id, field, epoch, obj_id=None) -> str:
    """Inverse of zk_encrypt_name; branches on the blob version (zk2: binds obj_id, zk1: does not).
    A v2 blob decrypted with the WRONG obj_id raises (GCM auth failure) — that IS the anti-
    transposition property."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if token.startswith(ZK_NAME_PREFIX_V2):
        b64, aad = token[len(ZK_NAME_PREFIX_V2):], _zk_name_aad_v2(vault_id, field, epoch, obj_id)
    else:
        b64 = token[len(ZK_NAME_PREFIX):] if token.startswith(ZK_NAME_PREFIX) else token
        aad = _zk_name_aad(vault_id, field, epoch)
    raw = _base64.b64decode(b64)
    return AESGCM(dek).decrypt(raw[:12], raw[12:], aad).decode()


def zk_name_blind_index(name: str, dek: bytes, vault_id, epoch) -> str:
    """Deterministic HMAC blind index, keyed by HKDF(DEK) per (vault, epoch) — the same
    digest the browser sends so the server can match same-name rows without the plaintext."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes as _h
    bi_key = HKDF(algorithm=_h.SHA256(), length=32, salt=b"dv-zk-name-bi-v1",
                  info=f"{vault_id}|{epoch}".encode()).derive(dek)
    return _hmac.new(bi_key, str(name).encode(), _hashlib.sha256).hexdigest()


def zk_chunked_upload(client, vault_id, name, content, dek, epoch=1, mime="text/plain",
                      folder_id=None, chunk_size=None, file_id=None):
    """Upload a file to a ZERO-KNOWLEDGE vault the browser way: the name + MIME are encrypted
    client-side (never sent in the clear) and the content is sent as opaque bytes. Returns the
    completed file id. `dek` is the 32-byte vault DEK the caller uses for the name crypto.

    If `file_id` is given, the name/MIME are sealed BOUND to that id (v2); otherwise the seal is
    legacy v1 and binds nothing. Either way an id is DECLARED, because an encrypted upload must now
    say at session-open what its material is bound to -- v1 vs v2 is a property of the seal, not of
    whether an id exists."""
    chunk_size = chunk_size or max(1, len(content))
    total_chunks = max(1, (len(content) + chunk_size - 1) // chunk_size)
    declared_id = file_id or uuid.uuid4()
    init = client.post(f"/vaults/{vault_id}/uploads", json={
        "total_size": len(content), "total_chunks": total_chunks, "chunk_size": chunk_size,
        "zk_key_version": epoch, "folder_id": folder_id,
        "enc_name": zk_encrypt_name(name, dek, vault_id, "name", epoch, obj_id=file_id),
        "enc_mime": zk_encrypt_name(mime, dek, vault_id, "mime", epoch, obj_id=file_id) if mime else None,
        "name_bi": zk_name_blind_index(name, dek, vault_id, epoch),
        "file_id": str(declared_id),
        # A fresh token per call: two calls are two encryptions and must never share a session.
        "blob_id": uuid.uuid4().hex,
    })
    init.raise_for_status()
    sid = init.json()["session_id"]
    for i in range(total_chunks):
        part = content[i * chunk_size:(i + 1) * chunk_size]
        r = client.put(f"/vaults/{vault_id}/uploads/{sid}/chunks/{i}", data=part,
                       headers={"Content-Type": "application/octet-stream"})
        r.raise_for_status()
    done = client.post(f"/vaults/{vault_id}/uploads/{sid}/complete",
                       json={"file_id": str(declared_id)})
    done.raise_for_status()
    return done.json()["id"]


def create_zk_vault(client, name=None, wrapped_dek=None, ephemeral_public_key=None):
    """Create a zero-knowledge vault the way the browser does — supplying a vault DEK
    that was generated and wrapped CLIENT-SIDE (the server never sees it). Ensures the
    creator has a keypair and returns the vault JSON. The caller must have enabled
    'zero_knowledge_enabled' (these helpers don't toggle deployment policy)."""
    ensure_ecc_keypair(client)
    r = client.post("/vaults", json={
        "name": name or unique("zk"),
        "type": "zero_knowledge",
        "wrapped_dek": wrapped_dek or ZK_WRAPPED_DEK_STUB,
        "ephemeral_public_key": ephemeral_public_key or ZK_EPHEMERAL_STUB,
    })
    r.raise_for_status()
    return r.json()


class ApiClient:
    """Thin requests.Session wrapper that knows the base URL and bearer token."""

    # Re-authenticate this many seconds before the token would expire. Comfortably longer than any
    # single request, short enough to cost one extra login per token lifetime.
    RENEW_MARGIN_SECONDS = 120
    # Floor between consecutive renewals; see _renew_if_stale.
    MIN_RENEW_INTERVAL_SECONDS = 30

    def __init__(self, base_url: str = BASE_URL, renew_before_expiry: bool = False):
        self.base_url = base_url
        self.session = requests.Session()
        # Each client uses a distinct source IP so the per-IP login rate limit
        # isn't shared across the whole suite.
        self.session.headers["X-Forwarded-For"] = _random_ip()
        self.token = None
        self.user = None
        # Opt-in; see _renew_if_stale for why it is off by default.
        self._renew_before_expiry = renew_before_expiry
        self._credentials = None
        self._last_renew_at = None

    # -- auth -------------------------------------------------------------
    def login(self, username: str, password: str):
        r = self.session.post(
            f"{self.base_url}/auth/login",
            json={"username": username, "password": password},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        self.token = data["access_token"]
        self.user = data.get("user")
        self._credentials = (username, password)
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})
        return data

    def _token_claims(self) -> dict:
        """This token's claims, or {} if they cannot be read.

        No signature check: the client is reading its own token to decide when to renew, which is
        not a trust decision.
        """
        if not self.token:
            return {}
        try:
            payload = self.token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            return json.loads(base64.urlsafe_b64decode(payload))
        except Exception:  # noqa: BLE001 — an unreadable token simply never triggers renewal
            return {}

    def _token_expires_at(self):
        return self._token_claims().get("exp")

    def _renew_if_stale(self):
        """Re-login when the access token is close to expiring.

        The token defaults to a 30-minute life while the session-scoped `admin` client logs in once
        and lives for the whole run, so any run longer than that failed every remaining admin call
        with 401 — and the `finally` blocks that clean up failed too, leaking fixtures into whatever
        ran next and producing a second, unrelated-looking set of failures.

        Deliberately PROACTIVE, and deliberately not a retry on 401. Several tests assert that a
        client which HAS logged in then gets 401 — once its session is denylisted, durably revoked,
        logged out, or its account locked. Re-authenticating in response to a 401 would turn those
        into 200s and silently mask the security regressions they exist to catch. Renewing on age
        never changes what a 401 means.

        Off by default for the same reason: only a client that outlives a token needs it, and every
        other client here is function-scoped.
        """
        if not (self._renew_before_expiry and self._credentials):
            return
        exp = self._token_expires_at()
        if exp is None or exp - time.time() > self.RENEW_MARGIN_SECONDS:
            return
        # Never renew more often than this. A token whose whole life is shorter than the margin is
        # "about to expire" the moment it is minted, so without a floor every single request would
        # log in again until the shared per-username login budget was exhausted — and deployments
        # really do run short tokens (a suite elsewhere sets the session timeout to one minute).
        # Rate-limiting the renewal handles that without assuming anything about the lifetime.
        now = time.time()
        if self._last_renew_at is not None and now - self._last_renew_at < self.MIN_RENEW_INTERVAL_SECONDS:
            return
        self._last_renew_at = now
        try:
            self.login(*self._credentials)
        except Exception:  # noqa: BLE001
            # Never raise out of a verb. login() raises for status, and a re-login can legitimately
            # fail — a 429 from the shared per-username login budget, say. Raising here would
            # replace a caller's expected response with an exception from deep inside the client,
            # and worse, would abort a `finally:` cleanup mid-teardown and leak fixtures into the
            # next test. That is the failure this renewal exists to prevent, so it must not become
            # a new way to cause it. Keeping the stale token is no worse than not renewing at all:
            # the caller sees the 401 it would have seen anyway.
            pass

    def clone_anonymous(self) -> "ApiClient":
        return ApiClient(self.base_url)

    # -- verb helpers (paths are relative to base_url) --------------------
    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base_url}{path}"

    def get(self, path, **kw):
        self._renew_if_stale()
        return self.session.get(self._url(path), timeout=30, **kw)

    def post(self, path, **kw):
        self._renew_if_stale()
        return self.session.post(self._url(path), timeout=60, **kw)

    def put(self, path, **kw):
        self._renew_if_stale()
        return self.session.put(self._url(path), timeout=30, **kw)

    def patch(self, path, **kw):
        self._renew_if_stale()
        return self.session.patch(self._url(path), timeout=30, **kw)

    def delete(self, path, **kw):
        self._renew_if_stale()
        return self.session.delete(self._url(path), timeout=30, **kw)

    # -- high-level helpers used by fixtures/tests -----------------------
    def create_vault(self, name=None, password=None, description="created by tests",
                     expire_files_after_days=None):
        body = {"name": name or unique("vault"), "description": description}
        if password is not None:
            body["password"] = password
        if expire_files_after_days is not None:
            body["expire_files_after_days"] = expire_files_after_days
        r = self.post("/vaults", json=body)
        r.raise_for_status()
        return r.json()

    def delete_vault(self, vault_id, vault_password=None):
        params = {"vault_password": vault_password} if vault_password else None
        return self.post(f"/vaults/{vault_id}/delete", params=params)

    def create_user(self, username=None, email=GENERATE_EMAIL, password=None, role="user"):
        """Create a user. `email` has three meanings, and the distinction matters.

        * omitted (the default) -> a unique address is generated, as it always was;
        * ``None``              -> the field is left OUT of the request entirely, creating an
                                   account with NO email;
        * a string              -> sent verbatim, so a test can supply a deliberately odd address
                                   (different case, surrounding whitespace, malformed).

        The default is a sentinel rather than ``None`` on purpose. This used to read
        ``email or f"{username}@example.com"``, so a test asking for an email-less account by
        passing ``email=None`` silently got a generated address instead -- and would have passed
        just as happily with optional-email support removed entirely.
        """
        username = username or unique("user")
        body = {
            "username": username,
            "password": password or "TestPassw0rd!123",
            "role": role,
        }
        if email is GENERATE_EMAIL:
            # NB: .test / .local TLDs are rejected by the email validator as
            # reserved/special-use, so use a normal domain.
            body["email"] = f"{username}@example.com"
        elif email is not None:
            body["email"] = email
        r = self.post("/users", json=body)
        r.raise_for_status()
        out = r.json()
        out["_password"] = body["password"]  # remember for login tests
        out["_username"] = body["username"]
        return out

    def delete_user(self, user_id):
        return self.post(f"/users/{user_id}/delete")


# ---------------------------------------------------------------------------
# Live-deployment guard. Unit tests bypass this; every other test is
# classified as integration during collection and must see a healthy stack.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def _live_container_health():
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        r.raise_for_status()
        health = r.json()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"Vault container not reachable at {BASE_URL} ({exc}). "
            f"Bring it up with 'docker compose up -d' first.",
            allow_module_level=True,
        )
    if health.get("database") != "connected":
        pytest.skip(f"Vault DB not connected: {health}", allow_module_level=True)
    return health


@pytest.fixture(scope="session")
def _sftp_service_health():
    host = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
    port = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
    try:
        with socket.create_connection((host, port), timeout=5):
            return {"host": host, "port": port}
    except OSError as exc:
        pytest.skip(
            f"SFTP server not reachable at {host}:{port} ({exc})",
            allow_module_level=True,
        )


@pytest.fixture(autouse=True)
def _require_running_container(request):
    if request.node.get_closest_marker("unit") is not None:
        return None
    health = request.getfixturevalue("_live_container_health")
    if request.node.get_closest_marker("sftp") is not None:
        request.getfixturevalue("_sftp_service_health")
    return health


def pytest_collection_modifyitems(items):
    """Give every test exactly one execution-environment classification."""
    for item in items:
        unit = item.get_closest_marker("unit")
        integration = item.get_closest_marker("integration")
        if unit is not None and integration is not None:
            raise pytest.UsageError(
                f"{item.nodeid} is marked both unit and integration"
            )
        if unit is None and integration is None:
            item.add_marker(pytest.mark.integration)


@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


@pytest.fixture(scope="session")
def admin_creds():
    if not ADMIN_PASS:
        pytest.skip(
            "No admin password available. Set VAULT_ADMIN_PASS or ensure "
            f"{ENV_FILE} has ADMIN_PASSWORD."
        )
    return {"username": ADMIN_USER, "password": ADMIN_PASS}


@pytest.fixture(scope="session")
def admin(admin_creds):
    """A session-scoped ApiClient logged in as the admin user.

    This is the one client that outlives an access token, so it is the one that renews before
    expiry. Without that, any run longer than the token's 30-minute life failed every remaining
    admin call — including the cleanup in `finally` blocks, which then leaked fixtures into the
    next run. See ApiClient._renew_if_stale for why this renews on age rather than on a 401.

    Note a renewal mints a NEW session for this account, and logging in terminates the account's
    other non-temp sessions — so a test that holds an open SFTP connection authenticated as this
    same admin account while making admin HTTP calls could see that connection dropped. No test
    does today (the SFTP suites authenticate as temp credentials or throwaway users), but it is
    the non-obvious consequence of renewing here.
    """
    client = ApiClient(renew_before_expiry=True)
    client.login(admin_creds["username"], admin_creds["password"])
    return client


# NOTE: an autouse fixture used to reset max_login_attempts / lockout_duration / session_timeout to
# 0 after every browser test, because the Settings page rendered the shipped default for a stored 0
# and "Save All Changes" then PERSISTED it — one incidental save throttled the rest of the run to 5
# logins per user, and everything after it died on 429. That was a product defect, not a test
# problem: the page now renders those fields blank and saves 0, so nothing needs undoing.
# test_ui_settings_auth_limits.py holds the line. Do not reintroduce the cleanup — it would hide a
# regression of the same bug from every file except that one.


@pytest.fixture
def anon():
    """An unauthenticated ApiClient."""
    return ApiClient()


@pytest.fixture
def temp_vault(admin):
    """A password-less vault owned by admin, deleted on teardown."""
    vault = admin.create_vault()
    yield vault
    admin.delete_vault(vault["id"])


@pytest.fixture
def temp_vault_pw(admin):
    """A password-protected vault owned by admin, deleted on teardown."""
    pw = "Vault-Secret-123"
    vault = admin.create_vault(password=pw)
    vault["_password"] = pw
    yield vault
    admin.delete_vault(vault["id"], vault_password=pw)


@pytest.fixture
def temp_user(admin):
    """A fresh non-admin user, deleted on teardown."""
    user = admin.create_user(role="user")
    yield user
    admin.delete_user(user["id"])


@pytest.fixture
def temp_user_client(admin, temp_user):
    """An ApiClient logged in as a fresh non-admin user."""
    client = ApiClient()
    client.login(temp_user["_username"], temp_user["_password"])
    return client
