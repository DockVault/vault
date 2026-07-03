"""
Shared pytest fixtures for the DockVault vault-service integration suite.

These tests run on the HOST and exercise the live container at
http://localhost:8200 (bring it up with `scripts/up.ps1` or the vault
docker-compose). Nothing here imports the application code — everything goes
over HTTP, so the suite tests the real, deployed surface.

Config (all optional, sensible defaults):
  VAULT_BASE_URL   default http://localhost:8200
  VAULT_ADMIN_USER / VAULT_ADMIN_PASS
        default: read from ../.env (ADMIN_USERNAME / ADMIN_PASSWORD)
"""
import os
import random
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


def unique(prefix: str = "t") -> str:
    """A short unique token for names/emails that won't collide across runs."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def ensure_ecc_keypair(client) -> None:
    """Ensure the logged-in user has a registered ECC keypair (idempotent).

    Zero-knowledge vault creation now requires the owner to have one — the server
    wraps a fresh vault DEK to their public key at creation time. Registers a real
    P-384 public key with an OPAQUE encrypted-private-key blob (the server stores
    the blob but can't read it, so this doesn't weaken the zero-knowledge model)."""
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


def _zk_name_aad(vault_id, field, epoch) -> bytes:
    return f"dv-zk-name-v1|{vault_id}|{field}|{epoch}".encode()


def zk_encrypt_name(plaintext: str, dek: bytes, vault_id, field, epoch) -> str:
    """AES-256-GCM(name) under the vault DEK, AAD-bound to vault|field|epoch. Returns the
    same ZK_NAME_PREFIX + base64(iv||ct+tag) blob the browser produces."""
    import os as _os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv = _os.urandom(12)
    ct = AESGCM(dek).encrypt(iv, str(plaintext).encode(), _zk_name_aad(vault_id, field, epoch))
    return ZK_NAME_PREFIX + _base64.b64encode(iv + ct).decode()


def zk_decrypt_name(token: str, dek: bytes, vault_id, field, epoch) -> str:
    """Inverse of zk_encrypt_name (proves a stored blob is decryptable with the DEK)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    b64 = token[len(ZK_NAME_PREFIX):] if token.startswith(ZK_NAME_PREFIX) else token
    raw = _base64.b64decode(b64)
    return AESGCM(dek).decrypt(raw[:12], raw[12:], _zk_name_aad(vault_id, field, epoch)).decode()


def zk_name_blind_index(name: str, dek: bytes, vault_id, epoch) -> str:
    """Deterministic HMAC blind index, keyed by HKDF(DEK) per (vault, epoch) — the same
    digest the browser sends so the server can match same-name rows without the plaintext."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes as _h
    bi_key = HKDF(algorithm=_h.SHA256(), length=32, salt=b"dv-zk-name-bi-v1",
                  info=f"{vault_id}|{epoch}".encode()).derive(dek)
    return _hmac.new(bi_key, str(name).encode(), _hashlib.sha256).hexdigest()


def zk_chunked_upload(client, vault_id, name, content, dek, epoch=1, mime="text/plain",
                      folder_id=None, chunk_size=None):
    """Upload a file to a ZERO-KNOWLEDGE vault the browser way: the name + MIME are encrypted
    client-side (never sent in the clear) and the content is sent as opaque bytes. Returns the
    completed file id. `dek` is the 32-byte vault DEK the caller uses for the name crypto."""
    chunk_size = chunk_size or max(1, len(content))
    total_chunks = max(1, (len(content) + chunk_size - 1) // chunk_size)
    init = client.post(f"/vaults/{vault_id}/uploads", json={
        "total_size": len(content), "total_chunks": total_chunks, "chunk_size": chunk_size,
        "zk_key_version": epoch, "folder_id": folder_id,
        "enc_name": zk_encrypt_name(name, dek, vault_id, "name", epoch),
        "enc_mime": zk_encrypt_name(mime, dek, vault_id, "mime", epoch) if mime else None,
        "name_bi": zk_name_blind_index(name, dek, vault_id, epoch),
    })
    init.raise_for_status()
    sid = init.json()["session_id"]
    for i in range(total_chunks):
        part = content[i * chunk_size:(i + 1) * chunk_size]
        r = client.put(f"/vaults/{vault_id}/uploads/{sid}/chunks/{i}", data=part,
                       headers={"Content-Type": "application/octet-stream"})
        r.raise_for_status()
    done = client.post(f"/vaults/{vault_id}/uploads/{sid}/complete")
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

    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        # Each client uses a distinct source IP so the per-IP login rate limit
        # isn't shared across the whole suite.
        self.session.headers["X-Forwarded-For"] = _random_ip()
        self.token = None
        self.user = None

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
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})
        return data

    def clone_anonymous(self) -> "ApiClient":
        return ApiClient(self.base_url)

    # -- verb helpers (paths are relative to base_url) --------------------
    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base_url}{path}"

    def get(self, path, **kw):
        return self.session.get(self._url(path), timeout=30, **kw)

    def post(self, path, **kw):
        return self.session.post(self._url(path), timeout=60, **kw)

    def put(self, path, **kw):
        return self.session.put(self._url(path), timeout=30, **kw)

    def patch(self, path, **kw):
        return self.session.patch(self._url(path), timeout=30, **kw)

    def delete(self, path, **kw):
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

    def create_user(self, username=None, email=None, password=None, role="user"):
        username = username or unique("user")
        body = {
            "username": username,
            # NB: .test / .local TLDs are rejected by the email validator as
            # reserved/special-use, so use a normal domain.
            "email": email or f"{username}@example.com",
            "password": password or "TestPassw0rd!123",
            "role": role,
        }
        r = self.post("/users", json=body)
        r.raise_for_status()
        out = r.json()
        out["_password"] = body["password"]  # remember for login tests
        out["_username"] = body["username"]
        return out

    def delete_user(self, user_id):
        return self.post(f"/users/{user_id}/delete")


# ---------------------------------------------------------------------------
# Session-wide guard: skip the whole suite cleanly if the container is down.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def _require_running_container():
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        r.raise_for_status()
        health = r.json()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"Vault container not reachable at {BASE_URL} ({exc}). "
            f"Bring it up with scripts/up.ps1 first.",
            allow_module_level=True,
        )
    if health.get("database") != "connected":
        pytest.skip(f"Vault DB not connected: {health}", allow_module_level=True)
    return health


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
    """A session-scoped ApiClient logged in as the admin user."""
    client = ApiClient()
    client.login(admin_creds["username"], admin_creds["password"])
    return client


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
