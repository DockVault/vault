"""Live candidate identity and server-side persisted-format compatibility gates."""

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import urlsplit

import pytest
import requests

from conftest import BASE_URL
from crypto_reference_vectors import load_vector


pytestmark = [pytest.mark.integration, pytest.mark.crypto_compatibility]

_REPO_ROOT = Path(__file__).resolve().parent.parent
_VECTOR_DIR = Path(__file__).resolve().parent / "fixtures" / "crypto" / "v0.10.0"
_RUNTIME_SOURCES = {
    "app/core/security.py": "/app/app/core/security.py",
    "app/api/ecc_router.py": "/app/app/api/ecc_router.py",
    "static/js/ecc_crypto.js": "/app/static/js/ecc_crypto.js",
    "static/js/app.js": "/app/static/js/app.js",
}


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.fail(
            f"required crypto compatibility environment variable is absent: {name}"
        )
    return value


# Everything a caller must state to bind this suite's evidence to one exact candidate.
_ROUND_DECLARATION_VARS = (
    "CRYPTO_COMPAT_API_CONTAINER",
    "CRYPTO_COMPAT_COMPOSE_PROJECT",
    "CRYPTO_COMPAT_EXPECTED_IMAGE_ID",
    "CRYPTO_COMPAT_EXPECTED_PORT",
    "CRYPTO_COMPAT_EXPECTED_TREE",
    "CRYPTO_COMPAT_ROUND_ID",
)


def _require_declared_round() -> None:
    """Skip when NO round is declared; never let a PARTIAL declaration through.

    These checks prove that the instance under test is one exact container, built from
    one exact image and source tree. That is only meaningful inside a release-candidate
    round which states what it claims to be. An ordinary suite run -- CI against a
    generic stack, or a developer's own instance -- claims nothing, and must skip rather
    than fail on a declaration it was never meant to make.

    The asymmetry is deliberate. Skipping on a COMPLETE absence is safe, but treating a
    missing variable as "skip" in general would turn provenance into something a failing
    round could opt out of by unsetting one name. So a partial declaration stays a hard
    error: state all of it, or none of it.
    """
    present = {n for n in _ROUND_DECLARATION_VARS if os.environ.get(n, "").strip()}
    if not present:
        pytest.skip(
            "no candidate round is declared; set the crypto compatibility round "
            "variables to bind this evidence to an exact container, image and tree"
        )
    missing = [n for n in _ROUND_DECLARATION_VARS if n not in present]
    if missing:
        pytest.fail(
            "a candidate round is only partially declared, so a provenance check cannot "
            "be trusted or skipped. Absent: " + ", ".join(sorted(missing))
        )


def _docker(*args: str, stdin: str | None = None, timeout: int = 30) -> str:
    try:
        completed = subprocess.run(
            ["docker", *args],
            input=stdin,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        pytest.fail("Docker CLI is required for live crypto compatibility gates")
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"Docker command timed out: docker {' '.join(args)} ({exc})")
    if completed.returncode != 0:
        pytest.fail(
            f"Docker command failed ({completed.returncode}): docker {' '.join(args)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed.stdout


def _expected_http_endpoint() -> tuple[str, str, int]:
    """Return the canonical loopback URL expected to reach the candidate's port 8000."""
    parsed = urlsplit(BASE_URL)
    if parsed.scheme != "http":
        pytest.fail(
            f"crypto compatibility BASE_URL must use http, got {parsed.scheme!r}"
        )
    if parsed.username or parsed.password:
        pytest.fail("crypto compatibility BASE_URL must not contain user information")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        pytest.fail(
            "crypto compatibility BASE_URL must contain only scheme, host, and port"
        )

    host = parsed.hostname
    if not host:
        pytest.fail("crypto compatibility BASE_URL has no host")
    if host.lower() == "localhost":
        expected_binding_ip = "127.0.0.1"
    else:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            pytest.fail(
                f"crypto compatibility BASE_URL host is not an IP loopback: {exc}"
            )
        if address.version != 4 or not address.is_loopback:
            pytest.fail(
                f"crypto compatibility BASE_URL host is not IPv4 loopback: {host}"
            )
        expected_binding_ip = str(address)

    try:
        base_port = parsed.port
    except ValueError as exc:
        pytest.fail(f"crypto compatibility BASE_URL port is invalid: {exc}")
    if base_port is None:
        pytest.fail("crypto compatibility BASE_URL must contain an explicit port")
    raw_expected_port = _required_env("CRYPTO_COMPAT_EXPECTED_PORT")
    try:
        expected_port = int(raw_expected_port)
    except ValueError:
        pytest.fail(
            f"CRYPTO_COMPAT_EXPECTED_PORT must be an integer, got {raw_expected_port!r}"
        )
    if not 1 <= expected_port <= 65535:
        pytest.fail(f"CRYPTO_COMPAT_EXPECTED_PORT is outside 1..65535: {expected_port}")
    assert base_port == expected_port, {
        "base_url_port": base_port,
        "expected_port": expected_port,
    }

    canonical = f"http://{host}:{expected_port}"
    assert BASE_URL.rstrip("/") == canonical, {
        "base_url": BASE_URL,
        "canonical": canonical,
    }
    return canonical, expected_binding_ip, expected_port


def _inspect_exact_candidate() -> dict:
    """Bind the live URL to one exact container, image, source tree, and runtime source set."""
    _require_declared_round()
    container = _required_env("CRYPTO_COMPAT_API_CONTAINER")
    expected_tree = _required_env("CRYPTO_COMPAT_EXPECTED_TREE")
    expected_image_id = _required_env("CRYPTO_COMPAT_EXPECTED_IMAGE_ID")
    expected_project = _required_env("CRYPTO_COMPAT_COMPOSE_PROJECT")
    expected_round = _required_env("CRYPTO_COMPAT_ROUND_ID")
    endpoint, expected_binding_ip, expected_port = _expected_http_endpoint()

    container_data = json.loads(_docker("inspect", container))
    assert len(container_data) == 1, container_data
    inspected = container_data[0]
    assert inspected["State"]["Running"] is True, inspected["State"]
    assert inspected["Image"] == expected_image_id, {
        "actual_image_id": inspected["Image"],
        "expected_image_id": expected_image_id,
    }

    image_data = json.loads(_docker("image", "inspect", expected_image_id))
    assert len(image_data) == 1, image_data
    assert image_data[0]["Id"] == expected_image_id, image_data[0]["Id"]

    container_labels = inspected.get("Config", {}).get("Labels") or {}
    image_labels = image_data[0].get("Config", {}).get("Labels") or {}
    assert container_labels.get("com.docker.compose.service") == "vault-api", (
        container_labels
    )
    assert container_labels.get("com.docker.compose.project") == expected_project, (
        container_labels
    )
    assert container_labels.get("com.dockvault.test-round") == expected_round, (
        container_labels
    )
    assert container_labels.get("com.dockvault.candidate-tree") == expected_tree, (
        container_labels
    )
    assert image_labels.get("org.opencontainers.image.revision") == expected_tree, (
        image_labels
    )

    published = (inspected.get("NetworkSettings", {}).get("Ports") or {}).get(
        "8000/tcp"
    )
    assert isinstance(published, list) and len(published) == 1, {
        "expected": "one unique host binding for container port 8000/tcp",
        "actual": published,
    }
    binding = published[0]
    binding_ip = str(binding.get("HostIp", ""))
    binding_port = str(binding.get("HostPort", ""))
    try:
        binding_address = ipaddress.ip_address(binding_ip)
    except ValueError as exc:
        pytest.fail(
            f"candidate port binding has an invalid HostIp {binding_ip!r}: {exc}"
        )
    assert binding_address.version == 4 and binding_address.is_loopback, {
        "expected": "a unique IPv4 loopback binding, never 0.0.0.0 or a foreign address",
        "actual": binding_ip,
    }
    assert binding_ip == expected_binding_ip, {
        "base_url_binding": expected_binding_ip,
        "container_binding": binding_ip,
    }
    assert binding_port == str(expected_port), {
        "base_url_port": expected_port,
        "container_binding_port": binding_port,
    }

    try:
        health_response = requests.get(f"{endpoint}/health", timeout=5)
        health_response.raise_for_status()
        health = health_response.json()
    except Exception as exc:  # noqa: BLE001 - required candidate health must fail, never skip
        pytest.fail(f"exact mapped candidate is not reachable at {endpoint}: {exc}")
    if health.get("database") != "connected":
        pytest.fail(f"exact mapped candidate database is not connected: {health}")

    runtime_script = """
import hashlib
import json
from pathlib import Path

paths = json.loads(__import__('sys').argv[1])
print(json.dumps({path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in paths}))
"""
    runtime_paths = list(_RUNTIME_SOURCES.values())
    runtime_hashes = json.loads(
        _docker(
            "exec", container, "python", "-c", runtime_script, json.dumps(runtime_paths)
        )
    )
    expected_hashes = {
        runtime_path: hashlib.sha256(
            (_REPO_ROOT / source_path).read_bytes()
        ).hexdigest()
        for source_path, runtime_path in _RUNTIME_SOURCES.items()
    }
    assert runtime_hashes == expected_hashes, {
        "runtime": runtime_hashes,
        "checkout": expected_hashes,
    }

    return {
        "container": container,
        "endpoint": endpoint,
        "health": health,
        "image_id": expected_image_id,
        "source_tree": expected_tree,
    }


@pytest.fixture(scope="module")
def _exact_candidate():
    return _inspect_exact_candidate()


@pytest.fixture(scope="module")
def _live_container_health(_exact_candidate):
    """Feed conftest's live guard only the health of the exact mapped candidate."""
    return _exact_candidate["health"]


def test_candidate_container_is_the_exact_expected_source_tree_and_image(
    _exact_candidate,
):
    """Reject a healthy but stale, foreign, reused, or differently mapped candidate."""
    assert _exact_candidate["endpoint"] == BASE_URL.rstrip("/")
    assert _exact_candidate["health"]["database"] == "connected"


@pytest.mark.parametrize(
    "fixture_name,reader",
    [
        ("standard-0x10.json", "gcm"),
        ("standard-fernet-chunk-stream.json", "fernet"),
    ],
)
def test_candidate_container_reads_pinned_standard_formats(
    fixture_name: str, reader: str, _exact_candidate
):
    """Read pinned current and legacy Standard blobs inside the exact candidate runtime."""
    vector_path = _VECTOR_DIR / fixture_name
    if not vector_path.is_file():
        pytest.fail(f"required Standard crypto vector is absent: {vector_path}")
    vector = load_vector(vector_path)
    container = _exact_candidate["container"]

    reader_script = """
import base64
import io
import json
import sys
from types import SimpleNamespace

from app.core import security

payload = json.load(sys.stdin)
vector = payload['vector']
inputs = vector['inputs']
security._runtime_settings = lambda: SimpleNamespace(encryption_key=inputs['encryption_key'])
encoded = base64.b64decode(vector['encoded_b64'], validate=True)
if payload['reader'] == 'gcm':
    plaintext = security.decrypt_gcm_chunk_stream(
        io.BytesIO(encoded), inputs['vault_id'], inputs['file_id'])
elif payload['reader'] == 'fernet':
    plaintext = b''.join(security.decrypt_chunk_stream(io.BytesIO(encoded)))
else:
    raise AssertionError(f"unknown compatibility reader: {payload['reader']}")
print(json.dumps({'plaintext_b64': base64.b64encode(plaintext).decode('ascii')}))
"""
    output = _docker(
        "exec",
        "-i",
        container,
        "python",
        "-c",
        reader_script,
        stdin=json.dumps({"reader": reader, "vector": vector}),
    )
    result = json.loads(output)
    assert result["plaintext_b64"] == vector["expected"]["plaintext_b64"]
