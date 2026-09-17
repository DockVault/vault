"""The owner-encrypted link-token re-copy wrap (purpose 0x06), run in Node against the shipped
ecc_crypto.js, plus a cross-runtime check that the container the client produces is exactly what the
Python server shape check accepts.

The re-copy is a client-side wrap of a link's URL token to the OWNER's own public key, so "Show link
again" is a client-side decrypt and the server never sees the plaintext after creation. A round-trip
alone would pass with the AAD binding removed, so the harness asserts the (link, owner) binding and
the rotated-key rejection explicitly.
"""
import base64
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "link_token_wrap.js"


@pytest.fixture(scope="module")
def out() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser-crypto side of this must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_round_trips_to_the_same_token(out: str) -> None:
    assert "ok   round-trips to the same token" in out, out


def test_the_container_is_a_v2_link_token_blob(out: str) -> None:
    for line in ("ok   magic is DVZ2", "ok   version is 2", "ok   purpose is link-token (0x06)",
                 "ok   reserved bytes are zero", "ok   carries a P-384 point + nonce + tag",
                 "ok   is NOT the fixed 68-byte key-wrap length (variable token)"):
        assert line in out, out


def test_bound_to_the_link_and_owner_and_rejects_a_rotated_key(out: str) -> None:
    assert "ok   a blob for another link id fails to unwrap" in out, out
    assert "ok   a blob for another owner id fails to unwrap" in out, out
    assert "ok   a rotated (different) private key cannot unwrap" in out, out


def test_the_client_container_satisfies_the_server_shape_check() -> None:
    # Cross-runtime: the exact blob the JS client produces must pass the Python server shape check,
    # and a raw plaintext token must fail it -- so the two ends cannot silently drift.
    import _bare_api_env
    _bare_api_env.set_bare_api_env()
    import app.api.api_server as api

    node = shutil.which("node")
    assert node, "Node is required"
    emit = (
        "const p=require('path');const c=require('crypto');global.window={crypto:c.webcrypto};"
        "const L=require(p.resolve('static/js/ecc_crypto.js'));"
        "(async()=>{const lib=new L();const o=await c.webcrypto.subtle.generateKey("
        "{name:'ECDH',namedCurve:'P-384'},true,['deriveBits']);"
        "const b=await lib.wrapLinkTokenV2('Xy7Qm2Zb9Kd4Rf1Ns',o.publicKey,"
        "{linkId:'aaaaaaaa-1111-4222-8333-444444444444',ownerId:'cccccccc-3333-4444-8555-666666666666'});"
        "process.stdout.write(b);})();"
    )
    done = subprocess.run([node, "-e", emit], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
    blob = done.stdout.strip()
    assert api._valid_link_token_copy(blob) is True, "the client container failed the server shape check"
    # A raw plaintext token (base64 or not) must fail the same check.
    assert api._valid_link_token_copy("Xy7Qm2Zb9Kd4Rf1Ns") is False
    assert api._valid_link_token_copy(base64.b64encode(b"Xy7Qm2Zb9Kd4Rf1Ns").decode()) is False
