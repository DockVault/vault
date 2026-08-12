"""What a single-chunk upload actually costs the running deployment.

`tests/test_bounded_receive.py` guards the receive loop's behaviour and runs everywhere. This
measures the consequence against a live stack, which is where the problem was found: a 128 MB file
sent as one chunk cost 273.7 MB, the same as a download, while the same file in 5 MB pieces cost
22.7 MB. Nothing about the server required the small pieces -- the client chose them, and so chose
how much memory the server spent.

It skips where the API container's cgroup cannot be read, so it confirms rather than guards.
`docs/resource-budgets.md` explains why page cache is subtracted and why each figure is a rise
within its own window.
"""

import hashlib
import os
import subprocess

import pytest

from conftest import unique


MB = 1024 * 1024
_OCTET = {"Content-Type": "application/octet-stream"}


def _anon_bytes():
    """Allocated memory inside the API container, page cache excluded.

    Cache is not a stand-in for allocation and the gap is not small: on a stack that has moved a
    few gigabytes it reaches 2.5 GB while allocation sits under 200 MB.
    """
    container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    script = (
        'if [ -r /sys/fs/cgroup/memory.current ]; then '
        'cur=$(cat /sys/fs/cgroup/memory.current); '
        'fil=$(awk \'/^inactive_file /{a=$2} /^active_file /{b=$2} END{print a+b}\' '
        '/sys/fs/cgroup/memory.stat); '
        'else cur=$(cat /sys/fs/cgroup/memory/memory.usage_in_bytes); '
        'fil=$(awk \'/^total_inactive_file /{a=$2} /^total_active_file /{b=$2} END{print a+b}\' '
        '/sys/fs/cgroup/memory/memory.stat); fi; echo $((cur - ${fil:-0}))'
    )
    try:
        out = subprocess.run(["docker", "exec", container, "sh", "-c", script],
                             capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.skip(f"cannot reach the API container to read its cgroup: {exc}")
    if out.returncode != 0 or not out.stdout.strip().isdigit():
        pytest.skip(f"cannot read the API container's cgroup: {out.stderr.strip()[:120]}")
    return int(out.stdout.strip())


def test_a_single_chunk_upload_does_not_cost_the_file_in_memory(admin, temp_vault):
    """A 64 MB file declared and sent as one chunk.

    Before the fix the rise was roughly twice the file. The threshold is deliberately loose --
    half the file, not a tight bound -- because this distinguishes "scales with the request" from
    "does not", on a host with other things happening on it.
    """
    vid = temp_vault["id"]
    size = 64 * MB
    body = bytes((i * 7 + 3) % 256 for i in range(65536)) * (size // 65536)
    name = unique("one-chunk") + ".bin"

    before = _anon_bytes()
    init = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": name, "total_size": len(body), "total_chunks": 1, "chunk_size": len(body),
        "mime_type": "application/octet-stream",
    })
    assert init.status_code == 200, init.text
    sid = init.json()["session_id"]
    put = admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=body, headers=_OCTET)
    assert put.status_code == 200, put.text
    done = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
    assert done.status_code == 200, done.text
    after = _anon_bytes()

    # Non-vacuity: if the upload did not store what was sent, the memory figure measured nothing.
    got = admin.get(f"/vaults/{vid}/files/{done.json()['id']}/download")
    assert got.status_code == 200
    assert hashlib.sha256(got.content).hexdigest() == hashlib.sha256(body).hexdigest()

    rise = after - before
    assert rise < size // 2, (
        f"a {size // MB} MB single-chunk upload raised allocated memory by {rise / MB:.1f} MB; "
        "the request body is being held rather than streamed")


def test_an_oversized_chunk_is_refused_and_the_session_still_works(admin, temp_vault):
    """The bound the streaming replaced has to keep working, and keep the session usable.

    The refusal now happens with part of the body already on disk, so this also covers the case
    where a client retries the same index after being refused.
    """
    vid = temp_vault["id"]
    declared = 4096
    init = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": unique("small") + ".bin", "total_size": declared,
        "total_chunks": 1, "chunk_size": declared,
    })
    assert init.status_code == 200, init.text
    sid = init.json()["session_id"]

    # Content-Length absent, so the fast-path header check cannot catch it and the receive loop
    # has to. A generator body makes requests use chunked transfer-encoding.
    def _oversized():
        for _ in range(8):
            yield b"x" * declared

    refused = admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=_oversized(), headers=_OCTET)
    assert refused.status_code == 413, (
        f"a body eight times the declared size, sent without a Content-Length, "
        f"was answered {refused.status_code}")

    good = admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=b"y" * declared, headers=_OCTET)
    assert good.status_code == 200, good.text
    done = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
    assert done.status_code == 200, done.text
    content = admin.get(f"/vaults/{vid}/files/{done.json()['id']}/download").content
    assert content == b"y" * declared, "the refused body contaminated the stored file"


def test_the_chunk_digests_still_describe_what_was_stored(admin, temp_vault):
    """They are taken from the stream now instead of from a whole-body copy.

    A resuming client compares against these to find out which of its own chunks no longer match,
    so a digest of the wrong thing either forces a needless re-send or lets a stale chunk stand.
    """
    vid = temp_vault["id"]
    first, second = b"A" * 4096, b"B" * 4096
    init = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": unique("two") + ".bin", "total_size": 8192,
        "total_chunks": 2, "chunk_size": 4096,
    })
    assert init.status_code == 200, init.text
    sid = init.json()["session_id"]
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=first,
                     headers=_OCTET).status_code == 200
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/1", data=second,
                     headers=_OCTET).status_code == 200

    sums = admin.get(f"/vaults/{vid}/uploads/{sid}").json().get("chunk_checksums") or {}
    assert sums, "no digests were reported, so a resuming client has nothing to check against"
    assert sums["0"] == hashlib.sha256(first).hexdigest()
    assert sums["1"] == hashlib.sha256(second).hexdigest()
