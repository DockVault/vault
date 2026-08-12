#!/usr/bin/env python3
"""Measure what a running deployment actually costs while transferring files.

The numbers the streaming work needs to assert against. This does not change behaviour and does
not tune anything: it drives a fixed load against a real stack and records what happened.

Three things were wrong in the first version and are worth stating, because each produced
plausible numbers that were not measurements:

* **Sampling through `docker stats` was too slow.** Even streaming it refreshes a few times a
  second, and the peak this chases is a transient buffer join, so it under-reported by about a
  quarter. Memory is now read from the container's own cgroup in a tight loop.
* **A mode that "skipped the download" still uploaded**, so an upload-and-download run and a
  download-only run were the same workload under two labels. Each mode now performs only its own
  half inside the sampled window.
* **The client chose the transport chunk size**, so the harness measured its own politeness rather
  than any property of the server. It is a parameter now, because the interesting case is a client
  that declares the whole file as a single chunk.

Run it against a stack that is already up:

    python scripts/measure_transfer_budget.py \\
        --base-url http://127.0.0.1:8200 --admin-user admin --admin-pass secret \\
        --containers vault-api vault-db vault-redis vault-sftp --sizes 128 512

Output is JSON on stdout and a table on stderr, so it can be both read and consumed.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import threading
import time
import urllib.request

MB = 1024 * 1024
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Read from inside the container in a tight loop rather than asked for from outside. The figure
# that matters is anonymous memory -- what was actually allocated -- so page cache is subtracted
# rather than argued about. Both cgroup generations are tried, because a deployment does not get
# to choose which one its host runs.
_SAMPLER_SH = r"""
while :; do
  if [ -r /sys/fs/cgroup/memory.current ]; then
    cur=$(cat /sys/fs/cgroup/memory.current 2>/dev/null)
    fil=$(awk '/^inactive_file /{a=$2} /^active_file /{b=$2} END{print a+b}' \
          /sys/fs/cgroup/memory.stat 2>/dev/null)
  else
    cur=$(cat /sys/fs/cgroup/memory/memory.usage_in_bytes 2>/dev/null)
    fil=$(awk '/^total_inactive_file /{a=$2} /^total_active_file /{b=$2} END{print a+b}' \
          /sys/fs/cgroup/memory/memory.stat 2>/dev/null)
  fi
  [ -n "$cur" ] && echo "$cur ${fil:-0}"
done
"""


class CgroupSampler(threading.Thread):
    """Peak memory for one container, sampled from inside it."""

    def __init__(self, container: str):
        super().__init__(daemon=True)
        self.container = container
        self._stop = threading.Event()
        self._proc = None
        self.peak_total = 0
        self.peak_anon = 0
        # The floor within this window, not a baseline taken earlier. Python does not return freed
        # memory to the operating system promptly, so a container that has already done work reads
        # HIGHER at rest than a later run's peak -- comparing against it produced a negative cost.
        # The honest figure is the rise from this run's own resting reading.
        self.floor_anon = None
        self.samples = 0

    def run(self) -> None:
        self._proc = subprocess.Popen(
            ["docker", "exec", self.container, "sh", "-c", _SAMPLER_SH],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )
        try:
            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                parts = _ANSI.sub("", line).split()
                if len(parts) != 2:
                    continue
                try:
                    total, cache = int(parts[0]), int(parts[1])
                except ValueError:
                    continue
                anon = total - cache
                self.peak_total = max(self.peak_total, total)
                self.peak_anon = max(self.peak_anon, anon)
                self.floor_anon = anon if self.floor_anon is None else min(self.floor_anon, anon)
                self.samples += 1
        except Exception:                          # noqa: BLE001 - a lost sample is not a failure
            pass

    def stop(self) -> None:
        self._stop.set()
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except Exception:                      # noqa: BLE001
                self._proc.kill()
        self.join(timeout=10)


class Api:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.token = ""

    def request(self, method: str, path: str, data=None, raw=False):
        req = urllib.request.Request(self.base_url + path, method=method)
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        body = None
        if raw:
            body = data
            req.add_header("Content-Type", "application/octet-stream")
        elif data is not None:
            body = json.dumps(data).encode()
            req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, body, timeout=3600) as resp:
            return resp.read()

    def login(self, username: str, password: str) -> None:
        payload = self.request("POST", "/auth/login",
                               {"username": username, "password": password})
        self.token = json.loads(payload)["access_token"]


def _payload(size_mb: int) -> bytes:
    return ((b"dockvault-budget-probe-" * 45)[:1024]) * (size_mb * 1024)


def _upload(api: Api, vault_id: str, body: bytes, label: str, chunk_bytes: int) -> str:
    total = len(body)
    chunks = max(1, -(-total // chunk_bytes))
    session = json.loads(api.request("POST", f"/vaults/{vault_id}/uploads", {
        "file_name": f"{label}.bin", "total_size": total,
        "total_chunks": chunks, "chunk_size": chunk_bytes,
    }))["session_id"]
    for index in range(chunks):
        api.request("PUT", f"/vaults/{vault_id}/uploads/{session}/chunks/{index}",
                    body[index * chunk_bytes:(index + 1) * chunk_bytes], raw=True)
    return json.loads(api.request(
        "POST", f"/vaults/{vault_id}/uploads/{session}/complete", {}))["id"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--admin-user", required=True)
    parser.add_argument("--admin-pass", required=True)
    parser.add_argument("--containers", nargs="+", required=True)
    parser.add_argument("--sizes", nargs="+", type=int, required=True)
    parser.add_argument("--mode", choices=("both", "upload", "download"), default="both",
                        help="both = one upload and one download at the same time; the single "
                             "modes attribute the cost to one half")
    parser.add_argument("--chunk-mb", type=float, default=5.0,
                        help="transport chunk the client declares. 0 means one chunk for the "
                             "whole file, which is what an impolite client can ask for")
    args = parser.parse_args()

    api = Api(args.base_url)
    api.login(args.admin_user, args.admin_pass)

    results = []
    for size_mb in args.sizes:
        chunk_bytes = int(args.chunk_mb * MB) if args.chunk_mb else size_mb * MB
        body = _payload(size_mb)
        vault_id = json.loads(api.request(
            "POST", "/vaults", {"name": f"budget-{size_mb}-{int(time.time())}"}))["id"]
        try:
            # Whatever the sampled window is not measuring happens before it opens. A
            # download-only run needs something to download, and uploading it inside the window is
            # what made an earlier report an upload-and-download run wearing another label.
            prepared = None
            if args.mode in ("both", "download"):
                prepared = _upload(api, vault_id, body, f"prepared-{size_mb}", chunk_bytes)

            samplers = [CgroupSampler(c) for c in args.containers]
            for sampler in samplers:
                sampler.start()
            time.sleep(0.3)                        # let each one take a resting reading first

            outcomes: list[dict] = []
            errors: list[str] = []

            def _do_upload():
                try:
                    started = time.monotonic()
                    _upload(api, vault_id, body, f"probe-up-{size_mb}", chunk_bytes)
                    outcomes.append({"half": "upload",
                                     "seconds": round(time.monotonic() - started, 2)})
                except Exception as exc:           # noqa: BLE001 - reported, not raised
                    errors.append(f"upload: {exc}")

            def _do_download():
                try:
                    started = time.monotonic()
                    got = api.request("GET", f"/vaults/{vault_id}/files/{prepared}/download")
                    if got != body:
                        errors.append("download: returned bytes did not match what was uploaded")
                        return
                    outcomes.append({"half": "download",
                                     "seconds": round(time.monotonic() - started, 2)})
                except Exception as exc:           # noqa: BLE001
                    errors.append(f"download: {exc}")

            work = []
            if args.mode in ("both", "upload"):
                work.append(threading.Thread(target=_do_upload))
            if args.mode in ("both", "download"):
                work.append(threading.Thread(target=_do_download))

            started = time.monotonic()
            for thread in work:
                thread.start()
            for thread in work:
                thread.join()
            wall = time.monotonic() - started
            for sampler in samplers:
                sampler.stop()

            # A run that did not do what it says is not a measurement. Each of these three states
            # produced a confident-looking table before it was checked for.
            if errors:
                raise SystemExit(
                    f"{size_mb} MB: transfers failed, so this is not a measurement: {errors}")
            if len(outcomes) != len(work):
                raise SystemExit(
                    f"{size_mb} MB: expected {len(work)} transfer(s), recorded {len(outcomes)}")
            thin = [s.container for s in samplers if s.samples < 50]
            if thin:
                raise SystemExit(
                    f"{size_mb} MB: too few samples from {thin} over {wall:.1f}s to call any of "
                    "this a peak")

            peaks = {s.container: round(s.peak_anon / MB, 1) for s in samplers}
            rises = {s.container: round((s.peak_anon - (s.floor_anon or s.peak_anon)) / MB, 1)
                     for s in samplers}
            results.append({
                "size_mb": size_mb,
                "mode": args.mode,
                "chunk_mb": round(chunk_bytes / MB, 1),
                "wall_seconds": round(wall, 2),
                "transfers": outcomes,
                "samples": {s.container: s.samples for s in samplers},
                "peak_anon_mb": peaks,
                "rise_anon_mb": rises,
                "floor_anon_mb": {s.container: round((s.floor_anon or 0) / MB, 1)
                                  for s in samplers},
                "peak_including_cache_mb": {s.container: round(s.peak_total / MB, 1)
                                            for s in samplers},
                "sum_of_peaks_mb": round(sum(peaks.values()), 1),
            })

            print(f"\n{size_mb} MB  mode={args.mode}  chunk={chunk_bytes // MB or size_mb} MB "
                  f"({wall:.1f}s wall)", file=sys.stderr)
            for sampler in samplers:
                rise = (sampler.peak_anon - (sampler.floor_anon or sampler.peak_anon)) / MB
                print(f"    {sampler.container:<22} peak {sampler.peak_anon / MB:8.1f} MB"
                      f"   rise {rise:8.1f} MB   ({sampler.samples} samples)", file=sys.stderr)
            print(f"    {'SUM OF PEAKS':<22} anon {sum(peaks.values()):8.1f} MB"
                  "   (an upper bound: the peaks need not coincide)", file=sys.stderr)
        finally:
            # An earlier version left these behind and filled a stack with gigabytes of probes.
            try:
                api.request("DELETE", f"/vaults/{vault_id}")
            except Exception:                      # noqa: BLE001 - best effort
                pass

    json.dump({"results": results}, sys.stdout, indent=2)
    print(file=sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
