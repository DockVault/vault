#!/usr/bin/env python3
"""What a zero-knowledge upload costs the BROWSER, split by process.

The server-side budget harness (`measure_transfer_budget.py`) samples container cgroups. It says
nothing about this: the claim under test is about the tab.

Three things this is built to avoid, each of which has already produced a wrong number in this
project:

* **Aggregating the browser's processes.** An earlier download measurement summed them, reported
  that the tab held about one copy of the file, and was wrong about the owner: split by role, the
  buffered path keeps a tenth in the renderer because Blob parts live in the *browser* process's
  blob store. Upload accumulates its ciphertext the same way, so an aggregate here would repeat
  the error while appearing to confirm the claim. Every figure below is per role.

* **Believing an instrument that was never checked.** The `control` arm holds one copy of the
  payload in the most obvious way available. If it does not report roughly 100% of the payload in
  the renderer, the instrument is broken and every other number in the run is void. Four memory
  probes in this project read plausibly and wrongly before one did.

* **Sampling before and after.** A peak only exists while the work is running. Sampling is
  continuous on a background thread; the reported figure is the maximum observed minus the
  quiescent baseline for that same process role.

Arms:
  control  -- hold one Uint8Array of the payload. Expect renderer ~= 100%.
  whole    -- `encryptFileV2` over an ArrayBuffer: the whole-file path. Expect ~3x, which is the
              number the shipped path exists to beat.
  shipped  -- `encryptBlobV2` over a Blob: what the uploader calls today (`app.js`). The claim is
              renderer ~= one chunk, browser process ~= one copy.

Usage:
  python scripts/measure_browser_upload_memory.py --base-url http://localhost:8290 --payload-mb 128
"""
from __future__ import annotations

import argparse
import json
import statistics
import threading
import time

MB = 1024 * 1024

# Sampling faster than this buys noise, not resolution: RSS is updated by the OS on its own
# schedule and a tighter loop mostly measures the loop.
SAMPLE_INTERVAL_S = 0.05

# How long to watch a quiet browser before an arm, to get the baseline the peak is measured
# against. Long enough for start-up allocation to settle.
BASELINE_SETTLE_S = 1.5


def classify(cmdline: list[str]) -> str:
    """Chromium's own `--type=` flag, which is the only reliable way to tell its processes apart.

    The parent has no `--type` at all; that is the browser process, and it is where Blob parts
    live. Everything else names itself.
    """
    for arg in cmdline:
        if arg.startswith("--type="):
            kind = arg.split("=", 1)[1]
            return kind if kind in ("renderer", "gpu-process", "utility", "zygote") else "other"
    return "browser"


class ProcessSampler(threading.Thread):
    """Peak RSS per process role, sampled continuously while an arm runs.

    Re-enumerates children every tick on purpose: Chromium spawns and reaps processes during a
    run, and a list captured once would miss a renderer that appeared after it.
    """

    def __init__(self, root_pid: int):
        super().__init__(daemon=True)
        import psutil
        self._psutil = psutil
        self._root = psutil.Process(root_pid)
        self._stop = threading.Event()
        self.samples: dict[str, list[int]] = {}

    def _tick(self) -> None:
        totals: dict[str, int] = {}
        procs = [self._root] + self._root.children(recursive=True)
        for p in procs:
            try:
                role = classify(p.cmdline())
                totals[role] = totals.get(role, 0) + p.memory_info().rss
            except (self._psutil.NoSuchProcess, self._psutil.AccessDenied):
                # A process that exits mid-enumeration is normal, not an error. Skipping it can
                # only understate a peak, never invent one.
                continue
        for role, value in totals.items():
            self.samples.setdefault(role, []).append(value)

    def run(self) -> None:
        while not self._stop.is_set():
            self._tick()
            time.sleep(SAMPLE_INTERVAL_S)

    def stop(self) -> None:
        self._stop.set()
        self.join(timeout=5)

    def peak(self) -> dict[str, int]:
        return {role: max(vals) for role, vals in self.samples.items() if vals}

    def median(self) -> dict[str, int]:
        return {role: int(statistics.median(vals)) for role, vals in self.samples.items() if vals}


# Each arm is split in two. `prepare` builds the payload and any handles the operation needs;
# `act` performs only the thing under test. The baseline is taken AFTER prepare, so what is
# reported is the cost of the OPERATION and not the cost of having a file to operate on.
#
# The first version of this harness measured them together, and the numbers were unusable in a way
# that looked authoritative: the shipped path appeared to cost more in total than the whole-file
# path it replaced, purely because constructing a Blob source puts a copy in the browser process
# before the operation starts.
ARMS = {
    # Calibration. `prepare` does nothing, so this measures one deliberate copy, and the renderer
    # must report roughly 100% of the payload or the instrument is not to be believed.
    "control": {
        "prepare": "async () => null",
        "act": """
            async (mb) => {
                const n = mb * 1024 * 1024;
                window.__held = new Uint8Array(n);
                // Touch every page: an untouched allocation may not be resident, and a probe that
                // reads zero for a live array is exactly the failure this arm exists to catch.
                for (let i = 0; i < n; i += 4096) window.__held[i] = 1;
                await new Promise(r => setTimeout(r, 400));
                return {held: window.__held.length};
            }
        """,
    },
    # The whole-file path: source already in the heap, encrypt it all, concatenate.
    "whole": {
        "prepare": """
            async (mb) => {
                window.__src = new ArrayBuffer(mb * 1024 * 1024);
                window.__dek = await crypto.subtle.generateKey(
                    {name:'AES-GCM',length:256}, true, ['encrypt','decrypt']);
                return {bytes: window.__src.byteLength};
            }
        """,
        "act": """
            async () => {
                const lib = new ECCCryptoLibrary();
                window.__out = await lib.encryptFileV2(window.__src, window.__dek,
                    {vaultId: '00000000-0000-4000-8000-000000000000',
                     objectId: '00000000-0000-4000-8000-000000000001', dekEpoch: 1});
                return {bytes: window.__out.byteLength || window.__out.size || 0};
            }
        """,
    },
    # What the uploader calls today: source is a Blob, sealed chunks are handed to a Blob as they
    # are produced. The source Blob is built in `prepare`, so its cost is in the baseline.
    "shipped": {
        "prepare": """
            async (mb) => {
                window.__src = new Blob([new Uint8Array(mb * 1024 * 1024)]);
                window.__dek = await crypto.subtle.generateKey(
                    {name:'AES-GCM',length:256}, true, ['encrypt','decrypt']);
                // Let the transient Uint8Array used to build the Blob be collected, so it is not
                // charged to the operation.
                if (window.gc) { window.gc(); }
                await new Promise(r => setTimeout(r, 600));
                return {bytes: window.__src.size};
            }
        """,
        "act": """
            async () => {
                const lib = new ECCCryptoLibrary();
                window.__out = await lib.encryptBlobV2(window.__src, window.__dek,
                    {vaultId: '00000000-0000-4000-8000-000000000000',
                     objectId: '00000000-0000-4000-8000-000000000001', dekEpoch: 1});
                return {bytes: window.__out.size || window.__out.byteLength || 0};
            }
        """,
    },
}


def _chromium_pids() -> set[int]:
    import psutil
    found = set()
    for p in psutil.process_iter(["name"]):
        try:
            if (p.info["name"] or "").lower().startswith(("chrome", "chromium", "headless")):
                found.add(p.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return found


def _browser_root_pid(before: set[int]) -> int:
    """The browser process of the instance we just launched.

    Playwright's sync API does not expose the pid, so it is identified by elimination: a Chromium
    process that did not exist before the launch and carries no `--type=` flag. Anchoring on
    "new since launch" matters because the developer's own browser is usually running, and
    sampling that instead would produce a number with no relationship to the arm.
    """
    import psutil
    candidates = []
    for pid in _chromium_pids() - before:
        try:
            p = psutil.Process(pid)
            if classify(p.cmdline()) == "browser":
                candidates.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not candidates:
        raise RuntimeError("could not identify the launched browser process; refusing to sample "
                           "an unrelated one")
    # The oldest new browser-role process is the parent; any others descend from it.
    return min(candidates, key=lambda p: p.create_time()).pid


def run_arm(playwright, base_url: str, arm: str, payload_mb: int, keep_open: bool) -> dict:
    """One arm in a FRESH browser, so nothing an earlier arm allocated is in the baseline."""
    before = _chromium_pids()
    browser = playwright.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--js-flags=--expose-gc"],
    )
    try:
        page = browser.new_page()
        # The library is a classic script; loading it into a real page from the deployment under
        # test means measuring the shipped file, not a copy of it.
        page.goto(f"{base_url}/", wait_until="domcontentloaded")
        page.add_script_tag(url="/static/js/ecc_crypto.js")
        page.wait_for_function("typeof ECCCryptoLibrary !== 'undefined'", timeout=30_000)

        # Build the payload FIRST, so its cost lands in the baseline rather than in the result.
        page.evaluate(ARMS[arm]["prepare"], payload_mb)

        sampler = ProcessSampler(_browser_root_pid(before))
        sampler.start()
        time.sleep(BASELINE_SETTLE_S)
        baseline = sampler.median()

        result = page.evaluate(ARMS[arm]["act"], payload_mb)

        # Let allocation settle into RSS before stopping: the peak can trail the JS call.
        time.sleep(0.6)
        sampler.stop()
        peak = sampler.peak()

        payload = payload_mb * MB
        rows = {}
        for role in sorted(set(peak) | set(baseline)):
            delta = peak.get(role, 0) - baseline.get(role, 0)
            rows[role] = {
                "peak_mb": round(peak.get(role, 0) / MB, 1),
                "baseline_mb": round(baseline.get(role, 0) / MB, 1),
                "growth_mb": round(delta / MB, 1),
                "pct_of_payload": round(100.0 * delta / payload, 1),
            }
        return {"arm": arm, "payload_mb": payload_mb, "js": result, "roles": rows}
    finally:
        if not keep_open:
            browser.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", required=True,
                        help="a running deployment; the shipped ecc_crypto.js is loaded from it")
    parser.add_argument("--payload-mb", type=int, default=128)
    parser.add_argument("--arms", default="control,whole,shipped")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright

    results = []
    with sync_playwright() as pw:
        for arm in [a.strip() for a in args.arms.split(",") if a.strip()]:
            if arm not in ARMS:
                raise SystemExit(f"unknown arm {arm!r}; choose from {', '.join(ARMS)}")
            results.append(run_arm(pw, args.base_url.rstrip("/"), arm, args.payload_mb, False))

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    print(f"\nPayload {args.payload_mb} MiB. Growth over each arm's own quiescent baseline, "
          f"as a percentage of the payload.\n")
    header = f"{'arm':10} {'role':14} {'growth MiB':>11} {'% of payload':>13}"
    print(header)
    print("-" * len(header))
    for r in results:
        for role, row in r["roles"].items():
            if abs(row["growth_mb"]) < 1.0:
                continue                      # noise floor; a role that did not move
            print(f"{r['arm']:10} {role:14} {row['growth_mb']:>11.1f} {row['pct_of_payload']:>12.1f}%")

    control = next((r for r in results if r["arm"] == "control"), None)
    if control:
        got = control["roles"].get("renderer", {}).get("pct_of_payload", 0)
        verdict = "instrument OK" if 80 <= got <= 150 else "INSTRUMENT SUSPECT — do not use these numbers"
        print(f"\nControl arm held one copy in the renderer and read {got}% — {verdict}.")
    else:
        print("\nNo control arm was run. The other numbers are unvalidated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
