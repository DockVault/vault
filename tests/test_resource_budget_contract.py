"""The budget harness's own guards, and the arithmetic in the document it produces.

The first version of this file grepped the harness for the text of its error messages and counted
`raise` statements. Four mutations passed it, including one that neutered all three refusal guards
while leaving their message strings in place — which is precisely the regression it existed to
catch. Greps do not test behaviour.

So these load the harness and run the parts that can run without a stack, and they parse the
document's numbers rather than looking for them.
"""

import importlib.util
import re
from pathlib import Path
import sys

import pytest


pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "measure_transfer_budget.py"
BUDGETS = ROOT / "docs" / "resource-budgets.md"


def _harness():
    spec = importlib.util.spec_from_file_location("_budget_harness", HARNESS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(argv, monkeypatch, api_behaviour):
    """Drive `main()` with the network and the sampler replaced, and capture how it exits."""
    module = _harness()

    class _Api:
        def __init__(self, base_url):
            self.token = ""

        def login(self, *_a):
            pass

        request = api_behaviour

    class _Sampler:
        def __init__(self, container):
            self.container = container
            self.peak_total = 500 * module.MB
            self.peak_anon = 400 * module.MB
            self.floor_anon = 100 * module.MB
            self.samples = 5000

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(module, "Api", _Api)
    monkeypatch.setattr(module, "CgroupSampler", _Sampler)
    monkeypatch.setattr(sys, "argv", ["measure_transfer_budget.py", *argv])
    return module


_BASE_ARGS = ["--base-url", "http://x", "--admin-user", "u", "--admin-pass", "p",
              "--containers", "api", "--sizes", "8"]


def test_a_failed_transfer_stops_the_run(monkeypatch, capsys):
    """The guard, exercised rather than grepped.

    Neutering all three refusals passed the previous version of this file because it looked for
    their message text, which the mutation left untouched.
    """
    def _request(self, method, path, data=None, raw=False):
        if path.endswith("/uploads"):
            raise RuntimeError("the server said no")
        return b'{"id": "f", "session_id": "s", "access_token": "t"}'

    module = _run(_BASE_ARGS + ["--mode", "upload"], monkeypatch, _request)
    with pytest.raises(SystemExit) as exit_info:
        module.main()
    assert "not a measurement" in str(exit_info.value)


def test_a_download_that_returns_the_wrong_bytes_stops_the_run(monkeypatch):
    """A download is only a measurement if it returned what was stored."""
    def _request(self, method, path, data=None, raw=False):
        if path.endswith("/download"):
            return b"not what was uploaded"
        return b'{"id": "f", "session_id": "s", "access_token": "t"}'

    module = _run(_BASE_ARGS + ["--mode", "download"], monkeypatch, _request)
    with pytest.raises(SystemExit) as exit_info:
        module.main()
    assert "did not match" in str(exit_info.value) or "not a measurement" in str(exit_info.value)


def test_too_few_samples_stops_the_run(monkeypatch):
    """A peak from a handful of readings is the value at an arbitrary instant."""
    module = _harness()

    class _Thin:
        def __init__(self, container):
            self.container = container
            self.peak_total = self.peak_anon = self.floor_anon = 0
            self.samples = 3

        def start(self):
            pass

        def stop(self):
            pass

    def _request(self, method, path, data=None, raw=False):
        return b'{"id": "f", "session_id": "s", "access_token": "t"}'

    module = _run(_BASE_ARGS + ["--mode", "upload"], monkeypatch, _request)
    monkeypatch.setattr(module, "CgroupSampler", _Thin)
    with pytest.raises(SystemExit) as exit_info:
        module.main()
    assert "too few samples" in str(exit_info.value)


def test_a_clean_run_reports_a_rise_and_not_a_bare_peak(monkeypatch, capsys):
    """The rise is the figure the document quotes, so it has to reach the output."""
    def _request(self, method, path, data=None, raw=False):
        if path.endswith("/download"):
            return ((b"dockvault-budget-probe-" * 45)[:1024]) * (8 * 1024)
        return b'{"id": "f", "session_id": "s", "access_token": "t"}'

    module = _run(_BASE_ARGS + ["--mode", "download"], monkeypatch, _request)
    assert module.main() == 0
    report = capsys.readouterr()
    assert "rise" in report.err
    payload = report.out[report.out.index("{"):]
    import json
    result = json.loads(payload)["results"][0]
    assert result["rise_anon_mb"]["api"] == 300.0, "the rise is peak minus this run's own floor"
    assert result["mode"] == "download"


def test_upload_mode_does_not_claim_a_download(monkeypatch):
    """It used to set the comparison buffer to the source and report an intact round trip.

    A byte count and an integrity verdict for a transfer that never happened is the shape of a
    number you can publish and be wrong about.
    """
    def _request(self, method, path, data=None, raw=False):
        assert not path.endswith("/download"), "upload mode performed a download"
        return b'{"id": "f", "session_id": "s", "access_token": "t"}'

    module = _run(_BASE_ARGS + ["--mode", "upload"], monkeypatch, _request)
    assert module.main() == 0


def test_download_mode_prepares_its_file_before_sampling_starts(monkeypatch):
    """Otherwise a download-only run is an upload-and-download run under another label.

    That was true of the first version, which is why its two rows differed by noise rather than by
    the cost of an upload.
    """
    module = _harness()
    order = []

    class _Api:
        def __init__(self, base_url):
            self.token = ""

        def login(self, *_a):
            pass

        def request(self, method, path, data=None, raw=False):
            if path.endswith("/uploads") or "/chunks/" in path or path.endswith("/complete"):
                order.append("upload")
            elif path.endswith("/download"):
                order.append("download")
                return ((b"dockvault-budget-probe-" * 45)[:1024]) * (8 * 1024)
            return b'{"id": "f", "session_id": "s", "access_token": "t"}'

    class _Sampler:
        def __init__(self, container):
            self.container = container
            self.peak_total = 500 * module.MB
            self.peak_anon = 400 * module.MB
            self.floor_anon = 100 * module.MB
            self.samples = 5000

        def start(self):
            order.append("sampling-started")

        def stop(self):
            pass

    monkeypatch.setattr(module, "Api", _Api)
    monkeypatch.setattr(module, "CgroupSampler", _Sampler)
    monkeypatch.setattr(sys, "argv",
                        ["m", *(_BASE_ARGS + ["--mode", "download"])])
    assert module.main() == 0
    assert "sampling-started" in order
    started = order.index("sampling-started")
    assert "upload" in order[:started], "the file was not prepared before sampling began"
    assert "upload" not in order[started:], "an upload happened inside the sampled window"


# ------------------------------------------------------------------ the document's arithmetic

def _document_rows():
    """The measured table: (case, rise MB, multiple of the file)."""
    text = BUDGETS.read_text(encoding="utf-8")
    return re.findall(r"\|\s*([^|]+?)\s*\|\s*([\d.]+) MB\s*\|\s*\*\*([\d.]+)×\*\*", text)


def test_the_measured_multiples_match_the_measured_rises():
    """Two numbers written side by side drift, and the one nobody re-derives gets quoted."""
    rows = _document_rows()
    assert len(rows) >= 3, f"expected the three measured cases, found {len(rows)}"
    for case, rise_mb, multiple in rows:
        expected = float(rise_mb) / 128.0          # every measured row is the 128 MB file
        assert abs(expected - float(multiple)) < 0.02, (
            f"{case}: {rise_mb} MB over a 128 MB file is {expected:.2f}x, not {multiple}x")


def test_the_sizing_table_follows_the_stated_formula():
    """The rows an operator acts on, checked against the rule the document gives for them.

    The previous version stated a formula and a table that disagreed by up to 18%, because nothing
    derived one from the other.
    """
    text = BUDGETS.read_text(encoding="utf-8")
    fixed = int(re.search(r"total ≈ (\d+) MB", text).group(1))
    slope = float(re.search(r"MB\s+\+\s+([\d.]+)F", text).group(1))

    rows = re.findall(r"\|\s*([\d.]+) (GB|MB)\s*\|\s*~([\d.]+) (GB|MB)\s*\|", text)
    assert len(rows) >= 4, f"expected the RAM sizing rows, found {len(rows)}"
    for ram_value, ram_unit, file_value, file_unit in rows:
        ram_mb = float(ram_value) * (1024 if ram_unit == "GB" else 1)
        file_mb = float(file_value) * (1024 if file_unit == "GB" else 1)
        predicted = (ram_mb - fixed) / slope
        assert abs(predicted - file_mb) / predicted < 0.12, (
            f"{ram_value} {ram_unit}: the formula gives {predicted:.0f} MB, the table says "
            f"{file_mb:.0f} MB")


def test_the_document_does_not_claim_upload_is_safe_or_the_target_met():
    """Two sentences that would be quoted onward and are both false.

    An earlier draft said upload was already bounded and needed no work. It is bounded only while
    the client chooses small chunks, which the server does not require.
    """
    # Whitespace-normalised, because these sentences wrap and an exact-substring check fails on
    # the line break rather than on the claim -- which is a test that breaks when the prose is
    # reflowed and stays silent when the meaning changes.
    text = " ".join(BUDGETS.read_text(encoding="utf-8").split())
    assert "A client decides how much server memory its upload consumes" in text
    assert "Not reachable at the configured maximum file size" in text
    assert "Nothing here was tuned to reach the target" in text
