"""Unit coverage for the CI JUnit completeness audit."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit

_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "pytest_result_audit.py"
_SPEC = importlib.util.spec_from_file_location("pytest_result_audit", _SCRIPT)
assert _SPEC and _SPEC.loader
_AUDIT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_AUDIT)


def _report(tmp_path: Path, *, tests: int, skipped: int = 0, failures: int = 0, errors: int = 0) -> Path:
    report = tmp_path / "results.xml"
    report.write_text(
        (
            f'<testsuites><testsuite tests="{tests}" skipped="{skipped}" '
            f'failures="{failures}" errors="{errors}" /></testsuites>'
        ),
        encoding="utf-8",
    )
    return report


def test_accepts_complete_successful_report(tmp_path):
    summary = _AUDIT.audit(_report(tmp_path, tests=100, skipped=5), 100, 0.15)
    assert "collected=100" in summary
    assert "ran=95" in summary


@pytest.mark.parametrize(
    ("tests", "skipped", "failures", "errors", "expected", "message"),
    [
        (99, 0, 0, 0, 100, "preflight collected 100"),
        (100, 0, 1, 0, 100, "1 failed, 0 errored"),
        (100, 0, 0, 1, 100, "0 failed, 1 errored"),
        (100, 16, 0, 0, 100, "ceiling is 15%"),
        (0, 0, 0, 0, 0, "contains no tests"),
    ],
)
def test_rejects_incomplete_or_failed_report(
    tmp_path, tests, skipped, failures, errors, expected, message
):
    report = _report(
        tmp_path,
        tests=tests,
        skipped=skipped,
        failures=failures,
        errors=errors,
    )
    with pytest.raises(ValueError, match=message):
        _AUDIT.audit(report, expected, 0.15)


def test_rejects_missing_and_malformed_reports(tmp_path):
    with pytest.raises(ValueError, match="no usable pytest report"):
        _AUDIT.audit(tmp_path / "missing.xml", 1, 0.15)

    malformed = tmp_path / "malformed.xml"
    malformed.write_text("<testsuite", encoding="utf-8")
    with pytest.raises(ValueError, match="no usable pytest report"):
        _AUDIT.audit(malformed, 1, 0.15)
