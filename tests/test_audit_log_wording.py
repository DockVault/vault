"""The audit log is described as what it is.

The retention setting's comments called the audit log "append-only" and its default "compliance-safe".
Neither is true of the table: the app deletes old rows when AUDIT_LOG_RETENTION_DAYS is positive, and
anyone with access to the database can change or delete any row. An operator reading those words could
take the log for tamper-evident evidence it is not. The text now says what the setting does.
"""
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent

# Words that promise more than an ordinary database table gives.
OVERSTATED = ("append-only", "append only", "compliance-safe", "compliance safe", "tamper-proof",
              "tamper proof")


def _shipped_text():
    """Every file an operator or a user reads: the code, the web app, the docs and the examples."""
    files = [ROOT / ".env.example", ROOT / "README.md", ROOT / "dockvault.py"]
    for base, patterns in ((ROOT / "app", ("*.py",)), (ROOT / "static", ("*.js", "*.html")),
                           (ROOT / "docs", ("*.md", "*.json")), (ROOT / "deploy", ("*.yml", "*.md"))):
        for pattern in patterns:
            files.extend(base.rglob(pattern))
    return [f for f in files if f.is_file()]


def test_the_scan_reads_the_files_that_carried_the_words():
    names = {f.relative_to(ROOT).as_posix() for f in _shipped_text()}
    assert {".env.example", "app/core/config.py", "app/services/audit_logger.py"} <= names


def test_nothing_shipped_calls_the_audit_log_append_only_or_compliance_safe():
    found = []
    for path in _shipped_text():
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        for word in OVERSTATED:
            if word in text:
                found.append(f"{path.relative_to(ROOT).as_posix()}: {word!r}")
    assert not found, "say what the audit log does instead: " + "; ".join(found)


def _comment_above(lines, setting):
    at = next(i for i, line in enumerate(lines) if line.startswith(setting + "="))
    block = []
    for line in reversed(lines[:at]):
        if not line.startswith("#"):
            break
        block.append(line.lstrip("# "))
    return " ".join(reversed(block))


def test_the_env_example_says_what_the_retention_setting_does():
    lines = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    comment = _comment_above(lines, "AUDIT_LOG_RETENTION_DAYS")
    assert "0 (the default) keeps every audit row" in comment, comment
    assert "deletes audit rows older than that many days" in comment, comment
    assert "at most once an hour" in comment, comment
    assert "anyone with access to the database" in comment, comment
