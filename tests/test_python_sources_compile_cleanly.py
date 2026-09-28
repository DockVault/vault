"""Every Python file in the repository compiles with warnings treated as errors.

An invalid escape in an ordinary string ("\\d" in a regular expression written into a test's
JavaScript) is only a SyntaxWarning today, and a string that means what it says by accident. It is an
error under -W error, and Python has said it will become one outright; then the whole file fails to
import and every test in it goes unrun. Such strings are written raw, or with the backslash doubled.
"""
import warnings
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


def _sources():
    files = sorted(ROOT.glob("*.py"))
    for folder in ("app", "tests", "scripts"):
        files += sorted((ROOT / folder).rglob("*.py"))
    return [f for f in files if "__pycache__" not in f.parts]


def test_every_python_file_compiles_with_warnings_as_errors():
    files = _sources()
    assert len(files) > 100 and (ROOT / "tests" / "test_ui_credential_requests.py") in files
    failing = []
    for path in files:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            try:
                compile(path.read_text(encoding="utf-8"), str(path), "exec")
            except (SyntaxError, SyntaxWarning) as exc:
                failing.append(f"{path.relative_to(ROOT).as_posix()}:{getattr(exc, 'lineno', '?')}: {exc}")
    assert not failing, failing
