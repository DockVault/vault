"""What the Settings page tells an install on an older release line, run under Node.

The words come from `lineBannerMessage` and `formatReleaseDay` in ``static/js/app.js``, lifted out
verbatim, so the tests run the SHIPPED functions: the newest release of the install's own line, a
notice once the line's security fixes have ended, and the key a dismissal remembers. What the browser
draws is the UI lane (``test_ui_update_check.py``).
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _top_level(name: str) -> str:
    """One top-level function of app.js, verbatim, up to its closing brace at column 0."""
    start = JS.index(f"\nfunction {name}(") + 1
    return JS[start:JS.index("\n}\n", start) + 3]


MONTHS = JS[JS.index("const RELEASE_MONTHS"):JS.index("\n\nfunction formatReleaseDay(")]


def _messages(*statuses):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    body = (MONTHS + "\n" + _top_level("formatReleaseDay") + _top_level("lineBannerMessage")
            + "const statuses = " + json.dumps(list(statuses)) + ";\n"
            + "process.stdout.write(JSON.stringify(statuses.map(s => lineBannerMessage(s))));\n")
    done = subprocess.run([node, "-"], input=body, capture_output=True, text=True, encoding="utf-8",
                          timeout=60, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout)


def _update(version="0.33.2", fixes=True, until="2027-06-10"):
    return {"version": version, "line": "0.33", "fixes_vulnerability": fixes,
            "security_fixes_until": until}


def test_a_security_update_on_the_installs_line_is_named_with_its_support_period():
    [message] = _messages({"latest": "v0.34.1", "line_update": _update()})
    assert message == {
        "text": "Security update v0.33.2 is available for your release line (0.33, security fixes "
                "until 10 June 2027). The newest release is v0.34.1.",
        "key": "0.33.2|"}


def test_an_update_that_fixes_nothing_the_install_has_is_not_called_a_security_update():
    [message] = _messages({"latest": "0.34.1", "line_update": _update(version="0.33.3", fixes=False)})
    assert message["text"].startswith("Update v0.33.3 is available for your release line (0.33, ")
    [message] = _messages({"latest": "0.34.1", "line_update": _update(fixes="true")})
    assert message["text"].startswith("Update v0.33.2"), "only a real true is a security update"


def test_a_line_whose_security_fixes_ended_says_so_and_points_to_a_newer_line():
    line = {"line": "0.33", "security_fixes_until": "2027-06-10", "ended": True}
    [ended, both] = _messages({"latest": "0.35.0", "line": line},
                              {"latest": "0.35.0", "line": line, "line_update": _update("0.33.3")})
    assert ended == {"text": "Security fixes for your release line (0.33) ended on 10 June 2027; move "
                             "to a newer line. The newest release is v0.35.0.",
                     "key": "|0.33"}
    assert both["text"].startswith("Security update v0.33.3 is available for your release line")
    assert "ended on 10 June 2027; move to a newer line." in both["text"]
    assert both["key"] == "0.33.3|0.33", "the line ending shows a dismissed banner again"


def test_nothing_to_say_is_no_banner():
    assert _messages({}, {"latest": "0.34.1"},
                     {"line": {"line": "0.33", "security_fixes_until": "2027-06-10", "ended": False}},
                     {"line": {"line": "0.33", "security_fixes_until": "2027-06-10",
                               "ended": "true"}}) == [None, None, None, None]


def test_only_a_plain_day_is_shown_and_the_text_is_bounded():
    [no_day, not_a_day, huge] = _messages(
        {"line_update": _update(until=None)},
        {"line_update": _update(until="2027-13-01")},
        {"latest": "9" * 500, "line_update": _update(version="v" + "1" * 500, until="soon")})
    assert no_day["text"] == "Security update v0.33.2 is available for your release line (0.33)."
    assert not_a_day["text"] == no_day["text"]
    assert len(huge["text"]) <= 400 and "soon" not in huge["text"]
    assert huge["key"] == "1" * 32 + "|"
