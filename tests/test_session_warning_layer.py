"""The stay-or-sign-out warning paints above everything else on the page, offline.

Every z-index the stylesheets and scripts set is read, and the warning's (static/css/components.css) is
above all of them: every dialog (the step-up and a lifted prompt included), every panel and tray, the drop
zone and the loading overlay. Only the toasts sit higher, so a message stays readable instead of being
dimmed behind the warning's backdrop.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
CSS = sorted((ROOT / "static" / "css").glob("*.css"))
JS = sorted((ROOT / "static" / "js").glob("*.js"))

_CSS_Z = re.compile(r"z-index\s*:\s*(-?\d+)")
_JS_Z = re.compile(r"""zIndex\s*=\s*['"]?(-?\d+)|z-index\s*:\s*(-?\d+)""")


def _match(text: str, selector: str):
    match = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", text)
    assert match, f"no rule for {selector}"
    return match


def _rule(text: str, selector: str) -> str:
    return _match(text, selector).group(1)


def _without_rule(text: str, selector: str) -> str:
    """The text with that one rule cut out where it stands (another rule with the same body stays)."""
    match = _match(text, selector)
    return text[:match.start()] + text[match.end():]


def _z_of(text: str, selector: str) -> int:
    found = _CSS_Z.findall(_rule(text, selector))
    assert len(found) == 1, (selector, found)
    return int(found[0])


def _every_other_z():
    """(where, value) for every z-index set in the stylesheets and scripts, the warning's and the toasts' own
    rules left out."""
    seen = []
    for path in CSS:
        text = path.read_text(encoding="utf-8")
        if path.name == "components.css":
            for selector in ("#session-expiry-modal.modal", ".toast-container"):
                text = _without_rule(text, selector)
        for value in _CSS_Z.findall(text):
            seen.append((path.name, int(value)))
    for path in JS:
        for a, b in _JS_Z.findall(path.read_text(encoding="utf-8")):
            seen.append((path.name, int(a or b)))
    return seen


def test_the_warning_is_above_every_other_layer_and_below_the_toasts_only():
    components = (ROOT / "static" / "css" / "components.css").read_text(encoding="utf-8")
    warning = _z_of(components, "#session-expiry-modal.modal")
    toasts = _z_of(components, ".toast-container")
    others = _every_other_z()
    # The scan reads what it should: the dialog layer, the step-up's lift, the panels, the reset-link overlay.
    values = {v for _, v in others}
    assert {1000, 1100, 1200, 1500, 9999, 10000} <= values, sorted(values)
    above = [(where, v) for where, v in others if v >= warning]
    assert not above, f"painted at or above the stay-or-sign-out warning ({warning}): {above}"
    assert toasts > warning


def test_the_scan_sees_the_scripts_lifts():
    # The step-up and the compliance prompt are lifted from the scripts; a scan that missed them would pass
    # with the warning under them.
    found = {path.name for path in JS for a, b in _JS_Z.findall(path.read_text(encoding="utf-8")) if (a or b) == "1100"}
    assert {"app.js", "compliance.js"} <= found, found


def test_a_rule_with_the_same_body_as_the_warnings_is_still_seen():
    text = "#session-expiry-modal.modal {\n    z-index: 10500;\n}\n#x.modal {\n    z-index: 10500;\n}\n"
    assert _CSS_Z.findall(_without_rule(text, "#session-expiry-modal.modal")) == ["10500"]


def test_a_dialog_lifted_over_another_stays_under_the_warning():
    # dialogs.js lifts a dialog opened over others to one above them, computed, so the scan above cannot
    # read it; its ceiling is what keeps it under the warning.
    components = (ROOT / "static" / "css" / "components.css").read_text(encoding="utf-8")
    warning = _z_of(components, "#session-expiry-modal.modal")
    dialogs = (ROOT / "static" / "js" / "dialogs.js").read_text(encoding="utf-8")
    ceiling = re.search(r"const LIFT_CEILING = (\d+);", dialogs)
    assert ceiling and int(ceiling.group(1)) <= warning
    assert "Math.min(highest + 1, LIFT_CEILING - 1)" in dialogs and "(z) => z < LIFT_CEILING" in dialogs
