"""The frontend has one coercing HTML-escaping contract."""

import re
from pathlib import Path

import pytest
from playwright.sync_api import Page


APP_JS = (
    Path(__file__).resolve().parent.parent / "static" / "js" / "app.js"
).read_text(encoding="utf-8")


@pytest.mark.unit
def test_escape_html_has_one_definition_and_no_raw_fallback():
    definitions = re.findall(r"(?m)^function escapeHtml\s*\(", APP_JS)
    assert len(definitions) == 1
    assert "escapeHtml ? escapeHtml" not in APP_JS
    assert "text.toString().replace" in APP_JS


@pytest.mark.ui
def test_escape_html_coerces_scalars_and_neutralizes_hostile_dom_value(page: Page):
    page.goto("/")
    page.wait_for_function("() => typeof escapeHtml === 'function'")

    values = page.evaluate(
        """() => {
            const hostile = `<img src=x onerror="window.__escapeXss=1">&"'`;
            const host = document.createElement('div');
            host.innerHTML = escapeHtml(hostile);
            document.body.appendChild(host);
            const result = {
                nullValue: escapeHtml(null),
                undefinedValue: escapeHtml(undefined),
                empty: escapeHtml(''),
                zero: escapeHtml(0),
                falseValue: escapeHtml(false),
                integer: escapeHtml(42),
                decimal: escapeHtml(3.5),
                metacharacters: escapeHtml(`&<>"'`),
                hostileText: host.textContent,
                hostileElements: host.querySelectorAll('*').length,
                executed: window.__escapeXss === 1,
            };
            host.remove();
            return result;
        }"""
    )

    assert values == {
        "nullValue": "",
        "undefinedValue": "",
        "empty": "",
        "zero": "0",
        "falseValue": "false",
        "integer": "42",
        "decimal": "3.5",
        "metacharacters": "&amp;&lt;&gt;&quot;&#039;",
        "hostileText": '<img src=x onerror="window.__escapeXss=1">&"\'',
        "hostileElements": 0,
        "executed": False,
    }
