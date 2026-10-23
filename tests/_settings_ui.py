"""The Settings pages in the browser: reveal a page's advanced settings (static/js/settings-levels.js hides them
behind "Show advanced settings (N)" until asked), for a test that works with one of them."""
import re

from playwright.sync_api import Page, expect

_SHOWN = "Hide advanced settings"


def show_advanced(page: Page, tab: str) -> None:
    """Show the advanced settings of the Settings page ``tab`` (its data-tab name), once the page has read
    the catalogue and hidden them. A page already showing them is left as it is."""
    toggle = page.locator(f"#settings-tab-{tab} .settings-advanced-toggle")
    expect(toggle).to_be_visible(timeout=15000)
    expect(toggle).to_have_text(re.compile(r"^(Show advanced settings \(\d+\)|Hide advanced settings)$"))
    if toggle.inner_text().strip() != _SHOWN:
        toggle.click()
    expect(toggle).to_have_text(_SHOWN)
