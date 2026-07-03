"""Verify vaults grid/list + temp-creds pagination (run directly)."""
import json
from pathlib import Path
import requests
from playwright.sync_api import sync_playwright

BASE = "http://localhost:8200"
HERE = Path(__file__).resolve().parent
SHOTS = HERE / "_shots" / "verify"; SHOTS.mkdir(parents=True, exist_ok=True)

E = {}
for line in (HERE.parent / ".env").read_text(encoding="utf-8", errors="ignore").splitlines():
    if "=" in line and not line.startswith("#"):
        k, _, v = line.partition("="); E[k.strip()] = v.strip()
USER, PW = E.get("ADMIN_USERNAME", "admin"), E.get("ADMIN_PASSWORD", "")

report = {"page_errors": [], "console_errors": []}
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_context(base_url=BASE, viewport={"width": 1440, "height": 900}).new_page()
    pg.on("pageerror", lambda e: report["page_errors"].append(str(e)))
    pg.on("console", lambda m: report["console_errors"].append(f"{m.type}: {m.text}") if m.type == "error" else None)

    pg.goto("/"); pg.wait_for_selector("#login-screen", timeout=15000)
    pg.fill("#username", USER); pg.fill("#password", PW)
    pg.click("#login-form button[type=submit]"); pg.wait_for_selector("#dashboard-screen", timeout=15000)

    # Vaults grid
    pg.click('.sidebar-item[data-section="vaults"]'); pg.wait_for_timeout(1000)
    pg.screenshot(path=str(SHOTS / "vaults_grid_new.png"), full_page=True)
    print("delete buttons present (admin):", len(pg.query_selector_all('.delete-vault-btn')))
    # List mode
    pg.click('[data-vaults-view="list"]'); pg.wait_for_timeout(700)
    print("vaults-as-list applied:", pg.eval_on_selector('#vaults-list', 'el => el.classList.contains("vaults-as-list")'))
    pg.screenshot(path=str(SHOTS / "vaults_list_new.png"), full_page=True)
    pg.click('[data-vaults-view="grid"]'); pg.wait_for_timeout(400)

    # Temp credentials — default Active + pagination
    pg.click('.sidebar-item[data-section="temp-creds"]'); pg.wait_for_timeout(1200)
    sel = pg.eval_on_selector('#tc-status-filter', 'el => el.value')
    count = pg.inner_text('#tc-count') if pg.is_visible('#tc-count') else '(none)'
    show_more = pg.is_visible('#tc-show-more')
    rows = len(pg.query_selector_all('#active-temp-creds .exp-row'))
    print(f"tc default filter={sel}  count='{count}'  show_more={show_more}  rendered_rows={rows}")
    pg.screenshot(path=str(SHOTS / "tempcreds_active_paginated.png"), full_page=False)
    if show_more:
        pg.click('#tc-show-more'); pg.wait_for_timeout(600)
        rows2 = len(pg.query_selector_all('#active-temp-creds .exp-row'))
        print("after show-more rendered_rows:", rows2)
    b.close()

print("\nREPORT:", json.dumps(report, indent=2))
