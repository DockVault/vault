"""Verify dashboard storage/icons, Info strip, Monitor tiles (run directly)."""
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
S = requests.Session()
tok = S.post(f"{BASE}/auth/login", json={"username": USER, "password": PW}, timeout=15).json()["access_token"]
S.headers["Authorization"] = f"Bearer {tok}"
vaults = S.get(f"{BASE}/vaults", timeout=15).json()
rich = next((v for v in vaults if v.get("name") == "DEMO Engineering Drop"), None) or vaults[0]

report = {"page_errors": [], "console_errors": []}
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_context(base_url=BASE, viewport={"width": 1440, "height": 900}).new_page()
    pg.on("pageerror", lambda e: report["page_errors"].append(str(e)))
    pg.on("console", lambda m: report["console_errors"].append(f"{m.type}: {m.text}") if m.type == "error" else None)
    pg.goto("/"); pg.wait_for_selector("#login-screen", timeout=15000)
    pg.fill("#username", USER); pg.fill("#password", PW)
    pg.click("#login-form button[type=submit]"); pg.wait_for_selector("#dashboard-screen", timeout=15000)
    pg.wait_for_timeout(1500)

    storage = pg.inner_text("#dashboard-storage")
    icons = pg.eval_on_selector_all("#events-feed .event-icon use", "els => els.map(e => e.getAttribute('href'))")
    print("dashboard storage:", storage, "| distinct event icons:", sorted(set(icons)))
    pg.screenshot(path=str(SHOTS / "dashboard_after.png"))

    pg.click('.sidebar-item[data-section="vaults"]'); pg.wait_for_timeout(800)
    pg.click(f'.open-vault-btn[data-vault-id="{rich["id"]}"]'); pg.wait_for_selector("#vault-view-section", timeout=10000)
    pg.click('[data-vault-tab="info"]'); pg.wait_for_timeout(700)
    pg.screenshot(path=str(SHOTS / "vault_info_after.png"))

    pg.click('.sidebar-item[data-section="monitor"]'); pg.wait_for_timeout(1500)
    pg.screenshot(path=str(SHOTS / "monitor_after.png"))
    b.close()

print("REPORT:", json.dumps(report, indent=2))
