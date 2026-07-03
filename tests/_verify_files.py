"""Focused verification of the reworked Files view (run directly)."""
import json
from pathlib import Path
import requests
from playwright.sync_api import sync_playwright

BASE = "http://localhost:8200"
HERE = Path(__file__).resolve().parent
SHOTS = HERE / "_shots" / "verify"
SHOTS.mkdir(parents=True, exist_ok=True)


def env():
    d = {}
    for line in (HERE.parent / ".env").read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("="); d[k.strip()] = v.strip()
    return d


E = env(); USER = E.get("ADMIN_USERNAME", "admin"); PW = E.get("ADMIN_PASSWORD", "")
S = requests.Session()
S.post(f"{BASE}/auth/login", json={"username": USER, "password": PW}, timeout=15).raise_for_status()
tok = S.post(f"{BASE}/auth/login", json={"username": USER, "password": PW}, timeout=15).json()["access_token"]
S.headers["Authorization"] = f"Bearer {tok}"
vaults = S.get(f"{BASE}/vaults", timeout=15).json()
rich = next((v for v in vaults if v.get("name") == "DEMO Engineering Drop"), None) or \
       next((v for v in vaults if (v.get("file_count") or 0) > 2 and not v.get("has_password")), None)
print("rich vault:", rich and rich["name"], rich and rich["id"])

report = {"page_errors": [], "console_errors": []}
with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(base_url=BASE, viewport={"width": 1440, "height": 900})
    pg = ctx.new_page()
    pg.on("pageerror", lambda e: report["page_errors"].append(str(e)))
    pg.on("console", lambda m: report["console_errors"].append(f"{m.type}: {m.text}") if m.type == "error" else None)

    pg.goto("/"); pg.wait_for_selector("#login-screen", timeout=15000)
    pg.fill("#username", USER); pg.fill("#password", PW)
    pg.click("#login-form button[type=submit]")
    pg.wait_for_selector("#dashboard-screen", timeout=15000)
    pg.click('.sidebar-item[data-section="vaults"]'); pg.wait_for_timeout(800)
    pg.click(f'.open-vault-btn[data-vault-id="{rich["id"]}"]')
    pg.wait_for_selector("#vault-view-section", timeout=10000)
    pg.wait_for_timeout(1200)
    pg.screenshot(path=str(SHOTS / "files_table_dense.png"), full_page=True)

    # Multi-select: tick first two file checkboxes
    checks = pg.query_selector_all("#vault-files-table-body .file-check")
    print("file checkboxes in table:", len(checks))
    for cb in checks[:2]:
        cb.check()
    pg.wait_for_timeout(400)
    bulk_visible = pg.is_visible("#files-bulk-bar")
    bulk_count = pg.inner_text("#files-bulk-count") if bulk_visible else "(hidden)"
    print("bulk bar visible:", bulk_visible, "count:", bulk_count)
    pg.screenshot(path=str(SHOTS / "files_table_selected.png"), full_page=True)

    # Select-all
    pg.click("#files-select-all"); pg.wait_for_timeout(300)
    print("after select-all count:", pg.inner_text("#files-bulk-count"))
    pg.click("#files-bulk-clear"); pg.wait_for_timeout(300)
    print("after clear visible:", pg.is_visible("#files-bulk-bar"))

    # Switch to grid view
    pg.click('[data-files-view="grid"]'); pg.wait_for_timeout(700)
    grid_shown = pg.is_visible("#vault-files-grid")
    tiles = len(pg.query_selector_all("#vault-files-grid .file-tile"))
    print("grid shown:", grid_shown, "tiles:", tiles)
    pg.screenshot(path=str(SHOTS / "files_grid.png"), full_page=True)

    # Persisted view across reload
    pg.reload(); pg.wait_for_selector("#vault-view-section", timeout=10000); pg.wait_for_timeout(1500)
    print("grid persisted after reload:", pg.is_visible("#vault-files-grid"))

    # Back to table for the e2e default
    pg.click('[data-files-view="table"]'); pg.wait_for_timeout(500)
    b.close()

print("\nREPORT:", json.dumps(report, indent=2))
print("shots:", str(SHOTS))
