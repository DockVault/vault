"""
Ad-hoc UI audit walkthrough (NOT a pytest test — run directly).

Seeds realistic demo data via the API, then drives the live SPA at
http://localhost:8200 with Playwright, screenshotting every screen/tab in
light + dark themes and collecting console errors + failed network requests.

Run:  ./.venv/Scripts/python.exe _audit_walkthrough.py
Output: _shots/audit/*.png  and a printed JSON-ish report.
"""
import json
import os
import sys
import time
from pathlib import Path

import requests
from playwright.sync_api import sync_playwright

BASE = "http://localhost:8200"
HERE = Path(__file__).resolve().parent
SHOTS = HERE / "_shots" / "audit"
SHOTS.mkdir(parents=True, exist_ok=True)


def read_env():
    env = {}
    p = HERE.parent / ".env"
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


ENV = read_env()
ADMIN_USER = ENV.get("ADMIN_USERNAME", "admin")
ADMIN_PASS = ENV.get("ADMIN_PASSWORD", "")

S = requests.Session()


def login_api():
    r = S.post(f"{BASE}/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS}, timeout=15)
    r.raise_for_status()
    tok = r.json()["access_token"]
    S.headers["Authorization"] = f"Bearer {tok}"
    return tok


def safe(fn, *a, **k):
    try:
        return fn(*a, **k)
    except Exception as e:  # noqa: BLE001
        print(f"  ! seed step failed: {e}")
        return None


FILE_SAMPLES = [
    ("Q3-financial-report.pdf", b"%PDF-1.4 demo report " * 40, "application/pdf"),
    ("company-logo.png", b"\x89PNG\r\n\x1a\n" + b"0" * 800, "image/png"),
    ("office-photo.jpg", b"\xff\xd8\xff" + b"0" * 1200, "image/jpeg"),
    ("customers-export.csv", b"id,name,email\n1,Acme,a@x.com\n" * 30, "text/csv"),
    ("meeting-notes.txt", b"notes notes notes " * 50, "text/plain"),
    ("backup-2026-06.zip", b"PK\x03\x04" + b"0" * 2000, "application/zip"),
    ("roadmap-deck.pptx", b"PK\x03\x04" + b"0" * 1500, "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    ("budget-2026.xlsx", b"PK\x03\x04" + b"0" * 1100, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    ("deploy.py", b"print('hello world')\n" * 20, "text/x-python"),
    ("demo-clip.mp4", b"\x00\x00\x00\x18ftyp" + b"0" * 3000, "video/mp4"),
    ("README.md", b"# Demo\nSome markdown content here.\n" * 10, "text/markdown"),
]


def seed():
    print("Seeding demo data ...")
    created = {"vaults": [], "users": [], "groups": []}

    # Vaults — a mix to fill the grid; one richly populated, no-password.
    names_pw = ["DEMO Engineering Backups", "DEMO Legal & Compliance"]
    names_open = ["DEMO Engineering Drop", "DEMO Marketing Assets",
                  "DEMO Customer Exports", "DEMO Shared Public"]
    rich_id = None
    for n in names_pw:
        v = safe(lambda n=n: S.post(f"{BASE}/vaults", json={"name": n, "description": "Demo vault (password-protected).", "password": "123456789"}, timeout=30).json())
        if v and "id" in v:
            created["vaults"].append(v["id"])
    for i, n in enumerate(names_open):
        v = safe(lambda n=n: S.post(f"{BASE}/vaults", json={"name": n, "description": "Demo vault for the UI audit."}, timeout=30).json())
        if v and "id" in v:
            created["vaults"].append(v["id"])
            if i == 0:
                rich_id = v["id"]

    # Populate the rich vault with files + folders.
    if rich_id:
        for fname, content, mime in FILE_SAMPLES:
            safe(lambda f=fname, c=content, m=mime: S.post(
                f"{BASE}/vaults/{rich_id}/files",
                files=[("files", (f, c, m))], timeout=60))
        for folder in ["Contracts", "Invoices", "Archive"]:
            safe(lambda fn=folder: S.post(f"{BASE}/vaults/{rich_id}/folders", json={"name": fn}, timeout=30))

    # Users with varied roles.
    user_specs = [
        ("demo_alice", "alice@example.com", "user"),
        ("demo_bob", "bob@example.com", "user"),
        ("demo_carol", "carol@example.com", "admin"),
        ("demo_dave", "dave@example.com", "external"),
        ("demo_erin", "erin@example.com", "user"),
        ("demo_frank", "frank@example.com", "external"),
    ]
    uid_first = None
    for un, em, role in user_specs:
        u = safe(lambda un=un, em=em, role=role: S.post(f"{BASE}/users", json={"username": un, "email": em, "password": "DemoPassw0rd!123", "role": role}, timeout=30).json())
        if u and "id" in u:
            created["users"].append(u["id"])
            uid_first = uid_first or u["id"]

    # Groups (departments). Body shape best-effort.
    for gname in ["Engineering", "Sales", "Legal"]:
        g = safe(lambda gn=gname: S.post(f"{BASE}/groups", json={"name": gn, "description": f"{gn} department"}, timeout=30).json())
        if g and isinstance(g, dict) and "id" in g:
            created["groups"].append(g["id"])

    # A permission grant on the rich vault.
    if rich_id and uid_first:
        safe(lambda: S.post(f"{BASE}/vaults/{rich_id}/permissions", json={"user_id": uid_first, "level": "read"}, timeout=30))

    # A few temp credentials.
    for mins in (65, 120, 30, 1440):
        safe(lambda m=mins: S.post(f"{BASE}/auth/temp-credentials", json={"validity_minutes": m}, timeout=30))

    print(f"  seeded: {len(created['vaults'])} vaults, {len(created['users'])} users, {len(created['groups'])} groups; rich vault={rich_id}")
    return created, rich_id


def run():
    login_api()
    created, rich_id = seed()

    report = {"console_errors": [], "page_errors": [], "failed_requests": [], "shots": []}

    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(base_url=BASE, viewport={"width": 1440, "height": 900})
        page = ctx.new_page()

        page.on("console", lambda m: report["console_errors"].append(f"{m.type}: {m.text}") if m.type in ("error", "warning") else None)
        page.on("pageerror", lambda e: report["page_errors"].append(str(e)))
        page.on("response", lambda r: report["failed_requests"].append(f"{r.status} {r.request.method} {r.url}") if r.status >= 400 else None)

        def shot(name):
            page.wait_for_timeout(700)
            f = SHOTS / f"{name}.png"
            page.screenshot(path=str(f), full_page=True)
            report["shots"].append(name)
            print(f"  shot: {name}")

        def goto_section(sec):
            page.click(f'.sidebar-item[data-section="{sec}"]')
            page.wait_for_timeout(900)

        # ---- Login screen (light + dark) ----
        page.goto("/")
        page.wait_for_selector("#login-screen", timeout=15000)
        shot("01_login_light")
        page.evaluate("localStorage.setItem('theme','dark')")
        page.reload()
        page.wait_for_selector("#login-screen", timeout=15000)
        shot("01_login_dark")
        page.evaluate("localStorage.setItem('theme','light')")
        page.reload()

        # ---- Login ----
        page.fill("#username", ADMIN_USER)
        page.fill("#password", ADMIN_PASS)
        page.click("#login-form button[type=submit]")
        page.wait_for_selector("#dashboard-screen", timeout=15000)
        page.wait_for_timeout(1200)

        # ---- Light theme walkthrough ----
        shot("02_dashboard_light")

        goto_section("vaults")
        shot("03_vaults_grid_light")

        # Open the rich vault
        if rich_id:
            try:
                page.click(f'.open-vault-btn[data-vault-id="{rich_id}"]', timeout=8000)
            except Exception:
                page.click(f'.vault-card[data-vault-id="{rich_id}"]', timeout=8000)
            page.wait_for_selector("#vault-view-section", timeout=10000)
            page.wait_for_timeout(1200)
            shot("04_vault_files_light")
            page.click('[data-vault-tab="info"]'); shot("05_vault_info_light")
            page.click('[data-vault-tab="permissions"]'); shot("06_vault_permissions_light")
            page.click('[data-vault-tab="settings"]'); shot("07_vault_settings_light")

        goto_section("temp-creds")
        shot("08_tempcreds_list_light")
        try:
            page.click("#generate-temp-creds-btn")
            page.wait_for_selector("#generate-temp-creds-modal", timeout=5000)
            shot("09_tempcreds_generate_modal")
            page.click("#generate-temp-creds-form button[type=submit]")
            page.wait_for_selector("#temp-creds-modal", timeout=8000)
            shot("10_tempcreds_result_modal")
            page.click("#close-temp-creds-modal")
        except Exception as e:
            print(f"  ! tempcred modal: {e}")

        goto_section("users")
        shot("11_users_list_light")
        try:
            page.click("#create-user-btn")
            page.wait_for_selector("#create-user-modal.active, #create-user-modal", timeout=5000)
            shot("12_users_create_modal")
            page.click("#create-user-modal .close-modal-btn")
        except Exception as e:
            print(f"  ! user modal: {e}")

        goto_section("groups")
        shot("13_groups_light")

        goto_section("monitor")
        page.wait_for_timeout(1500)
        shot("14_monitor_light")

        goto_section("settings")
        shot("15_settings_general_light")
        for tab, nm in [("security", "16_settings_security"), ("storage", "17_settings_storage"),
                        ("email", "18_settings_email"), ("audit", "19_settings_audit")]:
            try:
                page.click(f'.settings-tab-content, [data-tab="{tab}"]')
                page.click(f'[data-tab="{tab}"]')
                page.wait_for_timeout(500)
                if tab == "audit":
                    safe(lambda: page.click("#audit-search-btn"))
                    page.wait_for_timeout(1200)
                shot(nm)
            except Exception as e:
                print(f"  ! settings {tab}: {e}")

        # ---- Dark theme pass (key screens) ----
        page.click("#theme-toggle")
        page.wait_for_timeout(600)
        goto_section("dashboard"); shot("20_dashboard_dark")
        goto_section("vaults"); shot("21_vaults_grid_dark")
        if rich_id:
            try:
                page.click(f'.open-vault-btn[data-vault-id="{rich_id}"]', timeout=8000)
                page.wait_for_selector("#vault-view-section", timeout=10000)
                page.wait_for_timeout(1000)
                shot("22_vault_files_dark")
            except Exception as e:
                print(f"  ! dark vault: {e}")
        goto_section("temp-creds"); shot("23_tempcreds_dark")
        goto_section("users"); shot("24_users_dark")
        goto_section("monitor"); page.wait_for_timeout(1200); shot("25_monitor_dark")

        # ---- Responsive (narrow) check of the two core screens ----
        page.set_viewport_size({"width": 1024, "height": 800})
        goto_section("vaults"); shot("26_vaults_1024_dark")
        page.set_viewport_size({"width": 768, "height": 900})
        goto_section("vaults"); shot("27_vaults_768_dark")

        browser.close()

    # ---- Report ----
    print("\n==== AUDIT REPORT ====")
    print(json.dumps({
        "page_errors": report["page_errors"],
        "console_errors_sample": report["console_errors"][:40],
        "console_errors_count": len(report["console_errors"]),
        "failed_requests": sorted(set(report["failed_requests"])),
        "shots_count": len(report["shots"]),
        "shots_dir": str(SHOTS),
    }, indent=2))
    print(f"\nSeeded (for cleanup if needed): {json.dumps(created)}")


if __name__ == "__main__":
    run()
