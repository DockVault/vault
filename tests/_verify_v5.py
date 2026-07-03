"""Verify the temp-cred permission-builder modal + the owner login notification."""
import json, pathlib, requests
from playwright.sync_api import sync_playwright

B = "http://localhost:8200"
HERE = pathlib.Path(__file__).resolve().parent
SHOTS = HERE / "_shots" / "verify"; SHOTS.mkdir(parents=True, exist_ok=True)
E = {}
for l in (HERE.parent / ".env").read_text(encoding="utf-8", errors="ignore").splitlines():
    if "=" in l and not l.startswith("#"):
        k, _, v = l.partition("="); E[k.strip()] = v.strip()
U, P = E["ADMIN_USERNAME"], E["ADMIN_PASSWORD"]
a = requests.Session(); a.headers["Authorization"] = "Bearer " + a.post(f"{B}/auth/login", json={"username": U, "password": P}).json()["access_token"]

report = {"page_errors": [], "console_errors": []}
with sync_playwright() as p:
    b = p.chromium.launch()
    octx = b.new_context(base_url=B, viewport={"width": 1440, "height": 980})
    owner = octx.new_page()
    owner.on("pageerror", lambda e: report["page_errors"].append(str(e)))
    owner.on("console", lambda m: report["console_errors"].append(f"{m.type}: {m.text}") if m.type == "error" else None)

    owner.goto("/"); owner.wait_for_selector("#login-screen", timeout=15000)
    owner.fill("#username", U); owner.fill("#password", P)
    owner.click("#login-form button[type=submit]"); owner.wait_for_selector("#dashboard-screen", timeout=15000)
    owner.wait_for_timeout(1500)  # let the app-wide monitor socket connect

    # --- Permission-builder modal ---
    owner.click('.sidebar-item[data-section="temp-creds"]'); owner.wait_for_timeout(600)
    owner.click("#generate-temp-creds-btn"); owner.wait_for_selector("#generate-temp-creds-modal.active", timeout=5000)
    owner.check("#tc-scope-enable"); owner.wait_for_timeout(400)
    builder_shown = owner.is_visible("#tc-scope-builder")
    vault_rows = len(owner.query_selector_all("#tc-vault-list .member-pick-item"))
    print("builder shown:", builder_shown, "| selectable vaults:", vault_rows)
    owner.screenshot(path=str(SHOTS / "tempcred_scope_builder.png"))
    # close modal
    owner.click("#generate-temp-creds-modal .close-modal-btn"); owner.wait_for_timeout(400)

    # --- Owner login notification ---
    c = a.post(f"{B}/auth/temp-credentials", json={"validity_minutes": 30, "note": "notif test"}).json()
    tctx = b.new_context(base_url=B)
    tp = tctx.new_page()
    tp.goto("/"); tp.wait_for_selector("#login-screen", timeout=15000)
    tp.fill("#username", c["temp_username"]); tp.fill("#password", c["credential"])
    tp.click("#login-form button[type=submit]")
    tp.wait_for_timeout(1500)

    got_toast = False
    try:
        owner.wait_for_selector("#toast-container .toast", timeout=10000)
        txt = owner.inner_text("#toast-container")
        got_toast = "Temporary credential" in txt
        print("owner toast:", got_toast, "|", repr(txt[:120].replace(chr(10), " ")))
    except Exception as e:
        print("owner toast: NONE", e)
    owner.screenshot(path=str(SHOTS / "owner_notification.png"))
    b.close()

print("REPORT:", json.dumps(report, indent=2))
