"""Verify the temp-cred popup redesign, generate-modal fields, copy button,
and the unlock-modal X placement (run directly)."""
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

a = requests.Session()
a.headers["Authorization"] = "Bearer " + a.post(f"{B}/auth/login", json={"username": U, "password": P}).json()["access_token"]
vaults = a.get(f"{B}/vaults").json()
pw_vault = next((v for v in vaults if v.get("has_password")), None)

report = {"page_errors": [], "console_errors": []}
with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(base_url=B, viewport={"width": 1440, "height": 900},
                        permissions=["clipboard-read", "clipboard-write"])
    pg = ctx.new_page()
    pg.on("pageerror", lambda e: report["page_errors"].append(str(e)))
    pg.on("console", lambda m: report["console_errors"].append(f"{m.type}: {m.text}") if m.type == "error" else None)

    pg.goto("/"); pg.wait_for_selector("#login-screen", timeout=15000)
    pg.fill("#username", U); pg.fill("#password", P)
    pg.click("#login-form button[type=submit]"); pg.wait_for_selector("#dashboard-screen", timeout=15000)

    # Generate modal: note + can-create checkbox present
    pg.click('.sidebar-item[data-section="temp-creds"]'); pg.wait_for_timeout(700)
    pg.click("#generate-temp-creds-btn"); pg.wait_for_selector("#generate-temp-creds-modal.active", timeout=5000)
    print("generate modal: note field?", pg.is_visible("#temp-cred-note"), "| can-create?", pg.is_visible("#temp-cred-can-create"))
    pg.screenshot(path=str(SHOTS / "tempcred_generate_modal_new.png"))

    # Fill note + tick can-create, submit -> reveal popup
    pg.fill("#temp-cred-note", "Vendor X — Q3 audit files")
    pg.check("#temp-cred-can-create")
    pg.click("#generate-temp-creds-form button[type=submit]")
    pg.wait_for_selector("#temp-creds-modal", timeout=10000); pg.wait_for_timeout(500)
    copy_btns = pg.query_selector_all("#temp-creds-modal .cred-copy-btn")
    uname_val = pg.eval_on_selector("#temp-creds-modal .cred-field-input", "el => el.value")
    print("popup copy buttons:", len(copy_btns), "| username field starts temp_:", uname_val.startswith("temp_"))
    pg.screenshot(path=str(SHOTS / "tempcred_reveal_popup_new.png"))
    # Click first copy button, read clipboard back
    pg.click("#temp-creds-modal .cred-copy-btn")
    pg.wait_for_timeout(400)
    clip = pg.evaluate("navigator.clipboard.readText()")
    print("clipboard after copy == username:", clip == uname_val, "| value:", clip[:20])
    pg.click("#close-temp-creds-modal"); pg.wait_for_timeout(300)
    print("popup closed:", not pg.is_visible("#temp-creds-modal"))

    # Unlock modal X placement
    if pw_vault:
        pg.click('.sidebar-item[data-section="vaults"]'); pg.wait_for_timeout(700)
        pg.click(f'.open-vault-btn[data-vault-id="{pw_vault["id"]}"]')
        pg.wait_for_selector("#confirm-modal.active", timeout=6000); pg.wait_for_timeout(400)
        box = pg.eval_on_selector("#confirm-modal-close-btn",
            "el => { const r = el.getBoundingClientRect(); const cs = getComputedStyle(el); return {right: Math.round(r.right), border: cs.borderStyle, bg: cs.backgroundColor}; }")
        print("unlock X button:", box)
        pg.screenshot(path=str(SHOTS / "unlock_modal_x.png"))
    b.close()

print("REPORT:", json.dumps(report, indent=2))
