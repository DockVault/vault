"""Verify the vault-view redesign + download/upload/password fixes."""
import json, pathlib, requests, uuid
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
vaults = a.get(f"{B}/vaults").json()
rich = next((v for v in vaults if v.get("name") == "DEMO Engineering Drop"), None) or next((v for v in vaults if (v.get("file_count") or 0) > 2 and not v.get("has_password")), None)
existing_name = a.get(f"{B}/vaults/{rich['id']}/files").json()["items"]
existing_name = next((it["name"] for it in existing_name if it["type"] != "folder"), "company-logo.png")
print("rich vault:", rich["name"], "| existing file:", existing_name)

report = {"page_errors": [], "console_errors": []}
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_context(base_url=B, viewport={"width": 1440, "height": 900}).new_page()
    pg.on("pageerror", lambda e: report["page_errors"].append(str(e)))
    pg.on("console", lambda m: report["console_errors"].append(f"{m.type}: {m.text}") if m.type == "error" else None)
    pg.goto("/"); pg.wait_for_selector("#login-screen", timeout=15000)
    pg.evaluate("localStorage.setItem('theme','dark')")
    pg.fill("#username", U); pg.fill("#password", P)
    pg.click("#login-form button[type=submit]"); pg.wait_for_selector("#dashboard-screen", timeout=15000)
    pg.wait_for_timeout(800)

    # Open the vault -> compact files view
    pg.click('.sidebar-item[data-section="vaults"]'); pg.wait_for_timeout(700)
    pg.click(f'.open-vault-btn[data-vault-id="{rich["id"]}"]'); pg.wait_for_selector("#vault-view-section", timeout=10000)
    pg.wait_for_timeout(900)
    # header height (top of section to top of files table) — lower is better
    head_h = pg.evaluate("""() => {
        const sec = document.querySelector('.vault-view-head').getBoundingClientRect().top;
        const tbl = document.getElementById('vault-files-table-wrap').getBoundingClientRect().top;
        return Math.round(tbl - sec); }""")
    print("header+tabs+toolbar height to file table:", head_h, "px")
    print("upload btn visible on Files tab:", pg.is_visible("#upload-file-btn"))
    pg.screenshot(path=str(SHOTS / "vaultview_compact_dark.png"))

    # Info tab -> upload/new-folder must be hidden
    pg.click('[data-vault-tab="info"]'); pg.wait_for_timeout(500)
    print("upload btn visible on Info tab:", pg.is_visible("#upload-file-btn"), "(expect False)")
    pg.click('[data-vault-tab="files"]'); pg.wait_for_timeout(400)

    # Upload conflict: upload a file with an existing name
    pg.set_input_files("#file-upload-input", files=[{"name": existing_name, "mimeType": "text/plain", "buffer": b"dup"}])
    try:
        pg.wait_for_selector("#upload-conflict-modal.active", timeout=6000)
        auto = pg.inner_text("#uc-auto")
        print("conflict modal shown; auto-name:", auto)
        pg.screenshot(path=str(SHOTS / "upload_conflict_modal.png"))
        pg.click("#uc-confirm")  # default = autorename
        pg.wait_for_timeout(800)
    except Exception as e:
        print("conflict modal: NONE", e)

    # Download feedback toast
    pg.wait_for_timeout(500)
    pg.click("#vault-files-table-body .action-btn[data-action='download']")
    try:
        pg.wait_for_selector("#toast-container .toast", timeout=5000)
        t = pg.inner_text("#toast-container .toast").encode("ascii", "ignore").decode()
        print("download toast:", "Downloading" in t, "|", t.replace(chr(10), " ").strip()[:60])
    except Exception:
        print("download toast: NONE")

    # Create vault with NO password
    pg.click('.sidebar-item[data-section="vaults"]'); pg.wait_for_timeout(500)
    pg.click("#create-vault-btn"); pg.wait_for_selector("#create-vault-modal.active", timeout=5000)
    name = "NoPass " + uuid.uuid4().hex[:6]
    pg.fill("#vault-name", name)
    pg.click("#create-vault-form button[type=submit]")
    pg.wait_for_timeout(1500)
    made = [v for v in a.get(f"{B}/vaults").json() if v["name"] == name]
    print("no-password vault created:", bool(made), "| has_password:", made[0].get("has_password") if made else "?")
    if made:
        a.post(f"{B}/vaults/{made[0]['id']}/delete")
    b.close()

print("REPORT:", json.dumps(report, indent=2))
