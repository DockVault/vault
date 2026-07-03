"""Throwaway visual verification for the June-16 appearance changes:
  - background-palette picker in the profile dropdown (6 visible .bg-swatch circles,
    clicking one sets <html data-bg=...>)
  - empty-state centering (.empty-state-center label centered in its container)

Provisions a throwaway zero-state user via the admin API so the empty states
actually render, then deletes it. NOT collected by pytest (underscore prefix).
Run from the tests dir:
  .venv/Scripts/python.exe _verify_appearance.py
"""
import json
import os
import uuid
import requests
from playwright.sync_api import sync_playwright

BASE = os.environ.get("VAULT_BASE_URL", "http://localhost:8200")
USER = os.environ.get("VAULT_ADMIN_USER", "admin")
PW = os.environ.get("VAULT_ADMIN_PASS", "hie2JLrBXJtRTqXD")
SHOTS = os.path.join(os.path.dirname(__file__), "_shots")
os.makedirs(SHOTS, exist_ok=True)

CENTERED_TOL = 6  # px
FRESH_PW = "VerifyPass123!xyz"


def center_check(page, parent_sel, child_sel):
    """left/right gap of child within parent + whether horizontally centered."""
    return page.evaluate(
        """([ps, cs, tol]) => {
            const p = document.querySelector(ps), c = document.querySelector(cs);
            if (!p || !c) return null;
            const pr = p.getBoundingClientRect(), cr = c.getBoundingClientRect();
            const leftGap = Math.round(cr.left - pr.left);
            const rightGap = Math.round(pr.right - cr.right);
            return { leftGap, rightGap, centered: Math.abs(leftGap - rightGap) <= tol,
                     textAlign: getComputedStyle(c).textAlign };
        }""",
        [parent_sel, child_sel, CENTERED_TOL],
    )


def main():
    out = {}
    # --- provision a zero-state user via the admin API -----------------------
    r = requests.post(BASE + "/auth/login", json={"username": USER, "password": PW}, timeout=10)
    r.raise_for_status()
    token = r.json()["access_token"]
    H = {"Authorization": f"Bearer {token}"}
    uname = "verify_" + uuid.uuid4().hex[:8]
    cr = requests.post(BASE + "/users", headers=H, json={
        "username": uname, "email": f"{uname}@example.com",
        "password": FRESH_PW, "role": "user"}, timeout=10)
    cr.raise_for_status()
    uid = cr.json()["id"]

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 900})

            page.goto(BASE + "/")
            page.fill("#username", uname)
            page.fill("#password", FRESH_PW)
            page.click("#login-form button[type=submit]")
            page.wait_for_selector("#dashboard-screen", timeout=15000)

            # 1) Background palette picker
            page.click("#profile-btn")
            page.wait_for_timeout(300)
            out["bg_swatches_visible"] = page.eval_on_selector_all(
                ".bg-swatch[data-bg]",
                """els => els.filter(e => {const r=e.getBoundingClientRect();
                    return r.width>0 && r.height>0 && e.offsetParent!==null;})
                    .map(e => e.getAttribute('data-bg'))""")
            page.click('.bg-swatch[data-bg="navy"]')
            page.wait_for_timeout(250)
            out["html_data_bg_after_navy"] = page.get_attribute("html", "data-bg")
            page.screenshot(path=os.path.join(SHOTS, "profile_bg_navy.png"))
            page.click('.bg-swatch[data-bg="slate"]')
            page.wait_for_timeout(150)
            out["html_data_bg_after_slate"] = page.get_attribute("html", "data-bg")
            page.keyboard.press("Escape")
            page.wait_for_timeout(150)

            # 2) Vaults empty state (fresh user has zero vaults)
            page.click('.sidebar-item[data-section="vaults"]')
            page.wait_for_selector("#vaults-list .empty-state-center", timeout=8000)
            out["vaults_empty"] = center_check(
                page, "#vaults-list", "#vaults-list .empty-state-center p")
            page.screenshot(path=os.path.join(SHOTS, "vaults_empty.png"))

            # 3) Temp-creds empty state (fresh user has zero creds)
            page.click('.sidebar-item[data-section="temp-creds"]')
            page.wait_for_selector("#active-temp-creds .empty-state-center", timeout=8000)
            out["tempcreds_empty"] = center_check(
                page, "#active-temp-creds", "#active-temp-creds .empty-state-center p")
            page.screenshot(path=os.path.join(SHOTS, "tempcreds_empty.png"))

            browser.close()
    finally:
        try:
            requests.delete(BASE + f"/users/{uid}", headers=H, timeout=10)
        except Exception as e:
            out["cleanup_error"] = str(e)

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
