"""Drive the real SecureShare flow in Chromium and capture screenshots.

Flow: pick demo file -> 24h expiry + burn-after-reading -> encrypt & upload
-> share link -> paste link in Download tab -> load meta -> decrypt &
download -> reopen link (burned -> gone).
"""
import json
import re
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

APP_URL = "http://localhost:8081/"
DEMO_FILE = "/tmp/Q3-planning-notes.txt"
SHOTS = Path("/home/hatch/workspace/secure-file-transfer/docs/screenshots")
DL_DIR = Path("/tmp/secureshare-dl")
DL_DIR.mkdir(exist_ok=True)

js_errors = []


def shot(page, name):
    p = SHOTS / name
    page.screenshot(path=str(p))
    print(f"saved {name} ({p.stat().st_size} bytes)")
    return p


def main():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=["--no-sandbox"])
        ctx = browser.new_context(
            viewport={"width": 1280, "height": 800},
            accept_downloads=True,
        )
        page = ctx.new_page()
        page.on("pageerror", lambda e: js_errors.append(f"pageerror: {e}"))
        page.on("console", lambda m: js_errors.append(f"console.{m.type}: {m.text}") if m.type == "error" else None)

        print("== loading app ==")
        page.goto(APP_URL, wait_until="networkidle")
        page.wait_for_selector("text=Share a file securely", timeout=15000)

        # --- pick the demo file via the native file dialog ---
        print("== picking file ==")
        try:
            with page.expect_file_chooser(timeout=10000) as fc:
                page.get_by_text("Choose a file").click()
            fc.value.set_files(DEMO_FILE)
        except Exception:
            # Fallback: set the file input directly.
            print("file_chooser path failed, trying direct input")
            page.locator("input[type=file]").first.set_input_files(DEMO_FILE)
        page.wait_for_selector("text=Q3-planning-notes.txt", timeout=10000)
        print("file picked")

        # --- 24h expiry (default, but click explicitly) + burn ON ---
        page.get_by_text("24 hours", exact=True).click()
        switch = page.get_by_role("switch")
        if switch.count() == 0:
            switch = page.locator("input[type=checkbox]").first
        # RN Web renders Switch as <input type=checkbox role=switch> — state
        # is the checked property, not aria-checked.
        before = switch.is_checked()
        switch.click()
        time.sleep(0.3)
        after = switch.is_checked()
        print(f"burn switch checked: {before} -> {after}")
        if not after:
            raise RuntimeError("burn-after-reading switch did not turn on")

        # Shot 1: upload ready (scroll to top so header + file + expiry + burn show)
        page.evaluate("window.scrollTo(0, 0)")
        page.wait_for_timeout(400)
        shot(page, "flow-upload-ready.png")

        # --- encrypt & upload ---
        print("== uploading ==")
        page.get_by_text("Encrypt & Upload").click()
        page.wait_for_selector("text=Your secure link", timeout=30000)
        page.wait_for_timeout(500)

        # Extract the share link from the page text.
        body = page.evaluate("document.body.innerText")
        m = re.search(r"https?://[^\s]+/d/[A-Za-z0-9-]+#key=[A-Za-z0-9_-]+", body)
        if not m:
            raise RuntimeError("share link not found on page after upload")
        share_link = m.group(0)
        print(f"share link: {share_link[:60]}... (len {len(share_link)})")

        # Shot 2: share link screen. Scroll the Copy button (bottom of the
        # share box) into view so the WHOLE box — link with #key= fragment,
        # notes, expiry, copy button — fits in the viewport.
        page.locator("text=Copy link").scroll_into_view_if_needed()
        page.wait_for_timeout(400)
        shot(page, "flow-share-link.png")

        # --- download tab: paste link, load meta ---
        print("== download tab ==")
        page.get_by_text("⬇ Download").click()
        page.wait_for_selector("text=Open a shared file", timeout=10000)
        link_input = page.locator("input").first
        link_input.fill(share_link)
        page.get_by_text("Load file info").click()
        page.wait_for_selector("text=Protection:", timeout=15000)
        page.wait_for_timeout(500)
        # Shot 3: metadata shown
        page.locator("text=Protection:").scroll_into_view_if_needed()
        page.wait_for_timeout(400)
        shot(page, "flow-download-meta.png")

        # --- decrypt & download (capture the downloaded file) ---
        print("== decrypt & download ==")
        with page.expect_download(timeout=30000) as dl_info:
            page.get_by_text("Decrypt & Download").click()
        page.wait_for_selector("text=decrypted on your device", timeout=15000)
        page.wait_for_timeout(500)
        download = dl_info.value
        dl_path = DL_DIR / download.suggested_filename
        download.save_as(str(dl_path))
        print(f"downloaded: {dl_path} ({dl_path.stat().st_size} bytes)")

        # Shot 4: success state
        page.locator("text=decrypted on your device").scroll_into_view_if_needed()
        page.wait_for_timeout(400)
        shot(page, "flow-decrypted.png")

        # --- reopen the same link: burn-after-reading should have deleted it ---
        # NOTE: the raw /d share link returns the server's plain-text 404
        # ("File not found or already deleted.") when the file is gone, so
        # the clean in-app "gone" state is captured via the app's deep link
        # (/?id=...#key=...), which auto-loads the metadata and shows the
        # app's own "File not found" error. Both are the real behaviour.
        print("== reopening burned link ==")
        m2 = re.match(r"https?://[^/]+/d/([A-Za-z0-9-]+)#key=([A-Za-z0-9_-]+)", share_link)
        app_deep_link = f"http://localhost:8081/?id={m2.group(1)}#key={m2.group(2)}"
        page.goto(app_deep_link, wait_until="networkidle")
        page.wait_for_selector("text=Open a shared file", timeout=15000)
        page.wait_for_selector("text=File not found", timeout=15000)
        page.wait_for_timeout(500)
        shot(page, "flow-burned.png")

        browser.close()

    # Verify downloaded bytes match the original demo file.
    original = Path(DEMO_FILE).read_bytes()
    got = (DL_DIR / "Q3-planning-notes.txt").read_bytes()
    print(f"round-trip bytes match: {original == got} (orig {len(original)} B, got {len(got)} B)")
    if original != got:
        print("ERROR: decrypted file differs from original!", file=sys.stderr)
        sys.exit(1)

    real_errors = [e for e in js_errors if "favicon" not in e]
    print(f"JS errors captured: {len(real_errors)}")
    for e in real_errors:
        print("  ", e)
    print("DONE")


if __name__ == "__main__":
    main()
