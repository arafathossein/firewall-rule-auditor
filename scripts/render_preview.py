"""Render docs/preview.png from the demo report (needs: pip install playwright && playwright install chromium)."""

import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

root = Path(__file__).resolve().parents[1]
out = Path(tempfile.mkdtemp())
subprocess.run([sys.executable, "-m", "fw_audit.cli", "demo", "--out", str(out)], check=True, cwd=root)

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1100, "height": 1500}, device_scale_factor=2, color_scheme="light")
    page.goto((out / "fw-audit.html").as_uri())
    # Keep the summary table and the Cisco card, which shows exposure, any-any and shadowed rules.
    page.evaluate("""() => document.querySelectorAll('section.card').forEach(c => {
        if (!c.querySelector('h2').textContent.startsWith('core-sw')) c.remove(); })""")
    h = min(page.evaluate("document.body.scrollHeight"), 1500)
    page.screenshot(path=str(root / "docs" / "preview.png"), clip={"x": 0, "y": 0, "width": 1100, "height": h})
    browser.close()
print("wrote docs/preview.png")
