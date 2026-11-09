"""Renders docs/case-study.md to docs/case-study.pdf.

Needs the `markdown` package (pip install markdown) and Chrome or Edge, used headless to print.
Usage: python scripts/build-writeup-pdf.py [path-to-chrome]"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent.parent
SRC, OUT = ROOT / "docs" / "case-study.md", ROOT / "docs" / "case-study.pdf"
BROWSERS = [r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "google-chrome", "chromium", "chromium-browser",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]

CSS = """
@page { size: A4; margin: 18mm 16mm; }
body { font-family: "Segoe UI", Helvetica, Arial, sans-serif; font-size: 10.5pt; line-height: 1.45; color: #111827; }
h1 { font-size: 20pt; margin: 0 0 4pt; }
h1 + p strong { font-size: 12pt; color: #374151; }
h2 { font-size: 14pt; margin: 18pt 0 6pt; border-bottom: 1px solid #d1d5db; padding-bottom: 2pt; page-break-after: avoid; }
h3 { font-size: 11.5pt; margin: 12pt 0 4pt; page-break-after: avoid; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0 10pt; font-size: 9pt; }
tr { page-break-inside: avoid; }
thead { display: table-header-group; }
th, td { border: 1px solid #d1d5db; padding: 3pt 5pt; vertical-align: top; text-align: left; }
th { background: #f3f4f6; }
code { font-family: Consolas, "Courier New", monospace; font-size: 9pt; background: #f3f4f6; padding: 0 2pt; }
pre { background: #f3f4f6; padding: 6pt 8pt; font-size: 8.5pt; line-height: 1.25; page-break-inside: avoid; }
pre code { background: none; padding: 0; }
hr { border: 0; border-top: 1px solid #d1d5db; }
"""


def browser(arg):
    for b in ([arg] if arg else []) + BROWSERS:
        path = b if Path(b).exists() else shutil.which(b)
        if path:
            return path
    sys.exit("Chrome/Edge not found; pass its path as the first argument.")


def main():
    body = markdown.markdown(SRC.read_text(encoding="utf-8"), extensions=["tables", "fenced_code"])
    html = f'<!doctype html><html><head><meta charset="utf-8"><title>Detecting phishing from trusted accounts</title><style>{CSS}</style></head><body>{body}</body></html>'
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "case-study.html"
        page.write_text(html, encoding="utf-8")
        subprocess.run([browser(sys.argv[1] if len(sys.argv) > 1 else None), "--headless=new", "--disable-gpu",
                        "--no-pdf-header-footer", f"--user-data-dir={Path(tmp) / 'profile'}",
                        f"--print-to-pdf={OUT}", page.as_uri()], check=True, capture_output=True, timeout=120)
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
