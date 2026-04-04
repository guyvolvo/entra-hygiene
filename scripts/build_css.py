"""
Compiles Tailwind CSS from utility classes used in html_reporter.py
and embeds the minified output as TAILWIND_CSS in that file.

Run after modifying Tailwind classes in the HTML template:
    python scripts/build_css.py

Requires: Node.js (uses npx tailwindcss@3)
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
REPORTER = ROOT / "entra_hygiene" / "reporters" / "html_reporter.py"
TAILWIND_CONFIG = ROOT / "tailwind.config.js"
TAILWIND_INPUT = ROOT / "tailwind_src.css"

CONSTANT_RE = re.compile(
    r'(TAILWIND_CSS\s*=\s*""").*?(""")',
    re.DOTALL,
)


def build() -> None:
    with tempfile.NamedTemporaryFile(suffix=".css", delete=False) as tmp:
        out_path = Path(tmp.name)

    try:
        result = subprocess.run(
            "npx --yes tailwindcss@3"
            f" -i {TAILWIND_INPUT}"
            f" -o {out_path}"
            f" --config {TAILWIND_CONFIG}"
            " --minify",
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            shell=True,
        )
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            sys.exit(1)

        css = out_path.read_text(encoding="utf-8").strip()
    finally:
        out_path.unlink(missing_ok=True)

    source = REPORTER.read_text(encoding="utf-8")

    if not CONSTANT_RE.search(source):
        print("ERROR: TAILWIND_CSS constant not found in html_reporter.py", file=sys.stderr)
        sys.exit(1)

    new_source = CONSTANT_RE.sub(rf'\g<1>{css}\g<2>', source)
    REPORTER.write_text(new_source, encoding="utf-8")
    print(f"TAILWIND_CSS updated: {len(css):,} bytes")


if __name__ == "__main__":
    build()
