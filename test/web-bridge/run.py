#!/usr/bin/env python3
"""Run the WEB proxy bridge-page contract tests.

The bridge page (src/web/page.zig) is the only part of this project that runs in the
user's browser rather than on the server, and it talks to Telegram Desktop across two
boundaries that fail silently when they are wrong: the injected `TelegramWebProxy`
object in the hidden WebView, and the `tproxy-init` MessagePort in the system-browser
fallback. Neither is exercised by `zig build test`.

This script lifts the inline script out of page.zig exactly as the relay renders it and
hands it to harness.js, which impersonates the client.

Skips (exit 0) when node is unavailable, so a dev box without it still gets a green
`zig build`; CI runs on ubuntu-latest, which ships node.
"""

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PAGE = REPO / "src" / "web" / "page.zig"
HARNESS = Path(__file__).resolve().parent / "harness.js"
WS_PATH = "/api/v1/socket"


def multiline_literal(source: str, name: str) -> str:
    """Return the text of a `const <name> = \\\\...` Zig multiline string literal."""
    match = re.search(r"const %s =\n((?:[ \t]*\\\\.*\n)+)" % re.escape(name), source)
    if not match:
        raise SystemExit(f"could not find the {name} literal in {PAGE}")
    lines = []
    for raw in match.group(1).splitlines():
        stripped = raw.strip()
        if stripped.startswith("\\\\"):
            lines.append(stripped[2:])
    return "\n".join(lines)


def extract_script() -> str:
    source = PAGE.read_text(encoding="utf-8")
    # renderBridge() writes: script_head + <ws path as a JS string> + script_body
    page = multiline_literal(source, "script_head") + f'"{WS_PATH}"' + multiline_literal(source, "script_body")
    body = page.split("<script>", 1)
    if len(body) != 2:
        raise SystemExit("the bridge page no longer opens a <script> element")
    js = body[1].split("</script>", 1)[0]
    if "TelegramWebProxy" not in js or "tproxy-init" not in js:
        raise SystemExit("the extracted script is missing a client boundary")
    return js


def main() -> int:
    node = shutil.which("node")
    if node is None:
        print("web-bridge: node not found, skipping the bridge-page contract tests")
        return 0

    js = extract_script()
    print(f"web-bridge: checking {len(js)} bytes of bridge script")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "bridge.js"
        path.write_text(js, encoding="utf-8")

        syntax = subprocess.run([node, "--check", str(path)], capture_output=True, text=True)
        if syntax.returncode != 0:
            print(syntax.stderr.strip())
            return 1

        result = subprocess.run([node, str(HARNESS), str(path)], text=True)
        return result.returncode


if __name__ == "__main__":
    sys.exit(main())
