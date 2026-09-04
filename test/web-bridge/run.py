#!/usr/bin/env python3
"""Run the WEB proxy bridge-page contract tests.

The bridge page (src/web/page.zig) is the only part of this project that runs in the
user's browser rather than on the server, and it talks to Telegram Desktop across two
boundaries that fail silently when they are wrong: the injected `TelegramWebProxy`
object in the hidden WebView, and the `tproxy-init` MessagePort in the system-browser
fallback. Neither is exercised by `zig build test`.

This script lifts the inline script out of page.zig exactly as the relay renders it and
hands it to harness.js, which impersonates the client.

Missing node or zig is an error; contract tests cannot silently pass without running.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PAGE = REPO / "src" / "web" / "page.zig"
HARNESS = Path(__file__).resolve().parent / "harness.js"
WS_PATH = "/api/v1/socket"


def extract_script() -> tuple[str, str, str]:
    zig = os.environ.get("ZIG") or shutil.which("zig")
    if not zig:
        raise SystemExit("web-bridge: zig is required")
    rendered = subprocess.run([
        zig, "run", "--dep", "page", "--dep", "frame",
        "-Mroot=" + str(HARNESS.with_name("render.zig")),
        "-Mpage=" + str(PAGE),
        "-Mframe=" + str(PAGE.with_name("frame.zig")),
    ], check=True, text=True, capture_output=True, cwd=REPO).stdout
    hello, welcome, page = rendered.split("\n", 2)
    body = page.split("<script>", 1)
    if len(body) != 2:
        raise SystemExit("the bridge page no longer opens a <script> element")
    js = body[1].split("</script>", 1)[0]
    if "TelegramWebProxy" not in js or "tproxy-init" not in js:
        raise SystemExit("the extracted script is missing a client boundary")
    return js, hello, welcome


def main() -> int:
    node = shutil.which("node")
    if node is None:
        print("web-bridge: node is required", file=sys.stderr)
        return 1

    js, hello, welcome = extract_script()
    print(f"web-bridge: checking {len(js)} bytes of bridge script")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "bridge.js"
        path.write_text(js, encoding="utf-8")

        syntax = subprocess.run([node, "--check", str(path)], capture_output=True, text=True)
        if syntax.returncode != 0:
            print(syntax.stderr.strip())
            return 1

        result = subprocess.run([node, str(HARNESS), str(path), hello, welcome], text=True)
        return result.returncode


if __name__ == "__main__":
    sys.exit(main())
