#!/usr/bin/env python3
"""Run the real mtbuddy diagnostics against discussion #425 regressions (Linux)."""
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    binary = str(Path(sys.argv[1]).resolve())
    users = '[access.users]\nalice = "0123456789abcdef0123456789abcdef"\n'
    cases = [
        ("bare", '[server]\n  public_ip = tg.domain.ru\n', 2, "quotes"),
        ("section", '[server]\nport = 443\n[server]\n', 3, "section"),
        ("key", '[server]\nport = 443\nport = 8443\n', 3, "key"),
        ("secret", '[upstream.socks5]\npassword = private-secret\n', 2, "quotes"),
        ("valid", '[server]\npublic_ip = "tg.domain.ru"\n', None, None),
    ]
    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory) / "config.toml"
        for command in ("validate", "doctor", "print-effective"):
            for name, body, line, hint in cases:
                original = body + users
                config.write_text(original)
                result = subprocess.run(
                    [binary, "config", command, "--config", str(config)],
                    capture_output=True, text=True, timeout=10,
                )
                output = result.stdout + result.stderr
                assert (result.returncode == 0) == (line is None), (command, name, output)
                if line is not None:
                    assert f"line {line}" in output and hint in output.lower(), (command, name, output)
                    assert "private-secret" not in output and "0123456789abcdef" not in output
                assert config.read_text() == original, "diagnostics modified configuration"
                print(f"{command}: {name}: OK")


if __name__ == "__main__":
    main()
