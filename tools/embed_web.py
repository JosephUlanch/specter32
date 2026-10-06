"""Embed a deterministic gzip asset; no separate filesystem upload required."""
import gzip
from pathlib import Path


def generate(root):
    content = "#pragma once\n#include <Arduino.h>\n"
    for filename, symbol in (("index.html", "WEB_ASSET"), ("handshake.js", "HANDSHAKE_ASSET")):
        data = gzip.compress((root / "web" / filename).read_bytes(), mtime=0)
        body = ",".join(str(b) for b in data)
        content += f"static const uint8_t {symbol}[] PROGMEM = {{{body}}};\n"
    (root / "include/web_asset.h").write_text(content)


if __name__ == "__main__":
    generate(Path(__file__).resolve().parents[1])
else:
    Import("env")  # noqa: F821 -- PlatformIO SCons environment
    generate(Path(env["PROJECT_DIR"]))  # noqa: F821
