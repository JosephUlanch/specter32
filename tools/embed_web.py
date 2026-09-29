"""Embed a deterministic gzip asset; no separate filesystem upload required."""
import gzip
from pathlib import Path


def generate(root):
    data = gzip.compress((root / "web/index.html").read_bytes(), mtime=0)
    body = ",".join(str(b) for b in data)
    (root / "include/web_asset.h").write_text(
        "#pragma once\n#include <Arduino.h>\n"
        f"static const uint8_t WEB_ASSET[] PROGMEM = {{{body}}};\n"
    )


if __name__ == "__main__":
    generate(Path(__file__).resolve().parents[1])
else:
    Import("env")  # noqa: F821 -- PlatformIO SCons environment
    generate(Path(env["PROJECT_DIR"]))  # noqa: F821
