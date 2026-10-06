#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
g++ -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Iinclude tests/packet_test.cpp -o "$work/packet-test"
"$work/packet-test" "$work/fixture.pcap"
python3 tests/check_pcap.py "$work/fixture.pcap"
python3 tools/embed_web.py
python3 - "$work/dashboard.js" <<'PY'
from pathlib import Path
import sys
html = Path('web/index.html').read_text()
Path(sys.argv[1]).write_text(html.split('<script>')[1].split('</script>')[0])
PY
node --check "$work/dashboard.js"

node --check web/handshake.js
node tests/handshake_test.cjs
