#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

rm -rf build dist
python3 -m pytest -q
python3 -m compileall -q selfishnet.py selfishnet_tui.py

if ! command -v pyinstaller >/dev/null 2>&1; then
    echo "PyInstaller requis : python3 -m pip install pyinstaller" >&2
    exit 2
fi

pyinstaller --clean --noconfirm \
    --name SelfishNet-GUI \
    --onefile --windowed \
    --hidden-import scapy \
    --add-data "assets:assets" \
    selfishnet_tui.py

mkdir -p dist/release
tar -C dist -czf "dist/release/SelfishNet-Linux-$(date +%Y%m%d).tar.gz" SelfishNet-GUI
