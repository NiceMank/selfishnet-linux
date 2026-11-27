#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

rm -rf build dist
python3 -m pytest -q
python3 -m compileall -q selfishnet_core.py selfishnet_ui_common.py selfishnet.py selfishnet_tui.py selfishnet_windows.py selfishnet_windows_tui.py

if ! command -v pyinstaller >/dev/null 2>&1; then
    echo "PyInstaller requis : python3 -m pip install pyinstaller" >&2
    exit 2
fi

pyinstaller --clean --noconfirm \
    --name selfishnet \
    --onefile \
    --collect-submodules scapy \
    --add-data "assets:assets" \
    selfishnet.py

pyinstaller --clean --noconfirm \
    --name SelfishNet-GUI \
    --onefile --windowed \
    --add-data "assets:assets" \
    selfishnet_tui.py

mkdir -p dist/release
ARCHIVE="dist/release/SelfishNet-Linux-$(date +%Y%m%d).tar.gz"
tar -C dist -czf "$ARCHIVE" selfishnet SelfishNet-GUI
(cd dist/release && sha256sum "$(basename "$ARCHIVE")" > SHA256SUMS.txt)
echo "Release prête : $ARCHIVE"
