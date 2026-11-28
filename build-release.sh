#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

rm -rf build dist
python3 -m pytest -q
python3 -m compileall -q mynet_filter_core.py mynet_filter_ui_common.py mynet_filter.py mynet_filter_gui.py mynet_filter_windows.py mynet_filter_windows_gui.py

if ! command -v pyinstaller >/dev/null 2>&1; then
    echo "PyInstaller requis : python3 -m pip install pyinstaller" >&2
    exit 2
fi

pyinstaller --clean --noconfirm \
    --name mynet-filter \
    --onefile \
    --collect-submodules scapy \
    --add-data "assets:assets" \
    mynet_filter.py

pyinstaller --clean --noconfirm \
    --name MyNet-Filter-GUI \
    --onefile --windowed \
    --add-data "assets:assets" \
    mynet_filter_gui.py

mkdir -p dist/release
ARCHIVE="dist/release/MyNet-Filter-Linux-$(date +%Y%m%d).tar.gz"
tar -C dist -czf "$ARCHIVE" mynet-filter MyNet-Filter-GUI
(cd dist/release && sha256sum "$(basename "$ARCHIVE")" > SHA256SUMS.txt)
echo "Release prête : $ARCHIVE"
