$ErrorActionPreference = "Stop"

python -m pip install --upgrade pip
python -m pip install -r requirements.txt pyinstaller pytest
python -m pytest -q
python -m compileall selfishnet.py selfishnet_tui.py
pyinstaller --clean --noconfirm `
    --name SelfishNet-GUI `
    --onefile --windowed `
    --uac-admin `
    --hidden-import scapy `
    --add-data "assets;assets" `
    selfishnet_windows_tui.py

$date = Get-Date -Format "yyyyMMdd"
New-Item -ItemType Directory -Force -Path dist/release | Out-Null
Compress-Archive -Force -Path dist/SelfishNet-GUI.exe "dist/release/SelfishNet-Windows-$date.zip"
