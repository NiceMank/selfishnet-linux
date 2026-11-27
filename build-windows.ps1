$ErrorActionPreference = "Stop"

python -m pip install --upgrade pip
python -m pip install -r requirements.txt pyinstaller pytest
python -m pytest -q
python -m compileall selfishnet_core.py selfishnet.py selfishnet_tui.py selfishnet_windows.py selfishnet_windows_tui.py

$iconArgs = @()
if (Test-Path "assets/selfishnet.ico") {
    $iconArgs = @("--icon", "assets/selfishnet.ico")
}

pyinstaller --clean --noconfirm `
    --name SelfishNet-GUI `
    --onefile --windowed `
    --uac-admin `
    @iconArgs `
    --collect-submodules scapy `
    --add-data "assets;assets" `
    selfishnet_windows_tui.py

$date = Get-Date -Format "yyyyMMdd"
New-Item -ItemType Directory -Force -Path dist/release | Out-Null
$zipPath = "dist/release/SelfishNet-Windows-$date.zip"
Compress-Archive -Force -Path dist/SelfishNet-GUI.exe -DestinationPath $zipPath
$hash = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLower()
"$hash  $(Split-Path -Leaf $zipPath)" | Out-File -Encoding ascii "dist/release/SHA256SUMS.txt"
Write-Host "Release Windows prête : $zipPath ($hash)"
