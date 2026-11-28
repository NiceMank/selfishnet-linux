$ErrorActionPreference = "Stop"

python -m pip install --upgrade pip
python -m pip install -r requirements.txt pyinstaller pytest
python -m pytest -q
python -m compileall mynet_filter_core.py mynet_filter_ui_common.py mynet_filter.py mynet_filter_gui.py mynet_filter_windows.py mynet_filter_windows_gui.py

$iconArgs = @()
if (Test-Path "assets/mynet-filter.ico") {
    $iconArgs = @("--icon", "assets/mynet-filter.ico")
}

pyinstaller --clean --noconfirm `
    --name MyNet-Filter-GUI `
    --onefile --windowed `
    --uac-admin `
    @iconArgs `
    --collect-submodules scapy `
    --add-data "assets;assets" `
    mynet_filter_windows_gui.py

$date = Get-Date -Format "yyyyMMdd"
New-Item -ItemType Directory -Force -Path dist/release | Out-Null
$zipPath = "dist/release/MyNet-Filter-Windows-$date.zip"
Compress-Archive -Force -Path dist/MyNet-Filter-GUI.exe -DestinationPath $zipPath
$hash = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLower()
"$hash  $(Split-Path -Leaf $zipPath)" | Out-File -Encoding ascii "dist/release/SHA256SUMS.txt"
Write-Host "Release Windows prête : $zipPath ($hash)"
