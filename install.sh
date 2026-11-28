#!/usr/bin/env bash
# Installation de SelfishNet-Linux (équivalent Linux de SelfishNet)
# Usage : bash install.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="/usr/local/lib/selfishnet"
TARGET_USER="${SUDO_USER:-$USER}"

echo "==> 1/5 Vérification des dépendances système"
NEED_DEPS=0
for bin in python3 iptables ip tcpdump tc; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    NEED_DEPS=1
    break
  fi
done

if ! python3 -c "import tkinter, scapy" >/dev/null 2>&1; then
  NEED_DEPS=1
fi

if [ "$NEED_DEPS" -eq 1 ]; then
  echo "    Dépendances manquantes détectées, installation requise..."
  if command -v apt-get >/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y python3 python3-pip python3-tk iptables iproute2 tcpdump python3-scapy || true
  elif command -v dnf >/dev/null; then
    sudo dnf install -y python3 python3-pip python3-tkinter iptables iproute tcpdump python3-scapy || true
  elif command -v pacman >/dev/null; then
    sudo pacman -S --needed --noconfirm python python-pip tk iptables iproute2 tcpdump python-scapy
  fi
  if ! python3 -c "import scapy" 2>/dev/null; then
    echo "==> 2/5 Installation de Scapy via pip..."
    sudo pip install --break-system-packages -r "$HERE/requirements.txt" 2>/dev/null \
      || pip install --user -r "$HERE/requirements.txt"
  fi
else
  echo "    Toutes les dépendances (Python, Scapy, Tkinter, iptables, tc, tcpdump) sont déjà prêtes."
  echo "==> 2/5 Dépendances Python prêtes"
fi

echo "==> 3/5 Groupe système 'selfishnet' et forwarding IP"
if ! getent group selfishnet >/dev/null 2>&1; then
  sudo groupadd -r selfishnet
fi
if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ]; then
  sudo usermod -aG selfishnet "$TARGET_USER" 2>/dev/null || true
  if [ -S /run/selfishnet.sock ] && command -v setfacl >/dev/null 2>&1; then
    sudo setfacl -m "u:${TARGET_USER}:rw" /run/selfishnet.sock 2>/dev/null || true
  fi
fi
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-selfishnet.conf >/dev/null

echo "==> 4/5 Installation des modules, commandes, raccourci et service systemd"
sudo mkdir -p "$LIB_DIR/assets"
sudo install -m 0644 "$HERE/selfishnet_core.py" "$LIB_DIR/selfishnet_core.py"
sudo install -m 0644 "$HERE/selfishnet_ui_common.py" "$LIB_DIR/selfishnet_ui_common.py"
sudo install -m 0755 "$HERE/selfishnet.py" "$LIB_DIR/selfishnet.py"
sudo install -m 0755 "$HERE/selfishnet_tui.py" "$LIB_DIR/selfishnet_tui.py"
[ -f "$HERE/assets/oui.txt" ] && sudo install -m 0644 "$HERE/assets/oui.txt" "$LIB_DIR/assets/oui.txt"
[ -f "$HERE/assets/selfishnet.png" ] && sudo install -m 0644 "$HERE/assets/selfishnet.png" "$LIB_DIR/assets/selfishnet.png"
[ -f "$HERE/assets/selfishnet.svg" ] && sudo install -m 0644 "$HERE/assets/selfishnet.svg" "$LIB_DIR/assets/selfishnet.svg"

sudo ln -sf "$LIB_DIR/selfishnet.py" /usr/local/bin/selfishnet
sudo ln -sf "$LIB_DIR/selfishnet_tui.py" /usr/local/bin/selfishnet-gui
sudo ln -sf "$LIB_DIR/selfishnet.py" /usr/local/bin/mynet-filter
sudo ln -sf "$LIB_DIR/selfishnet_tui.py" /usr/local/bin/mynet-filter-gui
sudo ln -sf /usr/local/bin/selfishnet /usr/local/sbin/selfishnet
sudo ln -sf /usr/local/bin/selfishnet-gui /usr/local/sbin/selfishnet-gui
sudo ln -sf /usr/local/bin/mynet-filter /usr/local/sbin/mynet-filter
sudo ln -sf /usr/local/bin/mynet-filter-gui /usr/local/sbin/mynet-filter-gui

# Icônes et entrée de menu d'application (.desktop)
sudo mkdir -p /usr/share/icons/hicolor/scalable/apps /usr/share/icons/hicolor/256x256/apps /usr/share/applications
[ -f "$HERE/assets/selfishnet.svg" ] && sudo cp "$HERE/assets/selfishnet.svg" /usr/share/icons/hicolor/scalable/apps/selfishnet.svg
[ -f "$HERE/assets/selfishnet.png" ] && sudo cp "$HERE/assets/selfishnet.png" /usr/share/icons/hicolor/256x256/apps/selfishnet.png
[ -f "$HERE/selfishnet.desktop" ] && sudo cp "$HERE/selfishnet.desktop" /usr/share/applications/selfishnet.desktop
command -v update-desktop-database >/dev/null && sudo update-desktop-database /usr/share/applications 2>/dev/null || true

# Copie dans l'espace utilisateur local pour prise en compte immédiate
mkdir -p "$HOME/.local/share/applications" "$HOME/.local/share/icons/hicolor/256x256/apps" "$HOME/.local/share/icons/hicolor/scalable/apps"
cp "$HERE/selfishnet.desktop" "$HOME/.local/share/applications/" 2>/dev/null || true
[ -f "$HERE/assets/selfishnet.png" ] && cp "$HERE/assets/selfishnet.png" "$HOME/.local/share/icons/hicolor/256x256/apps/" 2>/dev/null || true
[ -f "$HERE/assets/selfishnet.svg" ] && cp "$HERE/assets/selfishnet.svg" "$HOME/.local/share/icons/hicolor/scalable/apps/" 2>/dev/null || true
command -v update-desktop-database >/dev/null && update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true

# Service systemd
sudo cp "$HERE/selfishnet.service" /etc/systemd/system/selfishnet.service 2>/dev/null || true
sudo systemctl daemon-reload 2>/dev/null || true
if systemctl is-active --quiet selfishnet 2>/dev/null; then
  sudo systemctl restart selfishnet
fi

echo "==> 5/5 Vérification"
chmod +x "$HERE/selfishnet.py" "$HERE/selfishnet_tui.py"
sudo /usr/local/bin/selfishnet doctor

cat <<'EOF'

✅ Installation terminée.

Note : votre utilisateur a été ajouté au groupe 'selfishnet' pour contrôler le
démon depuis la GUI sans sudo (reconnectez votre session ou exécutez `newgrp selfishnet`).

Démarrage rapide :
    sudo selfishnet scan          # voir les appareils du wifi
    sudo selfishnet watch         # console interactive (recommandé)
    selfishnet-gui                # interface graphique (sans sudo)

Ou en service permanent (démarre au boot) :
    sudo systemctl enable --now selfishnet

Tout est réversible :  sudo selfishnet clean
Désinstallation :      bash uninstall.sh
EOF
