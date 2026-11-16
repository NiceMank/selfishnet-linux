#!/usr/bin/env bash
# Désinstallation complète de SelfishNet-Linux
set -uo pipefail

echo "==> Arrêt du service et nettoyage des règles"
sudo systemctl disable --now selfishnet 2>/dev/null || true
sudo pkill -f "selfishnet.py" 2>/dev/null || true
sleep 1
sudo python3 /usr/local/sbin/selfishnet clean 2>/dev/null || true

echo "==> Suppression des fichiers"
sudo rm -f /usr/local/sbin/selfishnet /usr/local/sbin/selfishnet-gui
sudo rm -f /usr/local/bin/selfishnet /usr/local/bin/selfishnet-gui
sudo rm -f /usr/share/applications/selfishnet.desktop
rm -f "$HOME/.local/share/applications/selfishnet.desktop" 2>/dev/null || true
sudo rm -f /usr/share/icons/hicolor/scalable/apps/selfishnet.svg /usr/share/icons/hicolor/256x256/apps/selfishnet.png
rm -f "$HOME/.local/share/icons/hicolor/scalable/apps/selfishnet.svg" "$HOME/.local/share/icons/hicolor/256x256/apps/selfishnet.png" "$HOME/.local/share/icons/selfishnet.png" 2>/dev/null || true
sudo rm -f /etc/systemd/system/selfishnet.service
sudo rm -f /etc/sysctl.d/99-selfishnet.conf
sudo rm -rf /var/lib/selfishnet
sudo systemctl daemon-reload 2>/dev/null || true

echo "✅ Désinstallé. (ip_forward reste à 1 : remettez-le à 0 avec"
echo "   sudo sysctl -w net.ipv4.ip_forward=0 si vous n'en avez pas besoin.)"
