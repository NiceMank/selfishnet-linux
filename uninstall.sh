#!/usr/bin/env bash
# Désinstallation complète de MyNet Filter
set -uo pipefail

echo "==> Arrêt du service et nettoyage des règles"
sudo systemctl disable --now mynet-filter 2>/dev/null || true
sudo pkill -TERM -f "mynet-filter(\.py)? (daemon|watch)" 2>/dev/null || true
sleep 1
if [ -x /usr/local/bin/mynet-filter ]; then
  sudo /usr/local/bin/mynet-filter clean 2>/dev/null || true
fi

echo "==> Suppression des fichiers"
sudo rm -f /usr/local/sbin/mynet-filter /usr/local/sbin/mynet-filter-gui
sudo rm -f /usr/local/bin/mynet-filter /usr/local/bin/mynet-filter-gui
sudo rm -rf /usr/local/lib/mynet-filter
sudo rm -f /run/mynet-filter.sock
sudo rm -f /usr/share/applications/mynet-filter.desktop
rm -f "$HOME/.local/share/applications/mynet-filter.desktop" 2>/dev/null || true
sudo rm -f /usr/share/icons/hicolor/scalable/apps/mynet-filter.svg /usr/share/icons/hicolor/256x256/apps/mynet-filter.png
rm -f "$HOME/.local/share/icons/hicolor/scalable/apps/mynet-filter.svg" "$HOME/.local/share/icons/hicolor/256x256/apps/mynet-filter.png" "$HOME/.local/share/icons/mynet-filter.png" 2>/dev/null || true
sudo rm -f /etc/systemd/system/mynet-filter.service
sudo rm -f /etc/sysctl.d/99-mynet-filter.conf
sudo rm -rf /var/lib/mynet-filter
sudo systemctl daemon-reload 2>/dev/null || true

echo "✅ Désinstallé. (ip_forward reste à 1 : remettez-le à 0 avec"
echo "   sudo sysctl -w net.ipv4.ip_forward=0 si vous n'en avez pas besoin.)"
