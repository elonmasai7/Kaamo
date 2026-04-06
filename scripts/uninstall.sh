#!/usr/bin/env bash
set -euo pipefail

echo "This removes Kaamo configs and libraries but preserves models by default."
read -r -p "Continue? [y/N]: " confirm
[[ "${confirm}" =~ ^[Yy]$ ]] || exit 0

if command -v systemctl >/dev/null 2>&1; then
  sudo systemctl stop kaamo-daemon 2>/dev/null || true
  sudo systemctl disable kaamo-daemon 2>/dev/null || true
  sudo rm -f /etc/systemd/system/kaamo-daemon.service
  sudo systemctl daemon-reload 2>/dev/null || true
fi

python3 -m pip uninstall -y kaamo 2>/dev/null || true
rm -rf "${HOME}/.kaamo/agents" "${HOME}/.kaamo/lib" "${HOME}/.kaamo/logs"

read -r -p "Delete downloaded models too? [y/N]: " delete_models
[[ "${delete_models}" =~ ^[Yy]$ ]] && rm -rf "${HOME}/.kaamo/models"

echo "Kaamo uninstalled."

