#!/usr/bin/env bash
set -euo pipefail

LOGFILE="/var/log/px-test.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "[INFO] PX test script started at $(date)"

# Try to create folder as root
sudo mkdir -p /opt/px-test-folder
sudo chmod 777 /opt/px-test-folder

echo "[INFO] Folder /opt/px-test-folder created"
echo "[INFO] PX test script finished at $(date)"
