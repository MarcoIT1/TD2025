#!/usr/bin/env bash
set -euo pipefail

# --- Install Squid ---
echo "[*] Installing Squid..."
sudo yum install -y squid

# --- Enable and start Squid ---
echo "[*] Enabling and starting Squid service..."
sudo systemctl enable squid
sudo systemctl start squid

# --- Paths ---
SQUID_CONF="/etc/squid/squid.conf"
BACKUP_CONF="/etc/squid/squid.conf.bak.$(date +%s)"

# --- Backup config ---
echo "[*] Backing up current squid.conf -> $BACKUP_CONF"
sudo cp "$SQUID_CONF" "$BACKUP_CONF"

# --- Define LAN network (adjust if needed) ---
LAN_NET="10.0.0.0/24"

# --- Write minimal config ---
echo "[*] Writing new squid.conf..."
sudo tee "$SQUID_CONF" > /dev/null <<EOF
# Squid minimal config (RHEL version)

http_port 3128

acl localnet src $LAN_NET
acl blocked_sites dstdomain .maclife.de

acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT

http_access deny blocked_sites
http_access allow localnet
http_access deny all
EOF

# --- Open firewall port ---
echo "[*] Opening firewall for Squid (3128/tcp)..."
sudo firewall-cmd --add-port=3128/tcp --permanent
sudo firewall-cmd --reload

# --- Restart Squid ---
echo "[*] Restarting Squid with new config..."
sudo systemctl restart squid

echo "[*] Setup complete. Check with: tail -f /var/log/squid/access.log"
