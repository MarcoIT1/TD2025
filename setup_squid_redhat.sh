#!/usr/bin/env bash
set -euo pipefail

# --- Install and enable squid ---
dnf -y install squid
systemctl enable --now squid

# --- Paths ---
SQUID_CONF="/etc/squid/squid.conf"
BACKUP_CONF="/etc/squid/squid.conf.bak.$(date +%s)"

# --- Backup the config ---
cp "$SQUID_CONF" "$BACKUP_CONF"

# --- Define LAN network (adjust to your network) ---
LAN_NET="10.0.0.0/24"

# --- Rewrite squid.conf minimal rules ---
tee "$SQUID_CONF" > /dev/null <<EOF
# Squid minimal config (RHEL version)

http_port 3128

acl localnet src ${LAN_NET}
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

# --- Restart squid ---
systemctl restart squid
