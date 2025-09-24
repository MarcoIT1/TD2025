#!/usr/bin/env bash
set -euo pipefail

# --- Install and enable squid ---
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
apt-get install -y squid
systemctl enable squid

# --- Paths ---
SQUID_CONF="/etc/squid/squid.conf"
BACKUP_CONF="/etc/squid/squid.conf.bak.$(date +%s)"

# --- Backup the config ---
echo "[INFO] Backing up squid.conf to $BACKUP_CONF"
cp "$SQUID_CONF" "$BACKUP_CONF"

# --- Define LAN network (adjust to your network) ---
LAN_NET="10.0.0.0/24"

# --- Rewrite squid.conf minimal rules ---
tee "$SQUID_CONF" > /dev/null <<EOF
# Squid minimal config

# Squid normally listens on port 3128
http_port 3128

# ACL for LAN network
acl localnet src $LAN_NET

# Block maclife.com
acl blocked_sites dstdomain .maclife.com

# Safe ports (default set)
acl SSL_ports port 443
acl Safe_ports port 80       # http
acl Safe_ports port 21       # ftp
acl Safe_ports port 70       # gopher
acl Safe_ports port 210      # wais
acl Safe_ports port 1025-65535 # unregistered ports
acl Safe_ports port 280      # http-mgmt
acl Safe_ports port 488      # gss-http
acl Safe_ports port 591      # filemaker
acl Safe_ports port 777      # multiling http
acl CONNECT method CONNECT

# Access rules
http_access deny blocked_sites
http_access allow localnet
http_access deny all
EOF

# --- Restart squid ---
echo "[INFO] Restarting squid..."
systemctl restart squid

echo "[DONE] Squid is installed and blocking www.maclife.com

function " {
	function #statements {
		#statements
	}
	
}

LOG_TAG="K8S-SETUP"
 
log() {
    echo "$1" | tee >(logger -t "$LOG_TAG")
}
 
exec > >(tee >(logger -t "$LOG_TAG")) 2>&1  # Redirect all output to syslog and terminal

