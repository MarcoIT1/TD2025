#!/bin/bash

# squid-ssl-setup.sh - Complete Squid Proxy with SSL Bump Setup
# Usage: sudo ./squid-ssl-setup.sh

set -e

echo "🚀 Starting Squid SSL Proxy Setup..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

print_status "Updating package list..."
apt-get update

print_status "Installing Squid proxy server..."
apt-get install -y squid openssl

print_status "Stopping any existing Squid processes..."
systemctl stop squid 2>/dev/null || true
pkill -f squid 2>/dev/null || true

print_status "Cleaning up existing configuration..."
rm -f /run/squid.pid
rm -f /var/lock/squid*

print_status "Creating SSL directories..."
mkdir -p /etc/squid/ssl
mkdir -p /var/lib/ssl_db

print_status "Generating SSL certificate for SSL bumping..."
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -keyout /etc/squid/ssl/squid.key \
    -out /etc/squid/ssl/squid.crt \
    -subj "/C=US/ST=State/L=City/O=SquidProxy/CN=squid-proxy"

# Combine certificate and key
cat /etc/squid/ssl/squid.crt /etc/squid/ssl/squid.key > /etc/squid/ssl/squid.pem

print_status "Setting SSL file permissions..."
chown -R proxy:proxy /etc/squid/ssl
chmod 600 /etc/squid/ssl/*

print_status "Creating Squid configuration..."
cat > /etc/squid/squid.conf << 'EOF'
# Basic Squid Proxy Configuration with SSL Bump
http_port 3128
https_port 3129 intercept ssl-bump cert=/etc/squid/ssl/squid.pem

# Network ACLs
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl localnet src fc00::/7
acl localnet src fe80::/10

# Port ACLs
acl SSL_ports port 443
acl Safe_ports port 80 21 443 70 210 1025-65535 280 488 591 777

# Method ACLs
acl CONNECT method CONNECT

# SSL Bump ACLs
acl step1 at_step SslBump1
acl step2 at_step SslBump2
acl step3 at_step SslBump3

# Access control rules
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access allow localnet
http_access allow localhost
http_access deny all

# SSL Bump rules
ssl_bump peek step1
ssl_bump bump step2
ssl_bump bump step3

# Certificate generation
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/ssl_db -M 4MB
sslcrtd_children 8 startup=1 idle=1

# Cache configuration
coredump_dir /var/spool/squid

# Logging
access_log /var/log/squid/access.log squid

# Refresh patterns
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
EOF

print_status "Initializing SSL certificate database..."
/usr/lib/squid/security_file_certgen -c -s /var/lib/ssl_db -M 4MB
chown -R proxy:proxy /var/lib/ssl_db

print_status "Initializing Squid cache..."
squid -z

print_status "Starting and enabling Squid service..."
systemctl start squid
systemctl enable squid

sleep 3

# Check if Squid is running
if systemctl is-active --quiet squid; then
    print_success "Squid is running successfully!"
    
    print_status "Checking listening ports..."
    netstat -tlnp | grep -E ':(3128|3129)'
    
    print_success "Setup complete!"
    echo ""
    echo "📋 Configuration Summary:"
    echo "  • HTTP Proxy: http://$(hostname -I | awk '{print $1}'):3128"
    echo "  • HTTPS Proxy: https://$(hostname -I | awk '{print $1}'):3129"
    echo "  • SSL Certificate: /etc/squid/ssl/squid.pem"
    echo "  • Configuration: /etc/squid/squid.conf"
    echo "  • Logs: /var/log/squid/access.log"
    echo ""
    echo "🧪 Test Commands:"
    echo "  curl -x $(hostname -I | awk '{print $1}'):3128 http://www.google.com -I"
    echo "  sudo tail -f /var/log/squid/access.log"
    echo ""
    echo "🔧 Management Commands:"
    echo "  sudo systemctl status squid"
    echo "  sudo systemctl restart squid"
    echo "  sudo systemctl stop squid"
    
else
    print_error "Squid failed to start!"
    print_status "Checking Squid status..."
    systemctl status squid --no-pager
    
    print_status "Checking Squid logs..."
    tail -n 20 /var/log/squid/cache.log
    exit 1
fi

print_success "Squid SSL Proxy setup completed successfully! 🎉"
