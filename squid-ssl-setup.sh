#!/bin/bash

# Squid SSL Bump Setup Script with SSL Database Fix
# Author: Assistant
# Version: 2.0 (Fixed SSL DB initialization)

set -e  # Exit on any error

echo "🚀 Starting Squid SSL Bump Setup..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (use sudo)"
   exit 1
fi

# Step 1: Update system and install Squid
log_info "Updating system and installing Squid..."
apt update
apt install -y squid openssl

# Step 2: Stop Squid service
log_info "Stopping Squid service..."
systemctl stop squid || true

# Step 3: Backup original configuration
log_info "Backing up original Squid configuration..."
if [[ ! -f /etc/squid/squid.conf.backup ]]; then
    cp /etc/squid/squid.conf /etc/squid/squid.conf.backup
    log_success "Original configuration backed up"
else
    log_warning "Backup already exists, skipping..."
fi

# Step 4: Create SSL certificate and key for Squid
log_info "Creating SSL certificate for Squid..."
SSL_DIR="/etc/squid/ssl_cert"
mkdir -p $SSL_DIR

if [[ ! -f $SSL_DIR/squid.pem ]]; then
    openssl req -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 \
        -keyout $SSL_DIR/squid.pem \
        -out $SSL_DIR/squid.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=squid-proxy"
    
    chmod 600 $SSL_DIR/squid.pem
    chown proxy:proxy $SSL_DIR/squid.pem
    log_success "SSL certificate created"
else
    log_warning "SSL certificate already exists, skipping..."
fi

# Step 5: Prepare SSL database directory (FIXED VERSION)
log_info "Preparing SSL database directory..."
SSL_DB_DIR="/var/spool/squid/ssl_db"

# Remove existing SSL database if it exists (this was the fix!)
if [[ -d $SSL_DB_DIR ]]; then
    log_warning "Removing existing SSL database directory..."
    rm -rf $SSL_DB_DIR
fi

# Ensure parent directory exists with correct ownership
mkdir -p /var/spool/squid
chown proxy:proxy /var/spool/squid

# Step 6: Initialize SSL database (let the tool create the directory)
log_info "Initializing SSL certificate database..."
sudo -u proxy /usr/lib/squid/security_file_certgen -c -s $SSL_DB_DIR -M 4MB
log_success "SSL database initialized successfully"

# Verify SSL database structure
if [[ -d "$SSL_DB_DIR/certs" ]] && [[ -f "$SSL_DB_DIR/index.txt" ]] && [[ -f "$SSL_DB_DIR/size" ]]; then
    log_success "SSL database structure verified"
else
    log_error "SSL database structure verification failed"
    exit 1
fi

# Step 7: Create Squid configuration
log_info "Creating Squid SSL Bump configuration..."

cat > /etc/squid/squid.conf << 'EOF'
# Squid SSL Bump Configuration

# SSL Bump Certificate Configuration  
tls_outgoing_options capath=/etc/ssl/certs \
    options=NO_SSLv3,NO_TLSv1 \
    cipher=HIGH:MEDIUM:!RC4:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS

# SSL certificate for dynamic certificate generation
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/spool/squid/ssl_db -M 4MB
sslcrtd_children 8 startup=1 idle=1

# ACLs
acl localnet src 10.0.0.0/8     # RFC1918 possible internal network
acl localnet src 172.16.0.0/12  # RFC1918 possible internal network  
acl localnet src 192.168.0.0/16 # RFC1918 possible internal network
acl localnet src fc00::/7        # RFC 4193 local private network range
acl localnet src fe80::/10       # RFC 4291 link-local (directly plugged) machines

acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT

# SSL Bump ACLs
acl step1 at_step SslBump1
acl step2 at_step SslBump2  
acl step3 at_step SslBump3

# SSL Bump Rules (Conservative approach - mostly tunneling)
ssl_bump peek step1
ssl_bump splice all

# Basic Access Rules
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access allow localnet
http_access allow localhost
http_access deny all

# HTTP and HTTPS ports
http_port 3128
https_port 3129 tls-cert=/etc/squid/ssl_cert/squid.pem ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB

# Disable caching for simplicity
cache deny all

# Log format
logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt

# Access and cache logs
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log

# Misc settings
coredump_dir /var/spool/squid
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320

# Error page customization
error_directory /usr/share/squid/errors/English
EOF

log_success "Squid configuration created"

# Step 8: Set proper permissions
log_info "Setting proper permissions..."
chown -R proxy:proxy /var/spool/squid
chown -R proxy:proxy /var/log/squid
chmod -R 755 /var/spool/squid
chmod -R 644 /var/log/squid

# Step 9: Validate configuration
log_info "Validating Squid configuration..."
if squid -k parse; then
    log_success "Configuration syntax is valid"
else
    log_error "Configuration has syntax errors"
    exit 1
fi

# Step 10: Start and enable Squid
log_info "Starting Squid service..."
systemctl enable squid
systemctl start squid

# Wait for service to start
sleep 3

# Step 11: Verify service status
if systemctl is-active --quiet squid; then
    log_success "Squid service is running"
else
    log_error "Squid service failed to start"
    systemctl status squid
    exit 1
fi

# Step 12: Display status and instructions
echo ""
echo "🎉 ====================================="
echo "   SQUID SSL BUMP SETUP COMPLETE!"
echo "======================================"
echo ""
echo "📊 Service Status:"
systemctl status squid --no-pager -l
echo ""
echo "🔧 Configuration Details:"
echo "  • HTTP Proxy Port: 3128"
echo "  • HTTPS Proxy Port: 3129"  
echo "  • SSL Certificate: /etc/squid/ssl_cert/squid.pem"
echo "  • SSL Database: /var/spool/squid/ssl_db"
echo "  • Config File: /etc/squid/squid.conf"
echo "  • Backup Config: /etc/squid/squid.conf.backup"
echo ""
echo "🧪 Test Commands:"
echo "  • Test HTTP: curl -x localhost:3128 http://www.google.com"
echo "  • Test HTTPS: curl -x localhost:3128 -k https://www.google.com"
echo "  • Check logs: tail -f /var/log/squid/access.log"
echo ""
echo "⚙️  SSL Database Status:"
ls -la /var/spool/squid/ssl_db/
echo ""
echo "📝 Notes:"
echo "  • Current config uses conservative SSL bump (splice mode)"
echo "  • To enable full SSL inspection, modify ssl_bump rules"
echo "  • Install squid certificate on clients for full bump"
echo ""
log_success "Setup completed successfully! 🚀"
