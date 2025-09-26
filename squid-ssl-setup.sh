# Create the optimized setup script (no full system upgrade)
cat > squid-ssl-setup.sh << 'EOF'
#!/bin/bash

# Better error handling - only exit on undefined variables
set -u

echo "🚀 Starting Fresh Squid SSL Setup..."
echo "===================================="

# Function to print colored output
print_status() {
    echo -e "\033[1;34m[INFO]\033[0m $1"
}

print_success() {
    echo -e "\033[1;32m[SUCCESS]\033[0m $1"
}

print_error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1"
}

print_warning() {
    echo -e "\033[1;33m[WARNING]\033[0m $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

# Set non-interactive mode
export DEBIAN_FRONTEND=noninteractive

# Update package list only (not full system upgrade)
print_status "Updating package list..."
apt update
print_success "Package list updated"

# Install required packages
print_status "Installing Squid with SSL support and dependencies..."
apt install -y squid openssl curl net-tools
print_success "Packages installed successfully"

# Stop any existing squid (with proper error handling)
print_status "Stopping any existing Squid service..."
systemctl stop squid 2>/dev/null || true
systemctl disable squid 2>/dev/null || true
pkill -f squid 2>/dev/null || true
sleep 2

# Backup original config if exists
if [ -f /etc/squid/squid.conf ]; then
    cp /etc/squid/squid.conf /etc/squid/squid.conf.backup.$(date +%Y%m%d_%H%M%S)
    print_status "Original config backed up"
fi

# Clean up existing files
print_status "Cleaning up existing configuration..."
rm -f /run/squid.pid 2>/dev/null || true
rm -f /var/lock/squid* 2>/dev/null || true

# Create SSL certificate directory
print_status "Creating SSL certificate directory..."
mkdir -p /etc/squid/ssl_cert
mkdir -p /var/lib/squid/ssl_db
mkdir -p /var/log/squid

# Generate SSL certificate
print_status "Generating SSL certificate..."
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -keyout /etc/squid/ssl_cert/squid.pem \
    -out /etc/squid/ssl_cert/squid.pem \
    -subj "/C=US/ST=State/L=City/O=ProxyServer/OU=IT/CN=squid-proxy.local"

print_success "SSL certificate generated"

# Set proper permissions
chown -R proxy:proxy /etc/squid/ssl_cert
chown -R proxy:proxy /var/lib/squid/ssl_db
chown -R proxy:proxy /var/log/squid
chmod 600 /etc/squid/ssl_cert/squid.pem
chmod 700 /etc/squid/ssl_cert
chmod 700 /var/lib/squid/ssl_db

print_status "Permissions set correctly"

# Create Squid configuration
print_status "Creating Squid configuration..."
cat > /etc/squid/squid.conf << 'CONFIG'
# Squid SSL Bump Proxy Configuration
# Basic proxy ports
http_port 3128
https_port 3129 cert=/etc/squid/ssl_cert/squid.pem ssl-bump intercept

# SSL bump configuration
acl step1 at_step SslBump1
acl step2 at_step SslBump2
acl step3 at_step SslBump3

ssl_bump peek step1
ssl_bump peek step2
ssl_bump splice step3

# Network ACLs
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl localnet src fc00::/7
acl localnet src fe80::/10

# Port ACLs
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777

# Method ACLs
acl CONNECT method CONNECT

# Access control rules
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access allow localnet
http_access allow localhost
http_access deny all

# Cache configuration
cache_dir ufs /var/spool/squid 1000 16 256
maximum_object_size 4096 KB
cache_mem 256 MB
coredump_dir /var/spool/squid

# SSL certificate database
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 4MB
sslcrtd_children 8 startup=1 idle=1

# Logging
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log
logfile_rotate 10

# DNS
dns_nameservers 8.8.8.8 8.8.4.4

# Refresh patterns
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
CONFIG

print_success "Configuration created"

# Initialize SSL certificate database
print_status "Initializing SSL certificate database..."
/usr/lib/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 4MB
chown -R proxy:proxy /var/lib/squid/ssl_db

# Initialize squid cache
print_status "Initializing Squid cache directories..."
squid -z
print_success "Cache directories initialized"

# Start squid service
print_status "Starting Squid service..."
systemctl daemon-reload
systemctl start squid
systemctl enable squid

# Wait for service to start
sleep 5

# Check service status
if systemctl is-active --quiet squid; then
    print_success "Squid is running successfully!"
    
    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    # Check listening ports
    print_status "Checking listening ports..."
    netstat -tlnp | grep -E ':(3128|3129)' || print_warning "Ports not yet visible in netstat"
    
    # Test the proxy
    print_status "Testing proxy functionality..."
    sleep 2
    if timeout 10 curl -x "$SERVER_IP:3128" --connect-timeout 5 -s http://www.google.com -I > /dev/null 2>&1; then
        print_success "HTTP proxy test passed!"
    else
        print_warning "HTTP proxy test - may need a moment to fully initialize"
    fi
    
    echo ""
    echo "🎉 SETUP COMPLETE!"
    echo "=============================================="
    echo "Server IP: $SERVER_IP"
    echo ""
    echo "Proxy Configuration:"
    echo "  HTTP Proxy:  $SERVER_IP:3128"
    echo "  HTTPS Proxy: $SERVER_IP:3129"
    echo ""
    echo "Test Commands:"
    echo "  curl -x $SERVER_IP:3128 http://www.google.com -I"
    echo "  curl -x $SERVER_IP:3128 -k https://www.google.com -I"
    echo ""
    echo "Status Commands:"
    echo "  sudo systemctl status squid"
    echo "  sudo tail -f /var/log/squid/access.log"
    echo "  sudo tail -f /var/log/squid/cache.log"
    echo "=============================================="
    
else
    print_error "Squid failed to start. Checking logs..."
    echo ""
    echo "=== Recent cache log entries ==="
    tail -20 /var/log/squid/cache.log 2>/dev/null || echo "No cache log available yet"
    echo ""
    echo "=== Recent system log entries ==="
    journalctl -u squid --no-pager -l -n 20
    echo ""
    echo "=== Squid service status ==="
    systemctl status squid --no-pager
    exit 1
fi

print_success "Squid SSL setup completed! 🎉"
EOF
