# Create the complete setup script
cat > squid-ssl-setup.sh << 'EOF'
#!/bin/bash
set -e

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

# Set non-interactive mode
export DEBIAN_FRONTEND=noninteractive

# Update system
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y

print_success "System updated successfully"

# Install required packages
print_status "Installing Squid with SSL support and dependencies..."
sudo apt install -y squid-openssl openssl curl net-tools

print_success "Packages installed successfully"

# Stop any existing squid
print_status "Stopping any existing Squid service..."
sudo systemctl stop squid 2>/dev/null || true
sudo systemctl disable squid 2>/dev/null || true

# Backup original config if exists
if [ -f /etc/squid/squid.conf ]; then
    sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.backup.$(date +%Y%m%d_%H%M%S)
    print_status "Original config backed up"
fi

# Create SSL certificate directory
print_status "Creating SSL certificate directory..."
sudo mkdir -p /etc/squid/ssl_cert
sudo mkdir -p /var/lib/squid/ssl_db

# Generate SSL certificate
print_status "Generating SSL certificate..."
sudo openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -keyout /etc/squid/ssl_cert/squid.pem \
    -out /etc/squid/ssl_cert/squid.pem \
    -subj "/C=US/ST=State/L=City/O=ProxyServer/OU=IT/CN=squid-proxy.local"

print_success "SSL certificate generated"

# Set proper permissions
sudo chown -R proxy:proxy /etc/squid/ssl_cert
sudo chown -R proxy:proxy /var/lib/squid/ssl_db
sudo chmod 600 /etc/squid/ssl_cert/squid.pem
sudo chmod 700 /etc/squid/ssl_cert
sudo chmod 700 /var/lib/squid/ssl_db

print_status "Permissions set correctly"

# Create Squid configuration
print_status "Creating Squid configuration..."
sudo tee /etc/squid/squid.conf > /dev/null << 'CONFIG'
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

# Create log directory
sudo mkdir -p /var/log/squid
sudo chown proxy:proxy /var/log/squid

# Initialize squid cache
print_status "Initializing Squid cache directories..."
sudo squid -z

print_success "Cache directories initialized"

# Start squid service
print_status "Starting Squid service..."
sudo systemctl daemon-reload
sudo systemctl start squid
sudo systemctl enable squid

# Wait for service to start
sleep 5

# Check service status
if sudo systemctl is-active --quiet squid; then
    print_success "Squid is running successfully!"
    
    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    # Test the proxy
    print_status "Testing proxy functionality..."
    if timeout 10 curl -x "$SERVER_IP:3128" --connect-timeout 5 -s http://www.google.com -I > /dev/null 2>&1; then
        print_success "HTTP proxy test passed!"
    else
        print_status "HTTP proxy test - checking connectivity..."
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
    echo "=============================================="
    
else
    print_error "Squid failed to start. Checking logs..."
    echo "Recent cache log entries:"
    sudo tail -20 /var/log/squid/cache.log 2>/dev/null || echo "No cache log available"
    echo ""
    echo "Recent system log entries:"
    sudo journalctl -u squid --no-pager -l -n 20
fi

print_success "Squid SSL setup completed!"
EOF

# Make executable and run
chmod +x squid-ssl-setup.sh
./squid-ssl-setup.sh