#!/bin/bash

# =============================================================================
# Squid SSL Proxy Setup Script
# Complete automated installation with all working steps
# =============================================================================

set -e  # Exit on any error

echo "🚀 SQUID SSL PROXY SETUP"
echo "========================"
echo ""

# Function to print status messages
print_step() {
    echo "📋 STEP $1: $2"
    echo "$(printf '%.0s-' {1..50})"
}

print_status() {
    echo "[INFO] $1"
}

print_success() {
    echo "[SUCCESS] $1"
}

print_error() {
    echo "[ERROR] $1"
}

# =============================================================================
# STEP 0: Install squid-openssl
# =============================================================================
print_step "0" "Installing squid-openssl"
print_status "Updating package list..."
sudo apt update

print_status "Installing squid-openssl (includes SSL certificate generation tools)..."
if sudo apt install squid-openssl -y; then
    print_success "squid-openssl installed successfully"
    
    # Get version info
    SQUID_VERSION=$(squid -v | head -1 | grep -o 'Version [0-9.]*' | cut -d' ' -f2)
    print_success "Squid installed successfully (Version: $SQUID_VERSION)"
    
    # Enable service
    print_status "Enabling Squid service..."
    sudo systemctl enable squid
    print_success "Squid service is enabled and running"
else
    print_error "Failed to install squid-openssl"
    exit 1
fi

echo ""

# =============================================================================
# STEP 1: Create SSL certificate directory
# =============================================================================
print_step "1" "Creating SSL certificate directory"
print_status "Creating SSL certificate directory..."
sudo mkdir -p /etc/squid/ssl_cert
print_success "SSL certificate directory created"

echo ""

# =============================================================================
# STEP 2: Create the CA private key
# =============================================================================
print_step "2" "Creating CA private key"
print_status "Generating CA private key (4096 bits)..."
sudo openssl genrsa -out /etc/squid/ssl_cert/squid-ca-key.pem 4096
print_success "CA private key generated"

echo ""

# =============================================================================
# STEP 3: Create the CA certificate
# =============================================================================
print_step "3" "Creating CA certificate"
print_status "Generating CA certificate..."
sudo openssl req -new -x509 -days 3650 \
    -key /etc/squid/ssl_cert/squid-ca-key.pem \
    -out /etc/squid/ssl_cert/squid-ca-cert.pem \
    -utf8 -subj "/C=IE/ST=Cork/L=Cork/O=TM/OU=TS/CN=Squid CA"
print_success "CA certificate generated"

echo ""

# =============================================================================
# STEP 4: Set proper permissions
# =============================================================================
print_step "4" "Setting proper permissions"
print_status "Setting proper permissions..."
sudo chown -R proxy:proxy /etc/squid/ssl_cert/
sudo chmod 400 /etc/squid/ssl_cert/squid-ca-key.pem
sudo chmod 444 /etc/squid/ssl_cert/squid-ca-cert.pem
print_success "Permissions set correctly"

echo ""

# =============================================================================
# STEP 5: Backup original configuration
# =============================================================================
print_step "6" "Backing up original configuration"
if [ ! -f /etc/squid/squid.conf.original ]; then
    print_status "Backing up original squid configuration..."
    sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.original
    print_success "Configuration backed up to /etc/squid/squid.conf.original"
else
    print_success "Configuration backup already exists"
fi

echo ""

# =============================================================================
# STEP 6: Add SSL bump configuration
# =============================================================================
print_step "7" "Adding SSL bump configuration"
print_status "Adding SSL bump configuration to squid.conf..."
sudo tee -a /etc/squid/squid.conf << 'EOF'

# SSL Bump Configuration
http_port 3129 ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert=/etc/squid/ssl_cert/squid-ca-cert.pem key=/etc/squid/ssl_cert/squid-ca-key.pem

# ACL for SSL bumping
acl step1 at_step SslBump1
acl step2 at_step SslBump2
acl step3 at_step SslBump3

# SSL bump rules
ssl_bump peek step1
ssl_bump bump step2
ssl_bump bump step3

# Cache directory for SSL certificates
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 4MB
sslcrtd_children 5
EOF
print_success "SSL bump configuration added"

echo ""

# =============================================================================
# STEP 7: Test configuration
# =============================================================================
print_step "8" "Testing configuration"
print_status "Validating squid configuration..."
if sudo squid -k parse; then
    print_success "Configuration is valid"
else
    print_error "Configuration validation failed!"
    print_status "Configuration errors:"
    sudo squid -k parse 2>&1
    exit 1
fi

echo ""

# =============================================================================
# STEP 8: Restart squid
# =============================================================================
print_step "9" "Restarting Squid service"
print_status "Restarting squid service..."
if sudo systemctl restart squid; then
    print_success "Squid service restarted successfully"
    
    # Wait a moment for squid to fully start
    sleep 3
else
    print_error "Failed to restart squid service"
    exit 1
fi

echo ""

# =============================================================================
# STEP 9: Verify status
# =============================================================================
print_step "10" "Verifying installation"
print_status "Checking squid service status..."
if sudo systemctl is-active --quiet squid; then
    print_success "Squid service is running"
    
    # Show listening ports
    print_status "Squid is listening on the following ports:"
    sudo netstat -tlnp 2>/dev/null | grep squid || sudo ss -tlnp | grep squid
    
    echo ""
    echo "🎉 INSTALLATION COMPLETED SUCCESSFULLY!"
    echo "======================================"
    echo ""
    echo "📊 Configuration Summary:"
    echo "   Regular HTTP Proxy: http://localhost:3128"
    echo "   SSL Bump Proxy:     http://localhost:3129"
    echo "   CA Certificate:     /etc/squid/ssl_cert/squid-ca-cert.pem"
    echo ""
    echo "🧪 Test Commands:"
    echo "   # Test regular proxy"
    echo "   curl -x http://localhost:3128 http://www.google.com -I"
    echo ""
    echo "   # Test SSL bump proxy (use -k to ignore certificate warnings)"
    echo "   curl -x http://localhost:3129 https://www.google.com -I -k"
    echo ""
    echo "📋 Next Steps:"
    echo "   1. Install the CA certificate (/etc/squid/ssl_cert/squid-ca-cert.pem)"
    echo "      in your browser to avoid SSL warnings"
    echo "   2. Configure your applications to use the proxy"
    echo "   3. Monitor squid logs: sudo tail -f /var/log/squid/access.log"
    echo ""
    
else
    print_error "Squid service is not running!"
    print_status "Service status:"
    sudo systemctl status squid --no-pager
    exit 1
fi

echo "✅ Setup completed successfully!"
