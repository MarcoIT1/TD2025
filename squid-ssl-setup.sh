#!/bin/bash

# =============================================================================
# SQUID SSL BUMPING SETUP SCRIPT (Complete Installation - Password-Free)
# =============================================================================
# Description: Automated setup for Squid proxy with SSL bumping capability
# Author: Assistant
# Version: 2.1 - Password-free execution with sudo credential caching
# =============================================================================

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
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

print_header() {
    echo -e "\n${BLUE}==============================================================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}==============================================================================${NC}\n"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
        exit 1
    fi
}

# Function to maintain sudo credentials
maintain_sudo() {
    # Start a background process to refresh sudo credentials
    while true; do
        sleep 60
        sudo -n true 2>/dev/null || break
    done &
    SUDO_PID=$!
    
    # Clean up function
    cleanup_sudo() {
        if [[ -n $SUDO_PID ]]; then
            kill $SUDO_PID 2>/dev/null || true
        fi
    }
    
    # Set trap to clean up on exit
    trap cleanup_sudo EXIT
}

# Function to check sudo privileges and maintain them
check_sudo() {
    print_status "Checking sudo privileges..."
    if sudo -n true 2>/dev/null; then
        print_success "Sudo privileges confirmed"
    else
        print_status "Please enter your password for sudo access:"
        sudo true
        print_success "Sudo privileges confirmed"
    fi
    
    # Start maintaining sudo credentials
    maintain_sudo
    print_status "Sudo credentials will be maintained automatically"
}

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        print_status "Detected OS: $PRETTY_NAME"
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
}

# Function to install squid
install_squid() {
    print_status "Checking if Squid is installed..."
    
    if command -v squid &> /dev/null; then
        SQUID_VERSION=$(squid -v | head -n1 | awk '{print $4}')
        print_success "Squid is already installed (Version: $SQUID_VERSION)"
        return 0
    fi
    
    print_status "Squid not found. Installing Squid..."
    
    case $OS in
        ubuntu|debian)
            print_status "Updating package list..."
            sudo -n apt update
            print_status "Installing Squid proxy server..."
            sudo -n apt install squid openssl -y
            ;;
        centos|rhel|fedora)
            print_status "Installing Squid proxy server..."
            if command -v dnf &> /dev/null; then
                sudo -n dnf install squid openssl -y
            else
                sudo -n yum install squid openssl -y
            fi
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            print_status "Please install squid manually and run the script again"
            exit 1
            ;;
    esac
    
    # Verify installation
    if command -v squid &> /dev/null; then
        SQUID_VERSION=$(squid -v | head -n1 | awk '{print $4}')
        print_success "Squid installed successfully (Version: $SQUID_VERSION)"
        
        # Enable squid service
        print_status "Enabling Squid service..."
        sudo -n systemctl enable squid
        
        # Start squid service if not running
        if ! sudo -n systemctl is-active --quiet squid; then
            print_status "Starting Squid service..."
            sudo -n systemctl start squid
        fi
        
        print_success "Squid service is enabled and running"
    else
        print_error "Failed to install Squid"
        exit 1
    fi
}

# Function to backup original configuration
backup_config() {
    print_status "Backing up original squid configuration..."
    if [[ ! -f /etc/squid/squid.conf.original ]]; then
        sudo -n cp /etc/squid/squid.conf /etc/squid/squid.conf.original
        print_success "Configuration backed up to /etc/squid/squid.conf.original"
    else
        print_warning "Backup already exists at /etc/squid/squid.conf.original"
    fi
}

# Function to create SSL certificate directory
create_ssl_directory() {
    print_status "Creating SSL certificate directory..."
    sudo -n mkdir -p /etc/squid/ssl_cert
    print_success "SSL certificate directory created"
}

# Function to generate CA private key
generate_ca_key() {
    print_status "Generating CA private key (4096 bits)..."
    if [[ ! -f /etc/squid/ssl_cert/squid-ca-key.pem ]]; then
        sudo -n openssl genrsa -out /etc/squid/ssl_cert/squid-ca-key.pem 4096
        print_success "CA private key generated"
    else
        print_warning "CA private key already exists"
    fi
}

# Function to generate CA certificate
generate_ca_cert() {
    print_status "Generating CA certificate..."
    if [[ ! -f /etc/squid/ssl_cert/squid-ca-cert.pem ]]; then
        sudo -n openssl req -new -x509 -days 3650 \
            -key /etc/squid/ssl_cert/squid-ca-key.pem \
            -out /etc/squid/ssl_cert/squid-ca-cert.pem \
            -utf8 \
            -subj "/C=IE/ST=Cork/L=Cork/O=TM/OU=TS/CN=Squid CA"
        print_success "CA certificate generated"
    else
        print_warning "CA certificate already exists"
    fi
}

# Function to set proper permissions
set_permissions() {
    print_status "Setting proper permissions..."
    sudo -n chown -R proxy:proxy /etc/squid/ssl_cert/
    sudo -n chmod 400 /etc/squid/ssl_cert/squid-ca-key.pem
    sudo -n chmod 444 /etc/squid/ssl_cert/squid-ca-cert.pem
    print_success "Permissions set correctly"
}

# Function to create SSL database
create_ssl_database() {
    print_status "Creating SSL certificate database..."
    sudo -n mkdir -p /var/lib/squid/ssl_db
    
    if [[ ! -f /var/lib/squid/ssl_db/index.txt ]]; then
        sudo -n /usr/lib/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 4MB
        sudo -n chown -R proxy:proxy /var/lib/squid/ssl_db
        print_success "SSL database created and initialized"
    else
        print_warning "SSL database already exists"
    fi
}

# Function to add SSL bump configuration
add_ssl_config() {
    print_status "Adding SSL bump configuration..."
    
    # Check if SSL bump configuration already exists
    if grep -q "SSL Bump Configuration" /etc/squid/squid.conf; then
        print_warning "SSL bump configuration already exists in squid.conf"
        return 0
    fi
    
    sudo -n tee -a /etc/squid/squid.conf << 'EOF'

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

    print_success "SSL bump configuration added to squid.conf"
}

# Function to test configuration
test_config() {
    print_status "Testing squid configuration..."
    if sudo -n squid -k parse; then
        print_success "Configuration syntax is valid"
        return 0
    else
        print_error "Configuration syntax error detected!"
        return 1
    fi
}

# Function to restart squid service
restart_squid() {
    print_status "Restarting squid service..."
    if sudo -n systemctl restart squid; then
        print_success "Squid service restarted successfully"
        sleep 2
        
        # Check service status
        if sudo -n systemctl is-active --quiet squid; then
            print_success "Squid service is running"
        else
            print_error "Squid service failed to start"
            return 1
        fi
    else
        print_error "Failed to restart squid service"
        return 1
    fi
}

# Function to verify setup
verify_setup() {
    print_status "Verifying SSL bumping setup..."
    
    # Check if ports are listening
    sleep 3  # Give squid time to fully start
    
    if ss -tlnp | grep -q ":3128"; then
        print_success "Regular proxy listening on port 3128"
    else
        print_warning "Port 3128 not listening"
    fi
    
    if ss -tlnp | grep -q ":3129"; then
        print_success "SSL bumping proxy listening on port 3129"
    else
        print_warning "Port 3129 not listening"
    fi
    
    # Test regular proxy
    print_status "Testing regular proxy (port 3128)..."
    if timeout 10 curl -x http://localhost:3128 https://www.google.com -I -s > /dev/null; then
        print_success "Regular proxy working"
    else
        print_warning "Regular proxy test failed"
    fi
    
    # Test SSL bumping proxy
    print_status "Testing SSL bumping proxy (port 3129)..."
    if timeout 10 curl -x http://localhost:3129 https://www.google.com -I -k -s > /dev/null; then
        print_success "SSL bumping proxy working"
    else
        print_warning "SSL bumping proxy test failed"
    fi
    
    # Show service status
    print_status "Current Squid service status:"
    sudo -n systemctl status squid --no-pager -l
}

# Function to show final information
show_final_info() {
    print_header "SETUP COMPLETE - IMPORTANT INFORMATION"
    
    echo -e "${GREEN}✅ Squid SSL Bumping Setup Completed Successfully!${NC}\n"
    
    echo "📋 Configuration Summary:"
    echo "  • Regular HTTP Proxy: http://localhost:3128"
    echo "  • SSL Bumping Proxy:  http://localhost:3129"
    echo "  • CA Certificate:     /etc/squid/ssl_cert/squid-ca-cert.pem"
    echo "  • SSL Database:       /var/lib/squid/ssl_db"
    echo ""
    
    echo "🧪 Testing Commands:"
    echo "  # Test regular proxy:"
    echo "  curl -x http://localhost:3128 https://www.google.com -I -v 2>&1 | grep 'issuer'"
    echo ""
    echo "  # Test SSL bumping proxy:"
    echo "  curl -x http://localhost:3129 https://www.google.com -I -v -k 2>&1 | grep -E '(issuer|subject)'"
    echo ""
    
    echo "📁 Important Files:"
    echo "  • Original config: /etc/squid/squid.conf.original"
    echo "  • Current config:  /etc/squid/squid.conf"
    echo "  • CA certificate:  /etc/squid/ssl_cert/squid-ca-cert.pem"
    echo ""
    
    echo "⚠️  Note: To use SSL bumping with browsers, install the CA certificate"
    echo "   (/etc/squid/ssl_cert/squid-ca-cert.pem) in the browser's trust store."
    echo ""
    
    echo "🔧 Service Management:"
    echo "  sudo systemctl status squid    # Check status"
    echo "  sudo systemctl restart squid   # Restart service"
    echo "  sudo systemctl stop squid      # Stop service"
    echo "  sudo systemctl start squid     # Start service"
    echo ""
}

# Main execution function
main() {
    print_header "SQUID SSL BUMPING COMPLETE SETUP SCRIPT"
    
    print_status "Starting complete Squid SSL bumping setup..."
    
    # Pre-flight checks
    check_root
    check_sudo
    detect_os
    
    # Install squid if needed
    install_squid
    
    # Main setup steps
    backup_config
    create_ssl_directory
    generate_ca_key
    generate_ca_cert
    set_permissions
    create_ssl_database
    add_ssl_config
    
    # Test and restart
    if test_config; then
        restart_squid
        verify_setup
        show_final_info
    else
        print_error "Setup failed due to configuration errors"
        print_status "Restoring original configuration..."
        sudo -n cp /etc/squid/squid.conf.original /etc/squid/squid.conf
        exit 1
    fi
    
    print_success "🎉 Complete Squid SSL Bumping setup finished successfully!"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
