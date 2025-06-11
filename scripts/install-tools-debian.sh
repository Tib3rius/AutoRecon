#!/bin/bash

# Debian/Ubuntu Tool Installation Script
# Usage: ./scripts/install-tools-debian.sh [WSL_DETECTED]

WSL_DETECTED=${1:-$WSL_DETECTED}

install_debian_tools() {
    local OS_ID=${OS_ID:-$(grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')}
    
    echo "📦 Installing security tools for $OS_ID (Debian-based)..."
    echo "🔄 Updating package cache..."
    sudo apt update -qq
    
    echo "🐍 Installing Python venv package (fixes ensurepip issues)..."
    sudo apt install -y python3-venv python3-pip
    
    echo "📦 Installing core security tools..."
    sudo apt install -y curl wget git nmap nikto whatweb sslscan smbclient
    
    echo "📦 Installing available enumeration tools..."
    local FAILED_TOOLS=""
    
    local tools="seclists dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan onesixtyone oscanner redis-tools smbmap snmp sipvicious tnscmd10g"
    
    for tool in $tools; do
        if ! sudo apt install -y $tool 2>/dev/null; then
            echo "⚠️  $tool failed via apt, checking snap..."
            FAILED_TOOLS="$FAILED_TOOLS $tool"
        fi
    done
    
    # Try snap for failed tools in WSL
    if [ -n "$FAILED_TOOLS" ] && [ "$WSL_DETECTED" = "yes" ]; then
        echo "🫰 Installing snap for WSL compatibility..."
        sudo apt install -y snapd
        sudo systemctl enable snapd 2>/dev/null || true
        
        for tool in $FAILED_TOOLS; do
            case $tool in
                feroxbuster)
                    echo "Installing feroxbuster via snap..."
                    sudo snap install feroxbuster 2>/dev/null || echo "⚠️  feroxbuster snap install failed"
                    ;;
                gobuster)
                    echo "Installing gobuster via snap..."
                    sudo snap install gobuster 2>/dev/null || echo "⚠️  gobuster snap install failed"
                    ;;
                *)
                    echo "⚠️  No snap alternative for $tool"
                    ;;
            esac
        done
    fi
    
    echo "✅ Tool installation complete"
}

# Main execution
main() {
    install_debian_tools
}

# Run if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi 