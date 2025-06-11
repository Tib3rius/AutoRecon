#!/bin/bash

# Arch Linux Tool Installation Script
# Usage: ./scripts/install-tools-arch.sh

install_arch_tools() {
    local OS_ID=${OS_ID:-$(grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')}
    
    echo "📦 Installing security tools for $OS_ID (Arch-based)..."
    sudo pacman -Sy --noconfirm nmap curl wget git python python-pip || echo "⚠️  Some tools failed to install"
    echo "ℹ️  For full tool support, consider using Kali Linux or install tools manually"
    echo "✅ Basic tools installed"
}

# Main execution
main() {
    install_arch_tools
}

# Run if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi 