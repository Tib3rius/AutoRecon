#!/bin/bash

# Security Tools Installation Script (Main Router)
# Usage: ./scripts/install-tools.sh [OS_ID] [OS_ID_LIKE] [WSL_DETECTED]

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source system info from environment or parameters
OS_ID=${1:-$OS_ID}
OS_ID_LIKE=${2:-$OS_ID_LIKE}
WSL_DETECTED=${3:-$WSL_DETECTED}

install_fallback_tools() {
    echo "ℹ️  Unsupported Linux distribution: $OS_ID"
    echo "ℹ️  Installing basic requirements..."
    sudo apt update -qq 2>/dev/null || true
    sudo apt install -y python3-venv python3-pip curl wget git 2>/dev/null || true
    echo "ℹ️  Please install security tools manually or use Docker setup"
}

# Main installation logic
main() {
    if [ -z "$OS_ID" ]; then
        echo "❌ OS_ID not provided. Run system-check.sh first or provide OS_ID as parameter."
        exit 1
    fi
    
    # Export variables for sub-scripts
    export OS_ID OS_ID_LIKE WSL_DETECTED
    
    case "$OS_ID" in
        kali|parrot)
            "$SCRIPT_DIR/install-tools-debian.sh" "$WSL_DETECTED"
            ;;
        ubuntu|debian)
            if echo "$OS_ID_LIKE" | grep -q "debian\|ubuntu"; then
                "$SCRIPT_DIR/install-tools-debian.sh" "$WSL_DETECTED"
            else
                install_fallback_tools
            fi
            ;;
        arch|manjaro)
            "$SCRIPT_DIR/install-tools-arch.sh"
            ;;
        macos)
            "$SCRIPT_DIR/install-tools-macos.sh"
            ;;
        *)
            if [ -f /etc/os-release ] && echo "$OS_ID_LIKE" | grep -q "debian\|ubuntu"; then
                "$SCRIPT_DIR/install-tools-debian.sh" "$WSL_DETECTED"
            else
                install_fallback_tools
            fi
            ;;
    esac
}

# Run if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi 