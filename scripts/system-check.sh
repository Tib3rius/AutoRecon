#!/bin/bash

# System Prerequisites Check Script
# Usage: ./scripts/system-check.sh

echo "🔍 Checking prerequisites..."

# Check Python version
check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "❌ Python 3 is not installed"
        echo ""
        echo "Please install Python 3.8+ first:"
        echo "  • Ubuntu/Debian: sudo apt install python3 python3-pip python3-venv"
        echo "  • CentOS/RHEL: sudo yum install python3 python3-pip"
        echo "  • Arch: sudo pacman -S python python-pip"
        echo "  • macOS: brew install python3"
        echo "  • Or download from: https://www.python.org/downloads/"
        echo ""
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c "import sys; print('.'.join(map(str, sys.version_info[:2])))" 2>/dev/null || echo "unknown")
    if [ "$PYTHON_VERSION" != "unknown" ]; then
        echo "✅ Python $PYTHON_VERSION detected"
        MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        if [ $MAJOR -lt 3 ] || ([ $MAJOR -eq 3 ] && [ $MINOR -lt 8 ]); then
            echo "⚠️  Python $PYTHON_VERSION detected, but Python 3.8+ is recommended"
            echo "   Download latest from: https://www.python.org/downloads/"
        fi
    else
        echo "⚠️  Could not determine Python version"
    fi
}

# Detect operating system
detect_os() {
    echo "🔍 Detecting operating system..."
    
    if [ -f /etc/os-release ]; then
        OS_ID=$(grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
        OS_ID_LIKE=$(grep '^ID_LIKE=' /etc/os-release | cut -d'=' -f2 | tr -d '"' 2>/dev/null || echo "")
        
        # Check for WSL
        WSL_DETECTED=""
        if grep -q Microsoft /proc/version 2>/dev/null || [ -n "$WSL_DISTRO_NAME" ]; then
            WSL_DETECTED="yes"
            echo "🪟 WSL environment detected"
        fi
        
        export OS_ID OS_ID_LIKE WSL_DETECTED
        echo "✅ Detected: $OS_ID"
        
    elif [ "$(uname)" = "Darwin" ]; then
        OS_ID="macos"
        export OS_ID
        echo "✅ Detected: macOS"
        
        # Check for Homebrew
        if ! command -v brew >/dev/null 2>&1; then
            echo "⚠️  Homebrew not found. Please install Homebrew first:"
            echo "    /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        fi
    else
        OS_ID="unknown"
        export OS_ID
        echo "⚠️  Unknown operating system"
    fi
}

# Main execution
main() {
    check_python
    echo ""
    detect_os
    echo ""
    echo "✅ System check complete!"
}

# Run if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi 