#!/bin/bash

# Cleanup Script
# Usage: ./scripts/cleanup.sh

cleanup_python() {
    echo "🧹 Removing virtual environment and command..."
    
    # Check if currently in virtual environment
    if [ -n "$VIRTUAL_ENV" ]; then
        echo "⚠️  You are currently in a virtual environment"
        echo "💡 Please run 'deactivate' after cleanup completes"
    fi
    
    # Remove virtual environments
    rm -rf venv .venv
    rm -f autorecon-cmd
    
    # Remove global command
    echo "🗑️  Removing autorecon from /usr/local/bin..."
    sudo rm -f /usr/local/bin/autorecon
}

cleanup_tools() {
    echo "🗑️  Removing installed security tools..."
    
    # Detect OS for proper cleanup
    if [ -f /etc/os-release ]; then
        OS_ID=$(grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
        OS_ID_LIKE=$(grep '^ID_LIKE=' /etc/os-release | cut -d'=' -f2 | tr -d '"' 2>/dev/null || echo "")
        
        if [ "$OS_ID" = "kali" ] || [ "$OS_ID" = "parrot" ] || echo "$OS_ID_LIKE" | grep -q "debian\|ubuntu"; then
            cleanup_debian_tools
        elif [ "$OS_ID" = "arch" ] || [ "$OS_ID" = "manjaro" ]; then
            echo "ℹ️  Arch-based system detected. Basic tools (nmap, curl, wget, git) left installed."
        else
            echo "ℹ️  No tools to remove for $OS_ID."
        fi
        
    elif [ "$(uname)" = "Darwin" ]; then
        cleanup_macos_tools
    else
        echo "ℹ️  Unknown OS - no tools to remove."
    fi
}

cleanup_debian_tools() {
    echo "Removing security tools for Debian-based system..."
    echo "⚠️  Note: This will remove security tools that may be used by other applications"
    
    # Check if running interactively
    if [ -t 0 ]; then
        read -p "Remove security tools? [y/N]: " -n 1 -r
        echo
    else
        echo "Reading confirmation from input..."
        read -r REPLY
    fi
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing apt-installed security tools..."
        local tools="seclists dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nikto onesixtyone oscanner redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb"
        
        for tool in $tools; do
            if dpkg -l | grep -q "^ii.*$tool" 2>/dev/null; then
                echo "Removing $tool..."
                sudo apt remove -y $tool 2>/dev/null || echo "Failed to remove $tool"
            fi
        done
        
        echo "Core tools (nmap, curl, wget, git) left installed."
    else
        echo "Skipping tool removal."
    fi
}

cleanup_macos_tools() {
    echo "Removing security tools for macOS..."
    echo "⚠️  Note: This will remove security tools that may be used by other applications"
    
    # Check if running interactively
    if [ -t 0 ]; then
        read -p "Remove security tools? [y/N]: " -n 1 -r
        echo
    else
        echo "Reading confirmation from input..."
        read -r REPLY
    fi
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing Homebrew security tools..."
        local tools="gobuster nikto whatweb sslscan feroxbuster redis-tools smbclient hydra john-jumbo hashcat sqlmap exploitdb binwalk exiftool"
        
        for tool in $tools; do
            if brew list | grep -q "^$tool$" 2>/dev/null; then
                echo "Removing $tool..."
                brew uninstall --ignore-dependencies $tool 2>/dev/null || echo "Failed to remove $tool"
            fi
        done
        
        echo "Removing Python security tools..."
        python3 -m pip uninstall -y impacket crackmapexec enum4linux-ng 2>/dev/null || echo "Some Python tools couldn't be removed"
        echo "Core tools (nmap, curl, wget, git) left installed."
    else
        echo "Skipping tool removal."
    fi
}

cleanup_docker() {
    echo "🐳 Cleaning up Docker resources..."
    
    if command -v docker >/dev/null 2>&1; then
        if [ -n "$(docker images -q autorecon 2>/dev/null)" ]; then
            echo "Stopping any running autorecon containers..."
            docker ps -aq --filter ancestor=autorecon 2>/dev/null | xargs -r docker stop >/dev/null 2>&1 || true
            docker ps -aq --filter ancestor=autorecon 2>/dev/null | xargs -r docker rm >/dev/null 2>&1 || true
            
            echo "Removing autorecon Docker image..."
            docker rmi autorecon >/dev/null 2>&1 || true
            echo "Docker image removed."
        else
            echo "No autorecon Docker image found."
        fi
    else
        echo "Docker not available."
    fi
}

cleanup_results() {
    echo "🗂️  Cleaning up results directory..."
    
    if [ -d "results" ] && [ -z "$(ls -A results 2>/dev/null)" ]; then
        rm -rf results
        echo "Empty results directory removed."
    elif [ -d "results" ]; then
        echo "Results directory contains files - keeping it."
    else
        echo "No results directory found."
    fi
}

show_venv_warning() {
    if [ -n "$VIRTUAL_ENV" ]; then
        echo ""
        echo "┌─────────────────────────────────────────────────────────────┐"
        echo "│  ⚠️  WARNING: IMPORTANT FINAL STEP                          │"
        echo "│                                                             │"
        echo "│  You are still in a virtual environment!                   │"
        echo "│  Please run the following command:                         │"
        echo "│                                                             │"
        echo "│      deactivate                                             │"
        echo "│                                                             │"
        echo "│  This will restore your normal terminal prompt.            │"
        echo "└─────────────────────────────────────────────────────────────┘"
        echo ""
    fi
}

# Main execution
main() {
    echo "Cleaning up autorecon installation..."
    echo ""
    
    cleanup_python
    echo ""
    cleanup_tools
    echo ""
    cleanup_docker
    cleanup_results
    
    echo ""
    echo "✅ Clean complete!"
    echo "Virtual environment, Docker image, and empty directories removed."
    
    show_venv_warning
}

# Run if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi 