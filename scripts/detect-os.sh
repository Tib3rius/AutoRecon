#!/bin/bash

# OS Detection Script for Makefile sourcing
# Usage: . scripts/detect-os.sh

# Detect operating system and export variables
if [ -f /etc/os-release ]; then
    OS_ID=$(grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
    OS_ID_LIKE=$(grep '^ID_LIKE=' /etc/os-release | cut -d'=' -f2 | tr -d '"' 2>/dev/null || echo "")
    
    # Check for WSL
    WSL_DETECTED=""
    if grep -q Microsoft /proc/version 2>/dev/null || [ -n "$WSL_DISTRO_NAME" ]; then
        WSL_DETECTED="yes"
    fi
    
    export OS_ID OS_ID_LIKE WSL_DETECTED
    
elif [ "$(uname)" = "Darwin" ]; then
    OS_ID="macos"
    OS_ID_LIKE=""
    WSL_DETECTED=""
    export OS_ID OS_ID_LIKE WSL_DETECTED
else
    OS_ID="unknown"
    OS_ID_LIKE=""
    WSL_DETECTED=""
    export OS_ID OS_ID_LIKE WSL_DETECTED
fi 