# AutoRecon Modular Setup System - Contribution Guide

## Overview

This document outlines the modular setup system developed by **neur0map** for AutoRecon, providing comprehensive installation, management, and maintenance capabilities across multiple operating systems. The system consists of a Makefile and supporting shell scripts that automate the entire AutoRecon setup process.

## System Architecture

### Core Components

```
Makefile (Entry Point)
├── scripts/system-check.sh      (Prerequisites & OS detection)
├── scripts/detect-os.sh         (OS detection helper for Makefile)
├── scripts/install-tools.sh     (Installation router)
│   ├── scripts/install-tools-debian.sh   (Debian/Ubuntu/Kali/Parrot)
│   ├── scripts/install-tools-macos.sh    (macOS with Homebrew)
│   └── scripts/install-tools-arch.sh     (Arch Linux/Manjaro)
├── scripts/setup-python.sh      (Python environment & command setup)
├── scripts/setup-docker.sh      (Docker management)
├── scripts/update.sh            (Maintenance & updates)
└── scripts/cleanup.sh           (Complete removal)
```

### Workflow Dependencies

```
make setup:
    system-check.sh → detect-os.sh → install-tools.sh → setup-python.sh

make update:
    update.sh → (git pull → python update → tools update → docker rebuild)

make clean:
    cleanup.sh → (remove venv → remove tools → remove docker → cleanup results)
```

## Available Commands

### 1. Primary Setup Commands

#### `make setup`
**Purpose**: Complete local installation with auto-detected OS support  
**When to use**: First-time setup or fresh installation  
**What it does**:
- Detects operating system and prerequisites
- Installs security tools based on OS
- Sets up Python virtual environment
- Creates global `autorecon` command
- Provides ready-to-use AutoRecon installation

**Output Example**:
```
Setting up AutoRecon...

🔍 Checking prerequisites...
✅ Python 3.10.12 detected
✅ Detected: ubuntu

📦 Installing security tools for ubuntu (Debian-based)...
[...tool installation...]

🐍 Setting up Python environment...
📦 Installing Python dependencies...
🔧 Creating autorecon command...

✅ Setup complete!
```

#### `make setup-docker`
**Purpose**: Docker-based setup with interactive terminal  
**When to use**: 
- Non-Kali systems requiring full tool support
- Isolated/containerized environment preferred
- Local tool installation not desired

**What it does**:
- Builds AutoRecon Docker image
- Launches interactive container terminal
- Mounts results directory for persistence
- Provides full security toolkit in container

#### `make clean`
**Purpose**: Complete removal of AutoRecon installation  
**When to use**: 
- Uninstalling AutoRecon
- Starting fresh after issues
- Freeing up disk space

**What it does**:
- Removes Python virtual environment
- Removes installed security tools (with confirmation)
- Removes Docker images
- Removes global commands
- Cleans up temporary files

### 2. Maintenance Commands

#### `make update`
**Purpose**: Update all components to latest versions  
**When to use**: 
- Regular maintenance (weekly/monthly)
- After AutoRecon repository updates
- Before major scanning projects

**What it does**:
- Updates git repository with latest changes
- Updates Python packages
- Updates system security tools
- Rebuilds Docker image if needed
- Shows summary of changes

#### `make docker-cmd`
**Purpose**: Launch additional Docker terminal sessions  
**When to use**: 
- Multiple concurrent scanning sessions
- After `make setup-docker` for additional terminals

### 3. Help Command

#### `make help`
**Purpose**: Display comprehensive usage information  
**Contains**:
- All available commands
- OS compatibility matrix
- Usage recommendations
- Docker workflow guide

## Operating System Support

### Tier 1: Full Support (20+ Security Tools)
- **Kali Linux**: Native security distribution
- **Parrot OS**: Security-focused distribution  
- **Ubuntu/Debian**: Comprehensive apt-based installation
- **macOS**: Homebrew-based toolkit (15+ tools)

### Tier 2: Basic Support
- **Arch/Manjaro**: Core tools only (nmap, curl, wget, git)
- **Other Linux**: Fallback to basic tools

### Tier 3: Docker Recommended
- **Windows**: Use WSL + Docker
- **Unsupported systems**: Docker provides full functionality

## Script Details

### system-check.sh
**Purpose**: Prerequisites validation and OS detection  
**Exports**: `OS_ID`, `OS_ID_LIKE`, `WSL_DETECTED`  
**Checks**:
- Python 3.8+ availability
- Operating system identification
- WSL environment detection
- Package manager availability

### install-tools.sh (Router)
**Purpose**: Routes to appropriate OS-specific installer  
**Parameters**: `OS_ID`, `OS_ID_LIKE`, `WSL_DETECTED`  
**Routes to**:
- `install-tools-debian.sh` for Debian-based systems
- `install-tools-macos.sh` for macOS
- `install-tools-arch.sh` for Arch-based systems

### install-tools-debian.sh
**Tools Installed**:
```bash
# Core tools
curl wget git nmap nikto whatweb sslscan smbclient

# Enumeration tools  
seclists dnsrecon enum4linux feroxbuster gobuster 
impacket-scripts nbtscan onesixtyone oscanner 
redis-tools smbmap snmp sipvicious tnscmd10g
```

**WSL Compatibility**: Includes snap package fallbacks

### install-tools-macos.sh
**Tools Installed**:
```bash
# Core network tools
nmap curl wget git gobuster nikto whatweb sslscan

# Enumeration tools
feroxbuster redis-tools smbclient

# Additional security tools  
hydra john-jumbo hashcat sqlmap exploitdb binwalk exiftool

# Python tools
impacket crackmapexec enum4linux-ng
```

### install-tools-arch.sh
**Limited Installation**: Basic tools only (nmap, curl, wget, git, python)  
**Recommendation**: Use Docker for full functionality

### setup-python.sh
**Functions**:
- Creates Python virtual environment
- Installs requirements.txt dependencies
- Creates `autorecon-cmd` script
- Installs global `/usr/local/bin/autorecon` command
- Handles permission issues gracefully

### setup-docker.sh
**Functions**:
- Docker availability verification
- AutoRecon image building
- Interactive container launch
- Results directory mounting
- Container session management

### update.sh
**Update Process**:
1. **Git Update**: Pull latest changes, handle stashes
2. **Python Update**: Upgrade pip and packages
3. **Tools Update**: OS-appropriate tool updates
4. **Docker Update**: Rebuild if Dockerfile changed
5. **Summary**: Show what was updated

### cleanup.sh
**Removal Process**:
1. **Python Environment**: Remove venv and commands
2. **Security Tools**: OS-specific removal (with confirmation)
3. **Docker Resources**: Remove images and containers
4. **Results**: Clean empty directories
5. **Warning**: Notify about active virtual environments

## Usage Patterns

### 1. First Time Setup
```bash
# Clone AutoRecon repository
git clone https://github.com/Tib3rius/AutoRecon.git
cd AutoRecon

# Full local setup
make setup

# Test installation
autorecon --help
autorecon 127.0.0.1
```

### 2. Docker-Based Setup
```bash
# Docker setup (recommended for non-Kali)
make setup-docker

# Inside container:
autorecon --help
autorecon target.com
ls /scans  # View results

# Additional sessions
make docker-cmd
```

### 3. Regular Maintenance
```bash
# Weekly/monthly updates
make update

# Check for issues
autorecon --help

# If problems occur
make clean
make setup
```

### 4. Contributing Development
```bash
# Setup development environment
make setup

# Make changes to AutoRecon code
# ...

# Test changes
autorecon test-target

# Update after pulling latest
make update
```

## Integration Notes for AutoRecon

### Required Changes for Integration

1. **Project Name References**: Change all instances of "ipcrawler" to "autorecon" in:
   - `setup-python.sh` (command creation)
   - `setup-docker.sh` (image names and references)
   - `cleanup.sh` (removal procedures)
   - `Makefile` (help text and commands)

2. **Global Command**: Scripts create `/usr/local/bin/autorecon` instead of `/usr/local/bin/ipcrawler`

3. **Docker Integration**: Requires existing `Dockerfile` and `requirements.txt` in repository root

### File Structure Requirements
```
AutoRecon/
├── Makefile
├── scripts/
│   ├── system-check.sh
│   ├── detect-os.sh  
│   ├── install-tools.sh
│   ├── install-tools-debian.sh
│   ├── install-tools-macos.sh
│   ├── install-tools-arch.sh
│   ├── setup-python.sh
│   ├── setup-docker.sh
│   ├── update.sh
│   └── cleanup.sh
├── requirements.txt
├── Dockerfile
└── autorecon.py
```

## Benefits for AutoRecon Project

### 1. User Experience
- **Simplified Installation**: Single `make setup` command
- **Cross-Platform**: Automated OS detection and appropriate tool installation
- **Maintenance**: Easy updates with `make update`
- **Cleanup**: Complete removal with `make clean`

### 2. Developer Experience  
- **Consistent Environment**: Standardized setup across contributors
- **Docker Integration**: Isolated development environments
- **Modular Design**: Easy to modify and extend
- **Error Handling**: Graceful failures with helpful messages

### 3. Documentation
- **Self-Documenting**: `make help` provides comprehensive guidance
- **Status Messages**: Clear feedback during installation
- **OS-Specific**: Tailored instructions for each platform

### 4. Maintenance
- **Automated Updates**: Handles git, Python, tools, and Docker
- **Dependency Management**: Ensures all components stay current  
- **Clean Removal**: Complete uninstall capability

## Contribution Guidelines

### For Pull Request
1. Create feature branch from main AutoRecon repository
2. Update project references from "ipcrawler" to "autorecon"
3. Test on multiple operating systems:
   - Ubuntu/Debian
   - Kali Linux
   - macOS (with Homebrew)
   - Arch Linux
4. Verify Docker functionality
5. Update documentation as needed

### Testing Checklist
- [ ] `make setup` works on supported OS
- [ ] `make setup-docker` builds and runs
- [ ] `make update` updates all components
- [ ] `make clean` removes everything
- [ ] Global `autorecon` command functions
- [ ] Error handling works for unsupported systems
- [ ] WSL compatibility verified

## Author

**Contributor**: neur0map  
**Original Project**: AutoRecon by Tib3rius  
**Fork**: ipcrawler (source of these enhancements)  

This modular setup system significantly enhances AutoRecon's accessibility and maintainability across diverse operating systems and deployment scenarios. 