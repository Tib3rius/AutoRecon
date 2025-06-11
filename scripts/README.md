# AutoRecon Modular Setup System

This directory contains a comprehensive Makefile-based setup system that automates AutoRecon installation, maintenance, and deployment across multiple operating systems.

**Contributor**: neur0map  
**Compatible with**: AutoRecon by Tib3rius

## Quick Start

```bash
# Complete local installation
make setup

# Docker-based setup
make setup-docker

# Update everything
make update

# Remove everything
make clean
```

## Operating System Support

| OS | Tools | Status |
|---|---|---|
| **Kali Linux** | 20+ security tools | ✅ Full Support |
| **Parrot OS** | 20+ security tools | ✅ Full Support |
| **Ubuntu/Debian** | 20+ security tools | ✅ Full Support |
| **macOS** | 15+ tools via Homebrew | ✅ Full Support |
| **Arch/Manjaro** | Basic tools only | ⚠️ Limited Support |
| **Windows WSL** | Use Docker | 🐳 Docker Recommended |

## Script Overview

| Script | Purpose | Key Features |
|--------|---------|--------------|
| `system-check.sh` | Prerequisites & OS detection | Exports `OS_ID`, `OS_ID_LIKE`, `WSL_DETECTED` |
| `install-tools.sh` | Installation router | Routes to OS-specific installers |
| `install-tools-debian.sh` | Debian/Ubuntu/Kali tools | 20+ security tools, WSL support |
| `install-tools-macos.sh` | macOS Homebrew tools | 15+ tools, Python packages |
| `install-tools-arch.sh` | Arch Linux basic tools | Core tools only |
| `setup-python.sh` | Virtual environment setup | Creates global `/usr/local/bin/autorecon` |
| `setup-docker.sh` | Docker management | Image building, container launching |
| `cleanup.sh` | Complete removal | Removes all components with confirmation |
| `update.sh` | Maintenance | Git pull, package updates, Docker rebuild |

## System Architecture

```
Makefile (Entry Point)
├── system-check.sh          (Prerequisites & OS detection)
├── detect-os.sh             (OS detection helper)
├── install-tools.sh         (Installation router)
│   ├── install-tools-debian.sh  (Debian/Ubuntu/Kali/Parrot)
│   ├── install-tools-macos.sh   (macOS with Homebrew)
│   └── install-tools-arch.sh    (Arch Linux/Manjaro)
├── setup-python.sh          (Python environment & global command)
├── setup-docker.sh          (Docker management)
├── update.sh                (Maintenance & updates)
└── cleanup.sh               (Complete removal)
```

## Workflow Dependencies

```
make setup:
    system-check.sh → detect-os.sh → install-tools.sh → setup-python.sh
                                           ↓
                      OS-specific installer (debian/macos/arch)

make update:
    update.sh → git pull → python update → tools update → docker rebuild

make clean:
    cleanup.sh → remove venv → remove tools → remove docker → cleanup
```

## Command Reference

### Primary Commands

#### `make setup`
- Detects operating system automatically
- Installs appropriate security tools
- Creates Python virtual environment
- Installs global `autorecon` command
- Ready-to-use installation

#### `make setup-docker`
- Builds AutoRecon Docker image
- Launches interactive terminal
- Mounts results directory
- Full security toolkit in container

#### `make clean`
- Removes Python virtual environment
- Removes installed security tools (with confirmation)
- Removes Docker images and containers
- Cleans up temporary files

#### `make update`
- Updates git repository
- Updates Python packages
- Updates system security tools
- Rebuilds Docker image if needed

## Script Features

### Design Principles
- **Modular**: Single responsibility per script
- **Reusable**: Can be called independently or from Makefile
- **Error Handling**: Graceful failures with informative messages
- **Self-Documenting**: Clear output with emojis and status messages

## Usage Examples

### First Time Setup
```bash
git clone https://github.com/Tib3rius/AutoRecon.git
cd AutoRecon
make setup
autorecon --help
```

### Docker-Based Setup
```bash
make setup-docker
# Interactive container with full toolkit
```

### Direct Script Usage
```bash
# Check system requirements
./scripts/system-check.sh

# Install tools after system check
source ./scripts/system-check.sh
./scripts/install-tools.sh

# Setup Python environment
./scripts/setup-python.sh

# Full cleanup
./scripts/cleanup.sh
```

## Development Guidelines

### Adding New Features
1. Maintain single responsibility principle
2. Use consistent output formatting (emojis + clear messages)
3. Add proper error handling and exit codes
4. Update documentation
5. Test across multiple operating systems

### Testing Checklist
- [ ] `make setup` works on target OS
- [ ] `make setup-docker` builds and runs
- [ ] `make update` functions properly
- [ ] `make clean` removes everything
- [ ] Global `autorecon` command works
- [ ] Error handling for unsupported systems
- [ ] WSL compatibility verified

## Benefits

### For Users
- **Simplified Installation**: Single command setup
- **Cross-Platform**: Automated OS detection and tool installation
- **Maintenance**: Easy updates and cleanup
- **Docker Option**: Consistent environment across all systems

### For Developers
- **Consistent Environment**: Standardized setup across contributors
- **Modular Design**: Easy to modify and extend
- **Error Handling**: Graceful failures with helpful messages
- **Documentation**: Self-documenting with comprehensive help

---

**Contributor**: neur0map  
**Original Project**: AutoRecon by Tib3rius  
**Enhancement**: Modular setup system for improved accessibility and maintainability 