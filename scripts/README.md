# Scripts Directory

This directory contains modular scripts that handle different aspects of autorecon setup and maintenance. These scripts are called by the Makefile to keep it clean and organized.

## Script Overview

| Script | Purpose | Usage |
|--------|---------|-------|
| `system-check.sh` | System prerequisites and OS detection | `./scripts/system-check.sh` |
| `install-tools.sh` | Security tools installation router | `./scripts/install-tools.sh [OS_ID] [OS_ID_LIKE] [WSL_DETECTED]` |
| `install-tools-debian.sh` | Debian/Ubuntu specific tool installation | `./scripts/install-tools-debian.sh [WSL_DETECTED]` |
| `install-tools-macos.sh` | macOS specific tool installation | `./scripts/install-tools-macos.sh` |
| `install-tools-arch.sh` | Arch Linux specific tool installation | `./scripts/install-tools-arch.sh` |
| `setup-python.sh` | Python virtual environment setup | `./scripts/setup-python.sh` |
| `setup-docker.sh` | Docker image building and terminal launch | `./scripts/setup-docker.sh` |
| `cleanup.sh` | Complete installation cleanup | `./scripts/cleanup.sh` |
| `update.sh` | Git, tools, and Docker updates | `./scripts/update.sh` |

## Dependencies Between Scripts

```
system-check.sh
     ↓ (exports OS variables)
install-tools.sh → install-tools-debian.sh
                 → install-tools-macos.sh  
                 → install-tools-arch.sh
     ↓
setup-python.sh
     ↓
[Complete setup]
```

For updates:
```
update.sh → calls → system-check.sh (for OS detection)
```

## Script Features

### Common Features
- **Modular**: Each script has a single responsibility
- **Reusable**: Can be called independently or from Makefile
- **Source-able**: Functions can be sourced by other scripts
- **Self-documenting**: Clear output with emojis and status messages

### Error Handling
- Graceful failure with informative error messages
- Exit codes properly set for Makefile integration
- Fallback options when primary methods fail

### OS Support
- **Linux**: Debian/Ubuntu, Arch/Manjaro, Kali/Parrot
- **macOS**: Homebrew-based installation
- **Windows**: WSL detection and compatibility
- **Fallback**: Basic setup for unsupported systems

## Usage Examples

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

### Environment Variable Passing
```bash
# Export variables from system-check
source ./scripts/system-check.sh
export OS_ID OS_ID_LIKE WSL_DETECTED

# Use in install-tools
./scripts/install-tools.sh "$OS_ID" "$OS_ID_LIKE" "$WSL_DETECTED"
```

## Maintenance

### Adding New Features
1. Keep scripts focused on single responsibilities
2. Use consistent output formatting (emojis + clear messages)
3. Add proper error handling and exit codes
4. Update this README when adding new scripts

### Testing
Each script should work independently and be testable on various operating systems:
- Test on multiple Linux distributions
- Test on macOS with and without Homebrew
- Test in WSL environments
- Test error conditions and fallbacks

## Integration with Makefile

The Makefile calls these scripts to provide a clean interface:
- `make setup` → calls system-check, install-tools (→ OS-specific), setup-python
- `make clean` → calls cleanup.sh
- `make setup-docker` → calls setup-docker.sh (build + launch terminal)
- `make update` → calls update.sh

This modular approach makes the Makefile much cleaner and easier to maintain while providing the same functionality. 