# Required Changes for AutoRecon Integration

## CRITICAL: These scripts will NOT work with AutoRecon without the following changes

### 1. setup-python.sh Changes

**Line 35**: Change command name reference
```bash
# Current:
echo "🔧 Creating ipcrawler command..."

# Change to:
echo "🔧 Creating autorecon command..."
```

**Line 38**: Change command file name
```bash
# Current:
rm -f ipcrawler-cmd

# Change to:
rm -f autorecon-cmd
```

**Line 41**: Change command script name
```bash
# Current:
cat > ipcrawler-cmd << 'EOF'

# Change to:
cat > autorecon-cmd << 'EOF'
```

**Line 46**: Change Python script reference
```bash
# Current:
source "$DIR/venv/bin/activate" && python3 "$DIR/ipcrawler.py" "$@"

# Change to:
source "$DIR/venv/bin/activate" && python3 "$DIR/autorecon.py" "$@"
```

**Line 50**: Change command file name
```bash
# Current:
chmod +x ipcrawler-cmd

# Change to:
chmod +x autorecon-cmd
```

**Line 54**: Change global command installation
```bash
# Current:
if ! sudo ln -sf "$(pwd)/ipcrawler-cmd" /usr/local/bin/ipcrawler 2>/dev/null; then

# Change to:
if ! sudo ln -sf "$(pwd)/autorecon-cmd" /usr/local/bin/autorecon 2>/dev/null; then
```

**Line 56**: Change usage message
```bash
# Current:
echo "💡 You can still use: ./ipcrawler-cmd or add to PATH manually"

# Change to:
echo "💡 You can still use: ./autorecon-cmd or add to PATH manually"
```

**Lines 68-69**: Change help examples
```bash
# Current:
echo "  • Run: ipcrawler --help"
echo "  • Test with: ipcrawler 127.0.0.1"

# Change to:
echo "  • Run: autorecon --help"
echo "  • Test with: autorecon 127.0.0.1"
```

### 2. setup-docker.sh Changes

**Line 33**: Change Docker image name check
```bash
# Current:
if docker images -q ipcrawler >/dev/null 2>&1 && [ -n "$(docker images -q ipcrawler)" ]; then

# Change to:
if docker images -q autorecon >/dev/null 2>&1 && [ -n "$(docker images -q autorecon)" ]; then
```

**Line 34**: Change success message
```bash
# Current:
echo "✅ ipcrawler Docker image found"

# Change to:
echo "✅ autorecon Docker image found"
```

**Line 37**: Change not found message
```bash
# Current:
echo "ℹ️  ipcrawler Docker image not found"

# Change to:
echo "ℹ️  autorecon Docker image not found"
```

**Line 42**: Change function name
```bash
# Current:
build_ipcrawler_image() {

# Change to:
build_autorecon_image() {
```

**Line 43**: Change build message
```bash
# Current:
echo "🐳 Building ipcrawler Docker image..."

# Change to:
echo "🐳 Building autorecon Docker image..."
```

**Line 47**: Change directory reference
```bash
# Current:
echo "Please run this command from the ipcrawler directory"

# Change to:
echo "Please run this command from the autorecon directory"
```

**Line 51**: Change Docker build command
```bash
# Current:
if docker build -t ipcrawler . ; then

# Change to:
if docker build -t autorecon . ; then
```

**Line 52**: Change success message
```bash
# Current:
echo "✅ ipcrawler Docker image built successfully!"

# Change to:
echo "✅ autorecon Docker image built successfully!"
```

**Line 61**: Change terminal startup message
```bash
# Current:
echo "🚀 Starting ipcrawler Docker terminal..."

# Change to:
echo "🚀 Starting autorecon Docker terminal..."
```

**Lines 64-66**: Change command examples
```bash
# Current:
echo "  • ipcrawler --help          (Show help)"
echo "  • ipcrawler 127.0.0.1       (Test scan)"
echo "  • ipcrawler target.com      (Scan target)"

# Change to:
echo "  • autorecon --help          (Show help)"
echo "  • autorecon 127.0.0.1       (Test scan)"
echo "  • autorecon target.com      (Scan target)"
```

**Line 79**: Change working directory (verify AutoRecon Dockerfile)
```bash
# Current:
-w /opt/ipcrawler \

# Change to:
-w /opt/autorecon \
# OR check AutoRecon's Dockerfile for correct path
```

**Line 80**: Change container name
```bash
# Current:
--name ipcrawler-session \

# Change to:
--name autorecon-session \
```

**Line 81**: Change image name
```bash
# Current:
ipcrawler bash

# Change to:
autorecon bash
```

**Line 84**: Change session end message
```bash
# Current:
echo "👋 ipcrawler session ended"

# Change to:
echo "👋 autorecon session ended"
```

**Line 90**: Change setup title
```bash
# Current:
echo "🐳 ipcrawler Docker Setup"

# Change to:
echo "🐳 autorecon Docker Setup"
```

**Line 102**: Change function call
```bash
# Current:
build_ipcrawler_image

# Change to:
build_autorecon_image
```

### 3. cleanup.sh Changes

**Line 16**: Change command file name
```bash
# Current:
rm -f ipcrawler-cmd

# Change to:
rm -f autorecon-cmd
```

**Line 19**: Change removal message
```bash
# Current:
echo "🗑️  Removing ipcrawler from /usr/local/bin..."

# Change to:
echo "🗑️  Removing autorecon from /usr/local/bin..."
```

**Line 20**: Change global command removal
```bash
# Current:
sudo rm -f /usr/local/bin/ipcrawler

# Change to:
sudo rm -f /usr/local/bin/autorecon
```

**Lines 112-121**: Change all Docker references
```bash
# Current:
if [ -n "$(docker images -q ipcrawler 2>/dev/null)" ]; then
    echo "Stopping any running ipcrawler containers..."
    docker ps -aq --filter ancestor=ipcrawler 2>/dev/null | xargs -r docker stop >/dev/null 2>&1 || true
    docker ps -aq --filter ancestor=ipcrawler 2>/dev/null | xargs -r docker rm >/dev/null 2>&1 || true
    
    echo "Removing ipcrawler Docker image..."
    docker rmi ipcrawler >/dev/null 2>&1 || true
    echo "Docker image removed."
else
    echo "No ipcrawler Docker image found."
fi

# Change to:
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
```

**Line 160**: Change cleanup title
```bash
# Current:
echo "Cleaning up ipcrawler installation..."

# Change to:
echo "Cleaning up autorecon installation..."
```

### 4. update.sh Changes

**Line 125**: Change Docker image check
```bash
# Current:
if [ "$DOCKERFILE_CHANGED" = "true" ] || [ ! -n "$(docker images -q ipcrawler 2>/dev/null)" ]; then

# Change to:
if [ "$DOCKERFILE_CHANGED" = "true" ] || [ ! -n "$(docker images -q autorecon 2>/dev/null)" ]; then
```

**Line 127**: Change Docker build command
```bash
# Current:
if docker build -t ipcrawler .; then

# Change to:
if docker build -t autorecon .; then
```

**Line 167**: Change ready message
```bash
# Current:
echo "🎯 Ready to use updated ipcrawler!"

# Change to:
echo "🎯 Ready to use updated autorecon!"
```

**Line 172**: Change update title
```bash
# Current:
echo "Updating ipcrawler installation..."

# Change to:
echo "Updating autorecon installation..."
```

### 5. Makefile Changes

**Line 3**: Change setup message
```bash
# Current:
@echo "Setting up ipcrawler..." && \

# Change to:
@echo "Setting up autorecon..." && \
```

**Line 19**: Change Docker message
```bash
# Current:
@echo "Starting ipcrawler Docker container..."

# Change to:
@echo "Starting autorecon Docker container..."
```

**Line 23**: Change Docker run command
```bash
# Current:
docker run -it --rm -v "$$(pwd)/results:/scans" ipcrawler || true

# Change to:
docker run -it --rm -v "$$(pwd)/results:/scans" autorecon || true
```

**Line 30**: Change help text
```bash
# Current:
@echo "  setup-docker  - Build Docker image + open interactive terminal for ipcrawler"

# Change to:
@echo "  setup-docker  - Build Docker image + open interactive terminal for autorecon"
```

**Line 51**: Change usage example
```bash
# Current:
@echo "  2. ipcrawler --help     # Use the tool"

# Change to:
@echo "  2. autorecon --help     # Use the tool"
```

### 6. README.md Changes

**Line 2**: Change description
```bash
# Current:
This directory contains modular scripts that handle different aspects of ipcrawler setup and maintenance.

# Change to:
This directory contains modular scripts that handle different aspects of autorecon setup and maintenance.
```

## Additional Requirements

### Check AutoRecon Repository Structure
Before implementing changes, verify:
1. **Main script name**: Confirm AutoRecon uses `autorecon.py`
2. **Dockerfile working directory**: Check what path AutoRecon's Dockerfile uses
3. **Requirements file**: Ensure `requirements.txt` exists
4. **Dependencies**: Verify AutoRecon's dependency requirements

### Testing After Changes
1. Test `make setup` on clean system
2. Test `make setup-docker` builds correctly  
3. Test global `autorecon` command works
4. Test `make clean` removes everything
5. Test `make update` functions properly

## Summary
**73 lines across 6 files** need changes to work with AutoRecon. These are not optional - the scripts will fail without these modifications. 