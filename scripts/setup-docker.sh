#!/bin/bash

# Docker Build and Run Script  
# Usage: ./scripts/setup-docker.sh

check_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "❌ Docker is not installed"
        echo ""
        echo "Please install Docker first:"
        echo "  • Windows: https://docs.docker.com/desktop/install/windows/"
        echo "  • macOS: https://docs.docker.com/desktop/install/mac-install/"
        echo "  • Ubuntu: https://docs.docker.com/engine/install/ubuntu/"
        echo "  • Other Linux: https://docs.docker.com/engine/install/"
        echo ""
        exit 1
    fi
    
    if ! docker ps >/dev/null 2>&1; then
        echo "❌ Docker is installed but not running"
        echo ""
        echo "Please start Docker and try again:"
        echo "  • Windows/macOS: Start Docker Desktop"
        echo "  • Linux: sudo systemctl start docker"
        echo ""
        exit 1
    fi
    
    echo "✅ Docker is ready!"
    docker --version
}

check_image_exists() {
    if docker images -q autorecon >/dev/null 2>&1 && [ -n "$(docker images -q autorecon)" ]; then
        echo "✅ autorecon Docker image found"
        return 0
    else
        echo "ℹ️  autorecon Docker image not found"
        return 1
    fi
}

build_autorecon_image() {
    echo "🐳 Building autorecon Docker image..."
    
    if [ ! -f "Dockerfile" ]; then
        echo "❌ Dockerfile not found in current directory"
        echo "Please run this command from the autorecon directory"
        return 1
    fi
    
    if docker build -t autorecon . ; then
        echo "✅ autorecon Docker image built successfully!"
        return 0
    else
        echo "❌ Failed to build Docker image"
        return 1
    fi
}

start_docker_terminal() {
    echo "🚀 Starting autorecon Docker terminal..."
    echo ""
    echo "📋 Available commands once inside:"
    echo "  • autorecon --help          (Show help)"
    echo "  • autorecon 127.0.0.1       (Test scan)"
    echo "  • autorecon target.com      (Scan target)" 
    echo "  • ls /scans                 (View results)"
    echo "  • exit                      (Leave container)"
    echo ""
    echo "💾 Results will be saved to: $(pwd)/results/"
    echo ""
    
    # Create results directory if it doesn't exist
    mkdir -p results
    
    # Run the container interactively
    docker run -it --rm \
        -v "$(pwd)/results:/scans" \
        -w /opt/autorecon \
        --name autorecon-session \
        autorecon bash
        
    echo ""
    echo "👋 autorecon session ended"
    echo "📁 Check your results in: $(pwd)/results/"
}

# Main execution
main() {
    echo "🐳 autorecon Docker Setup"
    echo ""
    
    # Check Docker availability
    check_docker
    echo ""
    
    # Check if image exists, build if needed
    if check_image_exists; then
        echo "🚀 Image ready! Starting Docker terminal..."
    else
        echo ""
        build_autorecon_image
        if [ $? -ne 0 ]; then
            exit 1
        fi
    fi
    
    echo ""
    start_docker_terminal
}

# Run if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi 