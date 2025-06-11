.PHONY: setup clean setup-docker docker-cmd help update

setup:
	@echo "Setting up autorecon..." && \
	echo "" && \
	./scripts/system-check.sh && \
	echo "" && \
	. scripts/detect-os.sh && \
	./scripts/install-tools.sh "$$OS_ID" "$$OS_ID_LIKE" "$$WSL_DETECTED" && \
	echo "" && \
	./scripts/setup-python.sh

clean:
	@./scripts/cleanup.sh

setup-docker:
	@./scripts/setup-docker.sh

docker-cmd:
	@echo "Starting autorecon Docker container..."
	@echo "Results will be saved to: $$(pwd)/results"
	@echo "Type 'exit' to leave the container"
	@echo ""
	docker run -it --rm -v "$$(pwd)/results:/scans" autorecon || true

help:
	@echo "Available make commands:"
	@echo ""
	@echo "  setup         - Set up local Python virtual environment + install security tools"
	@echo "  clean         - Remove local setup, virtual environment, and Docker resources"
	@echo "  setup-docker  - Build Docker image + open interactive terminal for autorecon"
	@echo "  update        - Update repository, tools, and Docker image"
	@echo "  docker-cmd    - Run interactive Docker container"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Supported Operating Systems:"
	@echo "  • Kali Linux       - Full tool installation (20+ security tools)"
	@echo "  • Parrot OS        - Full tool installation (20+ security tools)"
	@echo "  • Ubuntu/Debian    - Full tool installation (20+ security tools)"
	@echo "  • macOS (Homebrew) - Comprehensive toolkit (15+ security tools)"
	@echo "  • Arch/Manjaro     - Basic tools (nmap, curl, wget, git)"
	@echo "  • Other systems    - Python setup only (use Docker for full features)"
	@echo ""
	@echo "Docker Usage (Recommended for non-Kali systems):"
	@echo "  1. Install Docker manually for your OS first"
	@echo "  2. make setup-docker    # Build image + open interactive terminal"
	@echo "  3. make docker-cmd      # Start additional interactive sessions"
	@echo "  4. Inside container: /show-tools.sh or /install-extra-tools.sh"
	@echo ""
	@echo "Local Usage:"
	@echo "  1. make setup           # Set up locally with auto tool installation"
	@echo "  2. autorecon --help     # Use the tool"
	@echo "  3. make update          # Keep everything updated"

update:
	@./scripts/update.sh
