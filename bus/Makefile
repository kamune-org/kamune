# Kamune Tauri App Makefile
# Simplifies building the daemon and Tauri application

.PHONY: all daemon daemon-all dev build clean help

# Default target
all: daemon build

# Go daemon source
DAEMON_SRC := ../cmd/daemon
BINARIES_DIR := src-tauri/binaries

# Current platform detection
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    ifeq ($(UNAME_M),arm64)
        CURRENT_DAEMON := daemon-darwin-arm64
    else
        CURRENT_DAEMON := daemon-darwin-amd64
    endif
else ifeq ($(UNAME_S),Linux)
    ifeq ($(UNAME_M),aarch64)
        CURRENT_DAEMON := daemon-linux-arm64
    else
        CURRENT_DAEMON := daemon-linux-amd64
    endif
else
    CURRENT_DAEMON := daemon-windows-amd64.exe
endif

# Build daemon for current platform
daemon: $(BINARIES_DIR)
	@echo "Building daemon for current platform ($(CURRENT_DAEMON))..."
	cd .. && go build -ldflags="-s -w" -o tauri-app/$(BINARIES_DIR)/$(CURRENT_DAEMON) ./cmd/daemon
	@echo "Daemon built: $(BINARIES_DIR)/$(CURRENT_DAEMON)"

# Build daemon for all platforms
daemon-all: $(BINARIES_DIR)
	@echo "Building daemon for all platforms..."
	@echo "  darwin/arm64..."
	cd .. && GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o tauri-app/$(BINARIES_DIR)/daemon-darwin-arm64 ./cmd/daemon
	@echo "  darwin/amd64..."
	cd .. && GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o tauri-app/$(BINARIES_DIR)/daemon-darwin-amd64 ./cmd/daemon
	@echo "  linux/amd64..."
	cd .. && GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o tauri-app/$(BINARIES_DIR)/daemon-linux-amd64 ./cmd/daemon
	@echo "  linux/arm64..."
	cd .. && GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o tauri-app/$(BINARIES_DIR)/daemon-linux-arm64 ./cmd/daemon
	@echo "  windows/amd64..."
	cd .. && GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o tauri-app/$(BINARIES_DIR)/daemon-windows-amd64.exe ./cmd/daemon
	@echo "All daemons built successfully!"
	@ls -la $(BINARIES_DIR)/

# Create binaries directory
$(BINARIES_DIR):
	mkdir -p $(BINARIES_DIR)

# Run in development mode
dev: daemon
	cargo tauri dev

# Build for production
build: daemon
	cargo tauri build

# Build for production (all platforms daemons)
build-all: daemon-all
	cargo tauri build

# Clean build artifacts
clean:
	rm -rf $(BINARIES_DIR)/daemon-*
	cd src-tauri && cargo clean
	@echo "Cleaned build artifacts"

# Run tests
test: daemon
	@echo "Testing daemon standalone..."
	@echo '{"type":"cmd","cmd":"shutdown","id":"test","params":{}}' | timeout 2 $(BINARIES_DIR)/$(CURRENT_DAEMON) || true
	@echo "Daemon test completed"

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@which go > /dev/null || (echo "ERROR: Go not found" && exit 1)
	@which cargo > /dev/null || (echo "ERROR: Rust/Cargo not found" && exit 1)
	@which cargo-tauri > /dev/null || (echo "WARNING: tauri-cli not found, install with: cargo install tauri-cli" && exit 1)
	@echo "All dependencies found!"

# Help
help:
	@echo "Kamune Tauri App Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all         - Build daemon and Tauri app (default)"
	@echo "  daemon      - Build daemon for current platform"
	@echo "  daemon-all  - Build daemon for all platforms"
	@echo "  dev         - Run in development mode"
	@echo "  build       - Build production release"
	@echo "  build-all   - Build with all platform daemons"
	@echo "  clean       - Remove build artifacts"
	@echo "  test        - Quick daemon smoke test"
	@echo "  check-deps  - Verify required tools are installed"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Current platform: $(UNAME_S)/$(UNAME_M)"
	@echo "Daemon binary: $(CURRENT_DAEMON)"
