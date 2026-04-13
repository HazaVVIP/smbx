#!/bin/bash
#
# SMBX Installation Script
# For Termux/Ubuntu proot or native Linux
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  SMBX Installation Script${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Detect environment
detect_env() {
    if [ -d "/data/data/com.termux" ]; then
        echo "termux"
    elif [ -f "/etc/os-release" ]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

ENV=$(detect_env)
echo -e "${YELLOW}[*] Detected environment: ${ENV}${NC}"

# Install dependencies
install_deps() {
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    
    case "$ENV" in
        termux)
            pkg update -y
            pkg install -y git curl build-essential pkg-config openssl-dev
            ;;
        ubuntu|debian)
            sudo apt update
            sudo apt install -y git curl build-essential pkg-config libssl-dev
            ;;
        fedora|centos|rhel)
            sudo dnf install -y git curl gcc pkg-config openssl-devel
            ;;
        arch|manjaro)
            sudo pacman -Syu --noconfirm git curl base-devel pkg-config openssl
            ;;
        *)
            echo -e "${RED}[-] Unknown environment. Please install manually:${NC}"
            echo "    - git, curl, build-essential/gcc, pkg-config, libssl-dev/openssl-devel"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}[+] Dependencies installed${NC}"
}

# Install Rust
install_rust() {
    if command -v rustc &> /dev/null; then
        RUST_VERSION=$(rustc --version)
        echo -e "${GREEN}[+] Rust already installed: ${RUST_VERSION}${NC}"
    else
        echo -e "${YELLOW}[*] Installing Rust...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
        echo -e "${GREEN}[+] Rust installed${NC}"
    fi
}

# Build SMBX
build_smbx() {
    echo -e "${YELLOW}[*] Building SMBX...${NC}"
    
    # Ensure cargo is in PATH
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
    
    # Build release
    cargo build --release
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Build successful!${NC}"
        echo -e "${GREEN}[+] Binary location: target/release/smbx${NC}"
    else
        echo -e "${RED}[-] Build failed${NC}"
        return 1
    fi
}

# Install to PATH
install_binary() {
    echo -e "${YELLOW}[*] Installing smbx to PATH...${NC}"
    
    if [ "$ENV" = "termux" ]; then
        INSTALL_DIR="$PREFIX/bin"
    else
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
    fi
    
    cp target/release/smbx "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/smbx"
    
    # Check if in PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$HOME/.bashrc"
        echo -e "${YELLOW}[!] Added $INSTALL_DIR to PATH in .bashrc${NC}"
        echo -e "${YELLOW}[!] Run: source ~/.bashrc${NC}"
    fi
    
    echo -e "${GREEN}[+] SMBX installed to $INSTALL_DIR/smbx${NC}"
}

# Verify installation
verify() {
    echo ""
    echo -e "${YELLOW}[*] Verifying installation...${NC}"
    
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
    
    if command -v smbx &> /dev/null; then
        echo -e "${GREEN}[+] SMBX is available in PATH${NC}"
        smbx --help | head -5
    elif [ -f "target/release/smbx" ]; then
        echo -e "${GREEN}[+] SMBX binary built successfully${NC}"
        ./target/release/smbx --help | head -5
    else
        echo -e "${RED}[-] SMBX not found${NC}"
        return 1
    fi
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Installation Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Usage examples:"
    echo "  smbx scan 192.168.1.0/24"
    echo "  smbx fingerprint 192.168.1.100"
    echo "  smbx full 192.168.1.100 --mode aggressive"
    echo "  smbx list --checks --exploits"
    echo ""
}

# Main
main() {
    echo ""
    
    # Check if we're in the project directory
    if [ ! -f "Cargo.toml" ]; then
        echo -e "${RED}[-] Error: Run this script from the SMBX project root directory${NC}"
        exit 1
    fi
    
    install_deps
    install_rust
    build_smbx
    install_binary
    verify
}

# Run
main "$@"
