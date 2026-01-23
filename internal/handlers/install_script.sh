#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="$HOME/.opencode-relay"
CONFIG_DIR="$HOME/.opencode-tunnel"

detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case "$ARCH" in
        x86_64)
            ARCH="amd64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="arm"
            ;;
        *)
            echo -e "${RED}Unsupported architecture: $ARCH${NC}"
            exit 1
            ;;
    esac
    
    case "$OS" in
        darwin)
            OS="darwin"
            ;;
        linux)
            OS="linux"
            ;;
        *)
            echo -e "${RED}Unsupported OS: $OS${NC}"
            exit 1
            ;;
    esac
    
    echo -e "${BLUE}Detected platform: ${OS}_${ARCH}${NC}"
}

install_tunnel_client() {
    echo -e "${BLUE}Installing tunnel-client...${NC}"
    
    mkdir -p "$INSTALL_DIR"
    
    FILENAME="tunnel-client-${OS}-${ARCH}"
    URLS=(
        "https://github.com/zero469/opencode-relay-server/releases/latest/download/$FILENAME"
        "https://ghfast.top/https://github.com/zero469/opencode-relay-server/releases/latest/download/$FILENAME"
        "https://mirror.ghproxy.com/https://github.com/zero469/opencode-relay-server/releases/latest/download/$FILENAME"
        "https://gh-proxy.com/https://github.com/zero469/opencode-relay-server/releases/latest/download/$FILENAME"
    )
    
    DOWNLOADED=false
    for url in "${URLS[@]}"; do
        echo "Trying: $url"
        if command -v curl &> /dev/null; then
            if curl -fSL --connect-timeout 15 --max-time 120 "$url" -o "$INSTALL_DIR/tunnel-client" 2>/dev/null; then
                DOWNLOADED=true
                echo -e "${GREEN}Download successful!${NC}"
                break
            fi
        elif command -v wget &> /dev/null; then
            if wget -q --timeout=120 "$url" -O "$INSTALL_DIR/tunnel-client" 2>/dev/null; then
                DOWNLOADED=true
                echo -e "${GREEN}Download successful!${NC}"
                break
            fi
        fi
        echo -e "${YELLOW}Failed, trying next mirror...${NC}"
    done
    
    if [ "$DOWNLOADED" = false ]; then
        echo -e "${RED}All download sources failed. Please download manually from:${NC}"
        echo "https://github.com/zero469/opencode-relay-server/releases/latest"
        echo ""
        echo -e "${YELLOW}Press Enter to exit...${NC}"
        read -r < /dev/tty
        exit 1
    fi
    
    chmod +x "$INSTALL_DIR/tunnel-client"
    
    if [ -w /usr/local/bin ]; then
        ln -sf "$INSTALL_DIR/tunnel-client" /usr/local/bin/tunnel-client 2>/dev/null || true
    fi
    
    echo -e "${GREEN}tunnel-client installed to $INSTALL_DIR/tunnel-client${NC}"
}

stop_running_tunnel() {
    echo -e "${BLUE}Stopping existing tunnel-client...${NC}"
    
    if [ "$OS" = "darwin" ]; then
        launchctl unload "$HOME/Library/LaunchAgents/com.opencode.relay.plist" 2>/dev/null || true
        pkill -f "tunnel-client" 2>/dev/null || true
    else
        systemctl --user stop opencode-relay 2>/dev/null || true
        pkill -f "tunnel-client" 2>/dev/null || true
    fi
    
    sleep 1
}

cleanup_old_install() {
    if [ "$OS" = "darwin" ]; then
        launchctl unload "$HOME/Library/LaunchAgents/com.opencode.relay.heartbeat.plist" 2>/dev/null || true
        rm -f "$HOME/Library/LaunchAgents/com.opencode.relay.heartbeat.plist"
    else
        systemctl --user stop opencode-relay-heartbeat.timer 2>/dev/null || true
        systemctl --user disable opencode-relay-heartbeat.timer 2>/dev/null || true
        rm -f "$HOME/.config/systemd/user/opencode-relay-heartbeat.timer"
        rm -f "$HOME/.config/systemd/user/opencode-relay-heartbeat.service"
    fi
    
    rm -f "$INSTALL_DIR/frpc" "$INSTALL_DIR/frpc.toml" "$INSTALL_DIR/heartbeat.sh"
    rm -f "$INSTALL_DIR/token" "$INSTALL_DIR/device_id" "$INSTALL_DIR/subdomain"
    rm -f "$INSTALL_DIR/auth_user" "$INSTALL_DIR/auth_password" "$INSTALL_DIR/local_port"
}

main() {
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}   OpenCode Relay Client Setup                  ${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    
    detect_platform
    
    if [ -f "$INSTALL_DIR/tunnel-client" ]; then
        echo -e "${YELLOW}tunnel-client already installed. Updating...${NC}"
        stop_running_tunnel
    fi
    
    install_tunnel_client
    cleanup_old_install
    
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}   Installation Complete!                       ${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    echo -e "${BLUE}Next step:${NC}"
    echo ""
    echo "Run tunnel-client:"
    echo -e "   ${YELLOW}$INSTALL_DIR/tunnel-client${NC}"
    echo ""
    echo "It will guide you through login and pairing automatically."
    echo ""
    echo -e "${BLUE}The tunnel will auto-start on boot after pairing.${NC}"
    echo ""
    
    if [ -f /usr/local/bin/tunnel-client ]; then
        echo -e "You can also use: ${YELLOW}tunnel-client${NC} (added to PATH)"
        echo ""
    fi
}

main
