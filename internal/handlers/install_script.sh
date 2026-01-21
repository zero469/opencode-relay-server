#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

RELAY_API_URL="${RELAY_API_URL:-https://opencode-relay-server.fly.dev}"
INSTALL_DIR="$HOME/.opencode-relay"
LOG_FILE="$INSTALL_DIR/tunnel.log"

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
        "https://mirror.ghproxy.com/https://github.com/zero469/opencode-relay-server/releases/latest/download/$FILENAME"
        "https://ghfast.top/https://github.com/zero469/opencode-relay-server/releases/latest/download/$FILENAME"
    )
    
    DOWNLOADED=false
    for url in "${URLS[@]}"; do
        echo "Trying: $url"
        if command -v curl &> /dev/null; then
            if curl -sSL --connect-timeout 10 "$url" -o "$INSTALL_DIR/tunnel-client" 2>/dev/null; then
                DOWNLOADED=true
                echo -e "${GREEN}Download successful!${NC}"
                break
            fi
        elif command -v wget &> /dev/null; then
            if wget -q --timeout=10 "$url" -O "$INSTALL_DIR/tunnel-client" 2>/dev/null; then
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
        exit 1
    fi
    
    chmod +x "$INSTALL_DIR/tunnel-client"
    
    echo -e "${GREEN}tunnel-client installed to $INSTALL_DIR/tunnel-client${NC}"
}

authenticate() {
    echo ""
    echo -e "${BLUE}=== OpenCode Relay Authentication ===${NC}"
    echo ""
    
    if [ -f "$INSTALL_DIR/token" ]; then
        echo "Found existing authentication. Do you want to use it? (y/n)"
        read -r use_existing
        if [ "$use_existing" = "y" ]; then
            TOKEN=$(cat "$INSTALL_DIR/token")
            return
        fi
    fi
    
    echo ""
    echo -e "${YELLOW}Logging in...${NC}"
    echo -e "(Don't have an account? Register via the OpenCode Anywhere iOS app first)"
    echo ""
    
    echo -n "Email: "
    read -r EMAIL
    echo -n "Password: "
    read -rs PASSWORD
    echo ""
    
    RESPONSE=$(curl -sSL -X POST "$RELAY_API_URL/api/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\"}" \
        2>&1)
    
    if echo "$RESPONSE" | grep -q "error"; then
        echo -e "${RED}Login failed: $RESPONSE${NC}"
        exit 1
    fi
    
    TOKEN=$(echo "$RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    
    if [ -z "$TOKEN" ]; then
        echo -e "${RED}Failed to extract token from response${NC}"
        exit 1
    fi
    
    echo "$TOKEN" > "$INSTALL_DIR/token"
    chmod 600 "$INSTALL_DIR/token"
    
    echo -e "${GREEN}Login successful!${NC}"
}

register_device() {
    echo ""
    echo -e "${BLUE}=== Device Registration ===${NC}"
    
    if [ -f "$INSTALL_DIR/device_id" ]; then
        DEVICE_ID=$(cat "$INSTALL_DIR/device_id")
        echo "Found existing device registration (ID: $DEVICE_ID)"
        echo "Do you want to use it? (y/n)"
        read -r use_existing
        if [ "$use_existing" = "y" ]; then
            return
        fi
    fi
    
    DEFAULT_NAME=$(hostname)
    echo -n "Device name [$DEFAULT_NAME]: "
    read -r DEVICE_NAME
    DEVICE_NAME="${DEVICE_NAME:-$DEFAULT_NAME}"
    
    RESPONSE=$(curl -sSL -X POST "$RELAY_API_URL/api/devices" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{\"name\": \"$DEVICE_NAME\"}" \
        2>&1)
    
    if echo "$RESPONSE" | grep -q "error"; then
        echo -e "${RED}Device registration failed: $RESPONSE${NC}"
        exit 1
    fi
    
    DEVICE_ID=$(echo "$RESPONSE" | grep -o '"id":[0-9]*' | cut -d':' -f2)
    SUBDOMAIN=$(echo "$RESPONSE" | grep -o '"subdomain":"[^"]*"' | cut -d'"' -f4)
    AUTH_USER=$(echo "$RESPONSE" | grep -o '"auth_user":"[^"]*"' | cut -d'"' -f4)
    AUTH_PASSWORD=$(echo "$RESPONSE" | grep -o '"auth_password":"[^"]*"' | cut -d'"' -f4)
    
    if [ -z "$DEVICE_ID" ] || [ -z "$SUBDOMAIN" ]; then
        echo -e "${RED}Failed to parse device response${NC}"
        exit 1
    fi
    
    echo "$DEVICE_ID" > "$INSTALL_DIR/device_id"
    echo "$SUBDOMAIN" > "$INSTALL_DIR/subdomain"
    echo "$AUTH_USER" > "$INSTALL_DIR/auth_user"
    echo "$AUTH_PASSWORD" > "$INSTALL_DIR/auth_password"
    chmod 600 "$INSTALL_DIR/auth_user" "$INSTALL_DIR/auth_password"
    
    echo -e "${GREEN}Device registered successfully!${NC}"
    echo -e "  Device ID: $DEVICE_ID"
    echo -e "  Subdomain: ${YELLOW}${SUBDOMAIN}${NC}"
}

get_opencode_port() {
    echo ""
    echo -e "${BLUE}=== OpenCode Configuration ===${NC}"
    
    DEFAULT_PORT="4096"
    echo -n "OpenCode API port [$DEFAULT_PORT]: "
    read -r OPENCODE_PORT
    OPENCODE_PORT="${OPENCODE_PORT:-$DEFAULT_PORT}"
    
    echo "$OPENCODE_PORT" > "$INSTALL_DIR/local_port"
}

load_device_config() {
    if [ ! -f "$INSTALL_DIR/device_id" ]; then
        echo -e "${RED}Device not registered. Please run setup first.${NC}"
        exit 1
    fi
    
    DEVICE_ID=$(cat "$INSTALL_DIR/device_id")
    LOCAL_PORT=$(cat "$INSTALL_DIR/local_port" 2>/dev/null || echo "4096")
    
    if [ -f "$INSTALL_DIR/subdomain" ]; then
        SUBDOMAIN=$(cat "$INSTALL_DIR/subdomain")
        AUTH_USER=$(cat "$INSTALL_DIR/auth_user")
        AUTH_PASSWORD=$(cat "$INSTALL_DIR/auth_password")
    else
        TOKEN=$(cat "$INSTALL_DIR/token")
        RESPONSE=$(curl -sSL -X GET "$RELAY_API_URL/api/devices/$DEVICE_ID" \
            -H "Authorization: Bearer $TOKEN" \
            2>&1)
        
        SUBDOMAIN=$(echo "$RESPONSE" | grep -o '"subdomain":"[^"]*"' | cut -d'"' -f4)
        AUTH_USER=$(echo "$RESPONSE" | grep -o '"auth_user":"[^"]*"' | cut -d'"' -f4)
        AUTH_PASSWORD=$(echo "$RESPONSE" | grep -o '"auth_password":"[^"]*"' | cut -d'"' -f4)
        
        echo "$SUBDOMAIN" > "$INSTALL_DIR/subdomain"
        echo "$AUTH_USER" > "$INSTALL_DIR/auth_user"
        echo "$AUTH_PASSWORD" > "$INSTALL_DIR/auth_password"
        chmod 600 "$INSTALL_DIR/auth_user" "$INSTALL_DIR/auth_password"
    fi
}

setup_launchd() {
    echo ""
    echo -e "${BLUE}Setting up auto-start (launchd)...${NC}"
    
    load_device_config
    
    PLIST_FILE="$HOME/Library/LaunchAgents/com.opencode.relay.plist"
    
    mkdir -p "$HOME/Library/LaunchAgents"
    
    cat > "$PLIST_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.opencode.relay</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/tunnel-client</string>
        <string>-relay</string>
        <string>$RELAY_API_URL</string>
        <string>-subdomain</string>
        <string>$SUBDOMAIN</string>
        <string>-auth-user</string>
        <string>$AUTH_USER</string>
        <string>-auth-password</string>
        <string>$AUTH_PASSWORD</string>
        <string>-local-port</string>
        <string>$LOCAL_PORT</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_FILE</string>
    <key>StandardErrorPath</key>
    <string>$LOG_FILE</string>
</dict>
</plist>
EOF
    
    launchctl unload "$PLIST_FILE" 2>/dev/null || true
    launchctl load "$PLIST_FILE"
    
    echo -e "${GREEN}Auto-start configured!${NC}"
}

setup_systemd() {
    echo ""
    echo -e "${BLUE}Setting up auto-start (systemd user service)...${NC}"
    
    load_device_config
    
    SYSTEMD_DIR="$HOME/.config/systemd/user"
    SERVICE_FILE="$SYSTEMD_DIR/opencode-relay.service"
    
    mkdir -p "$SYSTEMD_DIR"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=OpenCode Relay Tunnel Client
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/tunnel-client -relay $RELAY_API_URL -subdomain $SUBDOMAIN -auth-user $AUTH_USER -auth-password $AUTH_PASSWORD -local-port $LOCAL_PORT
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF
    
    systemctl --user daemon-reload
    systemctl --user enable opencode-relay
    systemctl --user start opencode-relay
    
    echo -e "${GREEN}Auto-start configured!${NC}"
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
}

main() {
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}   OpenCode Relay Client Setup                  ${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    
    detect_platform
    
    if [ -f "$INSTALL_DIR/tunnel-client" ]; then
        echo -e "${YELLOW}tunnel-client already installed at $INSTALL_DIR/tunnel-client${NC}"
        echo "Do you want to reinstall? (y/n)"
        read -r reinstall
        if [ "$reinstall" = "y" ]; then
            install_tunnel_client
        fi
    else
        install_tunnel_client
    fi
    
    cleanup_old_install
    
    authenticate
    register_device
    get_opencode_port
    
    if [ "$OS" = "darwin" ]; then
        setup_launchd
    else
        setup_systemd
    fi
    
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}   Setup Complete!                              ${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    
    SUBDOMAIN=$(cat "$INSTALL_DIR/subdomain")
    echo "Your OpenCode instance is now accessible via the relay."
    echo -e "  Subdomain: ${YELLOW}${SUBDOMAIN}${NC}"
    echo ""
    echo "Management commands:"
    if [ "$OS" = "darwin" ]; then
        echo "  Start:   launchctl start com.opencode.relay"
        echo "  Stop:    launchctl stop com.opencode.relay"
        echo "  Logs:    tail -f $LOG_FILE"
    else
        echo "  Start:   systemctl --user start opencode-relay"
        echo "  Stop:    systemctl --user stop opencode-relay"
        echo "  Status:  systemctl --user status opencode-relay"
        echo "  Logs:    journalctl --user -u opencode-relay -f"
    fi
    echo ""
    echo "You can now connect to this device using the OpenCode Anywhere app!"
}

main
