#!/bin/bash
#
# OpenCode Relay Client Setup Script
# This script sets up frpc on your computer to enable remote access via OpenCode Anywhere app
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/zero469/opencode-relay-server/main/scripts/setup-opencode-relay.sh | bash
#
# Or download and run:
#   chmod +x setup-opencode-relay.sh
#   ./setup-opencode-relay.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
RELAY_API_URL="${RELAY_API_URL:-https://opencode-relay.azurewebsites.net}"
FRPC_VERSION="0.61.1"
INSTALL_DIR="$HOME/.opencode-relay"
CONFIG_FILE="$INSTALL_DIR/frpc.toml"
LOG_FILE="$INSTALL_DIR/frpc.log"

# Detect OS and architecture
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

# Download and install frpc
install_frpc() {
    echo -e "${BLUE}Installing frpc v${FRPC_VERSION}...${NC}"
    
    mkdir -p "$INSTALL_DIR"
    
    DOWNLOAD_URL="https://github.com/fatedier/frp/releases/download/v${FRPC_VERSION}/frp_${FRPC_VERSION}_${OS}_${ARCH}.tar.gz"
    TEMP_DIR=$(mktemp -d)
    
    echo "Downloading from: $DOWNLOAD_URL"
    
    if command -v curl &> /dev/null; then
        curl -sSL "$DOWNLOAD_URL" -o "$TEMP_DIR/frp.tar.gz"
    elif command -v wget &> /dev/null; then
        wget -q "$DOWNLOAD_URL" -O "$TEMP_DIR/frp.tar.gz"
    else
        echo -e "${RED}Error: Neither curl nor wget found. Please install one of them.${NC}"
        exit 1
    fi
    
    tar -xzf "$TEMP_DIR/frp.tar.gz" -C "$TEMP_DIR"
    cp "$TEMP_DIR/frp_${FRPC_VERSION}_${OS}_${ARCH}/frpc" "$INSTALL_DIR/frpc"
    chmod +x "$INSTALL_DIR/frpc"
    
    rm -rf "$TEMP_DIR"
    
    echo -e "${GREEN}frpc installed to $INSTALL_DIR/frpc${NC}"
}

# User authentication
authenticate() {
    echo ""
    echo -e "${BLUE}=== OpenCode Relay Authentication ===${NC}"
    echo ""
    
    # Check if already logged in
    if [ -f "$INSTALL_DIR/token" ]; then
        echo "Found existing authentication. Do you want to use it? (y/n)"
        read -r use_existing
        if [ "$use_existing" = "y" ]; then
            TOKEN=$(cat "$INSTALL_DIR/token")
            return
        fi
    fi
    
    # Login (registration requires email verification, use the iOS app to register first)
    echo ""
    echo -e "${YELLOW}Logging in...${NC}"
    echo -e "${CYAN}(Don't have an account? Register via the OpenCode Anywhere iOS app first)${NC}"
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

# Register device
register_device() {
    echo ""
    echo -e "${BLUE}=== Device Registration ===${NC}"
    
    # Check for existing device config
    if [ -f "$INSTALL_DIR/device_id" ]; then
        DEVICE_ID=$(cat "$INSTALL_DIR/device_id")
        echo "Found existing device registration (ID: $DEVICE_ID)"
        echo "Do you want to use it? (y/n)"
        read -r use_existing
        if [ "$use_existing" = "y" ]; then
            return
        fi
    fi
    
    # Get device name
    DEFAULT_NAME=$(hostname)
    echo -n "Device name [$DEFAULT_NAME]: "
    read -r DEVICE_NAME
    DEVICE_NAME="${DEVICE_NAME:-$DEFAULT_NAME}"
    
    # Register device
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
    
    if [ -z "$DEVICE_ID" ] || [ -z "$SUBDOMAIN" ]; then
        echo -e "${RED}Failed to parse device response${NC}"
        exit 1
    fi
    
    echo "$DEVICE_ID" > "$INSTALL_DIR/device_id"
    
    echo -e "${GREEN}Device registered successfully!${NC}"
    echo -e "  Device ID: $DEVICE_ID"
    echo -e "  Subdomain: ${YELLOW}${SUBDOMAIN}.liuyao16.dpdns.org${NC}"
}

# Get OpenCode local port
get_opencode_port() {
    echo ""
    echo -e "${BLUE}=== OpenCode Configuration ===${NC}"
    
    DEFAULT_PORT="4096"
    echo -n "OpenCode API port [$DEFAULT_PORT]: "
    read -r OPENCODE_PORT
    OPENCODE_PORT="${OPENCODE_PORT:-$DEFAULT_PORT}"
    
    echo "$OPENCODE_PORT" > "$INSTALL_DIR/local_port"
}

# Fetch and save frpc config
fetch_frpc_config() {
    echo ""
    echo -e "${BLUE}Fetching frpc configuration...${NC}"
    
    DEVICE_ID=$(cat "$INSTALL_DIR/device_id")
    LOCAL_PORT=$(cat "$INSTALL_DIR/local_port")
    
    RESPONSE=$(curl -sSL -X GET "$RELAY_API_URL/api/devices/$DEVICE_ID/frpc-config?local_port=$LOCAL_PORT" \
        -H "Authorization: Bearer $TOKEN" \
        2>&1)
    
    if echo "$RESPONSE" | grep -q "error"; then
        echo -e "${RED}Failed to fetch frpc config: $RESPONSE${NC}"
        exit 1
    fi
    
    # Parse JSON and generate TOML config
    SERVER_ADDR=$(echo "$RESPONSE" | grep -o '"server_addr":"[^"]*"' | cut -d'"' -f4)
    SERVER_PORT=$(echo "$RESPONSE" | grep -o '"server_port":"[^"]*"' | cut -d'"' -f4)
    AUTH_TOKEN=$(echo "$RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    SUBDOMAIN=$(echo "$RESPONSE" | grep -o '"subdomain":"[^"]*"' | cut -d'"' -f4)
    AUTH_USER=$(echo "$RESPONSE" | grep -o '"auth_user":"[^"]*"' | cut -d'"' -f4)
    AUTH_PASSWORD=$(echo "$RESPONSE" | grep -o '"auth_password":"[^"]*"' | cut -d'"' -f4)
    
    cat > "$CONFIG_FILE" << EOF
# OpenCode Relay frpc configuration
# Generated by setup script

serverAddr = "$SERVER_ADDR"
serverPort = $SERVER_PORT

auth.method = "token"
auth.token = "$AUTH_TOKEN"

[[proxies]]
name = "opencode-$SUBDOMAIN"
type = "http"
localIP = "127.0.0.1"
localPort = $LOCAL_PORT
subdomain = "$SUBDOMAIN"
httpUser = "$AUTH_USER"
httpPassword = "$AUTH_PASSWORD"
EOF
    
    chmod 600 "$CONFIG_FILE"
    
    echo -e "${GREEN}frpc configuration saved to $CONFIG_FILE${NC}"
}

# Setup auto-start (macOS launchd)
setup_launchd() {
    echo ""
    echo -e "${BLUE}Setting up auto-start (launchd)...${NC}"
    
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
        <string>$INSTALL_DIR/frpc</string>
        <string>-c</string>
        <string>$CONFIG_FILE</string>
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
    
    # Load the service
    launchctl unload "$PLIST_FILE" 2>/dev/null || true
    launchctl load "$PLIST_FILE"
    
    echo -e "${GREEN}Auto-start configured!${NC}"
}

# Setup auto-start (Linux systemd)
setup_systemd() {
    echo ""
    echo -e "${BLUE}Setting up auto-start (systemd user service)...${NC}"
    
    SYSTEMD_DIR="$HOME/.config/systemd/user"
    SERVICE_FILE="$SYSTEMD_DIR/opencode-relay.service"
    
    mkdir -p "$SYSTEMD_DIR"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=OpenCode Relay Client
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/frpc -c $CONFIG_FILE
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

# Setup heartbeat cron job
setup_heartbeat() {
    echo ""
    echo -e "${BLUE}Setting up heartbeat...${NC}"
    
    SUBDOMAIN=$(grep 'subdomain = ' "$CONFIG_FILE" | cut -d'"' -f2)
    
    # Create heartbeat script
    cat > "$INSTALL_DIR/heartbeat.sh" << EOF
#!/bin/bash
curl -sSL "$RELAY_API_URL/api/heartbeat?subdomain=$SUBDOMAIN" > /dev/null 2>&1
EOF
    chmod +x "$INSTALL_DIR/heartbeat.sh"
    
    if [ "$OS" = "darwin" ]; then
        # macOS - use launchd for heartbeat
        HEARTBEAT_PLIST="$HOME/Library/LaunchAgents/com.opencode.relay.heartbeat.plist"
        
        cat > "$HEARTBEAT_PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.opencode.relay.heartbeat</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/heartbeat.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>30</integer>
</dict>
</plist>
EOF
        
        launchctl unload "$HEARTBEAT_PLIST" 2>/dev/null || true
        launchctl load "$HEARTBEAT_PLIST"
    else
        # Linux - use cron or systemd timer
        TIMER_FILE="$HOME/.config/systemd/user/opencode-relay-heartbeat.timer"
        SERVICE_FILE="$HOME/.config/systemd/user/opencode-relay-heartbeat.service"
        
        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=OpenCode Relay Heartbeat

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/heartbeat.sh
EOF
        
        cat > "$TIMER_FILE" << EOF
[Unit]
Description=OpenCode Relay Heartbeat Timer

[Timer]
OnBootSec=30
OnUnitActiveSec=30

[Install]
WantedBy=timers.target
EOF
        
        systemctl --user daemon-reload
        systemctl --user enable opencode-relay-heartbeat.timer
        systemctl --user start opencode-relay-heartbeat.timer
    fi
    
    echo -e "${GREEN}Heartbeat configured (every 30 seconds)${NC}"
}

# Main installation flow
main() {
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}   OpenCode Relay Client Setup                  ${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    
    detect_platform
    
    # Check if frpc already installed
    if [ -f "$INSTALL_DIR/frpc" ]; then
        echo -e "${YELLOW}frpc already installed at $INSTALL_DIR/frpc${NC}"
        echo "Do you want to reinstall? (y/n)"
        read -r reinstall
        if [ "$reinstall" = "y" ]; then
            install_frpc
        fi
    else
        install_frpc
    fi
    
    authenticate
    register_device
    get_opencode_port
    fetch_frpc_config
    
    # Setup auto-start based on OS
    if [ "$OS" = "darwin" ]; then
        setup_launchd
    else
        setup_systemd
    fi
    
    setup_heartbeat
    
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}   Setup Complete!                              ${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    echo "Your OpenCode instance is now accessible at:"
    SUBDOMAIN=$(grep 'subdomain = ' "$CONFIG_FILE" | cut -d'"' -f2)
    echo -e "  ${YELLOW}http://${SUBDOMAIN}.liuyao16.dpdns.org${NC}"
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

# Run main
main
