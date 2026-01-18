#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_DIR="$HOME/.opencode-relay"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

echo -e "${YELLOW}Uninstalling OpenCode Relay Client...${NC}"

if [ "$OS" = "darwin" ]; then
    launchctl unload "$HOME/Library/LaunchAgents/com.opencode.relay.plist" 2>/dev/null || true
    launchctl unload "$HOME/Library/LaunchAgents/com.opencode.relay.heartbeat.plist" 2>/dev/null || true
    rm -f "$HOME/Library/LaunchAgents/com.opencode.relay.plist"
    rm -f "$HOME/Library/LaunchAgents/com.opencode.relay.heartbeat.plist"
else
    systemctl --user stop opencode-relay 2>/dev/null || true
    systemctl --user disable opencode-relay 2>/dev/null || true
    systemctl --user stop opencode-relay-heartbeat.timer 2>/dev/null || true
    systemctl --user disable opencode-relay-heartbeat.timer 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/opencode-relay.service"
    rm -f "$HOME/.config/systemd/user/opencode-relay-heartbeat.service"
    rm -f "$HOME/.config/systemd/user/opencode-relay-heartbeat.timer"
    systemctl --user daemon-reload 2>/dev/null || true
fi

if [ -d "$INSTALL_DIR" ]; then
    echo -n "Remove all data including credentials? (y/n): "
    read -r remove_all
    if [ "$remove_all" = "y" ]; then
        rm -rf "$INSTALL_DIR"
        echo -e "${GREEN}All data removed.${NC}"
    else
        rm -f "$INSTALL_DIR/frpc"
        rm -f "$INSTALL_DIR/frpc.toml"
        rm -f "$INSTALL_DIR/frpc.log"
        rm -f "$INSTALL_DIR/heartbeat.sh"
        echo -e "${GREEN}Binaries and config removed. Credentials kept.${NC}"
    fi
fi

echo -e "${GREEN}OpenCode Relay Client uninstalled successfully!${NC}"
