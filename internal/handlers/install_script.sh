#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

check_npm() {
    if ! command -v npm &> /dev/null; then
        echo -e "${RED}npm is not installed.${NC}"
        echo ""
        echo "Please install Node.js first:"
        echo ""
        echo "  macOS:   brew install node"
        echo "  Ubuntu:  sudo apt install nodejs npm"
        echo "  Or visit: https://nodejs.org/"
        echo ""
        exit 1
    fi
}

install_tunnel_client() {
    echo -e "${BLUE}Installing opencode-tunnel via npm...${NC}"
    echo ""
    
    npm install -g @zero469/opencode-tunnel
    
    echo ""
    echo -e "${GREEN}Installation complete!${NC}"
}

main() {
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}   OpenCode Anywhere Client Setup               ${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    
    check_npm
    install_tunnel_client
    
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}   Installation Complete!                       ${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    echo -e "${BLUE}Next step:${NC}"
    echo ""
    echo "Run tunnel client:"
    echo -e "   ${YELLOW}opencode-tunnel${NC}"
    echo ""
    echo "It will guide you through login and pairing automatically."
    echo ""
    echo -e "${BLUE}The tunnel will auto-start on boot after pairing.${NC}"
    echo ""
    
    # Auto-launch prompt (only if running in interactive TTY)
    if [ -t 0 ]; then
        printf "Start opencode-tunnel now? (Y/n): "
        read -r answer < /dev/tty
        case "$answer" in
            [Nn]*)
                ;;
            *)
                exec opencode-tunnel
                ;;
        esac
    fi
}

main
