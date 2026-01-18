#!/bin/bash
set -e

echo "=== OpenCode Relay Server Deployment ==="

sudo mkdir -p /opt/opencode-relay/data

sudo cp opencode-relay-server /opt/opencode-relay/
sudo chmod +x /opt/opencode-relay/opencode-relay-server

sudo cp opencode-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable opencode-relay
sudo systemctl restart opencode-relay

sudo cp nginx-relay.conf /etc/nginx/sites-available/relay.zero469.dpdns.org
sudo ln -sf /etc/nginx/sites-available/relay.zero469.dpdns.org /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

echo "Checking service status..."
sleep 2
sudo systemctl status opencode-relay --no-pager

echo ""
echo "Deployment complete!"
echo "API available at: https://relay.zero469.dpdns.org"
