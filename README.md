# OpenCode Relay Server

<div align="center">

**Secure remote access to your OpenCode instances**

The relay infrastructure for [OpenCode Anywhere](https://github.com/zero469/opencode-anywhere) - enabling encrypted tunnels to your AI coding assistant from anywhere in the world.

[![Download iOS App](https://img.shields.io/badge/iOS_App-TestFlight-blue?style=for-the-badge&logo=apple)](https://testflight.apple.com/join/your-link)
[![GitHub Stars](https://img.shields.io/github/stars/zero469/opencode-relay-server?style=for-the-badge)](https://github.com/zero469/opencode-relay-server)

</div>

---

## Overview

This repository contains two components:

1. **Relay Server** - A Go-based WebSocket relay server (deployed on fly.io)
2. **Tunnel Client** - A CLI tool that runs on your computer to establish secure tunnels

## Quick Start

### Prerequisites

- [OpenCode Anywhere iOS App](https://github.com/zero469/opencode-anywhere) - Create an account first
- [OpenCode](https://github.com/sst/opencode) installed on your computer

### Download & Run

```bash
# macOS (Apple Silicon)
curl -L https://github.com/zero469/opencode-relay-server/releases/latest/download/tunnel-client-darwin-arm64 -o tunnel-client
chmod +x tunnel-client
./tunnel-client

# macOS (Intel)
curl -L https://github.com/zero469/opencode-relay-server/releases/latest/download/tunnel-client-darwin-amd64 -o tunnel-client
chmod +x tunnel-client
./tunnel-client

# Linux (x86_64)
curl -L https://github.com/zero469/opencode-relay-server/releases/latest/download/tunnel-client-linux-amd64 -o tunnel-client
chmod +x tunnel-client
./tunnel-client

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/zero469/opencode-relay-server/releases/latest/download/tunnel-client-windows-amd64.exe" -OutFile "tunnel-client.exe"
.\tunnel-client.exe
```

### What Happens

1. **Login** - Enter your email/password (account created in iOS app)
2. **QR Code** - A pairing QR code appears in your terminal
3. **Scan** - Use the iOS app to scan the QR code
4. **Connected** - Your computer is now accessible from anywhere!

The tunnel client will:
- Auto-start OpenCode if not running
- Configure auto-start on boot (launchd/systemd/Windows Task Scheduler)
- Maintain persistent connection with automatic reconnection

## Architecture

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│                 │   E2E   │                 │   E2E   │                 │
│    iOS App      │◄───────►│  Relay Server   │◄───────►│  tunnel-client  │
│                 │ Encrypt │   (fly.io)      │ Encrypt │                 │
└─────────────────┘         └─────────────────┘         └────────┬────────┘
                                                                 │
                                                                 │ HTTP
                                                                 ▼
                                                        ┌─────────────────┐
                                                        │ OpenCode Server │
                                                        │  (localhost)    │
                                                        └─────────────────┘
```

### How It Works

1. **tunnel-client** connects to Relay Server via WebSocket
2. **iOS App** sends encrypted requests to Relay Server
3. **Relay Server** forwards encrypted data to tunnel-client
4. **tunnel-client** decrypts and forwards to local OpenCode
5. Response travels back the same path (encrypted)

### Security Model

| Layer | Protection |
|-------|------------|
| **Transport** | TLS 1.3 (WSS/HTTPS) between all components |
| **Payload** | AES-256-GCM end-to-end encryption |
| **Key Exchange** | Encryption key embedded in QR code, never sent to relay |
| **Authentication** | JWT tokens + per-device credentials |
| **Zero Knowledge** | Relay server only sees encrypted blobs |

### How E2E Encryption Works

1. `tunnel-client` generates a random 256-bit AES key during pairing
2. Key is embedded in QR code data (JSON encoded)
3. iOS app scans QR → extracts key → stores locally
4. All subsequent requests/responses are encrypted with this key
5. Relay server forwards encrypted blobs, cannot decrypt

## Tunnel Client Usage

```bash
# Start tunnel (default)
./tunnel-client

# Start with custom port
./tunnel-client -port 8080

# Show status
./tunnel-client status

# Logout and clear credentials  
./tunnel-client logout

# Help
./tunnel-client help
```

### Configuration Files

Located in `~/.opencode-tunnel/`:

| File | Purpose |
|------|---------|
| `auth.json` | Login credentials (JWT token, email) |
| `device.json` | Device pairing info (subdomain, auth, encryption key) |
| `opencode.json` | OpenCode auto-start config |

## Self-Hosting the Relay Server

Want to run your own relay server? Here's how:

### Prerequisites

- Go 1.21+
- A server with public IP (or use Cloudflare Tunnel)

### Build & Run

```bash
# Clone
git clone https://github.com/zero469/opencode-relay-server.git
cd opencode-relay-server

# Build
go build -o server ./cmd/server

# Run
PORT=8080 JWT_SECRET=your-secret ./server
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `JWT_SECRET` | (required) | Secret for JWT signing |
| `DATABASE_PATH` | `./data/relay.db` | SQLite database path |
| `SINGLE_USER_MODE` | `false` | Skip email verification |

### Deploy to fly.io

```bash
fly launch
fly secrets set JWT_SECRET=your-secret
fly deploy
```

### Update Tunnel Client

After self-hosting, update the default relay URL in your tunnel client:

```bash
./tunnel-client -relay https://your-relay.fly.dev
```

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/send-verification` | Send email verification code |
| POST | `/api/register` | Register new account |
| POST | `/api/login` | Login and get JWT |
| POST | `/api/auto-login` | Refresh token |

### Devices

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/devices` | List user's devices |
| POST | `/api/devices` | Register new device |
| GET | `/api/devices/{id}` | Get device details |
| PUT | `/api/devices/{id}` | Update device |
| DELETE | `/api/devices/{id}` | Delete device |

### Pairing

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/pairing` | Create pairing request |
| GET | `/api/pairing/{id}/status` | Poll pairing status |
| POST | `/api/pairing/{id}/complete` | Complete pairing |

### Tunnel

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/tunnel/{subdomain}` | WebSocket tunnel connection |
| GET | `/api/events/{subdomain}` | SSE event forwarding |
| ANY | `/proxy/*` | HTTP proxy to tunnel |

## Development

### Build All Binaries

```bash
# Build server
go build -o server ./cmd/server

# Build tunnel client for all platforms
GOOS=darwin GOARCH=arm64 go build -o tunnel-client-darwin-arm64 ./cmd/tunnel-client
GOOS=darwin GOARCH=amd64 go build -o tunnel-client-darwin-amd64 ./cmd/tunnel-client
GOOS=linux GOARCH=amd64 go build -o tunnel-client-linux-amd64 ./cmd/tunnel-client
GOOS=linux GOARCH=arm64 go build -o tunnel-client-linux-arm64 ./cmd/tunnel-client
GOOS=windows GOARCH=amd64 go build -o tunnel-client-windows-amd64.exe ./cmd/tunnel-client
```

### Project Structure

```
├── cmd/
│   ├── server/          # Relay server entry point
│   └── tunnel-client/   # Tunnel client entry point
├── internal/
│   ├── config/          # Configuration loading
│   ├── database/        # SQLite database layer
│   ├── handlers/        # HTTP handlers
│   ├── middleware/      # Auth middleware
│   ├── models/          # Data models
│   ├── services/        # Business logic
│   └── tunnel/          # WebSocket tunnel management
├── scripts/             # Deployment scripts
└── dist/                # Pre-built binaries
```

## Related Projects

- **[opencode-anywhere](https://github.com/zero469/opencode-anywhere)** - The iOS app
- **[OpenCode](https://github.com/sst/opencode)** - The AI coding assistant

## License

MIT

## Credits

Built to enable secure remote access to [OpenCode](https://github.com/sst/opencode) by SST.
