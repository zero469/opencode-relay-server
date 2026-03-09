#!/bin/bash
set -e

VERSION="${1:-dev}"
BUILD_TIME=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
BUILD_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

LDFLAGS="-X 'main.buildVersion=${VERSION}' -X 'main.buildTime=${BUILD_TIME}' -X 'main.buildCommit=${BUILD_COMMIT}'"

echo "Building tunnel-client..."
echo "  Version: ${VERSION}"
echo "  Time:    ${BUILD_TIME}"
echo "  Commit:  ${BUILD_COMMIT}"

cd "$(dirname "$0")"

# Build for current platform
go build -ldflags "${LDFLAGS}" -o tunnel-client ./cmd/tunnel-client/

# Build for all platforms
GOOS=darwin GOARCH=arm64 go build -ldflags "${LDFLAGS}" -o tunnel-client-darwin-arm64 ./cmd/tunnel-client/
GOOS=darwin GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o tunnel-client-darwin-amd64 ./cmd/tunnel-client/
GOOS=linux GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o tunnel-client-linux-amd64 ./cmd/tunnel-client/
GOOS=linux GOARCH=arm64 go build -ldflags "${LDFLAGS}" -o tunnel-client-linux-arm64 ./cmd/tunnel-client/
GOOS=windows GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o tunnel-client-windows-amd64.exe ./cmd/tunnel-client/

echo "Done!"
ls -la tunnel-client*
