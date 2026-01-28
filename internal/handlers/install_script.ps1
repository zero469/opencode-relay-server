#
# OpenCode Relay Client Setup Script for Windows
# This script sets up tunnel-client on your Windows PC to enable remote access via OpenCode Anywhere app
#
# Usage:
#   irm https://opencode-relay.azurewebsites.net/install.ps1 | iex
#

$ErrorActionPreference = "Stop"

$INSTALL_DIR = "$env:USERPROFILE\.opencode-relay"

function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Detect-Platform {
    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    Write-ColorOutput "Detected platform: windows_$arch" "Cyan"
    return $arch
}

function Install-TunnelClient {
    param([string]$Arch)
    
    Write-ColorOutput "Installing tunnel-client..." "Cyan"
    
    if (-not (Test-Path $INSTALL_DIR)) {
        New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
    }
    
    $fileName = "tunnel-client-windows-$Arch.exe"
    $urls = @(
        "https://github.com/zero469/opencode-relay-server/releases/latest/download/$fileName",
        "https://ghfast.top/https://github.com/zero469/opencode-relay-server/releases/latest/download/$fileName",
        "https://mirror.ghproxy.com/https://github.com/zero469/opencode-relay-server/releases/latest/download/$fileName",
        "https://gh-proxy.com/https://github.com/zero469/opencode-relay-server/releases/latest/download/$fileName"
    )
    
    $downloaded = $false
    foreach ($url in $urls) {
        Write-Host "Trying: $url"
        try {
            Invoke-WebRequest -Uri $url -OutFile "$INSTALL_DIR\tunnel-client.exe" -UseBasicParsing -TimeoutSec 120
            $downloaded = $true
            Write-ColorOutput "Download successful!" "Green"
            break
        } catch {
            Write-ColorOutput "Failed, trying next mirror..." "Yellow"
        }
    }
    
    if (-not $downloaded) {
        Write-ColorOutput "All download sources failed. Please download manually from:" "Red"
        Write-Host "https://github.com/zero469/opencode-relay-server/releases/latest"
        Write-Host ""
        Read-Host "Press Enter to exit..."
        exit 1
    }
    
    Write-ColorOutput "tunnel-client installed to $INSTALL_DIR\tunnel-client.exe" "Green"
}

function Main {
    Write-Host ""
    Write-ColorOutput "================================================" "Green"
    Write-ColorOutput "   OpenCode Relay Client Setup (Windows)        " "Green"
    Write-ColorOutput "================================================" "Green"
    Write-Host ""
    
    $arch = Detect-Platform
    
    if (Test-Path "$INSTALL_DIR\tunnel-client.exe") {
        Write-ColorOutput "tunnel-client already installed at $INSTALL_DIR\tunnel-client.exe" "Yellow"
        $reinstall = Read-Host "Reinstall? (y/n)"
        if ($reinstall -eq "y") {
            Install-TunnelClient -Arch $arch
        }
    } else {
        Install-TunnelClient -Arch $arch
    }
    
    Write-Host ""
    Write-ColorOutput "================================================" "Green"
    Write-ColorOutput "   Installation Complete!                       " "Green"
    Write-ColorOutput "================================================" "Green"
    Write-Host ""
    Write-Host "Next step:"
    Write-Host ""
    Write-Host "Run tunnel-client:"
    Write-ColorOutput "   $INSTALL_DIR\tunnel-client.exe" "Yellow"
    Write-Host ""
    Write-Host "It will guide you through login and pairing automatically."
    Write-Host ""
    Write-ColorOutput "The tunnel will auto-start on boot after pairing." "Cyan"
    Write-Host ""
    
    $runNow = Read-Host "Run tunnel-client now? (y/n)"
    if ($runNow -eq "y") {
        & "$INSTALL_DIR\tunnel-client.exe"
    }
}

Main
