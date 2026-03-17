#
# OpenCode Anywhere Client Setup Script for Windows
#
# Usage:
#   irm https://opencode-relay.azurewebsites.net/install.ps1 | iex
#

$ErrorActionPreference = "Stop"

function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Check-Npm {
    try {
        $null = Get-Command npm -ErrorAction Stop
        return $true
    } catch {
        Write-ColorOutput "npm is not installed." "Red"
        Write-Host ""
        Write-Host "Please install Node.js first:"
        Write-Host ""
        Write-Host "  Download from: https://nodejs.org/"
        Write-Host "  Or use winget: winget install OpenJS.NodeJS"
        Write-Host ""
        return $false
    }
}

function Install-TunnelClient {
    Write-ColorOutput "Installing opencode-tunnel via npm..." "Cyan"
    Write-Host ""
    
    npm install -g @zero469/opencode-tunnel
    
    Write-Host ""
    Write-ColorOutput "Installation complete!" "Green"
}

function Main {
    Write-Host ""
    Write-ColorOutput "================================================" "Green"
    Write-ColorOutput "   OpenCode Anywhere Client Setup (Windows)     " "Green"
    Write-ColorOutput "================================================" "Green"
    Write-Host ""
    
    if (-not (Check-Npm)) {
        Read-Host "Press Enter to exit..."
        exit 1
    }
    
    Install-TunnelClient
    
    Write-Host ""
    Write-ColorOutput "================================================" "Green"
    Write-ColorOutput "   Installation Complete!                       " "Green"
    Write-ColorOutput "================================================" "Green"
    Write-Host ""
    Write-Host "Next step:"
    Write-Host ""
    Write-Host "Run tunnel client:"
    Write-ColorOutput "   opencode-tunnel" "Yellow"
    Write-Host ""
    Write-Host "It will guide you through login and pairing automatically."
    Write-Host ""
    Write-ColorOutput "The tunnel will auto-start on boot after pairing." "Cyan"
    Write-Host ""
    
    $runNow = Read-Host "Run opencode-tunnel now? (y/n)"
    if ($runNow -eq "y") {
        & opencode-tunnel
    }
}

Main
