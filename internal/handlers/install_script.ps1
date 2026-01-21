#
# OpenCode Relay Client Setup Script for Windows
# This script sets up tunnel-client on your Windows PC to enable remote access via OpenCode Anywhere app
#
# Usage:
#   irm https://opencode-relay-server.fly.dev/install.ps1 | iex
#

$ErrorActionPreference = "Stop"

$RELAY_API_URL = if ($env:RELAY_API_URL) { $env:RELAY_API_URL } else { "https://opencode-relay-server.fly.dev" }
$INSTALL_DIR = "$env:USERPROFILE\.opencode-relay"
$LOG_FILE = "$INSTALL_DIR\tunnel.log"

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
        "https://mirror.ghproxy.com/https://github.com/zero469/opencode-relay-server/releases/latest/download/$fileName",
        "https://ghfast.top/https://github.com/zero469/opencode-relay-server/releases/latest/download/$fileName"
    )
    
    $downloaded = $false
    foreach ($url in $urls) {
        Write-Host "Trying: $url"
        try {
            Invoke-WebRequest -Uri $url -OutFile "$INSTALL_DIR\tunnel-client.exe" -UseBasicParsing -TimeoutSec 60
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
        exit 1
    }
    
    Write-ColorOutput "tunnel-client installed to $INSTALL_DIR\tunnel-client.exe" "Green"
}

function Authenticate {
    Write-Host ""
    Write-ColorOutput "=== OpenCode Relay Authentication ===" "Cyan"
    Write-Host ""
    
    $tokenFile = "$INSTALL_DIR\token"
    
    if (Test-Path $tokenFile) {
        $useExisting = Read-Host "Found existing authentication. Use it? (y/n)"
        if ($useExisting -eq "y") {
            return Get-Content $tokenFile
        }
    }
    
    Write-ColorOutput "Logging in..." "Yellow"
    Write-Host "(Don't have an account? Register via the OpenCode Anywhere iOS app first)"
    
    $email = Read-Host "Email"
    $password = Read-Host "Password" -AsSecureString
    $passwordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    
    $body = @{ email = $email; password = $passwordPlain } | ConvertTo-Json
    try {
        $response = Invoke-RestMethod -Uri "$RELAY_API_URL/api/login" -Method Post -Body $body -ContentType "application/json"
        $token = $response.token
        $token | Out-File -FilePath $tokenFile -Encoding utf8 -NoNewline
        Write-ColorOutput "Login successful!" "Green"
        return $token
    } catch {
        Write-ColorOutput "Login failed: $_" "Red"
        exit 1
    }
}

function Register-Device {
    param([string]$Token)
    
    Write-Host ""
    Write-ColorOutput "=== Device Registration ===" "Cyan"
    
    $deviceIdFile = "$INSTALL_DIR\device_id"
    
    if (Test-Path $deviceIdFile) {
        $deviceId = Get-Content $deviceIdFile
        $useExisting = Read-Host "Found existing device (ID: $deviceId). Use it? (y/n)"
        if ($useExisting -eq "y") {
            return $deviceId
        }
    }
    
    $defaultName = $env:COMPUTERNAME
    $deviceName = Read-Host "Device name [$defaultName]"
    if (-not $deviceName) { $deviceName = $defaultName }
    
    $body = @{ name = $deviceName } | ConvertTo-Json
    $headers = @{ Authorization = "Bearer $Token" }
    
    try {
        $response = Invoke-RestMethod -Uri "$RELAY_API_URL/api/devices" -Method Post -Body $body -ContentType "application/json" -Headers $headers
        $deviceId = $response.id
        $subdomain = $response.subdomain
        $authUser = $response.auth_user
        $authPassword = $response.auth_password
        
        $deviceId | Out-File -FilePath $deviceIdFile -Encoding utf8 -NoNewline
        $subdomain | Out-File -FilePath "$INSTALL_DIR\subdomain" -Encoding utf8 -NoNewline
        $authUser | Out-File -FilePath "$INSTALL_DIR\auth_user" -Encoding utf8 -NoNewline
        $authPassword | Out-File -FilePath "$INSTALL_DIR\auth_password" -Encoding utf8 -NoNewline
        
        Write-ColorOutput "Device registered successfully!" "Green"
        Write-Host "  Device ID: $deviceId"
        Write-ColorOutput "  Subdomain: $subdomain" "Yellow"
        
        return $deviceId
    } catch {
        Write-ColorOutput "Device registration failed: $_" "Red"
        exit 1
    }
}

function Get-OpenCodePort {
    Write-Host ""
    Write-ColorOutput "=== OpenCode Configuration ===" "Cyan"
    
    $defaultPort = "4096"
    $port = Read-Host "OpenCode API port [$defaultPort]"
    if (-not $port) { $port = $defaultPort }
    
    $port | Out-File -FilePath "$INSTALL_DIR\local_port" -Encoding utf8 -NoNewline
    return $port
}

function Load-DeviceConfig {
    param([string]$Token)
    
    $deviceIdFile = "$INSTALL_DIR\device_id"
    if (-not (Test-Path $deviceIdFile)) {
        Write-ColorOutput "Device not registered. Please run setup first." "Red"
        exit 1
    }
    
    $script:DeviceId = Get-Content $deviceIdFile
    $script:LocalPort = if (Test-Path "$INSTALL_DIR\local_port") { Get-Content "$INSTALL_DIR\local_port" } else { "4096" }
    
    if (Test-Path "$INSTALL_DIR\subdomain") {
        $script:Subdomain = Get-Content "$INSTALL_DIR\subdomain"
        $script:AuthUser = Get-Content "$INSTALL_DIR\auth_user"
        $script:AuthPassword = Get-Content "$INSTALL_DIR\auth_password"
    } else {
        $headers = @{ Authorization = "Bearer $Token" }
        $response = Invoke-RestMethod -Uri "$RELAY_API_URL/api/devices/$($script:DeviceId)" -Headers $headers
        
        $script:Subdomain = $response.subdomain
        $script:AuthUser = $response.auth_user
        $script:AuthPassword = $response.auth_password
        
        $response.subdomain | Out-File -FilePath "$INSTALL_DIR\subdomain" -Encoding utf8 -NoNewline
        $response.auth_user | Out-File -FilePath "$INSTALL_DIR\auth_user" -Encoding utf8 -NoNewline
        $response.auth_password | Out-File -FilePath "$INSTALL_DIR\auth_password" -Encoding utf8 -NoNewline
    }
}

function Setup-ScheduledTask {
    param([string]$Token)
    
    Write-Host ""
    Write-ColorOutput "Setting up Windows scheduled task..." "Cyan"
    
    Load-DeviceConfig -Token $Token
    
    Unregister-ScheduledTask -TaskName "OpenCodeRelay" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "OpenCodeRelayHeartbeat" -Confirm:$false -ErrorAction SilentlyContinue
    
    $arguments = "-relay $RELAY_API_URL -subdomain $Subdomain -auth-user $AuthUser -auth-password $AuthPassword -local-port $LocalPort"
    $action = New-ScheduledTaskAction -Execute "$INSTALL_DIR\tunnel-client.exe" -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtLogon
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    
    Register-ScheduledTask -TaskName "OpenCodeRelay" -Action $action -Trigger $trigger -Settings $settings -Description "OpenCode Relay tunnel client" -RunLevel Highest | Out-Null
    
    Start-ScheduledTask -TaskName "OpenCodeRelay"
    
    Write-ColorOutput "Scheduled task configured!" "Green"
}

function Cleanup-OldInstall {
    Unregister-ScheduledTask -TaskName "OpenCodeRelayHeartbeat" -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path "$INSTALL_DIR\frpc.exe" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$INSTALL_DIR\frpc.toml" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$INSTALL_DIR\heartbeat.ps1" -Force -ErrorAction SilentlyContinue
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
    
    Cleanup-OldInstall
    
    $token = Authenticate
    $deviceId = Register-Device -Token $token
    $localPort = Get-OpenCodePort
    
    Setup-ScheduledTask -Token $token
    
    $subdomain = Get-Content "$INSTALL_DIR\subdomain"
    
    Write-Host ""
    Write-ColorOutput "================================================" "Green"
    Write-ColorOutput "   Setup Complete!                              " "Green"
    Write-ColorOutput "================================================" "Green"
    Write-Host ""
    Write-Host "Your OpenCode instance is now accessible via the relay."
    Write-ColorOutput "  Subdomain: $subdomain" "Yellow"
    Write-Host ""
    Write-Host "Management commands (PowerShell as Admin):"
    Write-Host "  Start:   Start-ScheduledTask -TaskName 'OpenCodeRelay'"
    Write-Host "  Stop:    Stop-ScheduledTask -TaskName 'OpenCodeRelay'"
    Write-Host "  Status:  Get-ScheduledTask -TaskName 'OpenCodeRelay'"
    Write-Host ""
    Write-Host "You can now connect to this device using the OpenCode Anywhere app!"
}

Main
