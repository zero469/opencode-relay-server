#
# OpenCode Relay Client Setup Script for Windows
# This script sets up frpc on your Windows PC to enable remote access via OpenCode Anywhere app
#
# Usage:
#   irm https://raw.githubusercontent.com/zero469/opencode-relay-server/main/scripts/setup-opencode-relay.ps1 | iex
#
# Or download and run:
#   .\setup-opencode-relay.ps1
#

$ErrorActionPreference = "Stop"

# Configuration
$RELAY_API_URL = if ($env:RELAY_API_URL) { $env:RELAY_API_URL } else { "https://opencode-relay-server.fly.dev" }
$FRPC_VERSION = "0.61.1"
$INSTALL_DIR = "$env:USERPROFILE\.opencode-relay"
$CONFIG_FILE = "$INSTALL_DIR\frpc.toml"
$LOG_FILE = "$INSTALL_DIR\frpc.log"

function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Detect-Platform {
    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    Write-ColorOutput "Detected platform: windows_$arch" "Cyan"
    return $arch
}

function Install-Frpc {
    param([string]$Arch)
    
    Write-ColorOutput "Installing frpc v$FRPC_VERSION..." "Cyan"
    
    if (-not (Test-Path $INSTALL_DIR)) {
        New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
    }
    
    $downloadUrl = "https://github.com/fatedier/frp/releases/download/v$FRPC_VERSION/frp_${FRPC_VERSION}_windows_$Arch.zip"
    $tempZip = "$env:TEMP\frp.zip"
    $tempDir = "$env:TEMP\frp_extract"
    
    Write-Host "Downloading from: $downloadUrl"
    
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -UseBasicParsing
    
    if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
    Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force
    
    $frpcPath = Get-ChildItem -Path $tempDir -Recurse -Filter "frpc.exe" | Select-Object -First 1
    Copy-Item -Path $frpcPath.FullName -Destination "$INSTALL_DIR\frpc.exe" -Force
    
    Remove-Item -Path $tempZip -Force
    Remove-Item -Recurse -Force $tempDir
    
    Write-ColorOutput "frpc installed to $INSTALL_DIR\frpc.exe" "Green"
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
    
    $hasAccount = Read-Host "Do you have an account? (y/n)"
    
    $email = $null
    $password = $null
    
    if ($hasAccount -ne "y") {
        Write-ColorOutput "Creating new account..." "Yellow"
        $email = Read-Host "Email"
        $password = Read-Host "Password" -AsSecureString
        $passwordConfirm = Read-Host "Confirm Password" -AsSecureString
        
        $passwordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
        $passwordConfirmPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordConfirm))
        
        if ($passwordPlain -ne $passwordConfirmPlain) {
            Write-ColorOutput "Passwords do not match!" "Red"
            exit 1
        }
        
        $body = @{ email = $email; password = $passwordPlain } | ConvertTo-Json
        try {
            $response = Invoke-RestMethod -Uri "$RELAY_API_URL/api/register" -Method Post -Body $body -ContentType "application/json"
            Write-ColorOutput "Account created successfully!" "Green"
        } catch {
            Write-ColorOutput "Registration failed: $_" "Red"
            exit 1
        }
    }
    
    Write-ColorOutput "Logging in..." "Yellow"
    
    if (-not $email) { $email = Read-Host "Email" }
    if (-not $password) { 
        $password = Read-Host "Password" -AsSecureString 
        $passwordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    }
    
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
        
        $deviceId | Out-File -FilePath $deviceIdFile -Encoding utf8 -NoNewline
        
        Write-ColorOutput "Device registered successfully!" "Green"
        Write-Host "  Device ID: $deviceId"
        Write-ColorOutput "  Subdomain: $subdomain.liuyao16.dpdns.org" "Yellow"
        
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

function Fetch-FrpcConfig {
    param([string]$Token, [string]$DeviceId, [string]$LocalPort)
    
    Write-Host ""
    Write-ColorOutput "Fetching frpc configuration..." "Cyan"
    
    $headers = @{ Authorization = "Bearer $Token" }
    
    try {
        $response = Invoke-RestMethod -Uri "$RELAY_API_URL/api/devices/$DeviceId/frpc-config?local_port=$LocalPort" -Headers $headers
        
        $config = @"
# OpenCode Relay frpc configuration
# Generated by setup script

serverAddr = "$($response.server_addr)"
serverPort = $($response.server_port)

auth.method = "token"
auth.token = "$($response.token)"

[[proxies]]
name = "opencode-$($response.subdomain)"
type = "http"
localIP = "127.0.0.1"
localPort = $LocalPort
subdomain = "$($response.subdomain)"
httpUser = "$($response.auth_user)"
httpPassword = "$($response.auth_password)"
"@
        
        $config | Out-File -FilePath $CONFIG_FILE -Encoding ascii
        
        Write-ColorOutput "frpc configuration saved to $CONFIG_FILE" "Green"
        
        return $response.subdomain
    } catch {
        Write-ColorOutput "Failed to fetch frpc config: $_" "Red"
        exit 1
    }
}

function Setup-ScheduledTask {
    param([string]$Subdomain)
    
    Write-Host ""
    Write-ColorOutput "Setting up Windows scheduled tasks..." "Cyan"
    
    # Remove existing tasks
    Unregister-ScheduledTask -TaskName "OpenCodeRelay" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "OpenCodeRelayHeartbeat" -Confirm:$false -ErrorAction SilentlyContinue
    
    # Create frpc task
    $frpcAction = New-ScheduledTaskAction -Execute "$INSTALL_DIR\frpc.exe" -Argument "-c `"$CONFIG_FILE`""
    $frpcTrigger = New-ScheduledTaskTrigger -AtLogon
    $frpcSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    
    Register-ScheduledTask -TaskName "OpenCodeRelay" -Action $frpcAction -Trigger $frpcTrigger -Settings $frpcSettings -Description "OpenCode Relay frpc client" -RunLevel Highest | Out-Null
    
    # Start frpc now
    Start-ScheduledTask -TaskName "OpenCodeRelay"
    
    # Create heartbeat script
    $heartbeatScript = @"
while (`$true) {
    try {
        Invoke-WebRequest -Uri "$RELAY_API_URL/api/heartbeat?subdomain=$Subdomain" -UseBasicParsing | Out-Null
    } catch {}
    Start-Sleep -Seconds 30
}
"@
    $heartbeatScript | Out-File -FilePath "$INSTALL_DIR\heartbeat.ps1" -Encoding utf8
    
    # Create heartbeat task
    $heartbeatAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$INSTALL_DIR\heartbeat.ps1`""
    $heartbeatTrigger = New-ScheduledTaskTrigger -AtLogon
    $heartbeatSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    
    Register-ScheduledTask -TaskName "OpenCodeRelayHeartbeat" -Action $heartbeatAction -Trigger $heartbeatTrigger -Settings $heartbeatSettings -Description "OpenCode Relay heartbeat" | Out-Null
    
    # Start heartbeat now
    Start-ScheduledTask -TaskName "OpenCodeRelayHeartbeat"
    
    Write-ColorOutput "Scheduled tasks configured!" "Green"
}

function Main {
    Write-Host ""
    Write-ColorOutput "================================================" "Green"
    Write-ColorOutput "   OpenCode Relay Client Setup (Windows)        " "Green"
    Write-ColorOutput "================================================" "Green"
    Write-Host ""
    
    $arch = Detect-Platform
    
    # Check if frpc already installed
    if (Test-Path "$INSTALL_DIR\frpc.exe") {
        Write-ColorOutput "frpc already installed at $INSTALL_DIR\frpc.exe" "Yellow"
        $reinstall = Read-Host "Reinstall? (y/n)"
        if ($reinstall -eq "y") {
            Install-Frpc -Arch $arch
        }
    } else {
        Install-Frpc -Arch $arch
    }
    
    $token = Authenticate
    $deviceId = Register-Device -Token $token
    $localPort = Get-OpenCodePort
    $subdomain = Fetch-FrpcConfig -Token $token -DeviceId $deviceId -LocalPort $localPort
    
    Setup-ScheduledTask -Subdomain $subdomain
    
    Write-Host ""
    Write-ColorOutput "================================================" "Green"
    Write-ColorOutput "   Setup Complete!                              " "Green"
    Write-ColorOutput "================================================" "Green"
    Write-Host ""
    Write-Host "Your OpenCode instance is now accessible at:"
    Write-ColorOutput "  http://$subdomain.liuyao16.dpdns.org" "Yellow"
    Write-Host ""
    Write-Host "Management commands (PowerShell as Admin):"
    Write-Host "  Start:   Start-ScheduledTask -TaskName 'OpenCodeRelay'"
    Write-Host "  Stop:    Stop-ScheduledTask -TaskName 'OpenCodeRelay'"
    Write-Host "  Status:  Get-ScheduledTask -TaskName 'OpenCodeRelay'"
    Write-Host ""
    Write-Host "You can now connect to this device using the OpenCode Anywhere app!"
}

# Run main
Main
