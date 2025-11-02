# WSL Network Setup Script for Windows
# Run this in PowerShell as Administrator
# This configures port forwarding from Windows to WSL for syslog

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WSL Network Setup for Firewall IDS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get WSL IP address
Write-Host "[+] Detecting WSL IP address..." -ForegroundColor Yellow
$wslIP = (wsl hostname -I).Trim()
if ($wslIP) {
    Write-Host "  -> WSL IP: $wslIP" -ForegroundColor Green
} else {
    Write-Host "  ! Could not detect WSL IP. Make sure WSL is running." -ForegroundColor Red
    exit 1
}

# Get Windows host IP on the network
Write-Host "[+] Finding Windows host IP address..." -ForegroundColor Yellow
$networkIPs = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notlike "127.*" -and 
    $_.IPAddress -notlike "169.254.*" -and
    $_.IPAddress -notlike "$wslIP*"
} | Select-Object -ExpandProperty IPAddress

if ($networkIPs) {
    Write-Host "  -> Available network IPs:" -ForegroundColor Green
    $networkIPs | ForEach-Object { Write-Host "     $_" -ForegroundColor White }
    $selectedIP = $networkIPs[0]
    Write-Host "  -> Using: $selectedIP" -ForegroundColor Green
} else {
    Write-Host "  ! Could not find network IP. You may need to connect to a network." -ForegroundColor Red
    $selectedIP = Read-Host "Enter your Windows IP address"
}

Write-Host ""
Write-Host "[+] Configuring port forwarding..." -ForegroundColor Yellow

# Remove existing port proxy rules for port 514
netsh interface portproxy delete v4tov4 listenport=514 listenaddress=0.0.0.0 2>$null
netsh interface portproxy delete v4tov4 listenport=514 listenaddress=$selectedIP 2>$null

# Add port forwarding from Windows to WSL
netsh interface portproxy add v4tov4 listenport=514 listenaddress=0.0.0.0 connectport=514 connectaddress=$wslIP

if ($LASTEXITCODE -eq 0) {
    Write-Host "  -> Port forwarding configured: 0.0.0.0:514 -> $wslIP:514" -ForegroundColor Green
} else {
    Write-Host "  ! Failed to configure port forwarding" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[+] Configuring Windows Firewall..." -ForegroundColor Yellow

# Add firewall rules for TCP
$tcpRule = Get-NetFirewallRule -DisplayName "WSL Syslog TCP" -ErrorAction SilentlyContinue
if (-not $tcpRule) {
    New-NetFirewallRule -DisplayName "WSL Syslog TCP" `
                       -Direction Inbound `
                       -LocalPort 514 `
                       -Protocol TCP `
                       -Action Allow | Out-Null
    Write-Host "  -> Added TCP firewall rule" -ForegroundColor Green
} else {
    Write-Host "  -> TCP firewall rule already exists" -ForegroundColor Yellow
}

# Add firewall rules for UDP
$udpRule = Get-NetFirewallRule -DisplayName "WSL Syslog UDP" -ErrorAction SilentlyContinue
if (-not $udpRule) {
    New-NetFirewallRule -DisplayName "WSL Syslog UDP" `
                       -Direction Inbound `
                       -LocalPort 514 `
                       -Protocol UDP `
                       -Action Allow | Out-Null
    Write-Host "  -> Added UDP firewall rule" -ForegroundColor Green
} else {
    Write-Host "  -> UDP firewall rule already exists" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration Summary:" -ForegroundColor White
Write-Host "  Windows Host IP: $selectedIP" -ForegroundColor Yellow
Write-Host "  WSL IP:          $wslIP" -ForegroundColor Yellow
Write-Host "  Port Forwarding: 0.0.0.0:514 -> $wslIP:514" -ForegroundColor Yellow
Write-Host ""
Write-Host "Client Configuration:" -ForegroundColor White
Write-Host "  Clients should forward syslog to: $selectedIP:514" -ForegroundColor Green
Write-Host ""
Write-Host "To verify port forwarding:" -ForegroundColor White
Write-Host "  netsh interface portproxy show all" -ForegroundColor Gray
Write-Host ""
Write-Host "To remove port forwarding later:" -ForegroundColor White
Write-Host "  netsh interface portproxy delete v4tov4 listenport=514 listenaddress=0.0.0.0" -ForegroundColor Gray
Write-Host ""

