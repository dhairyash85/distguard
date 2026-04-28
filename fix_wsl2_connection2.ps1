$remoteport = 5000
$found_wsl_ip = (wsl hostname -I).Trim()

if (-not $found_wsl_ip) {
    Write-Error "Could not determine WSL2 IP address. enhancing..."
    exit 1
}

Write-Host "WSL2 IP found: $found_wsl_ip"

# Remove existing rules to avoid duplicates
iex "netsh interface portproxy delete v4tov4 listenport=$remoteport listenaddress=0.0.0.0"
Remove-NetFirewallRule -DisplayName "Allow WSL2 Port $remoteport" -ErrorAction SilentlyContinue

# Add Port Proxy
$connectaddress = $found_wsl_ip
$listenaddress = "0.0.0.0"
iex "netsh interface portproxy add v4tov4 listenport=$remoteport listenaddress=$listenaddress connectport=$remoteport connectaddress=$connectaddress"

# Add Firewall Rule
New-NetFirewallRule -DisplayName "Allow WSL2 Port $remoteport" -Direction Inbound -LocalPort $remoteport -Protocol TCP -Action Allow

Write-Host "Port forwarding configured successfully."
Write-Host "Forwarding 0.0.0.0:$remoteport -> $found_wsl_ip`:$remoteport"
Write-Host ""
Write-Host "Please use one of the following IP addresses on your OTHER machine's config.toml:"
ipconfig | Select-String "IPv4" -Context 1
