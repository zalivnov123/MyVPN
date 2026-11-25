# Stops the VPN client and removes stale routes (safe even if already stopped)
$client = Get-Process vpn-client -ErrorAction SilentlyContinue
if ($client) {
    Stop-Process -Name vpn-client -Force
    Start-Sleep -Milliseconds 500
}
# Remove leftover routes in case the client was force-killed
route delete 0.0.0.0 mask 128.0.0.0 10.8.0.1 2>$null | Out-Null
route delete 128.0.0.0 mask 128.0.0.0 10.8.0.1 2>$null | Out-Null
route delete 64.176.74.108 2>$null | Out-Null
