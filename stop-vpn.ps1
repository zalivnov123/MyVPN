# Stops the VPN client, marks state=off (no autostart after reboot),
# and removes stale routes (safe even if already stopped).
$client = Get-Process vpn-client -ErrorAction SilentlyContinue
if ($client) {
    Stop-Process -Name vpn-client -Force
    Start-Sleep -Milliseconds 500
}
'off' | Out-File -Encoding ascii (Join-Path $PSScriptRoot 'state.txt')
# Remove leftover routes in case the client was force-killed
route delete 0.0.0.0 mask 128.0.0.0 10.8.0.1 2>$null | Out-Null
route delete 128.0.0.0 mask 128.0.0.0 10.8.0.1 2>$null | Out-Null
route delete 64.176.74.108 2>$null | Out-Null
