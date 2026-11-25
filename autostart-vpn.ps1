# Runs at logon via Task Scheduler: starts the VPN if it was left on.
$root = $PSScriptRoot
$state = Join-Path $root 'state.txt'
if ((Test-Path $state) -and (Get-Content $state -Raw).Trim() -eq 'on') {
    # Wait for the network to come up (max ~2 min).
    $cfg = Get-Content (Join-Path $root 'client.json') -Raw | ConvertFrom-Json
    $server = ($cfg.ssh_addr -split ':')[0]
    for ($i = 0; $i -lt 24; $i++) {
        if (Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue) { break }
        Start-Sleep 5
    }
    & (Join-Path $root 'start-vpn.ps1')
}
