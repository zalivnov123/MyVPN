# Starts the VPN client hidden, logging to client.log; own errors to start.log
$root = $PSScriptRoot
$exe = Join-Path $root 'vpn-client.exe'
$cfg = Join-Path $root 'client.json'
$log = Join-Path $root 'client.log'
$startLog = Join-Path $root 'start.log'
try {
    $p = Start-Process -FilePath $exe -ArgumentList '-config', "`"$cfg`"" -RedirectStandardError $log -WindowStyle Hidden -PassThru -ErrorAction Stop
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') started pid=$($p.Id)" | Out-File -Encoding utf8 $startLog
} catch {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') FAILED: $_" | Out-File -Encoding utf8 $startLog
}
