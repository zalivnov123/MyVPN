# Starts the VPN client hidden, logging to client.log; own errors to start.log
$root = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $root 'bin\vpn-client.exe'
$cfg = Join-Path $root 'configs\client.json'
$log = Join-Path $root 'client.log'
$startLog = Join-Path $root 'start.log'
try {
    $p = Start-Process -FilePath $exe -ArgumentList '-config', "`"$cfg`"" -RedirectStandardError $log -WindowStyle Hidden -PassThru -ErrorAction Stop
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') started pid=$($p.Id)" | Out-File -Encoding utf8 $startLog
} catch {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') FAILED: $_" | Out-File -Encoding utf8 $startLog
}
