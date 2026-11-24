# Starts the VPN client hidden, logging to client.log
$root = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $root 'bin\vpn-client.exe'
$cfg = Join-Path $root 'configs\client.json'
$log = Join-Path $root 'client.log'
Start-Process -FilePath $exe -ArgumentList '-config', "`"$cfg`"" -RedirectStandardError $log -WindowStyle Hidden
