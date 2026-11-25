# Starts the VPN client hidden, logging to client.log; own errors to start.log
# Marks state=on so the VPN auto-starts after reboot (see autostart-vpn.ps1).
$root = $PSScriptRoot
$exe = Join-Path $root 'vpn-client.exe'
$cfg = Join-Path $root 'client.json'
$log = Join-Path $root 'client.log'
$startLog = Join-Path $root 'start.log'
try {
    $p = Start-Process -FilePath $exe -ArgumentList '-config', "`"$cfg`"" -RedirectStandardError $log -WindowStyle Hidden -PassThru -ErrorAction Stop
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') started pid=$($p.Id)" | Out-File -Encoding utf8 $startLog
    'on' | Out-File -Encoding ascii (Join-Path $root 'state.txt')
} catch {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') FAILED: $_" | Out-File -Encoding utf8 $startLog
}

# Register the logon autostart task once (we are elevated here).
$taskName = 'MyVPN-Autostart'
if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$root\autostart-vpn.ps1`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description 'Start MyVPN at logon if it was left on' | Out-Null
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') autostart task registered" | Out-File -Encoding utf8 -Append $startLog
    } catch {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') autostart task FAILED: $_" | Out-File -Encoding utf8 -Append $startLog
    }
}
