$in = "$env:TEMP\in.txt"
$out = "$env:TEMP\out.txt"
"4`r`n" | Out-File -Encoding ascii $in
$p = Start-Process cmd -ArgumentList '/c','C:\Kimi\vpn\MyVPN.bat' -RedirectStandardInput $in -RedirectStandardOutput $out -Wait -PassThru -WindowStyle Hidden
Write-Output ("exit=" + $p.ExitCode)
