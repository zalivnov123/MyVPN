# Runs the VPN client for ~18s while pktmon captures traffic to/from the server.
pktmon stop 2>$null
pktmon filter remove 2>$null
pktmon filter add vpncap -i 64.176.74.108
pktmon start --capture --file-name C:\Kimi\vpn\cap.etl | Out-Null
$p = Start-Process -FilePath C:\Kimi\vpn\bin\vpn-client.exe -ArgumentList '-config','C:\Kimi\vpn\configs\client.json' -RedirectStandardError C:\Kimi\vpn\client.log -PassThru
Start-Sleep 18
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Start-Sleep 1
pktmon stop | Out-Null
pktmon filter remove 2>$null
pktmon format C:\Kimi\vpn\cap.etl -o C:\Kimi\vpn\cap.txt | Out-Null
Write-Output "capture done"
