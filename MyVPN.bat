@echo off
title MyVPN
set "DIR=%~dp0"

:menu
cls
echo ==============================
echo            MyVPN
echo ==============================
echo.
echo   1. Запустить
echo   2. Проверить статус
echo   3. Выключить
echo   4. Выход
echo.
set /p choice="Выбор: "

if "%choice%"=="1" goto start
if "%choice%"=="2" goto status
if "%choice%"=="3" goto stop
if "%choice%"=="4" exit /b
goto menu

:start
tasklist /FI "IMAGENAME eq vpn-client.exe" | findstr /I /C:"vpn-client.exe" >nul
if not errorlevel 1 (
    echo.
    echo Уже запущен.
    pause
    goto menu
)
echo.
echo Запускаю... (подтвердите запрос администратора)
powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','%DIR%scripts\start-vpn.ps1'"
%SystemRoot%\System32\timeout.exe /t 4 >nul
tasklist /FI "IMAGENAME eq vpn-client.exe" | findstr /I /C:"vpn-client.exe" >nul
if errorlevel 1 (
    echo Не удалось запустить. Подробности в client.log
) else (
    echo VPN запущен!
)
pause
goto menu

:status
echo.
tasklist /FI "IMAGENAME eq vpn-client.exe" | findstr /I /C:"vpn-client.exe" >nul
if errorlevel 1 (
    echo Процесс: НЕ ЗАПУЩЕН
) else (
    echo Процесс: РАБОТАЕТ
)
echo.
echo Ваш текущий внешний IP:
curl -4 -s --max-time 8 ifconfig.me
echo.
echo.
echo Если это 64.176.74.108 - трафик идёт через VPN (Варшава).
echo Если другой - VPN не активен, трафик идёт напрямую.
pause
goto menu

:stop
echo.
echo Выключаю... (подтвердите запрос администратора)
powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','%DIR%scripts\stop-vpn.ps1'"
tasklist /FI "IMAGENAME eq vpn-client.exe" | findstr /I /C:"vpn-client.exe" >nul
if errorlevel 1 (
    echo VPN выключен.
) else (
    echo Не удалось остановить - попробуйте ещё раз.
)
pause
goto menu
