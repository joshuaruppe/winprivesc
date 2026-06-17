@echo off
setlocal enabledelayedexpansion
title Windows Enumeration Script (Lab)

rem ============================================================
rem  enum.bat - Windows host enumeration for training labs
rem  Usage: enum.bat [quiet^|medium^|loud]      (default: quiet)
rem
rem    quiet  - registry/file reads + cmd internals only; minimal
rem             process spawns; avoids monitored discovery binaries
rem             (net / tasklist / netstat / systeminfo ...)
rem    medium - adds standard single-spawn discovery commands
rem             (systeminfo, net, getmac, route, netstat, arp, netsh)
rem    loud   - adds heavy/verbose collectors (driverquery, full
rem             hotfix list, gpresult)
rem
rem  Enumeration only - reads system state, changes nothing.
rem ============================================================

rem ---- parse noise level ----
set "LEVEL=%~1"
if not defined LEVEL set "LEVEL=quiet"
set "TIER=0"
if /i "%LEVEL%"=="quiet"  set "TIER=1"
if /i "%LEVEL%"=="medium" set "TIER=2"
if /i "%LEVEL%"=="loud"   set "TIER=3"
if "%TIER%"=="0" (
  echo Invalid level "%LEVEL%".
  echo Usage: %~nx0 [quiet^|medium^|loud]   ^(default: quiet^)
  endlocal
  exit /b 1
)

set "REPORT=enum_report.txt"

echo " _       ___       ____       _       ______
echo "| |     / (_)___  / __ \_____(_)   __/ ____/_________
echo "| | /| / / / __ \/ /_/ / ___/ / | / / __/ / ___/ ___/
echo "| |/ |/ / / / / / ____/ /  / /| |/ / /___(__  ) /__
echo "|__/|__/_/_/ /_/_/   /_/  /_/ |___/_____/____/\___/
echo.
echo Windows Enumeration Script  ^|  level: %LEVEL%
echo www.joshruppe.com ^| Bluesky: @joshruppe.com
echo.
echo [*] Writing report to %REPORT% ...

> "%REPORT%" call :BUILD

if exist systeminfo.txt del systeminfo.txt
if exist hotfix.txt del hotfix.txt

echo [*] Done. Report saved to %REPORT%
endlocal
exit /b 0

rem ============================================================
:BUILD
echo WinPrivEsc - Enumeration Report
echo www.joshruppe.com ^| Bluesky: @joshruppe.com
echo Report generated: %DATE% %TIME%
echo Noise level: %LEVEL%
echo.

echo __________________________
echo      OPERATING SYSTEM
echo __________________________
echo.
echo [*] Operating system >&2
if %TIER% geq 2 (
  systeminfo > systeminfo.txt 2>nul
  find "KB" systeminfo.txt > hotfix.txt 2>nul
  echo [++OS Name]
  for /F "tokens=3-7" %%a in ('find /i "OS Name:" systeminfo.txt') do echo %%a %%b %%c %%d %%e
  echo.
  echo [++OS Version]
  for /F "tokens=3-6" %%a in ('findstr /B /C:"OS Version:" systeminfo.txt') do echo %%a %%b %%c %%d
  echo.
  echo [++System Architecture]
  for /F "tokens=3-4" %%a in ('findstr /B /C:"System Type:" systeminfo.txt') do echo %%a %%b
  echo.
  echo [++System Boot Time]
  for /F "tokens=4-6" %%a in ('findstr /B /C:"System Boot Time:" systeminfo.txt') do echo %%a %%b %%c
  echo.
  echo [++Page File Location(s)]
  for /F "tokens=4" %%a in ('findstr /B /C:"Page File Location(s):" systeminfo.txt') do echo %%a
  echo.
  echo [++Hotfix(s) Installed]
  for /F "tokens=2" %%a in ('findstr /v ".TXT" hotfix.txt') do echo %%~a
  echo.
) else (
  echo [++OS Name]
  for /F "tokens=2,*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName 2^>nul ^| findstr /i ProductName') do echo %%b
  echo.
  echo [++OS Build]
  for /F "tokens=2,*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuild 2^>nul ^| findstr /i CurrentBuild') do echo Build %%b
  for /F "tokens=2,*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v DisplayVersion 2^>nul ^| findstr /i DisplayVersion') do echo Version %%b
  echo.
  echo [++System Architecture]
  echo %PROCESSOR_ARCHITECTURE%
  echo.
  echo [++Hotfixes]
  echo (skipped in quiet mode - run 'enum.bat medium' for systeminfo/hotfix list)
  echo.
)
echo [++Hosts File]
type %SystemRoot%\System32\drivers\etc\hosts 2>nul
echo.
echo [++Networks File]
type %SystemRoot%\System32\drivers\etc\networks 2>nul
echo.
if %TIER% geq 2 (
  echo [++Running Services]
  net start
  echo.
)

echo _________________
echo      STORAGE
echo _________________
echo.
echo [*] Storage / shares >&2
if %TIER% geq 2 (
  echo [++Physical/Shared Drives]
  net share
  echo.
  echo [++Network Drives]
  net use
  echo.
) else (
  echo [++Logical Drives]
  fsutil fsinfo drives 2>nul
  echo.
)

echo ____________________
echo      NETWORKING
echo ____________________
echo.
echo [*] Networking >&2
echo [++IP Configuration]
ipconfig /allcompartments /all
echo.
echo [++Domain / Host]
echo COMPUTERNAME=%COMPUTERNAME%
echo USERDOMAIN=%USERDOMAIN%
echo USERDNSDOMAIN=%USERDNSDOMAIN%
echo LOGONSERVER=%LOGONSERVER%
echo.
if %TIER% geq 2 (
  echo [++MAC Addresses]
  getmac
  echo.
  echo [++Route]
  route PRINT
  echo.
  echo [++Netstat]
  netstat -ano
  echo.
  echo [++ARP]
  arp -a
  echo.
  echo [++Firewall Configuration]
  netsh advfirewall show allprofiles
  echo.
)

echo ___________________
echo      PROCESSES
echo ___________________
echo.
echo [*] Processes >&2
if %TIER% geq 2 (
  echo [++Tasklist]
  tasklist /v
  echo.
) else (
  echo [++Processes]
  echo (skipped in quiet mode - run 'enum.bat medium' for tasklist)
  echo.
)
if %TIER% geq 3 (
  echo [++Drivers Installed]
  driverquery /v
  echo.
)

echo ___________________
echo      USER INFO
echo ___________________
echo.
echo [*] Users >&2
echo [++Current User]
if %TIER% geq 2 (
  whoami
) else (
  echo %USERDOMAIN%\%USERNAME%
)
echo.
echo [++Local User Profiles]
for /F "tokens=2,*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" /s /v ProfileImagePath 2^>nul ^| findstr /i /c:"C:\Users"') do echo %%b
echo.
if %TIER% geq 2 (
  echo [++All Users]
  net users
  echo.
  echo [++User Groups]
  net localgroup
  echo.
)
goto :EOF
