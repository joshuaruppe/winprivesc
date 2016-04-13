@echo off
title Windows XP Privilege Escalation Script
echo.
echo Loading System Information, 3secs...
systeminfo > systeminfo.txt 2> nul
find "KB" systeminfo.txt > hotfix.txt 2> nul
cls
:MENU
echo " _       ___       ____       _       ______         
echo "| |     / (_)___  / __ \_____(_)   __/ ____/_________
echo "| | /| / / / __ \/ /_/ / ___/ / | / / __/ / ___/ ___/
echo "| |/ |/ / / / / / ____/ /  / /| |/ / /___(__  ) /__  
echo "|__/|__/_/_/ /_/_/   /_/  /_/ |___/_____/____/\___/   
echo.
echo Windows Enumeration and Privilege Escalation Script
echo www.joshruppe.com ^| Twitter: @josh_ruppe
echo.

echo 1 - All to Report
echo 2 - Operating System
echo 3 - Storage
echo 4 - Networking
echo 5 - Processess
echo 6 - User Info
echo 7 - Hardware
echo 8 - Exit
echo.
SET /P C=Select^>
echo.
IF %C%==1 GOTO ALL
IF %C%==2 GOTO OS
IF %C%==3 GOTO STORAGE
IF %C%==4 GOTO NETWORK
IF %C%==5 GOTO PROCESSES
IF %C%==6 GOTO USERS
IF %C%==7 GOTO EXIT

:ALL
echo NOT READY YET!

:OS
echo __________________________
echo.
echo      OPERATING SYSTEM 
echo __________________________
echo.
echo [++OS Name]
echo.
for /F "tokens=3-7" %%a IN ('find /i "OS Name:" systeminfo.txt') do set Name=%%a %%b %%c %%d %%e
echo %Name%
echo.
echo [++OS Version]
echo.
for /F "tokens=3-6" %%a IN ('findstr /B /C:"OS Version:" systeminfo.txt') do set Version=%%a %%b %%c %%d
echo %Version%
echo.
echo [++System Architecture]
echo.
for /F "tokens=3-4"  %%a IN ('findstr /B /C:"System Type:" systeminfo.txt') do set Type=%%a %%b
echo %Type%
echo.
echo [++System Boot Time]
echo.
for /F "tokens=4-6" %%a IN ('findstr /B /C:"System Boot Time:" systeminfo.txt') do set UpTime=%%a %%b %%c
echo %UpTime%
echo.
echo [++Page File Location(s)]
echo.
for /F "tokens=4" %%a IN ('findstr /B /C:"Page File Location(s):" systeminfo.txt') do set Page=%%a
echo %Page%
echo.
echo [++Hotfix(s) Installed]
echo.
setlocal enabledelayedexpansion 
for /F "tokens=2" %%a IN ('findstr /v ".TXT" hotfix.txt') do (
  set Hot=%%~a
  echo !Hot!
)
echo.
echo [++Hosts File]
echo.
more c:\WINDOWS\System32\drivers\etc\hosts
echo.
echo [++Networks File]
echo.
more c:\WINDOWS\System32\drivers\etc\networks
echo.
echo [++Running Services]
echo.
net start
echo.
EXIT /B

:STORAGE
echo _________________
echo.
echo      STORAGE 
echo _________________
echo.
echo [++Physical Drives]
net share
echo.
echo [++Network Drives]
echo.
net use
EXIT /B

:NETWORK
echo ____________________
echo.
echo      NETWORKING 
echo ____________________
echo.
echo [++ICONFIG]
ipconfig /allcompartments /all
echo.
echo [++MAC Addresses]
getmac
echo.
echo [++Route]
echo.
route PRINT
echo.
echo [++Netstat]
netstat -ano
echo.
echo [++ARP]
arp -a
echo.
echo [++Firewall Configuration]
netsh firewall show config
echo.
echo [++Domain]
echo.
set userdomain
echo.
EXIT /B

:PROCESSES
echo ___________________
echo.
echo      PROCESSES 
echo ___________________
echo.
echo [++Tasklist]
tasklist /v
echo.
echo [++Drivers Installed]
driverquery /vw
EXIT /B

:USERS
echo ___________________
echo.
echo      USER INFO 
echo ___________________
echo.
echo [++Current User]
echo.
whoami
echo.
echo [++All Users]
net users
echo.
echo [++User Groups]
net localgroup
echo.

EXIT /B

:EXIT
EXIT /B