@echo off
title Windows XP Privilege Escalation Script
echo Loading System Information, 3secs...
systeminfo > systeminfo.txt 2> nul
wmic qfe list > hotfix.txt 2> nul
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
IF %C%==7 GOTO HARDWARE
IF %C%==8 GOTO EXIT

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
for /F "tokens=5 delims=KB" %%a IN ('hotfix.txt') do set Hot=%%a
echo %Hot%
echo.
echo [++Hosts File]
echo.
more c:\WINDOWS\System32\drivers\etc\hosts
echo.
EXIT /B

:STORAGE
echo [++Physical Drives]
net share
echo.
echo [++Network Drives]
net use

:NETWORK
echo ####################
echo #### NETWORKING ####
echo ####################
echo.
echo [++ICONFIG]
ipconfig /allcompartments /all
echo.
echo [++MAC Address]
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

DOMAIN
EXIT /B

:PROCESSES
echo ###################
echo #### PROCESSES ####
echo ###################

:USERS
echo ###################
echo #### USER INFO ####
echo ###################

:HARDWARE
echo ##################
echo #### HARDWARE ####
echo ##################

:EXIT
EXIT /B