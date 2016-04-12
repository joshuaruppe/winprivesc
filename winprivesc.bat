@echo off
title Windows XP Privilege Escalation Script
cls
:MENU
echo " _       ___       ____       _       ______         
echo "| |     / (_)___  / __ \_____(_)   __/ ____/_________
echo "| | /| / / / __ \/ /_/ / ___/ / | / / __/ / ___/ ___/
echo "| |/ |/ / / / / / ____/ /  / /| |/ / /___(__  ) /__  
echo "|__/|__/_/_/ /_/_/   /_/  /_/ |___/_____/____/\___/   
echo.
echo "Windows Enumeration and Privilege Escalation Script
echo "www.joshruppe.com | Twitter: @josh_ruppe
echo.
echo 1 - Run All Scripts
echo 2 - Operating System
echo 3 - Networking
echo 4 - Processess
echo 5 - User Info
echo 6 - Hardware
echo 7 - Exit
echo.
SET /P M=Type 1, 2, or 3 then press ENTER:
IF %M%==1 GOTO ALL
IF %M%==2 GOTO OS
IF %M%==3 GOTO NETWORK
IF %M%==4 GOTO PROCESSES
IF %M%==5 GOTO USERS
IF %M%==6 GOTO HARDWARE
IF %M%==7 GOTO EXIT

:ALL
GOTO OS
GOTO NETWORK

:OS
echo ##########################
echo #### OPERATING SYSTEM ####
echo ##########################
echo.
echo [++Windows Version]
ver
echo.
echo [++System Info]
systeminfo
echo [++Hostname]
hostname
echo.
echo [++Physical Drives]
net share
echo.
echo [++Network Drives]
net use
echo.
echo [++Hosts File]
more c:\WINDOWS\System32\drivers\etc\hosts
EXIT /B

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