@echo off
title Windows Enumeration and Privilege Escalation Script
echo.
echo Loading System Information, wait a few seconds...
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
echo www.joshruppe.com ^| Bluesky: @joshruppe.com
echo.

echo 1 - All to Report
echo 2 - Operating System
echo 3 - Storage
echo 4 - Networking
echo 5 - Processes
echo 6 - User Info
echo 7 - Privilege Escalation
echo 8 - Exit
echo.
SET "C="
SET /P C=Select^>
echo.
IF "%C%"=="1" GOTO ALL
IF "%C%"=="2" GOTO OS
IF "%C%"=="3" GOTO STORAGE
IF "%C%"=="4" GOTO NETWORK
IF "%C%"=="5" GOTO PROCESSES
IF "%C%"=="6" GOTO USERS
IF "%C%"=="7" GOTO PRIVESC
IF "%C%"=="8" GOTO EXIT
echo Invalid selection, please choose 1-8.
echo.
GOTO MENU

:ALL
echo WinPrivEsc >> report.txt
echo Windows Enumeration and Privilege Escalation Script>> report.txt
echo www.joshruppe.com ^| Bluesky: @joshruppe.com>> report.txt
echo.>> report.txt
echo Report generated: %DATE% %TIME% >> report.txt
echo. >> report.txt
echo __________________________ >> report.txt
echo. >> report.txt
echo      OPERATING SYSTEM >> report.txt
echo __________________________>> report.txt
echo.>> report.txt
echo [++OS Name]>> report.txt
echo.>> report.txt
for /F "tokens=3-7" %%a IN ('find /i "OS Name:" systeminfo.txt') do set Name=%%a %%b %%c %%d %%e>> report.txt
echo %Name%>> report.txt
echo.>> report.txt
echo [++OS Version]>> report.txt
echo.>> report.txt
for /F "tokens=3-6" %%a IN ('findstr /B /C:"OS Version:" systeminfo.txt') do set Version=%%a %%b %%c %%d>> report.txt
echo %Version%>> report.txt
echo.>> report.txt
echo.>> report.txt
echo [++System Architecture]>> report.txt
echo.>> report.txt
for /F "tokens=3-4"  %%a IN ('findstr /B /C:"System Type:" systeminfo.txt') do set Type=%%a %%b>> report.txt
echo %Type%>> report.txt
echo.>> report.txt
echo [++System Boot Time]>> report.txt
echo.>> report.txt
for /F "tokens=4-6" %%a IN ('findstr /B /C:"System Boot Time:" systeminfo.txt') do set UpTime=%%a %%b %%c>> report.txt
echo %UpTime%>> report.txt
echo.>> report.txt
echo [++Page File Location(s)]>> report.txt
echo.>> report.txt
for /F "tokens=4" %%a IN ('findstr /B /C:"Page File Location(s):" systeminfo.txt') do set Page=%%a>> report.txt
echo %Page%>> report.txt
echo.>> report.txt
echo [++Hotfix(s) Installed]>> report.txt
echo.>> report.txt
setlocal enabledelayedexpansion
for /F "tokens=2" %%a IN ('findstr /v ".TXT" hotfix.txt') do (
  set Hot=%%~a
  echo !Hot!>> report.txt
)
endlocal
echo.>> report.txt
echo [++Hosts File]>> report.txt
echo.>> report.txt
more %SystemRoot%\System32\drivers\etc\hosts>> report.txt
echo.>> report.txt
echo [++Networks File]>> report.txt
echo.>> report.txt
more %SystemRoot%\System32\drivers\etc\networks>> report.txt
echo.>> report.txt
echo [++Running Services]>> report.txt
echo.>> report.txt
net start>> report.txt
echo.>> report.txt
echo.>> report.txt
echo _________________>> report.txt
echo.>> report.txt
echo      STORAGE >> report.txt
echo _________________>> report.txt
echo.>> report.txt
echo [++Physical Drives]>> report.txt
net share>> report.txt
echo.>> report.txt
echo [++Network Drives]>> report.txt
echo.>> report.txt
net use>> report.txt
echo.>> report.txt
echo.>> report.txt
echo ____________________>> report.txt
echo.>> report.txt
echo      NETWORKING >> report.txt
echo ____________________>> report.txt
echo.>> report.txt
echo [++ICONFIG]>> report.txt
ipconfig /allcompartments /all>> report.txt
echo.>> report.txt
echo [++MAC Addresses]>> report.txt
getmac>> report.txt
echo.>> report.txt
echo [++Route]>> report.txt
echo.>> report.txt
route PRINT>> report.txt
echo.>> report.txt
echo [++Netstat]>> report.txt
netstat -ano>> report.txt
echo.>> report.txt
echo [++ARP]>> report.txt
arp -a>> report.txt
echo.>> report.txt
echo [++Firewall Configuration]>> report.txt
netsh advfirewall show allprofiles>> report.txt
echo [++Domain]>> report.txt
echo.>> report.txt
set userdomain>> report.txt
echo.>> report.txt
echo.>> report.txt
echo ___________________>> report.txt
echo.>> report.txt
echo      PROCESSES >> report.txt
echo ___________________>> report.txt
echo.>> report.txt
echo [++Tasklist]>> report.txt
tasklist /v>> report.txt
echo.>> report.txt
echo [++Drivers Installed]>> report.txt
driverquery /v>> report.txt
echo.>> report.txt
echo.>> report.txt
echo ___________________>> report.txt
echo.>> report.txt
echo      USER INFO >> report.txt
echo ___________________>> report.txt
echo.>> report.txt
echo [++Current User]>> report.txt
echo.>> report.txt
whoami>> report.txt
echo.>> report.txt
echo [++All Users]>> report.txt
net users>> report.txt
echo.>> report.txt
echo [++User Groups]>> report.txt
net localgroup>> report.txt
echo.>> report.txt
echo.>> report.txt
echo ____________________________>> report.txt
echo.>> report.txt
echo      PRIVILEGE ESCALATION >> report.txt
echo ____________________________>> report.txt
echo.>> report.txt
echo [++User Privileges - look for SeImpersonate/SeAssignPrimaryToken/SeBackup/SeDebug]>> report.txt
echo.>> report.txt
whoami /priv>> report.txt
echo.>> report.txt
echo [++Token Groups and SIDs]>> report.txt
echo.>> report.txt
whoami /groups>> report.txt
echo.>> report.txt
echo [++AlwaysInstallElevated - HKLM (1 = exploitable)]>> report.txt
echo.>> report.txt
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated >> report.txt 2>nul
echo.>> report.txt
echo [++AlwaysInstallElevated - HKCU (1 = exploitable)]>> report.txt
echo.>> report.txt
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated >> report.txt 2>nul
echo.>> report.txt
echo [++Service Binaries Outside Windows Dir - check for writable binaries/dirs]>> report.txt
echo.>> report.txt
setlocal enabledelayedexpansion
for /f "tokens=1,2,*" %%a in ('reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v ImagePath 2^>nul ^| findstr /i "ImagePath"') do (
  set "ip=%%c"
  echo !ip!| findstr /i /v "Windows SystemRoot System32" >nul && echo !ip!>> report.txt
)
endlocal
echo.>> report.txt
echo [++Stored Credentials - cmdkey]>> report.txt
echo.>> report.txt
cmdkey /list>> report.txt
echo.>> report.txt
echo [++Winlogon Autologon Credentials]>> report.txt
echo.>> report.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultDomainName DefaultPassword AutoAdminLogon">> report.txt
echo.>> report.txt
echo [++Scheduled Tasks (non-Microsoft) - look for SYSTEM tasks with writable binaries]>> report.txt
echo.>> report.txt
for /f "tokens=1 delims=," %%t in ('schtasks /query /fo csv /nh 2^>nul ^| findstr /i /v "\\Microsoft\\"') do schtasks /query /tn %%t /fo LIST /v >> report.txt 2>nul
echo.>> report.txt
echo [++Unquoted Service Path Candidates (wmic-free) - spaced path, unquoted, non-Windows]>> report.txt
echo.>> report.txt
setlocal enabledelayedexpansion
for /f "tokens=1,2,*" %%a in ('reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v ImagePath 2^>nul ^| findstr /i "ImagePath"') do (
  set "ip=%%c"
  set noq=!ip:"=!
  if "!ip!"=="!noq!" (
    echo !ip!| findstr /c:" " >nul && echo !ip!| findstr /i /v "Windows" >nul && echo !ip!>> report.txt
  )
)
endlocal
echo.>> report.txt
echo [++Unattend / Sysprep Credential Files]>> report.txt
echo.>> report.txt
for %%f in ("%SystemRoot%\Panther\Unattend.xml" "%SystemRoot%\Panther\Unattend\Unattended.xml" "%SystemRoot%\Panther\Unattended.xml" "%SystemRoot%\System32\Sysprep\sysprep.xml" "%SystemRoot%\System32\Sysprep\sysprep.inf" "%SystemDrive%\unattend.xml") do if exist %%f (
  echo --- %%f --->> report.txt
  type %%f 2>nul | findstr /i "password username useraccount autologon">> report.txt
)
echo.>> report.txt
echo [++Writable Directories in PATH (DLL hijack surface)]>> report.txt
echo.>> report.txt
setlocal enabledelayedexpansion
for %%d in ("%PATH:;=" "%") do (
  set "dir=%%~d"
  if exist "!dir!\" (
    icacls "!dir!" 2>nul | findstr /i "Users:( Everyone:( \Users:(" | findstr /i "(F) (M) (W)" >nul && echo POTENTIALLY WRITABLE: !dir!>> report.txt
  )
)
endlocal
echo.>> report.txt
echo Done, check report.txt
echo.
del systeminfo.txt
del hotfix.txt
EXIT /B

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
endlocal
echo.
echo [++Hosts File]
echo.
more %SystemRoot%\System32\drivers\etc\hosts
echo.
echo [++Networks File]
echo.
more %SystemRoot%\System32\drivers\etc\networks
echo.
echo [++Running Services]
echo.
net start
echo.
del systeminfo.txt
del hotfix.txt
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
del systeminfo.txt
del hotfix.txt
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
netsh advfirewall show allprofiles
echo [++Domain]
echo.
set userdomain
echo.
del systeminfo.txt
del hotfix.txt
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
driverquery /v
del systeminfo.txt
del hotfix.txt
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
del systeminfo.txt
del hotfix.txt
EXIT /B

:PRIVESC
echo ____________________________
echo.
echo      PRIVILEGE ESCALATION
echo ____________________________
echo.
echo [++User Privileges - look for SeImpersonate/SeAssignPrimaryToken/SeBackup/SeDebug]
echo.
whoami /priv
echo.
echo [++Token Groups and SIDs]
echo.
whoami /groups
echo.
echo [++AlwaysInstallElevated - HKLM (1 = exploitable)]
echo.
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
echo.
echo [++AlwaysInstallElevated - HKCU (1 = exploitable)]
echo.
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
echo.
echo [++Service Binaries Outside Windows Dir - check for writable binaries/dirs]
echo.
setlocal enabledelayedexpansion
for /f "tokens=1,2,*" %%a in ('reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v ImagePath 2^>nul ^| findstr /i "ImagePath"') do (
  set "ip=%%c"
  echo !ip!| findstr /i /v "Windows SystemRoot System32" >nul && echo !ip!
)
endlocal
echo.
echo [++Stored Credentials - cmdkey]
echo.
cmdkey /list
echo.
echo [++Winlogon Autologon Credentials]
echo.
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultDomainName DefaultPassword AutoAdminLogon"
echo.
echo [++Scheduled Tasks (non-Microsoft) - look for SYSTEM tasks with writable binaries]
echo.
for /f "tokens=1 delims=," %%t in ('schtasks /query /fo csv /nh 2^>nul ^| findstr /i /v "\\Microsoft\\"') do schtasks /query /tn %%t /fo LIST /v 2>nul
echo.
echo [++Unquoted Service Path Candidates (wmic-free) - spaced path, unquoted, non-Windows]
echo.
setlocal enabledelayedexpansion
for /f "tokens=1,2,*" %%a in ('reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v ImagePath 2^>nul ^| findstr /i "ImagePath"') do (
  set "ip=%%c"
  set noq=!ip:"=!
  if "!ip!"=="!noq!" (
    echo !ip!| findstr /c:" " >nul && echo !ip!| findstr /i /v "Windows" >nul && echo !ip!
  )
)
endlocal
echo.
echo [++Unattend / Sysprep Credential Files]
echo.
for %%f in ("%SystemRoot%\Panther\Unattend.xml" "%SystemRoot%\Panther\Unattend\Unattended.xml" "%SystemRoot%\Panther\Unattended.xml" "%SystemRoot%\System32\Sysprep\sysprep.xml" "%SystemRoot%\System32\Sysprep\sysprep.inf" "%SystemDrive%\unattend.xml") do if exist %%f (
  echo --- %%f ---
  type %%f 2>nul | findstr /i "password username useraccount autologon"
)
echo.
echo [++Writable Directories in PATH (DLL hijack surface)]
echo.
setlocal enabledelayedexpansion
for %%d in ("%PATH:;=" "%") do (
  set "dir=%%~d"
  if exist "!dir!\" (
    icacls "!dir!" 2>nul | findstr /i "Users:( Everyone:( \Users:(" | findstr /i "(F) (M) (W)" >nul && echo POTENTIALLY WRITABLE: !dir!
  )
)
endlocal
echo.
del systeminfo.txt
del hotfix.txt
EXIT /B

:EXIT
del systeminfo.txt
del hotfix.txt
EXIT /B
