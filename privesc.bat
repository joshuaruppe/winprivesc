@echo off
setlocal enabledelayedexpansion
title Windows Privilege Escalation Vector Checks (Lab)

rem ============================================================
rem  privesc.bat - Windows privilege-escalation VECTOR checks
rem  Usage: privesc.bat [quiet^|medium^|loud]    (default: quiet)
rem
rem    quiet  - targeted registry/file reads only. No monitored
rem             discovery binaries, no credential-store binaries,
rem             no per-item bursts:
rem               AlwaysInstallElevated (both keys), service
rem               ImagePath/unquoted-path enum, PATH listing, UAC
rem               config, Run/RunOnce listing, LAPS/WSUS, SAM/SYSTEM
rem               hive backups, environment-variable secrets.
rem    medium - adds single-spawn + credential-in-reg/file reads:
rem               whoami /priv + /groups (annotated), Winlogon
rem               autologon, unattend/sysprep, GPP cpassword,
rem               PowerShell history, PuTTY/WinSCP/RDP/VNC sessions,
rem               installed software, Defender status.
rem    loud   - adds credential-store + slow sweeps:
rem               cmdkey, full non-Microsoft scheduled-task detail,
rem               saved Wi-Fi keys, registry password sweep.
rem
rem  Enumeration only - reads system state and reports likely
rem  escalation VECTORS. It performs no exploitation and changes
rem  nothing on the host.
rem
rem  NOTE: writability / ACL CONFIRMATION (which service binaries,
rem  PATH dirs, autorun and task targets you can actually write,
rem  plus service DACLs) lives in the PowerShell companion
rem  privesc.ps1 - icacls in a cmd loop is unreliable. This script
rem  LISTS the candidates; privesc.ps1 CONFIRMS them via Get-Acl.
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

set "REPORT=privesc_report.txt"

echo " _       ___       ____       _       ______
echo "| |     / (_)___  / __ \_____(_)   __/ ____/_________
echo "| | /| / / / __ \/ /_/ / ___/ / | / / __/ / ___/ ___/
echo "| |/ |/ / / / / / ____/ /  / /| |/ / /___(__  ) /__
echo "|__/|__/_/_/ /_/_/   /_/  /_/ |___/_____/____/\___/
echo.
echo Privilege Escalation Vector Checks  ^|  level: %LEVEL%
echo www.joshruppe.com ^| Bluesky: @joshruppe.com
echo.
echo [*] Writing report to %REPORT% ...

> "%REPORT%" call :BUILD

if exist svc.txt del svc.txt
if exist priv.txt del priv.txt

echo [*] Done. Report saved to %REPORT%
endlocal
exit /b 0

rem ============================================================
rem  Report body. stdout is redirected to the report; status
rem  lines use >&2 so they show on the console in real time.
rem  Tier-gated sections are dispatched as subroutines so that
rem  literal parentheses in their output never break an if-block.
rem ============================================================
:BUILD
echo WinPrivEsc - Privilege Escalation Vector Report
echo www.joshruppe.com ^| Bluesky: @joshruppe.com
echo Report generated: %DATE% %TIME%
echo Noise level: %LEVEL%
echo.
echo Enumeration only - reads system state and reports likely escalation
echo vectors. No exploitation is performed and nothing on the host changes.
echo Writability / ACL confirmation is done by the companion privesc.ps1.
echo.

rem ---- quiet tier (always) ----
call :SEC_AIE
call :SEC_SERVICES
call :SEC_PATH
call :SEC_UAC
call :SEC_AUTORUN
call :SEC_POLICY
call :SEC_HIVEBAK
call :SEC_ENV

rem ---- medium tier ----
if %TIER% geq 2 (
  call :SEC_TOKENS
  call :SEC_WINLOGON
  call :SEC_UNATTEND
  call :SEC_GPP
  call :SEC_PSHISTORY
  call :SEC_APPCREDS
  call :SEC_SOFTWARE
  call :SEC_DEFENDER
) else call :SKIP_MEDIUM

rem ---- loud tier ----
if %TIER% geq 3 (
  call :SEC_CMDKEY
  call :SEC_SCHTASKS
  call :SEC_WIFI
  call :SEC_REGPWSWEEP
) else call :SKIP_LOUD
goto :EOF

rem ================= quiet tier =================
:SEC_AIE
echo ____________________________
echo      ALWAYSINSTALLELEVATED
echo ____________________________
echo.
echo [*] AlwaysInstallElevated policy >&2
set "AIE_HKLM=(unset)"
set "AIE_HKCU=(unset)"
for /f "tokens=3" %%v in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2^>nul ^| findstr /i AlwaysInstallElevated') do set "AIE_HKLM=%%v"
for /f "tokens=3" %%v in ('reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2^>nul ^| findstr /i AlwaysInstallElevated') do set "AIE_HKCU=%%v"
echo HKLM AlwaysInstallElevated = !AIE_HKLM!
echo HKCU AlwaysInstallElevated = !AIE_HKCU!
if /i "!AIE_HKLM!"=="0x1" if /i "!AIE_HKCU!"=="0x1" echo [!] EXPLOITABLE: both keys are 0x1 - any user can install an MSI as SYSTEM
echo (vector requires BOTH HKLM and HKCU set to 0x1; a single key does nothing)
echo.
goto :EOF

:SEC_SERVICES
echo ____________________________
echo      SERVICE MISCONFIGURATIONS
echo ____________________________
echo.
echo [*] Service binary / path checks >&2
rem one reg read, filtered to non-Windows ImagePaths in a single
rem findstr chain; per-row tests below are pure string ops (no
rem findstr per service, so the quiet tier stays quiet).
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v ImagePath 2>nul | findstr /i "ImagePath" | findstr /i /v "Windows SystemRoot System32" > svc.txt
echo [++Service Binaries Outside Windows Dir - review for writable binary/dir (privesc.ps1 tests writability)]
for /f "tokens=1,2,*" %%a in (svc.txt) do echo %%c
echo.
echo [++Unquoted Service Path Candidates - unquoted, spaced, non-Windows, non-driver]
echo (exploitable only if you can also WRITE to an intermediate directory)
for /f "tokens=1,2,*" %%a in (svc.txt) do (
  set "ip=%%c"
  set noq=!ip:"=!
  if "!ip!"=="!noq!" (
    set "t1=!ip:.sys=!"
    set "t2=!ip:\??\=!"
    if "!ip!"=="!t1!" if "!ip!"=="!t2!" (
      set "nospace=!ip: =!"
      if not "!ip!"=="!nospace!" echo !ip!
    )
  )
)
echo.
goto :EOF

:SEC_PATH
echo ____________________________
echo      PATH DIRECTORIES
echo ____________________________
echo.
echo [*] PATH directories (DLL hijack surface) >&2
echo [++Directories on PATH]
for %%d in ("%PATH:;=" "%") do (
  set "dir=%%~d"
  if defined dir if exist "!dir!\" echo !dir!
)
echo (writability of these directories is tested by privesc.ps1)
echo.
goto :EOF

:SEC_UAC
echo ____________________________
echo      UAC CONFIGURATION
echo ____________________________
echo.
echo [*] UAC configuration >&2
echo [++UAC policy values]
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 2>nul | findstr /i EnableLUA
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin 2>nul | findstr /i ConsentPromptBehaviorAdmin
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy 2>nul | findstr /i LocalAccountTokenFilterPolicy
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken 2>nul | findstr /i FilterAdministratorToken
echo (EnableLUA=0 means UAC off; LocalAccountTokenFilterPolicy=1 disables remote-UAC filtering = lateral/privesc relevant)
echo.
goto :EOF

:SEC_AUTORUN
echo ____________________________
echo      AUTORUN ENTRIES
echo ____________________________
echo.
echo [*] Autorun (Run/RunOnce) entries >&2
echo [++HKLM Run]
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul | findstr /i "REG_"
echo [++HKLM RunOnce]
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 2>nul | findstr /i "REG_"
echo [++HKLM Run (WOW6432Node)]
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" 2>nul | findstr /i "REG_"
echo [++HKCU Run]
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul | findstr /i "REG_"
echo [++HKCU RunOnce]
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 2>nul | findstr /i "REG_"
echo [++Policies Explorer Run]
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" 2>nul | findstr /i "REG_"
echo (writability of these target binaries is tested by privesc.ps1)
echo.
goto :EOF

:SEC_POLICY
echo ____________________________
echo      AGENT / UPDATE POLICY
echo ____________________________
echo.
echo [*] LAPS / WSUS config >&2
echo [++LAPS (AdmPwd) presence]
reg query "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" 2>nul
echo [++WSUS Update Server (flag http:// = update MITM to SYSTEM)]
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer 2>nul | findstr /i WUServer
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v UseWUServer 2>nul | findstr /i UseWUServer
echo.
goto :EOF

:SEC_HIVEBAK
echo ____________________________
echo      REGISTRY HIVE BACKUPS
echo ____________________________
echo.
echo [*] SAM/SYSTEM hive backups on disk >&2
echo [++Readable hive copies (offline hash dump if present/readable)]
dir /b "%SystemRoot%\Repair\SAM" "%SystemRoot%\Repair\SYSTEM" "%SystemRoot%\System32\config\RegBack\SAM" "%SystemRoot%\System32\config\RegBack\SYSTEM" 2>nul
echo.
goto :EOF

:SEC_ENV
echo ____________________________
echo      ENVIRONMENT SECRETS
echo ____________________________
echo.
echo [*] Environment variables for secrets >&2
echo [++Env vars matching pass/key/token/secret/cred/api/aws]
set | findstr /i "pass key token secret cred api_ aws_"
echo.
goto :EOF

rem ================= medium tier =================
:SEC_TOKENS
echo ____________________________
echo      TOKEN PRIVILEGES
echo ____________________________
echo.
echo [*] Token privileges and groups >&2
echo [++User Privileges]
whoami /priv > priv.txt 2>nul
type priv.txt
echo.
echo [++Notable privilege guidance]
findstr /i "SeImpersonate SeAssignPrimaryToken" priv.txt >nul && echo [!] SeImpersonate/SeAssignPrimaryToken -^> Potato/PrintSpoofer to SYSTEM
findstr /i "SeBackup SeRestore" priv.txt >nul && echo [!] SeBackup/SeRestore -^> read SAM/SYSTEM or overwrite protected files
findstr /i "SeDebug" priv.txt >nul && echo [!] SeDebug -^> inject into a SYSTEM process
findstr /i "SeTakeOwnership" priv.txt >nul && echo [!] SeTakeOwnership -^> seize objects/files then rewrite ACLs
findstr /i "SeLoadDriver" priv.txt >nul && echo [!] SeLoadDriver -^> load a vulnerable signed driver
findstr /i "SeManageVolume" priv.txt >nul && echo [!] SeManageVolume -^> arbitrary file write via volume management
echo.
echo [++Token Groups and SIDs]
whoami /groups
echo.
goto :EOF

:SEC_WINLOGON
echo ____________________________
echo      STORED CREDENTIALS (REG/FILE)
echo ____________________________
echo.
echo [*] Credential vectors (registry/files) >&2
echo [++Winlogon Autologon Credentials]
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultDomainName DefaultPassword AutoAdminLogon"
echo (creds set via netplwiz/Sysinternals Autologon live as an LSA secret; an empty DefaultPassword is not proof of safety)
echo.
goto :EOF

:SEC_UNATTEND
echo [++Unattend / Sysprep Credential Files]
for %%f in ("%SystemRoot%\Panther\Unattend.xml" "%SystemRoot%\Panther\Unattend\Unattended.xml" "%SystemRoot%\Panther\Unattended.xml" "%SystemRoot%\System32\Sysprep\sysprep.xml" "%SystemRoot%\System32\Sysprep\sysprep.inf" "%SystemDrive%\unattend.xml") do if exist %%f (
  echo --- %%f ---
  type %%f 2>nul | findstr /i "password username useraccount autologon"
)
echo.
goto :EOF

:SEC_GPP
echo ____________________________
echo      GROUP POLICY PREFERENCES
echo ____________________________
echo.
echo [*] GPP cpassword search >&2
echo [++Local GPP cache XML containing cpassword]
findstr /s /i cpassword "%ALLUSERSPROFILE%\Microsoft\Group Policy\History\*.xml" 2>nul
if defined USERDNSDOMAIN (
  echo [++Domain SYSVOL XML containing cpassword]
  findstr /s /i cpassword "\\%USERDNSDOMAIN%\SYSVOL\*.xml" 2>nul
)
echo.
goto :EOF

:SEC_PSHISTORY
echo ____________________________
echo      POWERSHELL HISTORY
echo ____________________________
echo.
echo [*] PowerShell console history >&2
echo [++ConsoleHost_history.txt (current user)]
type "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul
echo.
goto :EOF

:SEC_APPCREDS
echo ____________________________
echo      SAVED APP SESSIONS
echo ____________________________
echo.
echo [*] Saved sessions (PuTTY/WinSCP/RDP/VNC) >&2
echo [++PuTTY sessions]
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s 2>nul | findstr /i "SimonTatham HostName ProxyUsername ProxyPassword PortNumber"
echo [++WinSCP sessions]
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" /s 2>nul | findstr /i "Sessions HostName UserName Password"
echo [++RDP saved servers]
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s 2>nul | findstr /i "Servers UsernameHint"
echo [++Saved .rdp files]
dir /s /b "%USERPROFILE%\*.rdp" 2>nul
echo [++VNC passwords]
reg query "HKCU\Software\ORL\WinVNC3" /v Password 2>nul | findstr /i Password
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v Password 2>nul | findstr /i Password
reg query "HKCU\Software\TightVNC\Server" 2>nul | findstr /i Password
echo.
goto :EOF

:SEC_SOFTWARE
echo ____________________________
echo      INSTALLED SOFTWARE
echo ____________________________
echo.
echo [*] Installed software (exploit mapping) >&2
echo [++Uninstall entries - DisplayName]
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /v DisplayName 2>nul | findstr /i DisplayName
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s /v DisplayName 2>nul | findstr /i DisplayName
echo.
goto :EOF

:SEC_DEFENDER
echo ____________________________
echo      DEFENDER / AV STATUS
echo ____________________________
echo.
echo [*] Defender status >&2
sc query windefend 2>nul | findstr /i "SERVICE_NAME STATE"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware 2>nul | findstr /i DisableAntiSpyware
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring 2>nul | findstr /i DisableRealtimeMonitoring
echo.
goto :EOF

rem ================= loud tier =================
:SEC_CMDKEY
echo ____________________________
echo      STORED CREDENTIALS (cmdkey)
echo ____________________________
echo.
echo [*] Credential store - cmdkey >&2
echo [++Stored Credentials - cmdkey /list]
cmdkey /list
echo.
goto :EOF

:SEC_SCHTASKS
echo ____________________________
echo      SCHEDULED TASKS
echo ____________________________
echo.
echo [*] Non-Microsoft scheduled tasks >&2
echo [++Non-Microsoft tasks (full detail - review 'Task To Run' for writable binaries; privesc.ps1 tests writability)]
for /f "tokens=1 delims=," %%t in ('schtasks /query /fo csv /nh 2^>nul ^| findstr /i /v "\\Microsoft\\"') do schtasks /query /tn %%t /fo LIST /v 2>nul
echo.
goto :EOF

:SEC_WIFI
echo ____________________________
echo      SAVED WI-FI KEYS
echo ____________________________
echo.
echo [*] Saved Wi-Fi passwords >&2
for /f "tokens=2 delims=:" %%a in ('netsh wlan show profiles 2^>nul ^| findstr /c:"All User Profile"') do (
  set "wprof=%%a"
  set "wprof=!wprof:~1!"
  echo --- !wprof! ---
  netsh wlan show profile name="!wprof!" key=clear 2>nul | findstr /i "SSID Key"
)
echo.
goto :EOF

:SEC_REGPWSWEEP
echo ____________________________
echo      REGISTRY PASSWORD SWEEP
echo ____________________________
echo.
echo [*] Registry password search (slow) >&2
echo [++HKLM\SOFTWARE string values containing 'password']
reg query HKLM\SOFTWARE /f password /t REG_SZ /s 2>nul | findstr /i "password HKEY"
echo [++HKCU\SOFTWARE string values containing 'password']
reg query HKCU\SOFTWARE /f password /t REG_SZ /s 2>nul | findstr /i "password HKEY"
echo.
goto :EOF

rem ================= skip notes =================
:SKIP_MEDIUM
echo ____________________________
echo      MEDIUM-TIER CHECKS
echo ____________________________
echo.
echo (skipped in quiet mode - run 'privesc.bat medium' for token privileges, Winlogon/unattend/GPP/PS-history/app creds, installed software, Defender)
echo.
goto :EOF

:SKIP_LOUD
echo ____________________________
echo      LOUD-TIER CHECKS
echo ____________________________
echo.
echo (skipped - run 'privesc.bat loud' for cmdkey, scheduled tasks, Wi-Fi keys, registry password sweep)
echo.
goto :EOF
