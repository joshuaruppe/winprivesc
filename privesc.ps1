<#
  privesc.ps1 - Windows privilege-escalation VECTOR checks (PowerShell companion to privesc.bat)

  Usage:
    powershell -ExecutionPolicy Bypass -File privesc.ps1 [-Level quiet|medium|loud] [-Report <path>]

    quiet  - registry/file reads + Get-Acl writability of service binaries,
             PATH dirs and autorun targets; UAC, LAPS/WSUS, hive backups, env.
    medium - + token privileges (annotated), Winlogon/unattend/GPP/PS-history/
             app-session creds, installed software, Defender status, writable
             Run/service registry keys.
    loud   - + cmdkey, scheduled tasks (+ writable action binaries), service
             DACL analysis (SDDL), saved Wi-Fi keys, registry password sweep.

  Enumeration only - reads system state and reports likely escalation VECTORS.
  No exploitation is performed and nothing on the host changes.

  NOTE ON NOISE: PowerShell is heavily instrumented (AMSI, ScriptBlock logging
  / Event ID 4104, module logging, transcription). On hosts where that telemetry
  matters, prefer the cmd-only privesc.bat. This script is the LOUDER but more
  capable option: it CONFIRMS writability via Get-Acl effective permissions,
  which icacls-in-a-loop cannot do reliably from a batch file.

  Authorized use only.
#>
[CmdletBinding()]
param(
  [ValidateSet('quiet','medium','loud')]
  [string]$Level = 'quiet',
  [string]$Report = 'privesc_report.txt'
)

$ErrorActionPreference = 'SilentlyContinue'
$tier = @{ quiet = 1; medium = 2; loud = 3 }[$Level]

# ---- report buffer + helpers ----
$script:out = New-Object System.Collections.Generic.List[string]
function W { param([string]$s = '') $script:out.Add($s) }
function Hdr { param([string]$t) W '____________________________'; W "     $t"; W '____________________________'; W '' }
function Status { param([string]$s) Write-Host "[*] $s" -ForegroundColor Cyan }

# Principals that represent "any standard / low-privileged user": Everyone,
# Authenticated Users, BUILTIN\Users, INTERACTIVE, Guests. Writability by one of
# these is a real privesc vector. We deliberately do NOT count the current token's
# admin group memberships - running elevated would make everything look writable.
# If the tool is run as a NON-admin, we also add that user's own SIDs (their real
# attacker context).
$script:LowPrivSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-32-546')
$script:AmAdmin = $false
try {
  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $wp = New-Object System.Security.Principal.WindowsPrincipal($id)
  $script:AmAdmin = $wp.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
  # add only the current user's OWN account SID (catches direct user ACEs). We do
  # NOT add group memberships: an unelevated admin still carries Administrators as
  # a deny-only group, which would otherwise flag system files as writable.
  $script:LowPrivSids += $id.User.Value
} catch {}
$script:LowPrivSids = $script:LowPrivSids | Select-Object -Unique

# strip args/quotes/\??\ and return the executable path from a command line
function Get-BinaryPath {
  param([string]$cmd)
  if ([string]::IsNullOrWhiteSpace($cmd)) { return $null }
  $cmd = $cmd.Trim() -replace '^\\\?\?\\', ''
  if ($cmd.StartsWith('"')) {
    $end = $cmd.IndexOf('"', 1)
    if ($end -gt 1) { return $cmd.Substring(1, $end - 1) }
  }
  if ($cmd -match '^(.*?\.(?:exe|sys|dll|bat|cmd|scr|com))(\s|$)') { return $matches[1] }
  $sp = $cmd.IndexOf(' ')
  if ($sp -gt 0) { return $cmd.Substring(0, $sp) }
  return $cmd
}

# Rights that let a principal PLANT/REPLACE a file or seize the object. Uses raw
# bits so we exclude bare AppendData/create-dirs (0x4), which would over-flag roots
# like C:\.  WriteData/CreateFiles(0x2) | DeleteSubdirsAndFiles(0x40) |
# Delete(0x10000) | WriteDAC/ChangePermissions(0x40000) | WriteOwner/TakeOwnership(0x80000)
$script:WriteMask = 0x2 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000

# does a low-privilege principal have effective write access to this path?
function Test-PathWritable {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  if (-not (Test-Path -LiteralPath $Path)) { return $false }
  try { $acl = Get-Acl -LiteralPath $Path } catch { return $false }
  if (-not $acl) { return $false }
  foreach ($ace in $acl.Access) {
    if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
    if ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
    if ((([int]$ace.FileSystemRights) -band $script:WriteMask) -eq 0) { continue }
    $sid = $null
    try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $ace.IdentityReference.Value }
    if ($script:LowPrivSids -contains $sid) { return $true }
  }
  return $false
}

# registry key writable by a low-priv principal?
function Test-RegKeyWritable {
  param([string]$Path)  # e.g. HKLM:\SOFTWARE\...\Run
  if (-not (Test-Path -LiteralPath $Path)) { return $false }
  try { $acl = Get-Acl -LiteralPath $Path } catch { return $false }
  if (-not $acl) { return $false }
  $rw = [System.Security.AccessControl.RegistryRights]'SetValue, CreateSubKey, WriteKey, ChangePermissions, TakeOwnership, FullControl'
  foreach ($ace in $acl.Access) {
    if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
    if (($ace.RegistryRights -band $rw) -eq 0) { continue }
    $sid = $null
    try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $ace.IdentityReference.Value }
    if ($script:LowPrivSids -contains $sid) { return $true }
  }
  return $false
}

# ============================ quiet tier ============================
function Invoke-SecAIE {
  Status 'AlwaysInstallElevated policy'
  Hdr 'ALWAYSINSTALLELEVATED'
  $hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated).AlwaysInstallElevated
  $hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated).AlwaysInstallElevated
  W ("HKLM AlwaysInstallElevated = {0}" -f $(if ($null -eq $hklm) { '(unset)' } else { $hklm }))
  W ("HKCU AlwaysInstallElevated = {0}" -f $(if ($null -eq $hkcu) { '(unset)' } else { $hkcu }))
  if ($hklm -eq 1 -and $hkcu -eq 1) { W '[!] EXPLOITABLE: both keys are 1 - any user can install an MSI as SYSTEM' }
  W '(vector requires BOTH HKLM and HKCU set to 1; a single key does nothing)'
  W ''
}

function Invoke-SecServices {
  Status 'Service misconfigurations (+ writability)'
  Hdr 'SERVICE MISCONFIGURATIONS'
  $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
  if (-not $svcs) { W '(Win32_Service unavailable)'; W ''; return }
  W '[++Non-Windows service binaries  (svc) [run-as]  -> writability]'
  foreach ($s in ($svcs | Sort-Object Name)) {
    $bin = Get-BinaryPath $s.PathName
    if (-not $bin) { continue }
    if ($bin -match '(?i)\\Windows\\') { continue }
    $tag = ''
    if (Test-PathWritable $bin) { $tag = '  >> [WRITABLE BINARY]' }
    elseif (Test-PathWritable (Split-Path $bin -Parent)) { $tag = '  >> [WRITABLE DIR]' }
    W ("  {0}  ({1}) [{2}]{3}" -f $bin, $s.Name, $s.StartName, $tag)
  }
  W ''
  W '[++Unquoted service path candidates  (writable intermediate dir = exploitable)]'
  foreach ($s in ($svcs | Sort-Object Name)) {
    $p = $s.PathName
    if ([string]::IsNullOrWhiteSpace($p) -or $p.StartsWith('"')) { continue }
    $bin = Get-BinaryPath $p
    if ($bin -notmatch ' ' -or $bin -match '(?i)\\Windows\\' -or $bin -match '(?i)\.sys$') { continue }
    $hits = @()
    $dir = Split-Path $bin -Parent
    while ($dir -and ($dir -match '\\')) {
      if (Test-PathWritable $dir) { $hits += $dir }
      $parent = Split-Path $dir -Parent
      if (-not $parent -or $parent -eq $dir) { break }
      $dir = $parent
    }
    $tag = if ($hits.Count) { '  >> [WRITABLE: ' + ($hits -join '; ') + ']' } else { '' }
    W ("  {0}  ({1}){2}" -f $bin, $s.Name, $tag)
  }
  W ''
}

function Invoke-SecPath {
  Status 'PATH directories (+ writability)'
  Hdr 'PATH DIRECTORIES'
  W '[++Directories on PATH  -> writability (DLL hijack surface)]'
  foreach ($d in ($env:PATH -split ';')) {
    if ([string]::IsNullOrWhiteSpace($d)) { continue }
    if (-not (Test-Path -LiteralPath $d)) { continue }
    $tag = if (Test-PathWritable $d) { '  >> [WRITABLE]' } else { '' }
    W ("  {0}{1}" -f $d, $tag)
  }
  W ''
}

function Invoke-SecUAC {
  Status 'UAC configuration'
  Hdr 'UAC CONFIGURATION'
  $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  foreach ($v in 'EnableLUA', 'ConsentPromptBehaviorAdmin', 'LocalAccountTokenFilterPolicy', 'FilterAdministratorToken') {
    $val = (Get-ItemProperty $k -Name $v).$v
    W ("{0} = {1}" -f $v, $(if ($null -eq $val) { '(unset)' } else { $val }))
  }
  W '(EnableLUA=0 means UAC off; LocalAccountTokenFilterPolicy=1 disables remote-UAC filtering = privesc/lateral relevant)'
  W ''
}

function Invoke-SecAutorun {
  Status 'Autorun entries (+ writability)'
  Hdr 'AUTORUN ENTRIES'
  $keys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
  )
  foreach ($k in $keys) {
    if (-not (Test-Path -LiteralPath $k)) { continue }
    $keyTag = if (Test-RegKeyWritable $k) { '  >> [WRITABLE KEY]' } else { '' }
    W ("[$k]$keyTag")
    $props = Get-ItemProperty -LiteralPath $k
    foreach ($p in $props.PSObject.Properties) {
      if ($p.Name -like 'PS*') { continue }
      $bin = Get-BinaryPath ([string]$p.Value)
      $tag = if (Test-PathWritable $bin) { '  >> [WRITABLE TARGET]' } else { '' }
      W ("  {0} = {1}{2}" -f $p.Name, $p.Value, $tag)
    }
  }
  W ''
}

function Invoke-SecPolicy {
  Status 'LAPS / WSUS policy'
  Hdr 'AGENT / UPDATE POLICY'
  $laps = Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'
  W ("LAPS (AdmPwd) present: {0}" -f $laps)
  $wu = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name WUServer).WUServer
  W ("WSUS WUServer: {0}" -f $(if ($wu) { $wu } else { '(none)' }))
  if ($wu -match '^http://') { W '[!] WSUS over HTTP - update MITM to SYSTEM possible' }
  W ''
}

function Invoke-SecHiveBak {
  Status 'SAM/SYSTEM hive backups'
  Hdr 'REGISTRY HIVE BACKUPS'
  foreach ($f in @(
      "$env:SystemRoot\Repair\SAM", "$env:SystemRoot\Repair\SYSTEM",
      "$env:SystemRoot\System32\config\RegBack\SAM", "$env:SystemRoot\System32\config\RegBack\SYSTEM")) {
    if (Test-Path -LiteralPath $f) {
      $r = if (Test-PathWritable $f) { 'writable' } else { 'present' }
      W ("[!] {0}  ({1})" -f $f, $r)
    }
  }
  W ''
}

function Invoke-SecEnv {
  Status 'Environment secrets'
  Hdr 'ENVIRONMENT SECRETS'
  Get-ChildItem Env: | Where-Object { $_.Name -match '(?i)pass|key|token|secret|cred|api_|aws_' } |
    ForEach-Object { W ("{0}={1}" -f $_.Name, $_.Value) }
  W ''
}

# ============================ medium tier ============================
function Invoke-SecTokens {
  Status 'Token privileges and groups'
  Hdr 'TOKEN PRIVILEGES'
  $priv = whoami /priv 2>$null
  $priv | ForEach-Object { W $_ }
  W ''
  W '[++Notable privilege guidance]'
  $map = @{
    'SeImpersonatePrivilege'       = 'Potato/PrintSpoofer to SYSTEM'
    'SeAssignPrimaryTokenPrivilege'= 'Potato-style token assignment to SYSTEM'
    'SeBackupPrivilege'            = 'read SAM/SYSTEM or any file'
    'SeRestorePrivilege'           = 'overwrite protected files'
    'SeDebugPrivilege'             = 'inject into a SYSTEM process'
    'SeTakeOwnershipPrivilege'     = 'seize objects then rewrite ACLs'
    'SeLoadDriverPrivilege'        = 'load a vulnerable signed driver'
    'SeManageVolumePrivilege'      = 'arbitrary file write via volume mgmt'
  }
  $text = ($priv -join "`n")
  foreach ($k in $map.Keys) {
    if ($text -match $k -and $text -match "$k\s+\w") { W ("[!] {0} -> {1}" -f $k, $map[$k]) }
  }
  W ''
  W '[++Token Groups]'
  whoami /groups 2>$null | ForEach-Object { W $_ }
  W ''
}

function Invoke-SecCreds-RegFile {
  Status 'Credential vectors (registry/files)'
  Hdr 'STORED CREDENTIALS (REG/FILE)'
  W '[++Winlogon Autologon]'
  $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  foreach ($n in 'DefaultUserName', 'DefaultDomainName', 'DefaultPassword', 'AutoAdminLogon') {
    if ($wl.$n) { W ("  {0} = {1}" -f $n, $wl.$n) }
  }
  W '(creds set via netplwiz/Sysinternals Autologon live as an LSA secret; empty DefaultPassword is not proof of safety)'
  W ''
  W '[++Unattend / Sysprep credential files]'
  $files = @("$env:SystemRoot\Panther\Unattend.xml", "$env:SystemRoot\Panther\Unattended.xml",
    "$env:SystemRoot\Panther\Unattend\Unattended.xml", "$env:SystemRoot\System32\Sysprep\sysprep.xml",
    "$env:SystemRoot\System32\Sysprep\sysprep.inf", "$env:SystemDrive\unattend.xml")
  foreach ($f in $files) {
    if (Test-Path -LiteralPath $f) {
      W "--- $f ---"
      (Select-String -LiteralPath $f -Pattern 'password', 'username', 'useraccount', 'autologon' -ErrorAction SilentlyContinue) |
        ForEach-Object { W ("  " + $_.Line.Trim()) }
    }
  }
  W ''
}

function Invoke-SecGPP {
  Status 'GPP cpassword search'
  Hdr 'GROUP POLICY PREFERENCES'
  $roots = @("$env:ALLUSERSPROFILE\Microsoft\Group Policy\History")
  if ($env:USERDNSDOMAIN) { $roots += "\\$env:USERDNSDOMAIN\SYSVOL" }
  foreach ($r in $roots) {
    if (Test-Path -LiteralPath $r) {
      Get-ChildItem -LiteralPath $r -Recurse -Include *.xml -ErrorAction SilentlyContinue |
        Select-String -Pattern 'cpassword' -ErrorAction SilentlyContinue |
        ForEach-Object { W ("[!] {0}: {1}" -f $_.Path, $_.Line.Trim()) }
    }
  }
  W ''
}

function Invoke-SecPSHistory {
  Status 'PowerShell console history'
  Hdr 'POWERSHELL HISTORY'
  $h = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
  if (Test-Path -LiteralPath $h) { Get-Content -LiteralPath $h | ForEach-Object { W $_ } }
  W ''
}

function Invoke-SecAppCreds {
  Status 'Saved app sessions (PuTTY/WinSCP/RDP/VNC)'
  Hdr 'SAVED APP SESSIONS'
  W '[++PuTTY sessions]'
  Get-ChildItem 'HKCU:\Software\SimonTatham\PuTTY\Sessions' -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    W ("  {0}: HostName={1} ProxyUsername={2} ProxyPassword={3}" -f $_.PSChildName, $p.HostName, $p.ProxyUsername, $p.ProxyPassword)
  }
  W '[++WinSCP sessions]'
  Get-ChildItem 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions' -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    W ("  {0}: HostName={1} UserName={2} Password={3}" -f $_.PSChildName, $p.HostName, $p.UserName, $p.Password)
  }
  W '[++RDP saved servers]'
  Get-ChildItem 'HKCU:\Software\Microsoft\Terminal Server Client\Servers' -ErrorAction SilentlyContinue |
    ForEach-Object { W ("  {0}" -f $_.PSChildName) }
  W '[++VNC passwords]'
  foreach ($vk in 'HKCU:\Software\ORL\WinVNC3', 'HKLM:\SOFTWARE\RealVNC\WinVNC4', 'HKCU:\Software\TightVNC\Server') {
    $p = Get-ItemProperty $vk -ErrorAction SilentlyContinue
    if ($p.Password) { W ("  {0}\Password present" -f $vk) }
  }
  W ''
}

function Invoke-SecSoftware {
  Status 'Installed software'
  Hdr 'INSTALLED SOFTWARE'
  $paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
           'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  Get-ItemProperty $paths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } | Select-Object -ExpandProperty DisplayName -Unique |
    Sort-Object | ForEach-Object { W ("  {0}" -f $_) }
  W ''
}

function Invoke-SecDefender {
  Status 'Defender / AV status'
  Hdr 'DEFENDER / AV STATUS'
  $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
  if ($st) {
    W ("RealTimeProtectionEnabled = {0}" -f $st.RealTimeProtectionEnabled)
    W ("AntivirusEnabled          = {0}" -f $st.AntivirusEnabled)
    W ("TamperProtected           = {0}" -f $st.IsTamperProtected)
  } else {
    $svc = Get-Service WinDefend -ErrorAction SilentlyContinue
    W ("WinDefend service: {0}" -f $(if ($svc) { $svc.Status } else { 'not found' }))
  }
  W ''
}

function Invoke-SecRegKeyAcls {
  Status 'Writable Run/service registry keys'
  Hdr 'WRITABLE REGISTRY KEYS'
  W '[++Run keys writable by current user / low-priv groups]'
  foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
    if ((Test-Path -LiteralPath $k) -and (Test-RegKeyWritable $k)) { W ("[!] WRITABLE: $k") }
  }
  W '[++Service registry keys writable (set ImagePath = SYSTEM exec)]'
  Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object {
    $kp = "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.PSChildName)"
    if (Test-RegKeyWritable $kp) { W ("[!] WRITABLE: $kp  (service $($_.PSChildName))") }
  }
  W ''
}

# ============================ loud tier ============================
function Invoke-SecCmdkey {
  Status 'Credential store - cmdkey'
  Hdr 'STORED CREDENTIALS (cmdkey)'
  cmdkey /list 2>$null | ForEach-Object { W $_ }
  W ''
}

function Invoke-SecSchTasks {
  Status 'Scheduled tasks (+ writable action binaries)'
  Hdr 'SCHEDULED TASKS'
  $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }
  foreach ($t in $tasks) {
    $principal = $t.Principal.UserId
    W ("[$($t.TaskPath)$($t.TaskName)]  run-as: $principal")
    foreach ($a in $t.Actions) {
      $exe = $a.Execute
      if (-not $exe) { continue }
      $resolved = [System.Environment]::ExpandEnvironmentVariables($exe)
      $bin = Get-BinaryPath $resolved
      $tag = if (Test-PathWritable $bin) { '  >> [WRITABLE BINARY]' } elseif ($bin -and (Test-PathWritable (Split-Path $bin -Parent))) { '  >> [WRITABLE DIR]' } else { '' }
      W ("    exec: {0} {1}{2}" -f $exe, $a.Arguments, $tag)
    }
  }
  W ''
}

function Invoke-SecServiceDacls {
  Status 'Service DACL analysis (SDDL)'
  Hdr 'WEAK SERVICE DACLS'
  W '[++Services whose DACL grants change-config/write to low-priv principals]'
  # Only rights that let a low-priv principal RECONFIGURE/seize a service (-> SYSTEM exec).
  # Deliberately excludes the benign query/read bits (SERVICE_QUERY_*, READ_CONTROL, etc.):
  # INTERACTIVE holds those on almost every service by default, so including the full
  # SERVICE_ALL_ACCESS (0xF01FF) here flagged ~every service. SERVICE_CHANGE_CONFIG=0x2,
  # WRITE_DAC=0x40000, WRITE_OWNER=0x80000, GENERIC_ALL=0x10000000, GENERIC_WRITE=0x40000000.
  $dangerMask = 0x00000002 -bor 0x00040000 -bor 0x00080000 -bor 0x10000000 -bor 0x40000000
  $svcNames = (Get-Service -ErrorAction SilentlyContinue).Name
  foreach ($n in $svcNames) {
    $sddl = (& sc.exe sdshow "$n" 2>$null) -join ''
    if (-not $sddl -or $sddl -notmatch '^[OGDS]:') { continue }
    try { $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl) } catch { continue }
    if (-not $sd.DiscretionaryAcl) { continue }
    foreach ($ace in $sd.DiscretionaryAcl) {
      if ($ace.AceType -ne 'AccessAllowed') { continue }
      $sid = $ace.SecurityIdentifier.Value
      $isLow = $script:LowPrivSids -contains $sid
      if ($isLow -and (($ace.AccessMask -band $dangerMask) -ne 0)) {
        W ("[!] {0}: {1} has mask 0x{2:X}  (sddl: {3})" -f $n, $sid, $ace.AccessMask, $sddl)
        break
      }
    }
  }
  W ''
}

function Invoke-SecWifi {
  Status 'Saved Wi-Fi keys'
  Hdr 'SAVED WI-FI KEYS'
  $profiles = (netsh wlan show profiles 2>$null | Select-String 'All User Profile\s*:\s*(.+)$') |
    ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
  foreach ($p in $profiles) {
    W "--- $p ---"
    netsh wlan show profile name="$p" key=clear 2>$null |
      Select-String 'SSID name|Key Content|Authentication' | ForEach-Object { W ("  " + $_.Line.Trim()) }
  }
  if (-not $profiles) { W '(no wireless profiles / no adapter)' }
  W ''
}

function Invoke-SecRegPwSweep {
  Status 'Registry password sweep (slow)'
  Hdr 'REGISTRY PASSWORD SWEEP'
  W '[++HKLM\SOFTWARE / HKCU\SOFTWARE string values containing "password"]'
  foreach ($root in 'HKLM\SOFTWARE', 'HKCU\SOFTWARE') {
    reg query $root /f password /t REG_SZ /s 2>$null | Select-String 'password|HKEY' | ForEach-Object { W $_.Line }
  }
  W ''
}

# ============================ run ============================
Write-Host ''
Write-Host 'WinPrivEsc - Privilege Escalation Vector Checks (PowerShell)' -ForegroundColor Green
Write-Host "level: $Level   www.joshruppe.com | Bluesky: @joshruppe.com"
Write-Host "[*] Writing report to $Report ..."
Write-Host ''

W 'WinPrivEsc - Privilege Escalation Vector Report (PowerShell)'
W 'www.joshruppe.com | Bluesky: @joshruppe.com'
W ("Report generated: {0}" -f (Get-Date))
W "Noise level: $Level"
W ('Running as: {0}' -f $id.Name)
W ''
W 'Enumeration only - reads system state, reports likely escalation vectors,'
W 'and CONFIRMS writability via Get-Acl effective permissions. No exploitation;'
W 'nothing on the host is changed.'
W ''

Invoke-SecAIE
Invoke-SecServices
Invoke-SecPath
Invoke-SecUAC
Invoke-SecAutorun
Invoke-SecPolicy
Invoke-SecHiveBak
Invoke-SecEnv

if ($tier -ge 2) {
  Invoke-SecTokens
  Invoke-SecCreds-RegFile
  Invoke-SecGPP
  Invoke-SecPSHistory
  Invoke-SecAppCreds
  Invoke-SecSoftware
  Invoke-SecDefender
  Invoke-SecRegKeyAcls
} else {
  Hdr 'MEDIUM-TIER CHECKS'
  W "(skipped in quiet mode - run with -Level medium for token privileges, creds, software, Defender, writable registry keys)"
  W ''
}

if ($tier -ge 3) {
  Invoke-SecCmdkey
  Invoke-SecSchTasks
  Invoke-SecServiceDacls
  Invoke-SecWifi
  Invoke-SecRegPwSweep
} else {
  Hdr 'LOUD-TIER CHECKS'
  W "(skipped - run with -Level loud for cmdkey, scheduled tasks, service DACLs, Wi-Fi keys, registry password sweep)"
  W ''
}

$script:out | Set-Content -LiteralPath $Report -Encoding UTF8
Write-Host "[*] Done. Report saved to $Report" -ForegroundColor Green
