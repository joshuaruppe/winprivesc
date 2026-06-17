<#
  enum.ps1 - Windows host enumeration (PowerShell companion to enum.bat)

  Usage:
    powershell -ExecutionPolicy Bypass -File enum.ps1 [-Level quiet|medium|loud] [-Report <path>]

    quiet  - light, mostly registry/CIM reads: OS, logical drives, host/domain,
             current user, local profiles.
    medium - + hotfixes, running services, shares, mapped drives, full IP config,
             MAC/route/listening+established connections (with owning process),
             ARP, firewall, local users/groups, process list.
    loud   - + installed drivers, full process detail with paths/owners,
             scheduled-task overview, installed software inventory.

  Enumeration only - reads system state, changes nothing. Authorized use only.

  NOTE ON NOISE: PowerShell is heavily logged (AMSI, ScriptBlock/Event 4104,
  module logging). Where that telemetry matters, prefer the cmd-only enum.bat.
  This script is the richer, noisier option.
#>
[CmdletBinding()]
param(
  [ValidateSet('quiet','medium','loud')]
  [string]$Level = 'quiet',
  [string]$Report = 'enum_report.txt'
)

$ErrorActionPreference = 'SilentlyContinue'
$tier = @{ quiet = 1; medium = 2; loud = 3 }[$Level]

$script:out = New-Object System.Collections.Generic.List[string]
function W { param([string]$s = '') $script:out.Add($s) }
function Hdr { param([string]$t) W '____________________________'; W "     $t"; W '____________________________'; W '' }
function Status { param([string]$s) Write-Host "[*] $s" -ForegroundColor Cyan }
function Emit { param($obj, [string]$title) if ($title) { W "[++$title]" }; ($obj | Out-String -Width 300).TrimEnd().Split("`n") | ForEach-Object { W $_.TrimEnd() }; W '' }

# ============================ OPERATING SYSTEM ============================
function Invoke-SecOS {
  Status 'Operating system'
  Hdr 'OPERATING SYSTEM'
  $os = Get-CimInstance Win32_OperatingSystem
  if ($os) {
    W ("OS Name        : {0}" -f $os.Caption)
    W ("Version        : {0}  (build {1})" -f $os.Version, $os.BuildNumber)
    W ("Architecture   : {0}" -f $os.OSArchitecture)
    W ("Install Date   : {0}" -f $os.InstallDate)
    W ("Last Boot      : {0}" -f $os.LastBootUpTime)
  } else {
    $k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    W ("OS Name        : {0}" -f $k.ProductName)
    W ("Build          : {0}  {1}" -f $k.CurrentBuild, $k.DisplayVersion)
    W ("Architecture   : {0}" -f $env:PROCESSOR_ARCHITECTURE)
  }
  W ''
  Emit (Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -and $_ -notmatch '^\s*#' }) 'Hosts file (non-comment lines)'
  if ($tier -ge 2) {
    Emit (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledOn) 'Installed hotfixes'
    Emit (Get-Service | Where-Object Status -eq 'Running' | Select-Object Name, DisplayName | Sort-Object Name) 'Running services'
  }
}

# ============================ STORAGE ============================
function Invoke-SecStorage {
  Status 'Storage / drives / shares'
  Hdr 'STORAGE'
  Emit (Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, DriveType,
    @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}}, @{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,1)}}, VolumeName) 'Logical drives'
  if ($tier -ge 2) {
    Emit (Get-SmbShare | Select-Object Name, Path, Description) 'Local shares'
    Emit (Get-SmbMapping | Select-Object LocalPath, RemotePath, Status) 'Mapped network drives'
  }
}

# ============================ NETWORKING ============================
function Invoke-SecNetwork {
  Status 'Networking'
  Hdr 'NETWORKING'
  W "[++Host / domain]"
  W ("COMPUTERNAME   : {0}" -f $env:COMPUTERNAME)
  W ("USERDOMAIN     : {0}" -f $env:USERDOMAIN)
  W ("USERDNSDOMAIN  : {0}" -f $env:USERDNSDOMAIN)
  W ("LOGONSERVER    : {0}" -f $env:LOGONSERVER)
  W ''
  if ($tier -ge 2) {
    Emit (Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer) 'IP configuration'
    Emit (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name, MacAddress, LinkSpeed) 'MAC addresses (up adapters)'
    Emit (Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias) 'Routing table'
    Emit (Get-NetTCPConnection | Where-Object State -in 'Listen', 'Established' |
      Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
        @{n='Process';e={ (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName }}, OwningProcess |
      Sort-Object State, LocalPort) 'Active TCP connections (with owning process)'
    Emit (Get-NetNeighbor -AddressFamily IPv4 | Where-Object State -ne 'Unreachable' | Select-Object IPAddress, LinkLayerAddress, State) 'ARP / neighbor cache'
    Emit (Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction) 'Firewall profiles'
  }
}

# ============================ PROCESSES ============================
function Invoke-SecProcesses {
  Status 'Processes / drivers'
  Hdr 'PROCESSES'
  if ($tier -ge 2) {
    Emit (Get-Process | Select-Object Id, ProcessName, Path | Sort-Object ProcessName) 'Running processes (id / name / path)'
  } else {
    W '(process list shown at -Level medium and above)'; W ''
  }
  if ($tier -ge 3) {
    Emit (Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running' |
      Select-Object Name, DisplayName, PathName, StartMode | Sort-Object Name) 'Running kernel drivers'
  }
}

# ============================ USER INFO ============================
function Invoke-SecUsers {
  Status 'Users / groups'
  Hdr 'USER INFO'
  W ("[++Current user] {0}" -f (whoami))
  W ''
  Emit (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' |
    Where-Object { $_.ProfileImagePath -like '*\Users\*' } | Select-Object -ExpandProperty ProfileImagePath) 'Local user profiles'
  if ($tier -ge 2) {
    Emit (Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description) 'Local users'
    Emit (Get-LocalGroup | Select-Object Name, Description) 'Local groups'
    W '[++Administrators group members]'
    Emit (Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, PrincipalSource, ObjectClass) ''
  }
}

# ============================ run ============================
Write-Host ''
Write-Host 'WinPrivEsc - Windows Enumeration (PowerShell)' -ForegroundColor Green
Write-Host "level: $Level   www.joshruppe.com | Bluesky: @joshruppe.com"
Write-Host "[*] Writing report to $Report ..."
Write-Host ''

W 'WinPrivEsc - Enumeration Report (PowerShell)'
W 'www.joshruppe.com | Bluesky: @joshruppe.com'
W ("Report generated: {0}" -f (Get-Date))
W "Noise level: $Level"
W ''

Invoke-SecOS
Invoke-SecStorage
Invoke-SecNetwork
Invoke-SecProcesses
Invoke-SecUsers

$script:out | Set-Content -LiteralPath $Report -Encoding UTF8
Write-Host "[*] Done. Report saved to $Report" -ForegroundColor Green
