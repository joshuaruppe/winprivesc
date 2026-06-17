<p align="center">
  <img src="banner.svg" alt="WinPrivEsc" width="720">
</p>

<p align="center">
  <img alt="Batch" src="https://img.shields.io/badge/batch-cmd.exe-blue">
  <img alt="PowerShell" src="https://img.shields.io/badge/powershell-5%2B-5391FE?logo=powershell&logoColor=white">
  <img alt="Dependencies" src="https://img.shields.io/badge/dependencies-zero-brightgreen">
  <img alt="Platform" src="https://img.shields.io/badge/platform-windows-0078D6?logo=windows&logoColor=white">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-green"></a>
  <img alt="Use" src="https://img.shields.io/badge/use-authorized%20testing%20only-red">
</p>

A small Windows enumeration and privilege-escalation-discovery toolkit. It comes in two flavors so you can match the host:

- **cmd / batch** ([enum.bat](enum.bat), [privesc.bat](privesc.bat)) - dependency-free, stock `cmd.exe`, no PowerShell, no `wmic`, no external tools. Works on locked-down hosts and sidesteps the PowerShell logging stack.
- **PowerShell** ([enum.ps1](enum.ps1), [privesc.ps1](privesc.ps1)) - richer and more accurate (real `Get-Acl` writability, effective permissions, service DACLs), at the cost of PowerShell's heavier telemetry.

Every script is **read-only**: it reports likely escalation *vectors* and changes nothing on the host. It performs no exploitation.

## The scripts

| Scope | cmd (stealthier) | PowerShell (more capable) |
|---|---|---|
| Host enumeration | `enum.bat` | `enum.ps1` |
| Privesc vectors | `privesc.bat` | `privesc.ps1` |

Each takes a **noise level** and writes a report to the current directory:

```text
enum.bat    [quiet|medium|loud]            (default: quiet)  -> enum_report.txt
privesc.bat [quiet|medium|loud]            (default: quiet)  -> privesc_report.txt

powershell -ExecutionPolicy Bypass -File enum.ps1    -Level quiet|medium|loud
powershell -ExecutionPolicy Bypass -File privesc.ps1 -Level quiet|medium|loud
```

> `winprivesc.bat` is the original all-in-one menu tool, now **deprecated** - see [Legacy](#legacy-winprivescbat).

## Noise tiers

- **quiet** - targeted registry/file reads, minimal process spawns, no credential-store binaries, no bursts.
- **medium** - adds standard single-spawn discovery and credential-in-registry/file reads.
- **loud** - adds credential-store access, heavy sweeps, and (PowerShell) full writability / ACL confirmation.

Report and temporary files (`enum_report.txt`, `privesc_report.txt`, `svc.txt`, `priv.txt`, `systeminfo.txt`, `hotfix.txt`) are git-ignored.

## cmd or PowerShell?

Pick by what the host is watching.

- **Use the `.bat` flavor on hardened / monitored hosts.** cmd has no script-content logging: there is no AMSI scan, no Script Block Logging (Event ID 4104), and no module logging for a batch file. Its individual built-ins (`reg`, `whoami`, `sc`, ...) still appear as process-creation events, and a behavioral EDR can still correlate the discovery burst, but you sidestep the entire PowerShell logging stack.
- **Use the `.ps1` flavor when you need accuracy over stealth.** PowerShell is one of the most instrumented surfaces on Windows (AMSI, Event ID 4104, module logging, transcription), so assume it is logged. In return you get `Get-Acl` effective-permission writability (which binaries, directories, and keys *a low-privileged user* can actually write), service DACL analysis, and richer objects - things `icacls` in a cmd loop cannot do reliably.

## What it checks

**Enumeration (`enum.*`)**

- Operating system: name/version/architecture, build, install and boot time, hotfixes, hosts file, running services
- Storage: logical drives, local shares, mapped network drives
- Networking: IP config, MAC addresses, routing table, active TCP connections (with owning process), ARP/neighbor cache, firewall profiles, host/domain
- Processes: running processes (with paths), kernel drivers
- Users: current user, local user profiles, local users and groups, Administrators members

**Privilege escalation (`privesc.*`)**

- `AlwaysInstallElevated` policy (flagged only when **both** HKLM and HKCU are set to 1)
- Service binaries outside the Windows directory, and unquoted service path candidates (drivers/`.sys` filtered out)
- `PATH` directories (DLL hijack surface)
- UAC configuration (`EnableLUA`, `ConsentPromptBehaviorAdmin`, `LocalAccountTokenFilterPolicy`, `FilterAdministratorToken`)
- Autorun (Run / RunOnce) entries
- LAPS presence, WSUS-over-HTTP policy, SAM/SYSTEM hive backups, environment-variable secrets
- Token privileges (`SeImpersonate`, `SeAssignPrimaryToken`, `SeBackup`, `SeDebug`, ...) annotated with how each is abused, plus token groups
- Stored credentials: Winlogon autologon, unattend/sysprep files, `cmdkey`, GPP `cpassword`, PowerShell history, PuTTY/WinSCP/RDP/VNC sessions, saved Wi-Fi keys
- Installed software (exploit mapping), Defender/AV status, non-Microsoft scheduled tasks
- Registry password sweep

**PowerShell-only additions (`privesc.ps1`)**

- `Get-Acl` writability confirmation for service binaries, `PATH` directories, autorun targets, and scheduled-task action binaries, evaluated for **low-privilege principals** (Everyone / Users / Authenticated Users / your own account) rather than your admin token
- Writable Run / service **registry keys**
- Service **DACL analysis** via SDDL (who can reconfigure or restart a service)

## Noise and detection

These are recon tools, so it is worth knowing their footprint.

The `.bat` flavor uses only built-in Windows commands (no PowerShell, no downloads, no persistence, no registry or system changes), so it is quiet against signature-based AV. It is **not** quiet against behavioral EDR: firing a whole tier at once produces a tight burst of discovery commands from a single `cmd.exe`, which is a classic recon pattern detection engines correlate on. The `.ps1` flavor is inherently louder - PowerShell execution is logged via AMSI, Script Block Logging (Event ID 4104), and module logging regardless of what the script does.

Both flavors touch disk: each run writes its report (and the `.bat` scripts write small temp files such as `systeminfo.txt`, `hotfix.txt`, `svc.txt`). Those file-creation events (Sysmon Event ID 11) are part of the footprint even though nothing on the system is modified.

On a default install with only Microsoft Defender AV, real-time alerting is low. On a host with EDR (Defender for Endpoint, CrowdStrike, etc.) or Sysmon plus a SIEM, the discovery cluster and the credential checks below are likely to be logged or flagged.

**Loudest checks** (credential access and known privesc signatures):

- Winlogon autologon query (`DefaultPassword` / `AutoAdminLogon`)
- Stored credentials via `cmdkey /list`
- `whoami /priv` and `whoami /groups` in sequence
- Unattend/sysprep files searched for `password`, and the registry password sweep
- `AlwaysInstallElevated` registry keys
- Non-Microsoft scheduled task enumeration and saved Wi-Fi key extraction (`netsh wlan ... key=clear`)

On a modern hardened host (for example Windows 11 24H2 with Credential Guard on by default), several of the credential checks may simply come back empty, since plaintext secrets in the registry and Credential Manager are increasingly locked down.

**To minimize noise:**

- Prefer the **`.bat`** flavor where PowerShell telemetry matters; reserve the **`.ps1`** flavor for when you need writability/ACL confirmation.
- Run the lowest tier that answers your question (`quiet` first), and space runs out over time rather than firing `loud` immediately.
- Hold back the credential checks above unless you actually need them (they live in `medium`/`loud`).
- Clean up the report files when finished. They aggregate sensitive output in one place and are left on disk after the run.

## Legacy: winprivesc.bat

`winprivesc.bat` is the original all-in-one tool with an interactive menu (Operating System / Storage / Networking / Processes / User Info / Privilege Escalation / All to Report). It is **deprecated** in favor of the split, tiered `enum.bat` + `privesc.bat` and their PowerShell companions, which give finer control over noise and, in the `.ps1` flavor, real `Get-Acl` writability confirmation. The file is kept for now for anyone who prefers the single-menu workflow, but new checks land in the split scripts.

## Disclaimer

These tools are for **authorized** use only: your own systems, lab environments, CTFs, or engagements you have explicit permission to test. They are read-only and make no changes to the host; they only collect information. You are responsible for how you use them.

## License

Released under the [MIT License](LICENSE).
