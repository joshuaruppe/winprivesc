<p align="center">
  <img src="banner.svg" alt="WinPrivEsc" width="720">
</p>

<p align="center">
  <img alt="Batch" src="https://img.shields.io/badge/batch-cmd.exe-blue">
  <img alt="Dependencies" src="https://img.shields.io/badge/dependencies-zero-brightgreen">
  <img alt="Platform" src="https://img.shields.io/badge/platform-windows-0078D6?logo=windows&logoColor=white">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-green"></a>
  <img alt="Use" src="https://img.shields.io/badge/use-authorized%20testing%20only-red">
</p>

A simple, dependency-free Windows batch script for system enumeration and spotting potential privilege escalation routes. It runs on a stock `cmd.exe` with no PowerShell, no `wmic`, and no external tools, so it works on locked-down and modern hosts alike.

## Usage

Run `winprivesc.bat` from a command prompt and pick an option from the menu:

```text
1 - All to Report
2 - Operating System
3 - Storage
4 - Networking
5 - Processes
6 - User Info
7 - Privilege Escalation
8 - Exit
```

Options **2-7** print their section to the screen for a quick look. Option **1** runs every section and writes the combined output to `report.txt` in the current directory.

## What it checks

- **Operating System**: OS name/version, architecture, boot time, page file, installed hotfixes, hosts/networks files, running services
- **Storage**: local shares and mapped network drives
- **Networking**: full `ipconfig`, MAC addresses, routing table, active connections, ARP cache, firewall profiles, domain
- **Processes**: running tasks and installed drivers
- **User Info**: current user, all local users, local groups
- **Privilege Escalation**: the interesting bits:
  - User privileges (flags `SeImpersonate`, `SeAssignPrimaryToken`, `SeBackup`, `SeDebug`, etc.)
  - Token groups and SIDs
  - `AlwaysInstallElevated` policy (HKLM/HKCU)
  - Service binaries living outside the Windows directory
  - Unquoted service path candidates
  - Stored credentials (`cmdkey`), Winlogon autologon creds, and unattend/sysprep credential files
  - Non-Microsoft scheduled tasks
  - Writable directories on `PATH` (DLL hijack surface)

## Output

When run with option **1**, results are saved to `report.txt`. Temporary files (`systeminfo.txt`, `hotfix.txt`) are created during the run and cleaned up on exit.

## Noise and detection

This is a recon tool, so it is worth knowing its footprint.

Because it uses only built-in Windows commands (no PowerShell, no downloads, no persistence, and no registry or system changes), it is quiet against signature-based AV. It is **not** quiet against behavioral EDR. The convenience of option **1** is also its biggest tell: firing every check at once produces a tight burst of discovery commands from a single `cmd.exe`, which is a classic recon pattern that detection engines correlate on.

It does touch disk, though: `systeminfo.txt` and `hotfix.txt` are written on every run, plus `report.txt` under option **1**. Those file-creation events (Sysmon Event ID 11) are part of the footprint even though nothing on the system is modified.

On a default install with only Microsoft Defender AV, real-time alerting is low. On a host with EDR (Defender for Endpoint, CrowdStrike, etc.) or Sysmon plus a SIEM, the discovery cluster and the credential checks below are likely to be logged or flagged.

**Loudest checks** (credential access and known privesc signatures):

- Winlogon autologon query (`DefaultPassword` / `AutoAdminLogon`)
- Stored credentials via `cmdkey /list`
- `whoami /priv` and `whoami /groups` in sequence
- Unattend/sysprep files searched for `password`
- `AlwaysInstallElevated` registry keys
- Recursive service `ImagePath` enumeration and the `icacls` loop over `PATH`
- Non-Microsoft scheduled task enumeration (one `schtasks /query` per task, in a burst)

On a modern hardened host (for example Windows 11 24H2 with Credential Guard on by default), several of the credential checks may simply come back empty, since plaintext secrets in the registry and Credential Manager are increasingly locked down.

**To minimize noise:**

- Run the individual sections (**2-7**), spaced out over time, instead of option **1** in one burst.
- Hold back the credential checks above unless you actually need them.
- Clean up `report.txt` when finished. It aggregates sensitive output in one place and is left on disk after the run.

## Disclaimer

This tool is for **authorized** use only: your own systems, lab environments, CTFs, or engagements you have explicit permission to test. It is read-only and makes no changes to the host; it only collects information. You are responsible for how you use it.

## License

Released under the [MIT License](LICENSE).
