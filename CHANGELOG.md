# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] - 2026-06-23

### Fixed

- **`enum.bat` aborted at runtime on every tier.** Literal parentheses in `echo`
  lines inside `if`/`else` blocks (`Page File Location(s)`, `Hotfix(s)`,
  `(skipped ...)`) closed the block early, so the script failed with
  `] was unexpected at this time.` and produced no report. The parentheses are
  now escaped (`^(` / `^)`); `enum.bat` runs cleanly at quiet, medium, and loud.
- **`privesc.ps1` weak-service-DACL check flagged nearly every service.** The
  danger mask ORed in the full `SERVICE_ALL_ACCESS` (`0xF01FF`), which overlaps
  the benign query/read rights that `INTERACTIVE` holds on most services by
  default, so the check reported ~all services as weak. The mask now covers only
  rights that allow reconfiguration or seizure: `SERVICE_CHANGE_CONFIG`,
  `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_ALL`, and `GENERIC_WRITE`.
- **`privesc.ps1` referenced an undefined variable.** The service-DACL check
  tested `$script:MySids`, which was never defined; the current user's SID is
  already covered by `$script:LowPrivSids`, so the dead clause was removed.
- **`privesc.bat` service-binary filter dropped legitimate targets.** The filter
  excluded any path containing the substrings `Windows`, `SystemRoot`, or
  `System32`, which also discarded non-Windows binaries such as
  `...\WindowsHelper\...`. It now matches path segments (`\Windows\`,
  `\SystemRoot\`) instead, matching the behaviour of the PowerShell companion.
- **`enum.bat` hotfix detection over-matched.** `find "KB"` matched any line
  containing `KB`; replaced with `findstr /R "KB[0-9][0-9]"`.
- **`enum.bat` OS Name parsing emitted a stray line.** The OS Name field used
  `find`, which prints a filename header; switched to `findstr /B /C:` for
  consistency with the other operating-system fields.

### Changed

- **`enum.bat` / `privesc.bat` banner.** Removed a stray leading quote from each
  banner line and escaped the pipe characters directly, so the ASCII art renders
  without the leading `"`.

## [2.0.0] - 2026-06-16

### Changed

- Split the original all-in-one `winprivesc.bat` into focused scripts:
  `enum.bat` / `enum.ps1` for host enumeration and `privesc.bat` / `privesc.ps1`
  for privilege-escalation vector checks.
- Added a noise level (`quiet` / `medium` / `loud`) to each script for control
  over detection footprint.

### Deprecated

- `winprivesc.bat`, the original interactive single-menu tool, in favour of the
  split, tiered scripts.
