# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Two PowerShell scripts implementing a **Microsoft Intune Win32 application** that detects and remediates prerequisites for the Claude Desktop Cowork virtualization feature on Windows 11 Pro managed endpoints.

- `Detect-ClaudeCowork.ps1` — custom detection script (v1.8); emits a single stdout line on compliance, silent on non-compliance; always exits 0
- `Remediate-ClaudeCowork.ps1` — install command (v1.8); runs when detection reports "not detected" (i.e. prereqs not healthy)

Both scripts require `#Requires -RunAsAdministrator` and run as SYSTEM via Intune.

## Execution Model

Scripts are deployed as a **Win32 app** (`.intunewin`) rather than a Proactive Remediation. Intune retries the install command on its own cadence whenever the detection script reports "not detected"; no custom schedule is needed.

### Intune Win32 detection contract

| Detection-script output | Intune interprets as |
|-------------------------|----------------------|
| Exit 0 + single stdout line | **Detected** (prereqs healthy; no install) |
| Exit 0 + no stdout | **Not detected** (install command runs) |
| Non-zero exit | Script error (retry later) — reserved for unhandled exceptions |

The detection script's compliance-line format: `ClaudeCoworkPrereqs=Ready|Version=1.8|Host=<COMPUTERNAME>|Timestamp=<ISO8601>`.

### Intune app settings

| Setting | Value |
|---------|-------|
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Remediate-ClaudeCowork.ps1` |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Remove-Item '$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\Claude\ClaudePrereqsReady.flag' -Force -ErrorAction SilentlyContinue; exit 0"` |
| Install behavior | System |
| Device restart behavior | No specific action (script surfaces a user prompt; Intune must not force-restart) |
| Detection rules | Custom detection script → `Detect-ClaudeCowork.ps1` (run as 64-bit; signature check optional) |
| Requirements | OS = Windows 11, Architecture = x64 |
| Dependencies | Make the downstream Claude MSIX Win32 app depend on this one |

Uninstall only clears the flag — this package never removes Hyper-V features (destructive).

### Local test

```powershell
# Run detection
powershell.exe -ExecutionPolicy Bypass -File .\Detect-ClaudeCowork.ps1

# Run remediation (install command)
powershell.exe -ExecutionPolicy Bypass -File .\Remediate-ClaudeCowork.ps1
```

## Log and Flag Paths

All scripts write logs and flags to:

```
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Claude\
```

This directory is inside the IME Logs path, so Intune's **Collect diagnostics** action captures it automatically — no custom diagnostics profile configuration required.

| File | Written by | Purpose |
|------|-----------|---------|
| `ClaudeCowork-Detection.log` | Detect-ClaudeCowork.ps1 | Full audit trail |
| `ClaudeCowork-Remediation.log` | Remediate-ClaudeCowork.ps1 | Full audit trail |
| `ClaudePrereqsReady.flag` | Detection on compliance; remediation on first clean run | Gate consumed by `install_claude.ps1` |
| `ClaudeCowork-RestartNotified.flag` | Remediation after showing the restart prompt | Stores current `LastBootUpTime`; once-per-boot suppression |

The prereqs flag signals to `install_claude.ps1` that VM infrastructure is healthy and Claude can be provisioned.

## Architecture

### Detection flow

The detection script runs checks in sequence. **Gate checks** (CHECK 0 and CHECK 0b) set a skip flag when the issue cannot be remediated by script — later checks are short-circuited but the script still falls through to the single final output block so the Win32 detection contract is honoured (no mid-script `Exit 1`).

| Check | What | Gate? |
|-------|------|-------|
| 0 | Hypervisor present (VT-x/AMD-V in firmware) | Yes — script cannot fix BIOS |
| 0b | Guest VM without nested virtualization | Yes — script cannot fix parent host |
| 1 | VirtualMachinePlatform Windows feature | No |
| 1b | Full Hyper-V stack (Microsoft-Hyper-V, -Services, -Hypervisor) | No |
| 2 | vmcompute service running | No |
| 2b | HNS service running | No |
| 8 | 172.16.0.0/24 subnet conflict | No (flag only; cannot remediate) |

If all checks pass, the detection script emits its compliance stdout line and writes `ClaudePrereqsReady.flag`.

### Remediation flow

Mirrors the detection checks. Gates (0, 0b) exit 1 with an error message (remediation cannot usefully continue). Fixes:

- **FIX 1**: `Enable-WindowsOptionalFeature VirtualMachinePlatform` — sets `$rebootRequired = $true`
- **FIX 1b**: `Enable-WindowsOptionalFeature` for the three Hyper-V features — sets `$rebootRequired = $true`; service starts are skipped pending reboot
- **FIX 2**: Starts `vmcompute` if stopped (skipped if features were just enabled)
- **FIX 2b**: Starts `HNS` if stopped

After all fixes, if there are no failures and no reboot is required, the remediation script writes `ClaudePrereqsReady.flag`.

### Restart notification

When `$rebootRequired` is set, the remediation script calls `Show-RestartNotification`:

1. **No interactive user** (`Win32_ComputerSystem.UserName` is null) ⇒ log, skip, return success.
2. **Once-per-boot guard**: compares the current `LastBootUpTime` against the value stored in `ClaudeCowork-RestartNotified.flag`. If matched, the user was already notified this boot — skip. A fresh reboot bumps the boot time and a future remediation run will re-prompt once if the reboot didn't actually happen.
3. **Broadcast** a `msg.exe * /time:60` message box to all active console sessions with instructions to restart at the user's convenience. Stores the current boot time in the sentinel flag.

`msg.exe` is used in preference to a toast/scheduled-task approach because it is built-in, works from SYSTEM to all logon sessions without registering an `AppUserModelID`, and has no external dependencies.

### Logging (three layers)

| Layer | Location | Purpose |
|-------|----------|---------|
| File | `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Claude\ClaudeCowork-*.log` | Full audit trail; rotates at 5 MB; auto-collected by Intune diagnostics |
| Event Log | Windows Application Log, Source `ClaudeCoworkMSIX` | EventID 1000/1002 = compliant/success, 1001/1003 = non-compliant/partial |
| Stdout | Detection: single compliance line or silence (per Win32 contract). Remediation: key=value summary for Intune install logs. | Visible in Intune portal |

## Known limitations

- **Feature enablement requires reboot**: `vmcompute` won't start until after the reboot that follows feature enablement; the script detects this state and skips service-start attempts. The user is prompted via `msg.exe`.
- **Subnet conflicts**: If another adapter already uses 172.16.0.0/24, the issue is flagged but cannot be automatically resolved.
- **msg.exe requirements**: Relies on Remote Desktop Services components shipped with Windows 11 Pro. If `msg.exe` is stripped (non-standard SKU or policy) the notification is logged as a failure but the remediation itself still succeeds.
  

