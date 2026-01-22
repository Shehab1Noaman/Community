# Secure Boot 2026 Readiness (UEFI CA 2023) – Intune Detection + Remediation

This repository contains two PowerShell scripts designed for **Microsoft Intune Proactive Remediations** (or local admin use) to help IT admins **detect** and **remediate** Windows devices that are not yet ready for the Secure Boot certificate lifecycle changes landing in 2026.

The goal is simple:
- **Detection** answers: **“Is this device safe for June 2026?”**
- **Remediation** triggers the supported update workflow and returns **clear next steps** (most commonly: reboot)

---

## Repository structure

```
SecureBoot/
├─ Detect-SecureBoot2026Readiness.ps1
├─ Remediate-SecureBoot2026Readiness.ps1
└─ README.md
```

---

## What these scripts help you do

Across a mixed Windows estate, Secure Boot readiness isn’t just “did Windows download something.” You need evidence that:
- Secure Boot is enabled
- OS-side staging has completed
- firmware-side application has completed (or is still pending)
- firmware isn’t rejecting the update flow
- you can explain failures quickly (for service desk / OEM escalation)

These scripts are built for that real-world workflow:
- One JSON output object
- Clear verdict/state fields
- Intune-friendly exit codes

---

# 1) Detection Script – `Detect-SecureBoot2026Readiness.ps1`

## What it checks

### Secure Boot state
- `Confirm-SecureBootUEFI` → `SecureBootOn`

### Registry servicing state
Reads:
- `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing`
  - `UEFICA2023Status`
  - `UEFICA2023Error`
  - `WindowsUEFICA2023Capable`
- `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot`
  - `AvailableUpdates`
  - `HighConfidenceOptOut`
  - `MicrosoftUpdateManagedOptIn`

### TPM-WMI event evidence (System log)
The script inspects TPM-WMI provider events:
- **1808** = success (firmware applied)
- **1801** = staged/pending (not applied yet)
- **1795–1799** = firmware/update error signals

It computes:
- `FirmwareState`: `Applied` / `Pending` / `Unknown`
- `ErrorsAfterSuccess`: true if failures occur after a success event

### Optional UEFI certificate inventory (KEK/DB)
If the platform and execution context allow it, the script reads UEFI variables via `Get-SecureBootUEFI` and parses X.509 certs from:
- `KEK`
- `DB`

> Note: Some devices (or SYSTEM/Intune context) may return 0 certs even when Secure Boot is enabled. This does not always indicate missing certificates—treat cert inventory as supporting evidence, not the only proof.

### Expiry awareness
- Uses `ExpiryThreshold = 2026-11-01`
- Flags:
  - `ExpiringButReplaced`
  - `ExpiringAndNotReplaced` (this is the actionable one)

---

## Exit codes
- **Exit 0** = Compliant
- **Exit 1** = Not compliant

---

## Output (JSON)
The detection script outputs a single compressed JSON object including:
- system identity + firmware version
- Secure Boot state
- registry servicing state
- event-derived firmware state + timestamps
- (optional) UEFI cert details
- compliance verdict and reasons

Key fields you’ll use daily:
- `SafeForJune2026`
- `ComplianceReasons`
- `ComplianceDetails`
- `UEFICA2023Status`
- `UEFICA2023Error`
- `FirmwareState`
- `LatestEvent1808`
- `LatestEvent1801`
- `LatestFailureEventId`

---

## How to read the detection output quickly

Start here:
- ✅ `SafeForJune2026 : true` → SAFE (exit 0)
- ❌ `SafeForJune2026 : false` → NOT SAFE (exit 1)

If NOT SAFE, immediately read:
- `ComplianceReasons` (short flags)
- `ComplianceDetails` (human explanation)

Common patterns:
- `UEFICA2023Status = NotStarted / InProgress`  
  Usually means the update workflow hasn’t completed. Often resolved after time + reboot.
- `FirmwareState = Pending`  
  1801 is newest; firmware application hasn’t completed yet. Reboot and re-check until 1808 appears.
- `LatestFailureEventId = 1795` (or 1796–1798)  
  Firmware rejection patterns—prioritise OEM BIOS/UEFI updates for that model.

---

# 2) Remediation Script – `Remediate-SecureBoot2026Readiness.ps1`

This script is designed to pair with the detection script in **Intune Proactive Remediations**.
It triggers the workflow and returns **Status/Reason/NextSteps** that you can paste into a ticket.

## What it does (step-by-step)

### Pre-flight
- Confirms Secure Boot is ON.
  - If not ON (or can’t be determined), remediation stops and returns `NotCompleted` with next steps.
- If the device already shows `FirmwareState = Applied` and has no servicing error, it exits **0** (already compliant).

### Action 1: Set AvailableUpdates
Sets:
- `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates = 0x5944`

This is the enterprise trigger used to initiate the Secure Boot update workflow.

### Action 2: Start the scheduled task immediately
Runs:
- `\Microsoft\Windows\PI\Secure-Boot-Update`

It records:
- whether the task was found
- whether it started
- whether it completed within a short wait window
- `LastTaskResult` (when available)

> Important: Even if the task starts successfully, firmware-side completion may still require reboot(s) and time.

### Action 3: Suspend BitLocker for two reboots
If BitLocker protection is ON, it attempts:
- `Suspend-BitLocker -RebootCount 2`
Fallback:
- `manage-bde -protectors -disable C: -RebootCount 2`

This reduces the chance of BitLocker recovery prompts during boot chain/firmware changes.
If suspension fails, the script warns you so you can ensure recovery keys are available.

### Post-state assessment
Re-checks:
- servicing registry values
- event-derived `FirmwareState`

Then decides:
- **Completed (exit 0)** if `FirmwareState = Applied` and no servicing error exists
- **NotCompleted (exit 1)** otherwise, with tailored next steps

---

## Exit codes
- **Exit 0** = Completed (compliant now)
- **Exit 1** = NotCompleted (requires action)

---

## Output (JSON)
The remediation script outputs compressed JSON:

- `Status`: `Completed` / `NotCompleted`
- `Reason`: single paragraph (ticket-friendly)
- `NextSteps`: checklist
- `PreState`: snapshot before changes
- `Actions`: what it attempted + success/failure evidence
- `PostState`: snapshot after changes

---

## How to read the remediation output quickly

Start with:
- `Status`
- `Reason`
- `NextSteps`

Most common outcome after triggering:
- `Status = NotCompleted`
- `FirmwareState = Pending`
- `NextSteps` includes **reboot** (often twice if BitLocker was suspended)

That’s not a failure—it usually means the workflow is staged and waiting for reboot completion.

---

# Intune deployment (recommended)

## Option A (Best): Proactive Remediations (Detection + Remediation together)

1. Intune Admin Center → **Reports** (or **Endpoint analytics**) → **Proactive remediations**
2. Create a new package
3. Upload:
   - Detection: `Detect-SecureBoot2026Readiness.ps1`
   - Remediation: `Remediate-SecureBoot2026Readiness.ps1`
4. Script settings:
   - Run using logged-on credentials: **No**
   - Run script in 64-bit PowerShell: **Yes**
5. Assign to a pilot device group first
6. Schedule:
   - Pilot: Daily
   - Broad rollout: Weekly (once stable)

## Option B: Platform Scripts (detection only)
Use this if you only want reporting first.

---

# Local testing (admin)

Run detection:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Detect-SecureBoot2026Readiness.ps1
echo $LASTEXITCODE
```

Run remediation:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Remediate-SecureBoot2026Readiness.ps1
echo $LASTEXITCODE
```

Tip: If you want readable JSON while testing, remove `-Compress` from `ConvertTo-Json`.

---

# Troubleshooting matrix (fast)

## Detection says NOT SAFE
- **SecureBootDisabled** → enable Secure Boot in BIOS/UEFI
- **UpdateNotStaged** (`UEFICA2023Status` not Updated) → allow servicing cycle + reboot
- **FirmwareNotAppliedYet** (`FirmwareState = Pending`) → reboot and re-check until 1808 is newest
- **UEFICA2023ErrorPresent** → investigate servicing error + related TPM-WMI events
- **1795/1796/1797/1798 present** → firmware rejection patterns → update OEM BIOS/UEFI first

## Remediation returns NotCompleted
- **Pending** → reboot (twice if BitLocker was suspended), re-run detection
- **Unknown** → reboot + check TPM-WMI events exist; verify task ran
- **Task not found** → confirm `\Microsoft\Windows\PI\Secure-Boot-Update` exists and Windows servicing components are present
- **BitLocker suspension failed** → ensure recovery key is available before rebooting

---

# Notes / operational guidance

- Don’t mix multiple deployment methods on the same pilot devices during testing.
- Treat Event 1795+ as a signal to prioritise OEM firmware updates for that model.
- Expect staged/pending states during rollout—reboots are often part of the completion path.

---

# Versioning
- v1.0 – Initial release (Detection + Remediation, JSON reporting, Intune-friendly exit codes)

---

# License
Provided as-is. Review internally before broad deployment and align with your change control process.

---

# Contributing
Issues and pull requests are welcome.
If you modify output fields, keep backward compatibility where possible (Intune reporting and dashboards depend on stable keys).
