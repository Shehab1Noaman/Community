# 🛡️ Windows 11 24H2 — MDE Sense Client Detection & Remediation

> PowerShell scripts for detecting and remediating **Microsoft Defender for Endpoint (MDE) Sense client health** on **Windows 11 24H2** devices — designed for use with **Microsoft Intune Remediations**.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Repository Contents](#repository-contents)
- [Detection Logic](#detection-logic)
- [Remediation Logic](#remediation-logic)
- [Usage with Intune Remediations](#usage-with-intune-remediations)
- [Supported Scenarios](#supported-scenarios)
- [Important Notes](#important-notes)
- [Disclaimer](#disclaimer)

---

## Overview

This project helps IT admins identify and fix Windows 11 24H2 devices that are:

- ✅ Locally protected by **Microsoft Defender Antivirus**
- ✅ Onboarded (or partially onboarded) to **MDE**
- ❌ **Not appearing correctly in the Defender portal** — because the Sense client prerequisite is missing, incomplete, or not running

Microsoft documents a known issue for **Windows 11 24H2** where Defender for Endpoint may need to be installed manually using:

```cmd
DISM /online /Add-Capability /CapabilityName:Microsoft.Windows.Sense.Client~~~~
```

---

## Problem Statement

On Windows 11 24H2, the **SENSE Client** for Microsoft Defender for Endpoint is treated as a **Feature on Demand (FoD)**.

This means a device can show:

| Indicator | State |
|---|---|
| Defender Antivirus | ✅ Healthy |
| `OnboardingState` | ✅ `1` |
| Defender Portal visibility | ❌ Missing / Incorrect |

…because the Sense capability is not fully installed or the service is not running.

---

## Repository Contents

| Script | Purpose |
|---|---|
| `Detect-MDESenseHealth.ps1` | Checks whether the device is healthy from an MDE Sense client perspective |
| `Remediate-MDESenseHealth.ps1` | Attempts to repair the missing or unhealthy Sense client state |

Both scripts are designed for use with:

- **Intune Remediations**
- **Intune Custom Compliance**
- Other managed PowerShell deployment workflows

---

## Detection Logic

The detection script checks the following conditions:

| Check | Expected Value |
|---|---|
| `OnboardingState` | `1` |
| Windows build | `≥ 26100` (Windows 11 24H2+) |
| `Microsoft.Windows.Sense.Client~~~~` capability | `Installed` |
| Sense service existence | `true` |
| Sense service status | `Running` |
| `Microsoft-Windows-SENSE/Operational` log | Accessible |

### Detection Output

The script returns a **single-line JSON object** for Intune compatibility.

**✅ Healthy Example:**
```json
{
  "status": "Healthy",
  "build": 26100,
  "capabilityName": "Microsoft.Windows.Sense.Client~~~~",
  "capabilityState": "Installed",
  "onboardingState": 1,
  "senseService": { "exists": true, "status": "Running", "startMode": "Manual" },
  "senseLogAccessible": true,
  "issues": []
}
```

**❌ Unhealthy Example:**
```json
{
  "status": "Unhealthy",
  "build": 26100,
  "capabilityName": "Microsoft.Windows.Sense.Client~~~~",
  "capabilityState": "NotPresent",
  "onboardingState": 1,
  "senseService": { "exists": false, "status": null, "startMode": null },
  "senseLogAccessible": false,
  "issues": ["Sense service is missing."]
}
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Healthy |
| `1` | Unhealthy |

---

## Remediation Logic

The remediation script attempts to:

1. Install the Sense capability if missing
2. Verify `OnboardingState`
3. Start the Sense service if present but not running
4. Return JSON output for Intune reporting
5. Include recent SENSE event log entries on failure for easier triage

### Remediation Output

**✅ Healthy Example:**
```json
{
  "status": "Healthy",
  "build": 26100,
  "capabilityName": "Microsoft.Windows.Sense.Client~~~~",
  "onboardingState": 1,
  "logs": [
    "Detected build: 26100",
    "Product type: 1 (isWorkstation: True)",
    "Sense capability already Installed.",
    "Success. Sense service is Running and OnboardingState=1."
  ]
}
```

**❌ Unhealthy Example:**
```json
{
  "status": "Unhealthy",
  "build": 26100,
  "capabilityName": "Microsoft.Windows.Sense.Client~~~~",
  "onboardingState": 1,
  "logs": [
    "Detected build: 26100",
    "Product type: 1 (isWorkstation: True)",
    "Sense service is missing — cannot start a service that does not exist."
  ]
}
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Remediation succeeded |
| `1` | Remediation failed or requires manual intervention |

---

## Usage with Intune Remediations

| Setting | Value |
|---|---|
| **Detection script** | `Detect-MDESenseHealth.ps1` |
| **Remediation script** | `Remediate-MDESenseHealth.ps1` |
| **Run context** | `SYSTEM` |
| **Architecture** | `64-bit PowerShell` |

### Optional Parameter

The remediation script supports an optional `-CapabilitySource` parameter:

```powershell
-CapabilitySource "\\server\FoDRepo"
```

> Use this when devices **cannot retrieve Features on Demand** content from Windows Update or your normal servicing source.

---

## Supported Scenarios

This repo is intended primarily for:

- 🖥️ **Windows 11 24H2** workstations
- 🔐 **Microsoft Defender for Endpoint** environments
- 📱 **Intune-managed** (or similarly managed) enterprise endpoints

### Root Cause This Repo Addresses

This repo specifically targets the scenario where:

- A device has moved through a **Pro / Enterprise provisioning or upgrade path**
- The device **looks protected locally**
- But the **MDE Sense client prerequisite is missing or incomplete**
- So the device **does not report correctly in Defender**

This became especially relevant after Microsoft's documented **Windows 11 24H2** changes to the Defender for Endpoint Sense client packaging model.

---

## Important Notes

> ⚠️ **These scripts do NOT perform full MDE onboarding.**

If `OnboardingState` is not `1`, the remediation script will report the issue but **cannot fix it on its own**. The device still needs a valid onboarding method:

- ✅ Intune MDE onboarding policy
- ✅ Configuration Manager onboarding package
- ✅ Other supported onboarding method

---

## Disclaimer

> ⚠️ **Test these scripts in a lab or pilot group before broad deployment.**  
> Review change-control requirements before enabling automatic remediation in production.