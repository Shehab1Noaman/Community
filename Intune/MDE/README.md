# Windows 11 24H2 MDE Sense Client Detection and Remediation

PowerShell detection and remediation scripts for **Microsoft Defender for Endpoint (MDE) Sense client health** on **Windows 11 24H2** devices.

This project was created to help IT admins identify and fix devices that are:

- locally protected by Microsoft Defender Antivirus
- onboarded or partially onboarded to MDE
- but **not appearing correctly in the Defender portal** because the **Sense client prerequisite is missing, incomplete, or not running**

Microsoft documents a known issue for **Windows 11 version 24H2** where Defender for Endpoint may need to be installed manually on affected devices, and the supported workaround uses:

```cmd
DISM /online /Add-Capability /CapabilityName:Microsoft.Windows.Sense.Client~~~~
```


**What this repo contains**
- Detect-MDESenseHealth.ps1
Checks whether the device is healthy from an MDE Sense client perspective.
- Remediate-MDESenseHealth.ps1
Attempts to repair the missing or unhealthy Sense client state.

Both scripts are designed for use with:

- Intune Remediations
- Intune Custom Compliance
- other managed PowerShell deployment workflows
  
**Why this matters**

On Windows 11 24H2, the SENSE Client for Microsoft Defender for Endpoint is treated as a Feature on Demand.

Microsoft also documents a known Windows 11 24H2 issue where Defender for Endpoint onboarding can fail unless the Sense client prerequisite is installed manually.

**That means a device can show:**

Defender Antivirus healthy
OnboardingState = 1
but still fail to appear properly in the Defender portal because the Sense capability is not fully installed or the service is not running
Detection logic

The detection script checks:

OnboardingState = 1
Windows build is 26100 or later for Windows 11 24H2+
The capability Microsoft.Windows.Sense.Client~~~~ is Installed
The sense service exists
The sense service is Running
The Microsoft-Windows-SENSE/Operational log is accessible
Detection output

The script returns a single-line JSON object for Intune compatibility.

Healthy example:

{"status":"Healthy","build":26100,"capabilityName":"Microsoft.Windows.Sense.Client~~~~","capabilityState":"Installed","onboardingState":1,"senseService":{"exists":true,"status":"Running","startMode":"Manual"},"senseLogAccessible":true,"issues":[]}

Unhealthy example:
```jason
{"status":"Unhealthy","build":26100,"capabilityName":"Microsoft.Windows.Sense.Client~~~~","capabilityState":"NotPresent","onboardingState":1,"senseService":{"exists":false,"status":null,"startMode":null},"senseLogAccessible":false,"issues":["Sense service is missing."]}
```

Exit codes:

0 = Healthy
1 = Unhealthy
Remediation logic

The remediation script attempts to:

Install the Sense capability if required
Verify OnboardingState
Start the sense service if it is present but not running
Return JSON output for Intune reporting
Include recent SENSE events on failure for easier triage
Remediation output

Healthy example:

{"status":"Healthy","build":26100,"capabilityName":"Microsoft.Windows.Sense.Client~~~~","onboardingState":1,"logs":["Detected build: 26100","Product type: 1 (isWorkstation: True)","Sense capability already Installed.","Success. Sense service is Running and OnboardingState=1."]}

Unhealthy example:

{"status":"Unhealthy","build":26100,"capabilityName":"Microsoft.Windows.Sense.Client~~~~","onboardingState":1,"logs":["Detected build: 26100","Product type: 1 (isWorkstation: True)","Sense service is missing — cannot start a service that does not exist."]}

Exit codes:

0 = Remediation succeeded
1 = Remediation failed or requires manual intervention
Important note about onboarding

These scripts do not perform full MDE onboarding.

If OnboardingState is not 1, the remediation script will report the issue but cannot fix it by itself. In that case, the device still needs the correct:

Intune MDE onboarding policy
Configuration Manager onboarding package
or other supported onboarding method
Usage with Intune Remediations
Detection script

Upload Detect-MDESenseHealth.ps1 as the detection script.

Remediation script

Upload Remediate-MDESenseHealth.ps1 as the remediation script.

Run context

Use SYSTEM context.

Architecture

Use 64-bit PowerShell.

Optional parameter

The remediation script supports an optional parameter:

-CapabilitySource "\\server\FoDRepo"

Use this when devices cannot retrieve Features on Demand content from Windows Update or your normal servicing source.

Supported scenario

This repo is intended primarily for:

Windows 11 24H2
workstations
Microsoft Defender for Endpoint environments
Intune-managed or similarly managed enterprise endpoints
Root cause this repo addresses

This repo specifically targets the scenario where:

a device has moved through a Pro / Enterprise provisioning or upgrade path
the device looks protected locally
but the MDE Sense client prerequisite is missing or incomplete
so the device does not report correctly in Defender

This became especially relevant after Microsoft’s documented Windows 11 24H2 changes to the Defender for Endpoint Sense client packaging model.

Disclaimer

Test these scripts in a lab or pilot group before broad deployment.
Review change-control requirements before enabling automatic remediation in production.
