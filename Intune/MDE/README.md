# Windows 11 24H2 MDE Sense Client Detection and Remediation

PowerShell detection and remediation scripts for **Microsoft Defender for Endpoint (MDE) Sense client health** on **Windows 11 24H2** devices.

This project was created to help IT admins identify and fix devices that are:

- locally protected by Microsoft Defender Antivirus
- onboarded or partially onboarded to MDE
- but **not appearing correctly in the Defender portal** because the **Sense client prerequisite is missing, incomplete, or not running**

Microsoft documents a known issue for **Windows 11 version 24H2** where Defender for Endpoint may need to be installed manually on affected devices, and the supported workaround uses:

```cmd
DISM /online /Add-Capability /CapabilityName:Microsoft.Windows.Sense.Client~~~~
