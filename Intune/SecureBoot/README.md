# UEFI Secure Boot 2026 Readiness Detection Script

## Overview

This PowerShell detection script for Microsoft Intune checks whether Windows devices have the required 2023 UEFI certificate updates installed and are ready for the upcoming certificate expiration in 2026. The script provides comprehensive diagnostics including BIOS version, registry status, event logs, and full UEFI certificate details.

## Background

In 2026, certain UEFI certificates used for Secure Boot will expire. Microsoft released updates in 2023 to replace these expiring certificates.  This script helps identify devices that: 
- Have successfully applied the updates
- Have expiring certificates without 2023 replacements
- May encounter issues during the update process
- Are not compliant and require attention

## Exit Codes

- **Exit 0**: Compliant (Device is updated and safe for June 2026)
- **Exit 1**: Not Compliant (Device needs updates or has issues)

## Features

### Comprehensive Checks

1. **BIOS/Firmware Version Detection**
2. **Secure Boot Status** - Verifies if Secure Boot is enabled
3. **Registry Analysis** - Checks multiple registry keys: 
   - `UEFICA2023Status`
   - `UEFICA2023Error`
   - `WindowsUEFICA2023Capable`
   - `AvailableUpdates`
   - `HighConfidenceOptOut`
   - `MicrosoftUpdateManagedOptIn`
4. **Event Log Analysis** - Monitors System event log for: 
   - Event 1808 (success)
   - Events 1801, 1795, 1796, 1797, 1798 (failures)
5. **UEFI Certificate Inspection** - Full parsing of KEK and DB certificates with: 
   - Subject and Issuer
   - Thumbprint
   - Validity dates (NotBefore/NotAfter)
   - Serial number
6. **Certificate Expiration Check** - Identifies certificates expiring before July 2026
7. **2023 Certificate Detection** - Verifies presence of replacement certificates

### Certificate Detection

The script specifically checks for: 

**KEK (Key Exchange Keys):**
- Microsoft Corporation KEK CA 2011
- Microsoft KEK 2023 certificates

**DB (Signature Database):**
- Microsoft UEFI CA 2011
- Microsoft UEFI CA 2023
- Windows UEFI CA 2023
- Option ROM UEFI CA 2023

## Output

The script outputs a JSON object with detailed information: 

```json
{
  "Timestamp": "2026-01-05T10:30:00",
  "Computer": "DESKTOP-ABC123",
  "UEFI_FirmwareVersion": "1.2.3",
  "SecureBootOn":  true,
  "UEFICA2023Status": "Updated",
  "UEFICA2023Error": null,
  "WindowsUEFICA2023Capable": 1,
  "LatestEvent1808": "2025-12-15T08:00:00",
  "KEK_CertCount": 2,
  "DB_CertCount": 4,
  "HasMicrosoftKEK2023": true,
  "HasWindowsUEFI2023":  true,
  "HasExpiringCerts": true,
  "ExpiringCertificates": ["Microsoft Corporation KEK CA 2011 (expires 14-07-2026)"],
  "Has2023ReplacementCerts": true,
  "SafeForJune2026": true
}
```

## Compliance Logic

A device is considered **compliant** when:
1.  Secure Boot is enabled
2. Update status shows "Updated" OR Event 1808 exists
3. No UEFI errors present
4. Either: 
   - No expiring certificates detected, OR
   - Expiring certificates exist BUT 2023 replacement certificates are present

A device is **non-compliant** if:
- Secure Boot is disabled
- UEFI errors detected
- Update not completed
- Expiring certificates exist without 2023 replacements

## Deployment in Intune

### Create Detection Script

1. Navigate to **Microsoft Intune admin center**
2. Go to **Devices** > **Scripts** > **Platform scripts**
3. Click **Add** > **Windows 10 and later**
4. Upload `Detect-SecureBoot2026Readiness.ps1`
5. Configure settings:
   - **Run this script using the logged-on credentials**:  No
   - **Enforce script signature check**: No
   - **Run script in 64-bit PowerShell**: Yes

### Assign to Devices

1. Assign to appropriate device groups
2. Set schedule (recommended: Daily or Weekly)
3. Review compliance in Intune reports

### Monitor Results

- **Compliant devices**: Exit code 0
- **Non-compliant devices**: Exit code 1
- Review JSON output for detailed diagnostics

## Requirements

- **PowerShell**:  Version 5.1 or higher
- **Permissions**: Must run with administrator privileges
- **OS**: Windows 10/11 with UEFI firmware
- **Secure Boot**: Device must support UEFI Secure Boot

## Troubleshooting

### Common Issues

**1. "Secure Boot is disabled"**
- Enable Secure Boot in BIOS/UEFI settings
- May require clearing existing keys and resetting to factory defaults

**2. "UpdateNotCompleted"**
- Ensure KB5025885 or later is installed
- Check Windows Update history
- Manually trigger Windows Update

**3. "ExpiringCertsWithout2023Replacement"**
- Device detected expiring certificates but no 2023 replacements
- May require firmware update from manufacturer
- Check with OEM for BIOS/UEFI updates

**4. "UEFIErrorsDetected"**
- Review System event log for events 1801, 1795-1798
- May indicate hardware incompatibility
- Contact device manufacturer

### Event Log Investigation

Check System event log for TPM-WMI provider events:
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1808,1801,1795,1796,1797,1798} -MaxEvents 10 | 
    Where-Object {$_. ProviderName -like "*TPM-WMI*"} | 
    Format-List TimeCreated, Id, Message
```

## Related Resources

- [Microsoft Security Update Guide - UEFI CA](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24932)
- [KB5025885: UEFI Secure Boot certificate updates](https://support.microsoft.com/kb/5025885)
- [Managing Secure Boot in Windows](https://learn.microsoft.com/windows-hardware/manufacture/desktop/secure-boot-landing)

## Version History

- **v1.0** (2026-01-05): Initial release with full certificate inspection and 2026 readiness check

## License

This script is provided as-is for use in Intune environments. Modify as needed for your organization's requirements. 

## Author

Community contribution for Microsoft Intune deployments

## Contributing

Contributions, issues, and feature requests are welcome.  Please ensure any modifications maintain backward compatibility with existing Intune deployments.
