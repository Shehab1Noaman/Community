#requires -Version 5.1
<#
.SYNOPSIS
Intune Detection Script - UEFI Certificate Update Status with Full Certificate Details

.DESCRIPTION
Detects if the 2023 UEFI certificate updates are installed.
Includes BIOS version and UEFI certificate details (KEK and DB).

Exit 0 = Compliant (Updated)
Exit 1 = Not Compliant (Needs Update)
#>

# Helper function to parse EFI Signature List
function ConvertFrom-EfiSignatureList {
    param([byte[]]$Data)
    
    $out = @()
    if ($null -eq $Data -or $Data.Length -lt 28) { return $out }
    
    $offset = 0
    while ($offset -lt $Data.Length) {
        if (($Data.Length - $offset) -lt 28) { break }
        $listStart = $offset
        
        # SignatureType GUID (16 bytes)
        $sigTypeGuid = [Guid]::new([byte[]]$Data[$offset..($offset + 15)])
        $offset += 16
        
        # ESL header fields
        $listSize = [BitConverter]::ToUInt32($Data, $offset); $offset += 4
        $headerSize = [BitConverter]::ToUInt32($Data, $offset); $offset += 4
        $signatureSize = [BitConverter]::ToUInt32($Data, $offset); $offset += 4
        
        if ($listSize -lt 28 -or $signatureSize -le 0) { break }
        
        $listEnd = $listStart + $listSize
        if ($listEnd -gt $Data.Length) { break }
        
        # Skip signature list header
        if ($headerSize -gt 0) {
            $offset += $headerSize
            if ($offset -gt $listEnd) { $offset = $listEnd }
        }
        
        # Walk signatures
        while (($offset + 16 + ($signatureSize - 16)) -le $listEnd) {
            # Owner GUID (16 bytes)
            $ownerGuid = [Guid]::new([byte[]]$Data[$offset..($offset + 15)])
            $offset += 16
            
            # Signature data
            $payloadSize = $signatureSize - 16
            if (($offset + $payloadSize) -gt $listEnd) { break }
            
            $payload = [byte[]]$Data[$offset..($offset + $payloadSize - 1)]
            $offset += $payloadSize
            
            $out += [PSCustomObject]@{
                SignatureType = $sigTypeGuid
                OwnerGuid = $ownerGuid
                Data = $payload
            }
        }
        
        $offset = $listEnd
    }
    
    return $out
}

# Get X.509 certificates from UEFI variable
function Get-UefiX509Certs {
    param(
        [ValidateSet('pk','kek','db')]
        [string]$Name
    )
    
    $x509Guid = [Guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
    
    try {
        $var = Get-SecureBootUEFI -Name $Name -ErrorAction Stop
        if ($null -eq $var -or $null -eq $var.Bytes -or $var.Bytes.Length -eq 0) { return @() }
        
        $sigs = ConvertFrom-EfiSignatureList -Data $var.Bytes
        $certSigs = $sigs | Where-Object { $_.SignatureType -eq $x509Guid }
        
        $certs = @()
        foreach ($s in $certSigs) {
            try {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($s.Data)
                $certs += $cert
            } catch {
                # Skip invalid certs
            }
        }
        return $certs
    } catch {
        return @()
    }
}

# Check 1: BIOS/Firmware Version
$UEFI_FirmwareVersion = "Unavailable"
try {
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $UEFI_FirmwareVersion = $bios.SMBIOSBIOSVersion
} catch {
    $UEFI_FirmwareVersion = "Unavailable"
}

# Check 2: Secure Boot enabled
$secureBootOn = $null
try {
    $secureBootOn = Confirm-SecureBootUEFI -ErrorAction Stop
} catch {
    $secureBootOn = $false
}

# Check 3: Registry values
$statusPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
$bootPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"

$UEFICA2023Status = $null
$UEFICA2023Error = $null
$WindowsUEFICA2023Capable = $null
$AvailableUpdates = $null
$HighConfidenceOptOut = $null
$MicrosoftUpdateManagedOptIn = $null

try {
    $UEFICA2023Status = (Get-ItemProperty -Path $statusPath -Name "UEFICA2023Status" -ErrorAction SilentlyContinue).UEFICA2023Status
} catch {}

try {
    $UEFICA2023Error = (Get-ItemProperty -Path $statusPath -Name "UEFICA2023Error" -ErrorAction SilentlyContinue).UEFICA2023Error
} catch {}

try {
    $WindowsUEFICA2023Capable = (Get-ItemProperty -Path $statusPath -Name "WindowsUEFICA2023Capable" -ErrorAction SilentlyContinue).WindowsUEFICA2023Capable
} catch {}

try {
    $AvailableUpdates = (Get-ItemProperty -Path $bootPath -Name "AvailableUpdates" -ErrorAction SilentlyContinue).AvailableUpdates
} catch {}

try {
    $HighConfidenceOptOut = (Get-ItemProperty -Path $bootPath -Name "HighConfidenceOptOut" -ErrorAction SilentlyContinue).HighConfidenceOptOut
} catch {}

try {
    $MicrosoftUpdateManagedOptIn = (Get-ItemProperty -Path $bootPath -Name "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue).MicrosoftUpdateManagedOptIn
} catch {}

# Check 4: Event 1808 (success event)
$latestSuccessTime = $null
$event1808 = $null

try {
    $event1808 = Get-WinEvent -FilterHashtable @{
        LogName = "System"
        Id = 1808
    } -MaxEvents 1 -ErrorAction SilentlyContinue | 
    Where-Object { $_.ProviderName -like "*TPM-WMI*" } |
    Select-Object -First 1
    
    if ($event1808) {
        $latestSuccessTime = $event1808.TimeCreated
    }
} catch {}

# Check 5: Latest failure event
$latestFailureTime = $null
$latestFailureEventId = $null

try {
    $failureEvents = Get-WinEvent -FilterHashtable @{
        LogName = "System"
        Id = 1801, 1795, 1796, 1797, 1798
    } -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -like "*TPM-WMI*" }
    
    if ($failureEvents) {
        $latestFailure = $failureEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $latestFailureTime = $latestFailure.TimeCreated
        $latestFailureEventId = $latestFailure.Id
    }
} catch {}

# Check 6: Errors after success?
$errorsAfterSuccess = $false
if ($latestSuccessTime -and $latestFailureTime) {
    if ($latestFailureTime -gt $latestSuccessTime) {
        $errorsAfterSuccess = $true
    }
}

# Check 7: UEFI Certificates (KEK and DB)
$KekCerts = @()
$DbCerts = @()

try {
    $KekCerts = Get-UefiX509Certs -Name kek
} catch {}

try {
    $DbCerts = Get-UefiX509Certs -Name db
} catch {}

# Parse certificate details
$KekCertDetails = @()
foreach ($cert in $KekCerts) {
    $KekCertDetails += [PSCustomObject]@{
        Subject = $cert.Subject
        Issuer = $cert.Issuer
        Thumbprint = $cert.Thumbprint
        NotBefore = $cert.NotBefore.ToString("dd-MM-yyyy")
        NotAfter = $cert.NotAfter.ToString("dd-MM-yyyy")
        Serial = $cert.SerialNumber
    }
}

$DbCertDetails = @()
foreach ($cert in $DbCerts) {
    $DbCertDetails += [PSCustomObject]@{
        Subject = $cert.Subject
        Issuer = $cert.Issuer
        Thumbprint = $cert.Thumbprint
        NotBefore = $cert.NotBefore.ToString("dd-MM-yyyy")
        NotAfter = $cert.NotAfter.ToString("dd-MM-yyyy")
        Serial = $cert.SerialNumber
    }
}

# Detect specific certificates
$HasMicrosoftKEK2011 = ($KekCerts | Where-Object { $_.Subject -match "Microsoft Corporation KEK CA 2011" }).Count -gt 0
$HasMicrosoftKEK2023 = ($KekCerts | Where-Object { $_.Subject -match "KEK.*2023" }).Count -gt 0

$HasMicrosoftUEFI2011 = ($DbCerts | Where-Object { $_.Subject -match "Microsoft.*UEFI.*2011" }).Count -gt 0
$HasMicrosoftUEFI2023 = ($DbCerts | Where-Object { $_.Subject -match "Microsoft.*UEFI.*2023" }).Count -gt 0
$HasWindowsUEFI2023 = ($DbCerts | Where-Object { $_.Subject -match "Windows.*UEFI.*2023" }).Count -gt 0
$HasOptionRomUEFI2023 = ($DbCerts | Where-Object { $_.Subject -match "Option ROM.*UEFI.*2023" }).Count -gt 0

# Decision Logic
$statusSaysUpdated = ($UEFICA2023Status -eq "Updated")
$eventSaysUpdated = ($event1808 -ne $null)
$hasUEFIError = ($UEFICA2023Error -and $UEFICA2023Error -ne 0)

# Check for expiring certificates (expires before July 2026)
$expiryThreshold = [DateTime]"01-07-2026"
$hasExpiringCerts = $false
$expiringCertList = @()

foreach ($cert in $KekCerts + $DbCerts) {
    if ($cert.NotAfter -lt $expiryThreshold) {
        $hasExpiringCerts = $true
        $expiringCertList += "$($cert.Subject) (expires $($cert.NotAfter.ToString('dd-MM-yyyy')))"
    }
}

# Check if 2023 replacement certificates are present
$has2023Certs = $false
if ($HasMicrosoftKEK2023 -or $HasWindowsUEFI2023) {
    $has2023Certs = $true
}

# Compliance Logic
$safe = $false
$complianceReasons = @()

if (-not $secureBootOn) {
    $complianceReasons += "SecureBootDisabled"
} elseif ($statusSaysUpdated -or $eventSaysUpdated) {
    if (-not $hasUEFIError -and -not $errorsAfterSuccess) {
        # Basic update completed, but check certificates
        if ($hasExpiringCerts -and -not $has2023Certs) {
            $complianceReasons += "ExpiringCertsWithout2023Replacement"
            $safe = $false
        } else {
            $safe = $true
        }
    } else {
        $complianceReasons += "UEFIErrorsDetected"
    }
} else {
    $complianceReasons += "UpdateNotCompleted"
}

# Build output object
$summary = [PSCustomObject]@{
    Timestamp = (Get-Date -Format s)
    Computer  = $env:COMPUTERNAME
    
    UEFI_FirmwareVersion = $UEFI_FirmwareVersion
    
    SecureBootOn = $secureBootOn
    UEFICA2023Status = $UEFICA2023Status
    UEFICA2023Error  = $UEFICA2023Error
    WindowsUEFICA2023Capable = $WindowsUEFICA2023Capable
    
    AvailableUpdates = $AvailableUpdates
    HighConfidenceOptOut = $HighConfidenceOptOut
    MicrosoftUpdateManagedOptIn = $MicrosoftUpdateManagedOptIn
    
    LatestEvent1808 = $latestSuccessTime
    LatestFailureTime = $latestFailureTime
    LatestFailureEventId = $latestFailureEventId
    ErrorsAfterSuccess = $errorsAfterSuccess
    
    KEK_CertCount = $KekCerts.Count
    DB_CertCount = $DbCerts.Count
    
    HasMicrosoftKEK2011 = $HasMicrosoftKEK2011
    HasMicrosoftKEK2023 = $HasMicrosoftKEK2023
    HasMicrosoftUEFI2011 = $HasMicrosoftUEFI2011
    HasMicrosoftUEFI2023 = $HasMicrosoftUEFI2023
    HasWindowsUEFI2023 = $HasWindowsUEFI2023
    HasOptionRomUEFI2023 = $HasOptionRomUEFI2023
    
    KEK_Certificates = $KekCertDetails
    DB_Certificates = $DbCertDetails
    
    HasExpiringCerts = $hasExpiringCerts
    ExpiringCertificates = $expiringCertList
    Has2023ReplacementCerts = $has2023Certs
    ComplianceReasons = $complianceReasons
    
    SafeForJune2026 = $safe
}

# Output JSON
#$summary | ConvertTo-Json -Depth 5

# Exit with appropriate code
if ($safe) {
$summary | ConvertTo-Json -Depth 5 -Compress
    exit 0
} else {
$summary | ConvertTo-Json -Depth 5 -Compress
    exit 1
}
