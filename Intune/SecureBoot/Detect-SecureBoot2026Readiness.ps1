#requires -Version 5.1
<#
.SYNOPSIS
Intune Detection Script - Secure Boot 2026 (UEFI CA 2023) status with full cert + event reporting

.DESCRIPTION
- Reads Secure Boot state
- Reads SecureBoot servicing registry values
- Reads TPM-WMI events 1801/1808 (and related IDs)
- Reads KEK/DB X.509 certs from UEFI variables
- Outputs a single JSON object (compressed)
- Exit 0 = Compliant (firmware applied / Event 1808 not superseded)
- Exit 1 = Not compliant

REPORTING IMPROVEMENTS
- ExpiringButReplaced / ExpiringAndNotReplaced flags
- When 1801 is newest, ComplianceReasons includes FirmwareNotAppliedYet and a human-readable FirmwareNotAppliedReason
- FirmwareNotAppliedReason is derived from the latest 1801 message (first line)

#>

# -----------------------------
# Helpers
# -----------------------------

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
        $listSize      = [BitConverter]::ToUInt32($Data, $offset); $offset += 4
        $headerSize    = [BitConverter]::ToUInt32($Data, $offset); $offset += 4
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
            $ownerGuid = [Guid]::new([byte[]]$Data[$offset..($offset + 15)])
            $offset += 16

            $payloadSize = $signatureSize - 16
            if (($offset + $payloadSize) -gt $listEnd) { break }

            $payload = [byte[]]$Data[$offset..($offset + $payloadSize - 1)]
            $offset += $payloadSize

            $out += [PSCustomObject]@{
                SignatureType = $sigTypeGuid
                OwnerGuid     = $ownerGuid
                Data          = $payload
            }
        }

        $offset = $listEnd
    }

    return $out
}

function Get-UefiX509Certs {
    param(
        [ValidateSet('pk','kek','db')]
        [string]$Name
    )

    # EFI_CERT_X509_GUID
    $x509Guid = [Guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072"

    try {
        $var = Get-SecureBootUEFI -Name $Name -ErrorAction Stop
        if ($null -eq $var -or $null -eq $var.Bytes -or $var.Bytes.Length -eq 0) { return @() }

        $sigs     = ConvertFrom-EfiSignatureList -Data $var.Bytes
        $certSigs = $sigs | Where-Object { $_.SignatureType -eq $x509Guid }

        $certs = @()
        foreach ($s in $certSigs) {
            try { $certs += [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($s.Data) } catch {}
        }

        return $certs
    } catch {
        return @()
    }
}

function Get-FirstLine {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    return (($Text -split "(\r?\n)")[0]).Trim()
}

function Get-ConfidenceFrom1801 {
    param([string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return $null }
    if ($Message -match '(High Confidence|Needs More Data|Unknown|Paused)') { return $matches[1] }
    return $null
}

# -----------------------------
# Collect basic state
# -----------------------------

$timestampIso = (Get-Date).ToString("o")
$computerName = $env:COMPUTERNAME

# BIOS/Firmware Version
$UEFI_FirmwareVersion = "Unavailable"
try {
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $UEFI_FirmwareVersion = $bios.SMBIOSBIOSVersion
} catch {}

# Secure Boot enabled?
$secureBootOn = $null
try { $secureBootOn = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $secureBootOn = $false }

# Registry values
$statusPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
$bootPath   = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"

$UEFICA2023Status            = $null
$UEFICA2023Error             = $null
$WindowsUEFICA2023Capable    = $null
$AvailableUpdates            = $null
$HighConfidenceOptOut        = $null
$MicrosoftUpdateManagedOptIn = $null

try { $UEFICA2023Status         = (Get-ItemProperty -Path $statusPath -Name "UEFICA2023Status" -ErrorAction SilentlyContinue).UEFICA2023Status } catch {}
try { $UEFICA2023Error          = (Get-ItemProperty -Path $statusPath -Name "UEFICA2023Error"  -ErrorAction SilentlyContinue).UEFICA2023Error  } catch {}
try { $WindowsUEFICA2023Capable = (Get-ItemProperty -Path $statusPath -Name "WindowsUEFICA2023Capable" -ErrorAction SilentlyContinue).WindowsUEFICA2023Capable } catch {}
try { $AvailableUpdates         = (Get-ItemProperty -Path $bootPath   -Name "AvailableUpdates" -ErrorAction SilentlyContinue).AvailableUpdates } catch {}
try { $HighConfidenceOptOut     = (Get-ItemProperty -Path $bootPath   -Name "HighConfidenceOptOut" -ErrorAction SilentlyContinue).HighConfidenceOptOut } catch {}
try { $MicrosoftUpdateManagedOptIn = (Get-ItemProperty -Path $bootPath -Name "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue).MicrosoftUpdateManagedOptIn } catch {}

$osStaged = ($UEFICA2023Status -eq "Updated")
$hasUEFIError = ($UEFICA2023Error -and $UEFICA2023Error -ne 0)

# -----------------------------
# TPM-WMI events
# -----------------------------

$latest1808 = $null
$latest1801 = $null
$latestFailure = $null
$latestTpm = $null
$firmwareNotAppliedReason = $null

try {
    $tpmEvents = Get-WinEvent -FilterHashtable @{
        LogName = "System"
        Id      = 1795,1796,1797,1798,1799,1801,1808
    } -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -eq "Microsoft-Windows-TPM-WMI" }

    if ($tpmEvents) {
        $latest1808 = $tpmEvents | Where-Object { $_.Id -eq 1808 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $latest1801 = $tpmEvents | Where-Object { $_.Id -eq 1801 } | Sort-Object TimeCreated -Descending | Select-Object -First 1

        $latestFailure = $tpmEvents | Where-Object { $_.Id -in 1795,1796,1797,1798,1801 } |
            Sort-Object TimeCreated -Descending | Select-Object -First 1

        $latestTpm = $tpmEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
    }
} catch {}

$LatestEvent1808 = if ($latest1808) { $latest1808.TimeCreated.ToString("o") } else { $null }
$LatestEvent1801 = if ($latest1801) { $latest1801.TimeCreated.ToString("o") } else { $null }

$latestFailureTime    = if ($latestFailure) { $latestFailure.TimeCreated.ToString("o") } else { $null }
$latestFailureEventId = if ($latestFailure) { $latestFailure.Id } else { $null }

# Firmware state from events:
$firmwareApplied = $false
$firmwarePending = $false
$firmwareState   = "Unknown"

if ($latest1808 -and (-not $latest1801 -or $latest1808.TimeCreated -ge $latest1801.TimeCreated)) {
    $firmwareApplied = $true
    $firmwareState   = "Applied"
}
elseif ($latest1801 -and (-not $latest1808 -or $latest1801.TimeCreated -gt $latest1808.TimeCreated)) {
    $firmwarePending = $true
    $firmwareState   = "Pending"
    $firmwareNotAppliedReason = $latest1801.Message #Get-FirstLine -Text $latest1801.Message 
}

# Errors after success?
$errorsAfterSuccess = $false
if ($latest1808 -and $latestFailure -and $latestFailure.TimeCreated -gt $latest1808.TimeCreated) {
    $errorsAfterSuccess = $true
}

# Nice-to-have reporting
$LatestTPMEventId      = if ($latestTpm) { $latestTpm.Id } else { $null }
$LatestTPMEventTime    = if ($latestTpm) { $latestTpm.TimeCreated.ToString("o") } else { $null }
$LatestTPMEventMessage = if ($latestTpm) { (Get-FirstLine -Text $latestTpm.Message) } else { $null }
$Event1801Confidence   = if ($latest1801) { (Get-ConfidenceFrom1801 -Message $latest1801.Message) } else { $null }

# -----------------------------
# UEFI certificates (KEK/DB)
# -----------------------------

$KekCerts = @()
$DbCerts  = @()
try { $KekCerts = Get-UefiX509Certs -Name kek } catch {}
try { $DbCerts  = Get-UefiX509Certs -Name db  } catch {}

$KekCertDetails = foreach ($cert in $KekCerts) {
    [PSCustomObject]@{
        Subject    = $cert.Subject
        Issuer     = $cert.Issuer
        Thumbprint = $cert.Thumbprint
        NotBefore  = $cert.NotBefore.ToString("yyyy-MM-dd")
        NotAfter   = $cert.NotAfter.ToString("yyyy-MM-dd")
        Serial     = $cert.SerialNumber
    }
}

$DbCertDetails = foreach ($cert in $DbCerts) {
    [PSCustomObject]@{
        Subject    = $cert.Subject
        Issuer     = $cert.Issuer
        Thumbprint = $cert.Thumbprint
        NotBefore  = $cert.NotBefore.ToString("yyyy-MM-dd")
        NotAfter   = $cert.NotAfter.ToString("yyyy-MM-dd")
        Serial     = $cert.SerialNumber
    }
}

# Detect specific certificates (by Subject text)
$HasMicrosoftKEK2011 = ($KekCerts | Where-Object { $_.Subject -match "Microsoft Corporation KEK CA 2011" }).Count -gt 0
$HasMicrosoftKEK2023 = ($KekCerts | Where-Object { $_.Subject -match "Microsoft Corporation KEK.*2023" -or $_.Subject -match "KEK 2K CA 2023" }).Count -gt 0

$HasWindowsPCA2011   = ($DbCerts  | Where-Object { $_.Subject -match "Microsoft Windows Production PCA 2011" }).Count -gt 0
$HasWindowsUEFI2023  = ($DbCerts  | Where-Object { $_.Subject -match "Windows UEFI CA 2023" }).Count -gt 0
$HasMicrosoftUEFI2011 = ($DbCerts | Where-Object { $_.Subject -match "Microsoft UEFI CA 2011" }).Count -gt 0
$HasMicrosoftUEFI2023 = ($DbCerts | Where-Object { $_.Subject -match "Microsoft UEFI CA 2023" }).Count -gt 0
$HasOptionRomUEFI2023 = ($DbCerts | Where-Object { $_.Subject -match "Option ROM UEFI CA 2023" }).Count -gt 0

# Expiring certs reporting (unambiguous date parsing)
# Captures June 2026 + Oct 2026 expirations
$expiryThreshold = [datetime]::ParseExact('2026-11-01','yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture)

$hasExpiringCerts = $false
$expiringCertList = @()

foreach ($cert in ($KekCerts + $DbCerts)) {
    if ($cert.NotAfter -lt $expiryThreshold) {
        $hasExpiringCerts = $true
        $expiringCertList += "$($cert.Subject) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))"
    }
}

# Replacement flags (informational)
$Has2023ReplacementForKEK2011     = $HasMicrosoftKEK2023
$Has2023ReplacementForWindowsPCA  = $HasWindowsUEFI2023
$Has2023ReplacementFor3rdPartyUEFI = $HasMicrosoftUEFI2023
$Has2023ReplacementForOptionRom   = $HasOptionRomUEFI2023

# NEW: clearer “expiring” interpretation
$ExpiringButReplaced    = $hasExpiringCerts -and $HasMicrosoftKEK2023 -and $HasWindowsUEFI2023
$ExpiringAndNotReplaced = $hasExpiringCerts -and (-not $HasMicrosoftKEK2023 -or -not $HasWindowsUEFI2023)

# -----------------------------
# Compliance logic (reasons include 1801-derived message)
# -----------------------------

$complianceReasons = @()
$complianceDetails = @()

if (-not $secureBootOn) {
    $complianceReasons += "SecureBootDisabled"
    $complianceDetails += "Secure Boot is disabled."
}

if (-not $osStaged) {
    $complianceReasons += "UpdateNotStaged"
    $complianceDetails += "UEFICA2023Status is not 'Updated' (OS-side staging not complete)."
}

if ($hasUEFIError) {
    $complianceReasons += "UEFICA2023ErrorPresent"
    $complianceDetails += "UEFICA2023Error indicates an error applying updates."
}

if ($errorsAfterSuccess) {
    $complianceReasons += "ErrorsAfterSuccess"
    $complianceDetails += "Failure events occurred after a success event."
}

# 1801 newest => firmware not applied yet
if ($firmwareState -eq "Pending") {
    $complianceReasons += "FirmwareNotAppliedYet"
    if ($firmwareNotAppliedReason) {
        $complianceDetails += "Latest 1801: $firmwareNotAppliedReason"
    } else {
        $complianceDetails += "Latest TPM-WMI event indicates firmware application is pending."
    }
}
elseif ($firmwareState -eq "Unknown") {
    # If logs missing/cleared, use strong signals to assume applied (still recorded)
    $strongSignals =
        ($WindowsUEFICA2023Capable -eq 2) -and
        $HasMicrosoftKEK2023 -and
        $HasWindowsUEFI2023 -and
        (-not $hasUEFIError) -and
        $osStaged -and
        $secureBootOn

    if (-not $strongSignals) {
        $complianceReasons += "CannotConfirmFirmwareApplied"
        $complianceDetails += "No 1808/1801 events found and strong signals are not all present."
    } else {
        $complianceReasons += "NoEventsFound_AssumedApplied"
        $complianceDetails += "No 1808/1801 events found; assumed applied based on strong signals."
    }
}

# Expiry logic: only a problem if expiring AND replacements are missing
if ($ExpiringAndNotReplaced) {
    $complianceReasons += "ExpiringCertsWithout2023Replacement"
    $complianceDetails += "Certificates expire before $($expiryThreshold.ToString('yyyy-MM-dd')) and 2023 replacements are missing."
}

# Final safe flag:
$safe =
    $secureBootOn -and
    $osStaged -and
    (-not $hasUEFIError) -and
    (-not $errorsAfterSuccess) -and
    ($firmwareState -ne "Pending") -and
    (-not $ExpiringAndNotReplaced)

# If firmware is Unknown, only safe if we did NOT add CannotConfirmFirmwareApplied
if ($firmwareState -eq "Unknown") {
    $safe = $safe -and (-not ($complianceReasons -contains "CannotConfirmFirmwareApplied"))
}

# -----------------------------
# Output JSON
# -----------------------------

$summary = [PSCustomObject]@{
    Timestamp  = $timestampIso
    Computer   = $computerName

    UEFI_FirmwareVersion = $UEFI_FirmwareVersion

    SecureBootOn = $secureBootOn

    # Registry state
    UEFICA2023Status         = $UEFICA2023Status
    UEFICA2023Error          = $UEFICA2023Error
    WindowsUEFICA2023Capable = $WindowsUEFICA2023Capable
    AvailableUpdates         = $AvailableUpdates
    HighConfidenceOptOut     = $HighConfidenceOptOut
    MicrosoftUpdateManagedOptIn = $MicrosoftUpdateManagedOptIn

    # Event-driven firmware state
    FirmwareState          = $firmwareState   # Applied / Pending / Unknown
    FirmwareAppliedToUEFI  = $firmwareApplied
    FirmwareApplyPending   = $firmwarePending
    FirmwareNotAppliedReason = $firmwareNotAppliedReason

    LatestEvent1801        = $LatestEvent1801
    LatestEvent1808        = $LatestEvent1808
    Event1801Confidence    = $Event1801Confidence

    LatestFailureTime      = $latestFailureTime
    LatestFailureEventId   = $latestFailureEventId
    ErrorsAfterSuccess     = $errorsAfterSuccess

    LatestTPMEventId       = $LatestTPMEventId
    LatestTPMEventTime     = $LatestTPMEventTime
    LatestTPMEventMessage  = $LatestTPMEventMessage

    # Cert inventory
    KEK_CertCount = $KekCerts.Count
    DB_CertCount  = $DbCerts.Count

    HasMicrosoftKEK2011    = $HasMicrosoftKEK2011
    HasMicrosoftKEK2023    = $HasMicrosoftKEK2023

    HasWindowsPCA2011      = $HasWindowsPCA2011
    HasWindowsUEFI2023     = $HasWindowsUEFI2023

    HasMicrosoftUEFI2011   = $HasMicrosoftUEFI2011
    HasMicrosoftUEFI2023   = $HasMicrosoftUEFI2023
    HasOptionRomUEFI2023   = $HasOptionRomUEFI2023

    KEK_Certificates = $KekCertDetails
    DB_Certificates  = $DbCertDetails

    # Expiry reporting
    ExpiryThreshold      = $expiryThreshold.ToString("yyyy-MM-dd")
    HasExpiringCerts     = $hasExpiringCerts
    ExpiringCertificates = $expiringCertList

    # Replacement flags (informational)
    Has2023ReplacementForKEK2011      = $Has2023ReplacementForKEK2011
    Has2023ReplacementForWindowsPCA   = $Has2023ReplacementForWindowsPCA
    Has2023ReplacementFor3rdPartyUEFI = $Has2023ReplacementFor3rdPartyUEFI
    Has2023ReplacementForOptionRom    = $Has2023ReplacementForOptionRom

    # NEW: clearer “expiring” interpretation
    ExpiringButReplaced    = $ExpiringButReplaced
    ExpiringAndNotReplaced = $ExpiringAndNotReplaced

    # Compliance
    ComplianceReasons = $complianceReasons
    ComplianceDetails = $complianceDetails
    SafeForJune2026   = $safe
}


if ($safe) { 
$summary | ConvertTo-Json -Depth 10 -Compress
exit 0 
} else {
$summary | ConvertTo-Json -Depth 10 -Compress
exit 1
}
