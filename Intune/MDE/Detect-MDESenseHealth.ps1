<#
.SYNOPSIS
    Intune detection script — MDE Sense service health check.

.DESCRIPTION
    Performs the following checks and exits 0 (healthy) or 1 (unhealthy):

    1. OnboardingState registry value equals 1 (device is onboarded to MDE).
    2. On Windows 11 24H2+ workstations (build >= 26100), the optional capability
       "Microsoft.Windows.Sense.Client~~~~" is in the Installed state.
    3. The "sense" Windows service exists and its Status is Running.
    4. The Microsoft-Windows-SENSE/Operational event log is accessible.

    Exit codes:
        0 — All checks passed (healthy).
        1 — One or more checks failed (unhealthy).

.NOTES
    Designed for use as an Intune Proactive Remediation detection script or
    an Intune Custom Compliance detection script.

    Outputs a single-line JSON object for cleaner Intune reporting.
#>

$ErrorActionPreference = 'Stop'
$issues = [System.Collections.Generic.List[string]]::new()

$CapabilityName = 'Microsoft.Windows.Sense.Client~~~~'

function Get-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    }
    catch {
        return $null
    }
}

function Get-SenseCapabilityState {
    try {
        $cap = Get-WindowsCapability -Online -Name $CapabilityName -ErrorAction Stop
        return [PSCustomObject]@{
            Name  = $cap.Name
            State = $cap.State.ToString()
            Error = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            Name  = $CapabilityName
            State = $null
            Error = $_.Exception.Message
        }
    }
}


# Check 3: MDE onboarding state
$onboardingState = Get-RegistryValue `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' `
    -Name 'OnboardingState'

if ($null -eq $onboardingState -or [int]$onboardingState -ne 1) {
    $issues.Add("OnboardingState is '$onboardingState' (expected 1).")
}

# Check 4: Sense optional capability
$capabilityChecked = $false
$capabilityState = $null
if ($build -ge 26100 -and $isWorkstation) {
    $capabilityChecked = $true
    $cap = Get-SenseCapabilityState
    $capabilityState = $cap.State

    if ($null -ne $cap.Error) {
        $issues.Add("Failed to query Sense capability '$CapabilityName'. Error: $($cap.Error)")
    }
    elseif ($cap.State -ne 'Installed') {
        $issues.Add("Sense capability '$($cap.Name)' state is '$($cap.State)' (expected Installed).")
    }
}

# Check 5: Sense Windows service
$service = Get-Service -Name 'sense' -ErrorAction SilentlyContinue
$serviceStatus = $null
$serviceStartMode = $null

if (-not $service) {
    $issues.Add("Sense service is missing.")
}
else {
    $serviceStatus = $service.Status.ToString()

    if ($service.Status -ne 'Running') {
        try {
            $svcCim = Get-CimInstance Win32_Service -Filter "Name='sense'" -ErrorAction Stop
            $serviceStartMode = $svcCim.StartMode
        }
        catch {
            $serviceStartMode = 'Unknown'
        }

        $issues.Add("Sense service is '$serviceStatus' with StartMode '$serviceStartMode' (expected Running).")
    }
    else {
        try {
            $svcCim = Get-CimInstance Win32_Service -Filter "Name='sense'" -ErrorAction Stop
            $serviceStartMode = $svcCim.StartMode
        }
        catch {
            $serviceStartMode = 'Unknown'
        }
    }
}

# Check 6: SENSE operational event log accessibility
$logAccessible = $false
try {
    $null = Get-WinEvent -ListLog 'Microsoft-Windows-SENSE/Operational' -ErrorAction Stop
    $logAccessible = $true
}
catch {
    $issues.Add("Microsoft-Windows-SENSE/Operational log is inaccessible. Error: $($_.Exception.Message)")
}

# Build JSON output
$result = [ordered]@{
    status            = if ($issues.Count -gt 0) { 'Unhealthy' } else { 'Healthy' }
    capabilityName    = $CapabilityName
    capabilityState   = $capabilityState
    senseService      = [ordered]@{
        exists     = [bool]($null -ne $service)
        status     = $serviceStatus
        startMode  = $serviceStartMode
    }
    senseLogAccessible = $logAccessible
    issues            = @($issues)
}

$result | ConvertTo-Json -Compress -Depth 4 | Write-Output

if ($issues.Count -gt 0) {
    exit 1
}

exit 0
