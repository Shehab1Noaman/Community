#requires -Version 5.1
<#
.SYNOPSIS
    Intune detection script — MDE Sense service health check.

.DESCRIPTION
    Performs the following checks and exits 0 (healthy) or 1 (unhealthy):

    1. OnboardingState registry value equals 1 (device is onboarded to MDE).
    2. On Windows builds >= 26100, the DISM optional capability
       "Microsoft.Windows.Sense.Client~~~~0.0.1.0" is in the Installed state.
    3. The "sense" Windows service exists and its Status is Running.
    4. The Microsoft-Windows-SENSE/Operational event log is accessible.

    Exit codes:
        0 — All checks passed (healthy).
        1 — One or more checks failed (unhealthy).

.NOTES
    Designed for use as an Intune Proactive Remediation detection script or
    an Intune Custom Compliance detection script.

    The unhealthy output is written as a single semicolon-delimited line so
    that Intune can capture it cleanly as a single compliance string.
#>

$ErrorActionPreference = 'Stop'
$issues = [System.Collections.Generic.List[string]]::new()

# --------------------------------------------------
# Helper: safely read a single registry value
# --------------------------------------------------
function Get-RegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    try {
        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    }
    catch {
        return $null
    }
}

# --------------------------------------------------
# Helper: query the Sense DISM optional capability
# Stdout and stderr are captured separately so that
# stderr details can be surfaced in issue messages.
# --------------------------------------------------
function Get-SenseCapabilityState {
    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()

    try {
        $proc = Start-Process -FilePath 'dism.exe' `
            -ArgumentList '/Online', '/Get-CapabilityInfo', '/CapabilityName:Microsoft.Windows.Sense.Client~~~~0.0.1.0' `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError $stderrFile

        $exitCode  = $proc.ExitCode
        $stdout    = Get-Content -Path $stdoutFile -Raw -ErrorAction SilentlyContinue
        $stderr    = Get-Content -Path $stderrFile -Raw -ErrorAction SilentlyContinue

        $state = $null
        if ($exitCode -eq 0) {
            $match = $stdout | Select-String -Pattern '^\s*State\s*:\s*(.+)$' | Select-Object -First 1
            if ($match) {
                $state = $match.Matches.Groups[1].Value.Trim()
            }
        }

        [PSCustomObject]@{
            ExitCode = $exitCode
            State    = $state
            Stdout   = $stdout
            Stderr   = $stderr
        }
    }
    finally {
        Remove-Item -Path $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
    }
}

# --------------------------------------------------
# Check 1: Windows build number (used for capability
# check gate). Use TryParse so a missing/non-numeric
# registry value does not throw.
# --------------------------------------------------
$rawBuild = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuildNumber'
$build    = 0
if (-not [int]::TryParse($rawBuild, [ref]$build)) {
    $issues.Add("Could not read Windows build number (registry value: '$rawBuild'). Capability check skipped.")
}

# --------------------------------------------------
# Check 2: MDE onboarding state
# --------------------------------------------------
$onboardingState = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name 'OnboardingState'

if ($null -eq $onboardingState -or [int]$onboardingState -ne 1) {
    $issues.Add("OnboardingState is '$onboardingState' (expected 1).")
}

# --------------------------------------------------
# Check 3: Sense optional capability (Windows 11 24H2+)
# Only checked on builds >= 26100
# --------------------------------------------------
if ($build -ge 26100) {
    $cap = Get-SenseCapabilityState

    if ($cap.ExitCode -ne 0) {
        $stderrDetail = if (-not [string]::IsNullOrWhiteSpace($cap.Stderr)) { " Stderr: $($cap.Stderr.Trim())" } else { '' }
        $issues.Add("Failed to query Sense capability. DISM exit code: $($cap.ExitCode).$stderrDetail")
    }
    elseif ($cap.State -ne 'Installed') {
        $issues.Add("Sense capability state is '$($cap.State)' (expected Installed).")
    }
}

# --------------------------------------------------
# Check 4: Sense Windows service status
# Also captures StartType to distinguish Disabled
# from simply Stopped.
# --------------------------------------------------
$service = Get-Service -Name 'sense' -ErrorAction SilentlyContinue
if (-not $service) {
    $issues.Add("Sense service is missing.")
}
elseif ($service.Status -ne 'Running') {
    $issues.Add("Sense service is '$($service.Status)' with StartType '$($service.StartType)' (expected Running).")
}

# --------------------------------------------------
# Check 5: SENSE operational event log accessibility
# --------------------------------------------------
try {
    $null = Get-WinEvent -ListLog 'Microsoft-Windows-SENSE/Operational' -ErrorAction Stop
}
catch {
    $issues.Add("Microsoft-Windows-SENSE/Operational log is missing or inaccessible. Error: $($_.Exception.Message)")
}

# --------------------------------------------------
# Output: single line for Intune compatibility
# --------------------------------------------------
if ($issues.Count -gt 0) {
    Write-Output "Unhealthy: $($issues -join '; ')"
    exit 1
}

$capabilityNote = if ($build -ge 26100) { ', Sense capability is installed' } else { '' }
Write-Output "Healthy: OnboardingState=1$capabilityNote, Sense log exists, and Sense service is running. WindowsBuild=$build."
exit 0
