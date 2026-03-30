<#
.SYNOPSIS
    Intune remediation script — MDE Sense service health.

.DESCRIPTION
    Remediates the issues detected by the companion detection script:

    1. On Windows 11 24H2+ workstations (build >= 26100), installs the
       "Microsoft.Windows.Sense.Client~~~~" optional capability if it
       is not already in the Installed state.
    2. Warns if OnboardingState != 1 (cannot be remediated by script alone —
       requires the correct Intune/SCCM onboarding policy or package).
    3. Starts the Sense service if it exists but is not running.
    4. On failure, returns recent SENSE/Operational events in JSON to aid triage.

    Exit codes:
        0 — Remediation succeeded (or nothing needed remediation).
        1 — Remediation failed or a condition exists that requires manual
            intervention (e.g. device not onboarded).

.PARAMETER CapabilitySource
    Optional UNC path to a Features-on-Demand repository. When provided,
    DISM is called with /LimitAccess so Windows Update is not used.
    Leave empty to use the default servicing source (Windows Update / WSUS).

.NOTES
    Requires SYSTEM or Administrator privileges.
#>

[CmdletBinding()]
param(
    [string]$CapabilitySource = ''
)

$ErrorActionPreference = 'Stop'
$CapabilityName = 'Microsoft.Windows.Sense.Client~~~~'
$LogMessages = [System.Collections.Generic.List[string]]::new()
$build = $null
$onboardingState = $null

function Write-Log {
    param([string]$Message)
    $LogMessages.Add($Message)
}

function Write-JsonAndExit {
    param(
        [Parameter(Mandatory)][string]$Status,
        [int]$Code = 0,
        [object]$SenseEvents = $null
    )

    $result = [ordered]@{
        status          = $Status
        build           = $build
        capabilityName  = $CapabilityName
        onboardingState = $onboardingState
        logs            = @($LogMessages)
    }

    if ($null -ne $SenseEvents) {
        $result.senseEvents = $SenseEvents
    }

    $result | ConvertTo-Json -Compress -Depth 6 | Write-Output
    exit $Code
}

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

function Install-SenseCapability {
    param([string]$Source)

    if ([string]::IsNullOrWhiteSpace($Source)) {
        Write-Log "Installing Sense capability via Add-WindowsCapability (default source)."
        try {
            Add-WindowsCapability -Online -Name $CapabilityName -ErrorAction Stop | Out-Null
            return $true
        }
        catch {
            Write-Log "Add-WindowsCapability failed: $($_.Exception.Message)"
            return $false
        }
    }
    else {
        Write-Log "Installing Sense capability via DISM from source: $Source"
        $dismArgs = @(
            '/Online',
            '/Add-Capability',
            "/CapabilityName:$CapabilityName",
            "/Source:$Source",
            '/LimitAccess'
        )
        try {
            $proc = Start-Process -FilePath 'dism.exe' -ArgumentList $dismArgs -Wait -PassThru -NoNewWindow -ErrorAction Stop
            if ($proc.ExitCode -ne 0) {
                Write-Log "DISM Add-Capability exited with code $($proc.ExitCode)."
                return $false
            }
            return $true
        }
        catch {
            Write-Log "Failed to launch DISM: $($_.Exception.Message)"
            return $false
        }
    }
}

function Get-SenseEvents {
    try {
        return Get-WinEvent -LogName 'Microsoft-Windows-SENSE/Operational' -MaxEvents 10 -ErrorAction Stop |
            Sort-Object TimeCreated -Descending |
            Select-Object TimeCreated, Id, LevelDisplayName, Message
    }
    catch {
        Write-Log "Could not read Microsoft-Windows-SENSE/Operational: $($_.Exception.Message)"
        return $null
    }
}

try {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "This script must run elevated."
        Write-JsonAndExit -Status 'Unhealthy' -Code 1
    }

    $rawBuild = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuildNumber'
    $build = 0
    [int]::TryParse($rawBuild, [ref]$build) | Out-Null
    Write-Log "Detected build: $build"

    $isWorkstation = $false
    try {
        $productType = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType
        $isWorkstation = ($productType -eq 1)
        Write-Log "Product type: $productType (isWorkstation: $isWorkstation)"
    }
    catch {
        Write-Log "Could not determine OS product type; skipping capability remediation. Error: $($_.Exception.Message)"
    }

    if ($build -ge 26100 -and $isWorkstation) {
        $cap = Get-SenseCapabilityState

        if ($null -ne $cap.Error) {
            Write-Log "Failed to query Sense capability: $($cap.Error)"
            Write-JsonAndExit -Status 'Unhealthy' -Code 1
        }

        if ($cap.State -ne 'Installed') {
            Write-Log "Sense capability state is '$($cap.State)'. Attempting install..."

            $installed = Install-SenseCapability -Source $CapabilitySource
            if (-not $installed) {
                Write-Log "Sense capability installation failed."
                Write-JsonAndExit -Status 'Unhealthy' -Code 1
            }

            Start-Sleep -Seconds 5

            $cap = Get-SenseCapabilityState
            if ($cap.State -ne 'Installed') {
                Write-Log "Sense capability state is still '$($cap.State)' after remediation."
                Write-JsonAndExit -Status 'Unhealthy' -Code 1
            }

            Write-Log "Sense capability is now Installed."
        }
        else {
            Write-Log "Sense capability already Installed."
        }
    }

    $onboardingState = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name 'OnboardingState'

    if ($null -eq $onboardingState -or [int]$onboardingState -ne 1) {
        Write-Log "OnboardingState is '$onboardingState'. Device requires the MDE onboarding policy or package — this script cannot remediate that."
        Write-JsonAndExit -Status 'Unhealthy' -Code 1
    }

    $service = Get-Service -Name 'sense' -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Log "Sense service is missing — cannot start a service that does not exist."
        $events = Get-SenseEvents
        Write-JsonAndExit -Status 'Unhealthy' -Code 1 -SenseEvents $events
    }

    if ($service.Status -ne 'Running') {
        $startType = $null
        try {
            $svcCim = Get-CimInstance Win32_Service -Filter "Name='sense'" -ErrorAction Stop
            $startType = $svcCim.StartMode
        }
        catch {
            $startType = 'Unknown'
        }

        Write-Log "Sense service is '$($service.Status)' (StartType: $startType). Attempting to start..."

        try {
            Start-Service -Name 'sense' -ErrorAction Stop
        }
        catch {
            Write-Log "Start-Service failed ($($_.Exception.Message)); retrying via sc.exe..."
            & sc.exe start sense | Out-Null
        }

        Write-Log "Waiting 20 s for service to reach Running state..."
        Start-Sleep -Seconds 20
        $service.Refresh()
    }

    if ($service.Status -ne 'Running') {
        Write-Log "Sense service is '$($service.Status)' after remediation attempt."
        $events = Get-SenseEvents
        Write-JsonAndExit -Status 'Unhealthy' -Code 1 -SenseEvents $events
    }

    Write-Log "Success. Sense service is Running and OnboardingState=1."
    Write-JsonAndExit -Status 'Healthy' -Code 0
}
catch {
    Write-Log "Unhandled error: $($_.Exception.Message)"
    $events = Get-SenseEvents
    Write-JsonAndExit -Status 'Unhealthy' -Code 1 -SenseEvents $events
}
