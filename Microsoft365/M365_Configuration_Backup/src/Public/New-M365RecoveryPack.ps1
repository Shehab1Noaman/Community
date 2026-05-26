function New-M365RecoveryPack {
    <#
    .SYNOPSIS
        Creates a scenario-scoped recovery pack from a backup snapshot.

    .DESCRIPTION
        Packages a subset of a backup snapshot into a named recovery pack JSON file
        targeted at a specific disaster recovery scenario. Recovery packs simplify
        the restore process by pre-defining the workloads and object types needed
        for common recovery situations.

        Supported scenarios:
          - FullTenant       — all workloads.
          - IntuneBaseline   — compliance policies, configuration profiles, update rings.
          - TeamsCore        — meeting/messaging policies and tenant federation config.
          - SharePointTenant — SharePoint tenant-level settings only.
          - IdentityCore     — Entra ID conditional access, authentication, and roles.

    .PARAMETER Scenario
        Recovery scenario name. See description for supported values.

    .PARAMETER BackupPath
        Path to the source backup snapshot folder.

    .PARAMETER OutputPath
        Path where the recovery pack JSON is written.
        Defaults to recovery-pack-<Scenario>.json inside BackupPath.

    .PARAMETER ObjectNames
        Optional list of specific object names to include in the recovery pack.

    .OUTPUTS
        String. The path of the generated recovery pack file.

    .EXAMPLE
        New-M365RecoveryPack -Scenario IntuneBaseline `
                             -BackupPath C:\backup\tenant\20260101-120000

    .EXAMPLE
        New-M365RecoveryPack -Scenario FullTenant -BackupPath .\snapshot `
                             -OutputPath C:\dr\full-recovery.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('FullTenant', 'IntuneBaseline', 'TeamsCore', 'SharePointTenant', 'IdentityCore')]
        [string]$Scenario,

        [Parameter(Mandatory)]
        [string]$BackupPath,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [string[]]$ObjectNames
    )

    $resolvedBackupPath = Resolve-BackupM365Path -Path $BackupPath
    if (-not (Test-Path -Path $resolvedBackupPath -PathType Container)) {
        throw "Backup path not found: $resolvedBackupPath"
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path -Path $resolvedBackupPath -ChildPath ("recovery-pack-{0}.json" -f $Scenario)
    }
    else {
        $OutputPath = Resolve-BackupM365Path -Path $OutputPath
    }

    $workloadSwitches = [ordered]@{
        EntraID = $false
        ExchangeOnline = $false
        Teams = $false
        SharePoint = $false
        Intune = $false
        Compliance = $false
        Defender = $false
        PowerPlatform = $false
        Planner = $false
        Users = $false
    }
    $workloadObjectTypes = [ordered]@{}
    $scopeMode = 'Workload'

    switch ($Scenario) {
        'FullTenant' {
            $scopeMode = 'Tenant'
            foreach ($key in @($workloadSwitches.Keys)) { $workloadSwitches[$key] = $true }
        }
        'IntuneBaseline' {
            $workloadSwitches.Intune = $true
            $workloadObjectTypes.Intune = [ordered]@{
                CompliancePolicies = $true
                ConfigurationProfiles = $true
                SettingsCatalogPolicies = $true
                UpdateRings = $true
                AssignmentFilters = $true
                AutopilotProfiles = $true
            }
        }
        'TeamsCore' {
            $workloadSwitches.Teams = $true
        }
        'SharePointTenant' {
            $workloadSwitches.SharePoint = $true
        }
        'IdentityCore' {
            $workloadSwitches.EntraID = $true
            $workloadSwitches.Users = $true
        }
    }

    $pack = [pscustomobject]@{
        source = [pscustomobject]@{
            backupPath = $resolvedBackupPath
        }
        scope = [pscustomobject]@{
            mode = $scopeMode
            workloadSwitches = [pscustomobject]$workloadSwitches
            workloadObjectTypes = [pscustomobject]$workloadObjectTypes
            workloads = @()
            relativeFolder = ''
            files = @()
            objectNames = @($ObjectNames)
        }
        target = [pscustomobject]@{
            mode = 'SameTenant'
        }
        execution = [pscustomobject]@{
            force = $false
            stopOnError = $false
        }
        recoveryPack = [pscustomobject]@{
            scenario = $Scenario
            generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        }
    }

    $pack | ConvertTo-Json -Depth 30 | Set-Content -Path $OutputPath -Encoding UTF8
    return $OutputPath
}