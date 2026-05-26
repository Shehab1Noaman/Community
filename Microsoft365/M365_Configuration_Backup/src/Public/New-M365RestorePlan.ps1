function New-M365RestorePlan {
    <#
    .SYNOPSIS
        Builds a restore plan from a backup snapshot and an optional restore config.

    .DESCRIPTION
        Resolves which workloads, object types, and individual objects to restore based
        on the supplied parameters and/or restore.config.json. Returns a restore plan
        object that can be reviewed before being passed to Restore-M365TenantConfig or
        Import-M365TenantConfig.

    .PARAMETER ConfigPath
        Path to restore.config.json. When supplied, config-file values are used as
        defaults for workloads, scope, and remap settings.

    .PARAMETER BackupPath
        Path to the backup snapshot folder. Overrides config.source.backupPath.

    .PARAMETER Workloads
        Workloads to include in the restore plan.

    .PARAMETER ObjectNames
        Optional list of specific object names to scope the restore to.

    .PARAMETER WorkloadObjectTypes
        Hashtable mapping workload name to an array of object type names to include.

    .PARAMETER TargetMode
        Restore target mode (e.g. Overwrite, MergeOrSkip).

    .PARAMETER RemapConfig
        Identifier remapping hashtable for cross-tenant restores.

    .PARAMETER CurrentSnapshotPath
        Optional path to the current live snapshot used for pre-restore comparison.

    .PARAMETER OutputPath
        Optional path to write the restore plan JSON.

    .OUTPUTS
        PSCustomObject describing the restore plan.

    .EXAMPLE
        New-M365RestorePlan -ConfigPath .\config\restore.config.json

    .EXAMPLE
        New-M365RestorePlan -BackupPath C:\backup\tenant\20260101-120000 `
                            -Workloads Intune -TargetMode MergeOrSkip
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$BackupPath,

        [Parameter()]
        [string[]]$Workloads,

        [Parameter()]
        [string[]]$ObjectNames,

        [Parameter()]
        [hashtable]$WorkloadObjectTypes,

        [Parameter()]
        [string]$TargetMode,

        [Parameter()]
        [hashtable]$RemapConfig,

        [Parameter()]
        [string]$CurrentSnapshotPath,

        [Parameter()]
        [string]$OutputPath
    )

    $config = $null
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        $resolvedConfigPath = Resolve-BackupM365Path -Path $ConfigPath
        if (-not (Test-Path -Path $resolvedConfigPath -PathType Leaf)) {
            throw "Restore config not found: $resolvedConfigPath"
        }
        $config = Get-Content -Path $resolvedConfigPath -Raw | ConvertFrom-Json -ErrorAction Stop
    }

    if ([string]::IsNullOrWhiteSpace($BackupPath) -and $config -and $config.source) {
        $BackupPath = [string]$config.source.backupPath
    }
    $resolvedBackupPath = Resolve-BackupM365Path -Path $BackupPath

    if (-not $Workloads -and $config -and $config.scope -and $config.scope.workloadSwitches) {
        $Workloads = @($config.scope.workloadSwitches.PSObject.Properties | Where-Object { [bool]$_.Value } | Select-Object -ExpandProperty Name)
    }
    if (-not $Workloads -or $Workloads.Count -eq 0) {
        $Workloads = @(Get-ChildItem -Path $resolvedBackupPath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'Logs' } | Select-Object -ExpandProperty Name)
    }

    if (-not $ObjectNames -and $config -and $config.scope) {
        $ObjectNames = @($config.scope.objectNames)
    }
    if ($null -eq $WorkloadObjectTypes -and $config -and $config.scope -and $config.scope.workloadObjectTypes) {
        $WorkloadObjectTypes = @{}
        foreach ($property in $config.scope.workloadObjectTypes.PSObject.Properties) {
            if ($property.Name.StartsWith('_')) { continue }
            $WorkloadObjectTypes[$property.Name] = @($property.Value.PSObject.Properties | Where-Object { [bool]$_.Value } | Select-Object -ExpandProperty Name)
        }
    }
    if ([string]::IsNullOrWhiteSpace($TargetMode) -and $config -and $config.target) {
        $TargetMode = [string]$config.target.mode
    }
    if ([string]::IsNullOrWhiteSpace($TargetMode)) {
        $TargetMode = 'SameTenant'
    }
    if ($null -eq $RemapConfig -and $config -and $config.target -and ($config.target.PSObject.Properties.Name -contains 'remap')) {
        $RemapConfig = Resolve-BackupRemapConfig -Config $config.target.remap
    }

    $resolvedCurrentSnapshotPath = $null
    if (-not [string]::IsNullOrWhiteSpace($CurrentSnapshotPath)) {
        $resolvedCurrentSnapshotPath = Resolve-BackupM365Path -Path $CurrentSnapshotPath
    }

    $plan = New-RestorePlanData -BackupPath $resolvedBackupPath -Workloads $Workloads -ObjectNames $ObjectNames -WorkloadObjectTypes $WorkloadObjectTypes -TargetMode $TargetMode -RemapConfig $RemapConfig -CurrentSnapshotPath $resolvedCurrentSnapshotPath

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $resolvedOutputPath = Resolve-BackupM365Path -Path $OutputPath
        $plan | ConvertTo-Json -Depth 30 | Set-Content -Path $resolvedOutputPath -Encoding UTF8
    }

    return $plan
}