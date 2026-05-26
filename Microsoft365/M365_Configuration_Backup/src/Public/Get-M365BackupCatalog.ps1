function Get-M365BackupCatalog {
    <#
    .SYNOPSIS
        Lists all M365 backup snapshots stored under a backup root path.

    .DESCRIPTION
        Scans the backup root folder hierarchy (root / tenant / snapshot) and returns
        a catalog row for each snapshot found. Each row includes the tenant name,
        snapshot name, timestamp, workloads, status, and integrity score read from the
        snapshot's metadata.json.

        Use -IncludeObjects to also return a flat list of the JSON files present in each
        snapshot (useful for identifying what was exported).

    .PARAMETER RootPath
        Root path that contains tenant backup folders.
        Defaults to output/Backups relative to the module root.

    .PARAMETER TenantName
        Filter results to a specific tenant name.

    .PARAMETER Workloads
        Filter results to snapshots that include specific workloads.

    .PARAMETER IncludeObjects
        When set, includes a list of exported JSON file names for each snapshot.

    .OUTPUTS
        PSCustomObject per snapshot with: TenantName, SnapshotName, BackupTimestamp,
        IncludedWorkloads, Status, IntegrityScore, BackupPath, and optionally Objects.

    .EXAMPLE
        Get-M365BackupCatalog

    .EXAMPLE
        Get-M365BackupCatalog -RootPath C:\backup -TenantName contoso.onmicrosoft.com
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$RootPath,

        [Parameter()]
        [string]$TenantName,

        [Parameter()]
        [string[]]$Workloads,

        [Parameter()]
        [switch]$IncludeObjects
    )

    $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
    $repoRoot = Split-Path -Path $moduleRoot -Parent

    if ([string]::IsNullOrWhiteSpace($RootPath)) {
        $RootPath = Join-Path -Path $repoRoot -ChildPath 'output/Backups'
    }
    elseif (-not [System.IO.Path]::IsPathRooted($RootPath)) {
        $RootPath = Join-Path -Path $repoRoot -ChildPath $RootPath
    }

    if (-not (Test-Path -Path $RootPath)) {
        throw "Backup root not found: $RootPath"
    }

    $allCatalogRows = [System.Collections.Generic.List[object]]::new()
    $tenantFolders = @(Get-ChildItem -Path $RootPath -Directory -ErrorAction SilentlyContinue)

    if (-not [string]::IsNullOrWhiteSpace($TenantName)) {
        $tenantFolders = @($tenantFolders | Where-Object { $_.Name -eq $TenantName })
    }

    foreach ($tenantFolder in $tenantFolders) {
        $snapshotFolders = @(Get-ChildItem -Path $tenantFolder.FullName -Directory -ErrorAction SilentlyContinue)
        foreach ($snapshotFolder in $snapshotFolders) {
            $metadataPath = Join-Path -Path $snapshotFolder.FullName -ChildPath 'metadata.json'
            $metadata = $null
            if (Test-Path -Path $metadataPath) {
                try {
                    $metadata = Get-Content -Path $metadataPath -Raw | ConvertFrom-Json -ErrorAction Stop
                }
                catch {
                    $metadata = $null
                }
            }

            $resolvedTenantName = if ($metadata -and -not [string]::IsNullOrWhiteSpace([string]$metadata.TenantName)) {
                [string]$metadata.TenantName
            }
            else {
                $tenantFolder.Name
            }

            $backupTimestamp = $null
            if ($metadata -and $metadata.BackupTimestamp) {
                try { $backupTimestamp = [datetime]$metadata.BackupTimestamp } catch { $backupTimestamp = $null }
            }

            $workloadFolders = @(Get-ChildItem -Path $snapshotFolder.FullName -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ne 'Logs' })

            if ($Workloads -and $Workloads.Count -gt 0) {
                $workloadFolders = @($workloadFolders | Where-Object { $_.Name -in $Workloads })
            }

            foreach ($workloadFolder in $workloadFolders) {
                $jsonFiles = @(Get-ChildItem -Path $workloadFolder.FullName -Filter '*.json' -File -ErrorAction SilentlyContinue)
                foreach ($jsonFile in $jsonFiles) {
                    $row = [ordered]@{
                        TenantName      = $resolvedTenantName
                        SnapshotName    = $snapshotFolder.Name
                        BackupTimestamp = $backupTimestamp
                        Workload        = $workloadFolder.Name
                        ObjectType      = [System.IO.Path]::GetFileNameWithoutExtension($jsonFile.Name)
                        FilePath        = $jsonFile.FullName
                        ItemCount       = $null
                        HasMetadata     = [bool]$metadata
                        Status          = if ($metadata -and $metadata.Status) { [string]$metadata.Status } else { $null }
                    }

                    try {
                        $parsed = Get-Content -Path $jsonFile.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
                        if ($parsed -and ($parsed.PSObject.Properties.Name -contains 'value')) {
                            $items = @($parsed.value)
                        }
                        else {
                            $items = @($parsed)
                        }
                        $row.ItemCount = @($items).Count

                        if ($IncludeObjects) {
                            $names = @(
                                $items | ForEach-Object {
                                    if ($null -eq $_) { return }
                                    if ($_.PSObject.Properties.Name -contains 'displayName') { [string]$_.displayName; return }
                                    if ($_.PSObject.Properties.Name -contains 'name') { [string]$_.name; return }
                                    if ($_.PSObject.Properties.Name -contains 'userPrincipalName') { [string]$_.userPrincipalName; return }
                                    if ($_.PSObject.Properties.Name -contains 'id') { [string]$_.id }
                                } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                            )
                            $row.ObjectNames = $names
                        }
                    }
                    catch {
                        $row.ItemCount = $null
                        if ($IncludeObjects) {
                            $row.ObjectNames = @()
                        }
                    }

                    [void]$allCatalogRows.Add([pscustomobject]$row)
                }
            }
        }
    }

    $allCatalogRows | Sort-Object TenantName, BackupTimestamp, Workload, ObjectType
}