function Test-M365BackupIntegrity {
    <#
    .SYNOPSIS
        Validates the completeness and integrity of an M365 backup snapshot.

    .DESCRIPTION
        Checks the snapshot folder against its metadata.json to verify that all
        expected workload folders are present and contain exported files. Returns a
        per-workload integrity report including status (Success / Empty), file count,
        warning count, and error count.

        Use this after every backup run to confirm that all workloads were exported
        successfully, and before a restore to verify the source snapshot is usable.

    .PARAMETER BackupPath
        Path to the backup snapshot folder to validate.

    .OUTPUTS
        PSCustomObject with properties: Score (0–100), Status, Workloads (array of
        per-workload rows with Workload, Status, Files, Warnings, Errors, Reason).

    .EXAMPLE
        Test-M365BackupIntegrity -BackupPath C:\backup\tenant\20260101-120000

    .EXAMPLE
        $report = Test-M365BackupIntegrity -BackupPath .\snapshot
        $report.Workloads | Format-Table
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BackupPath
    )

    $resolvedPath = Resolve-BackupM365Path -Path $BackupPath
    if (-not (Test-Path -Path $resolvedPath -PathType Container)) {
        throw "Backup path not found: $resolvedPath"
    }

    $metadataPath = Join-Path -Path $resolvedPath -ChildPath 'metadata.json'
    $summary = @()
    if (Test-Path -Path $metadataPath -PathType Leaf) {
        $metadata = Get-Content -Path $metadataPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($metadata -and $metadata.IncludedWorkloads) {
            foreach ($workload in @($metadata.IncludedWorkloads)) {
                $workloadPath = Join-Path -Path $resolvedPath -ChildPath $workload
                $files = @(Get-ChildItem -Path $workloadPath -Recurse -File -ErrorAction SilentlyContinue)
                $summary += [pscustomobject]@{
                    Workload = $workload
                    Status   = if ($files.Count -gt 0) { 'Success' } else { 'Empty' }
                    Files    = $files.Count
                    Warnings = 0
                    Errors   = 0
                    Reason   = if ($files.Count -gt 0) { $null } else { 'No files found for included workload.' }
                }
            }
        }
    }

    Get-BackupIntegrityReport -BackupPath $resolvedPath -Summary $summary
}