function New-M365BackupDelta {
    <#
    .SYNOPSIS
        Generates a delta manifest describing what changed between two backup snapshots.

    .DESCRIPTION
        Compares the JSON files in a reference (older) snapshot against those in a
        difference (newer) snapshot and writes a delta.manifest.json to the difference
        snapshot folder (or a custom OutputPath). The manifest lists every file that
        was Added, Removed, or Changed and is used by Invoke-M365DeltaRestore to
        perform targeted restores.

    .PARAMETER ReferencePath
        Path to the older (baseline) backup snapshot folder.

    .PARAMETER DifferencePath
        Path to the newer backup snapshot folder.

    .PARAMETER Workloads
        Optional. Restrict the diff to specific workloads.

    .PARAMETER OutputPath
        Path where the delta manifest JSON is written.
        Defaults to delta.manifest.json inside DifferencePath.

    .OUTPUTS
        String. The path of the generated delta manifest file.

    .EXAMPLE
        New-M365BackupDelta -ReferencePath C:\backup\tenant\20260101-120000 `
                            -DifferencePath C:\backup\tenant\20260401-120000

    .EXAMPLE
        New-M365BackupDelta -ReferencePath .\snap-old -DifferencePath .\snap-new `
                            -OutputPath C:\reports\delta.manifest.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ReferencePath,

        [Parameter(Mandatory)]
        [string]$DifferencePath,

        [Parameter()]
        [string[]]$Workloads,

        [Parameter()]
        [string]$OutputPath
    )

    $resolvedReferencePath = Resolve-BackupM365Path -Path $ReferencePath
    $resolvedDifferencePath = Resolve-BackupM365Path -Path $DifferencePath

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path -Path $resolvedDifferencePath -ChildPath 'delta.manifest.json'
    }
    else {
        $OutputPath = Resolve-BackupM365Path -Path $OutputPath
    }

    $diffItems = @(Compare-BackupSnapshotFiles -ReferencePath $resolvedReferencePath -DifferencePath $resolvedDifferencePath -Workloads $Workloads)
    $payload = [pscustomobject]@{
        GeneratedUtc   = (Get-Date).ToUniversalTime().ToString('o')
        ReferencePath  = $resolvedReferencePath
        DifferencePath = $resolvedDifferencePath
        Summary        = [pscustomobject]@{
            Total   = $diffItems.Count
            Added   = @($diffItems | Where-Object { $_.Status -eq 'Added' }).Count
            Removed = @($diffItems | Where-Object { $_.Status -eq 'Removed' }).Count
            Changed = @($diffItems | Where-Object { $_.Status -eq 'Changed' }).Count
        }
        Items          = $diffItems
    }

    $payload | ConvertTo-Json -Depth 30 | Set-Content -Path $OutputPath -Encoding UTF8
    return $payload
}