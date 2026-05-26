function Compare-M365BackupSnapshot {
    <#
    .SYNOPSIS
        Compares two M365 backup snapshots and reports file-level differences.

    .DESCRIPTION
        Performs a file-level diff between a reference (older) snapshot folder and a
        difference (newer) snapshot folder. Returns a list of objects describing which
        workload JSON files were Added, Removed, or Changed between the two snapshots.
        Use this for a quick structural comparison; for a deep JSON-field diff use
        Compare-M365TenantConfig.

    .PARAMETER ReferencePath
        Path to the older (baseline) backup snapshot folder.

    .PARAMETER DifferencePath
        Path to the newer backup snapshot folder to compare against the reference.

    .PARAMETER Workloads
        Optional. Restrict the comparison to specific workloads
        (e.g. 'EntraID', 'Intune'). When omitted all workloads in both snapshots
        are compared.

    .PARAMETER OutputRoot
        Optional. Base output root used to create Compare\<timestamp>\Compare-<snapshot>.html.
        When omitted the cmdlet derives the tenant root from DifferencePath.

    .PARAMETER PassThru
        When specified, returns a single result object with Items, Summary, HtmlReportPath,
        JsonReportPath, and LogPath instead of emitting diff items to the pipeline.

    .OUTPUTS
        PSCustomObject with properties: RelativePath, Status (Added/Removed/Changed).
        With -PassThru: PSCustomObject with Items, Summary, HtmlReportPath, JsonReportPath, LogPath.

    .EXAMPLE
        Compare-M365BackupSnapshot -ReferencePath C:\backup\tenant\20260101-120000 `
                                   -DifferencePath C:\backup\tenant\20260401-120000

    .EXAMPLE
        Compare-M365BackupSnapshot -ReferencePath .\snap-old -DifferencePath .\snap-new `
                                   -Workloads EntraID, Intune

    .EXAMPLE
        Compare-M365BackupSnapshot -ReferencePath .\snap-old -DifferencePath .\snap-new `
                                   -OutputRoot C:\backup2904\contoso.onmicrosoft.com
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
        [string]$OutputRoot,

        [Parameter()]
        [switch]$PassThru
    )

    $resolvedReferencePath = Resolve-BackupM365Path -Path $ReferencePath
    $resolvedDifferencePath = Resolve-BackupM365Path -Path $DifferencePath

    if (-not (Test-Path -Path $resolvedReferencePath -PathType Container)) {
        throw "Reference snapshot not found: $resolvedReferencePath"
    }
    if (-not (Test-Path -Path $resolvedDifferencePath -PathType Container)) {
        throw "Difference snapshot not found: $resolvedDifferencePath"
    }

    $compareItems = @(Compare-BackupSnapshotFiles -ReferencePath $resolvedReferencePath -DifferencePath $resolvedDifferencePath -Workloads $Workloads)
    $artifacts = New-CompareReportArtifacts -DifferencePath $resolvedDifferencePath -Kind Snapshot -OutputRoot $OutputRoot

    $summary = [pscustomobject]@{
        Total   = $compareItems.Count
        Added   = @($compareItems | Where-Object { $_.Status -eq 'Added' }).Count
        Removed = @($compareItems | Where-Object { $_.Status -eq 'Removed' }).Count
        Changed = @($compareItems | Where-Object { $_.Status -eq 'Changed' }).Count
    }

    $payload = [pscustomobject]@{
        GeneratedUtc   = (Get-Date).ToUniversalTime().ToString('o')
        Kind           = 'Snapshot'
        ReferencePath  = $resolvedReferencePath
        DifferencePath = $resolvedDifferencePath
        Workloads      = @($Workloads)
        Summary        = $summary
        Items          = $compareItems
        Output         = [pscustomobject]@{
            RunFolder = $artifacts.RunFolder
            HtmlPath  = $artifacts.HtmlPath
            JsonPath  = $artifacts.JsonPath
            LogPath   = $artifacts.LogPath
        }
    }

    ConvertTo-SafeJson -InputObject $payload -Depth 20 | Set-Content -Path $artifacts.JsonPath -Encoding UTF8
    New-CompareSnapshotHtmlReport -CompareItems $compareItems -OutputPath $artifacts.HtmlPath -ReferencePath $resolvedReferencePath -DifferencePath $resolvedDifferencePath -Summary $summary
    Write-CompareReportLog -LogPath $artifacts.LogPath -Level Information -Message 'Compare-M365BackupSnapshot report generated.' -Data ([pscustomobject]@{ HtmlPath = $artifacts.HtmlPath; JsonPath = $artifacts.JsonPath; Summary = $summary })
    Write-Verbose "Compare report (HTML): $($artifacts.HtmlPath)"

    if ($PassThru) {
        return [pscustomobject]@{
            Items          = $compareItems
            Summary        = $summary
            HtmlReportPath = $artifacts.HtmlPath
            JsonReportPath = $artifacts.JsonPath
            LogPath        = $artifacts.LogPath
        }
    }

    return $compareItems
}