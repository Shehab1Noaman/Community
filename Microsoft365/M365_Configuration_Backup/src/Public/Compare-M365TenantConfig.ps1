function Compare-M365TenantConfig {
    <#
    .SYNOPSIS
        Deep JSON-field comparison between two M365 backup snapshots.

    .DESCRIPTION
        Recursively diffs the JSON content of every matching file in two backup
        snapshot folders. Returns per-field differences, making it possible to see
        exactly which policy settings changed between two points in time.
        Volatile metadata fields (createdDateTime, eTag, etc.) are excluded by
        default to reduce noise.

    .PARAMETER ReferencePath
        Path to the older (baseline) backup snapshot folder.

    .PARAMETER DifferencePath
        Path to the newer backup snapshot folder to compare against the reference.

    .PARAMETER IgnoreFields
        Property names to exclude from the comparison regardless of depth.
        Defaults to common volatile fields such as lastModifiedDateTime, eTag, etc.

    .PARAMETER IgnoreFieldSuffixes
        Property name suffixes to exclude (e.g. '@odata.context').
        Defaults to standard OData annotation suffixes.

    .PARAMETER NoSortArrays
        When specified, array elements are compared in their original order.
        By default arrays are sorted before comparison to avoid false positives
        caused by ordering differences.

    .PARAMETER OutputRoot
        Optional. Base output root used to create Compare\<timestamp>\Compare-<tenant>.html.
        When omitted the cmdlet derives the tenant root from DifferencePath.

    .PARAMETER PassThru
        When specified, returns a single result object with Items, Summary, HtmlReportPath,
        JsonReportPath, and LogPath instead of emitting diff items to the pipeline.

    .OUTPUTS
        PSCustomObject per difference: File, Path, ReferenceValue, DifferenceValue.
        With -PassThru: PSCustomObject with Items, Summary, HtmlReportPath, JsonReportPath, LogPath.

    .EXAMPLE
        Compare-M365TenantConfig -ReferencePath C:\backup\tenant\20260101-120000 `
                                 -DifferencePath C:\backup\tenant\20260401-120000

    .EXAMPLE
        # Compare only selected fields, treating array order as significant
        Compare-M365TenantConfig -ReferencePath .\snap-old -DifferencePath .\snap-new `
                                 -IgnoreFields @() -NoSortArrays
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ReferencePath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DifferencePath,

        [Parameter()]
        [string[]]$IgnoreFields = @(
            'lastModifiedDateTime',
            'createdDateTime',
            'eTag',
            'version',
            'lastContactedDateTime',
            'lastSyncDateTime',
            'lastReportedDateTime',
            'lastCheckInDateTime',
            'enrolledDateTime',
            'deploymentProfileAssignedDateTime',
            'deploymentProfileAssignmentStatus',
            'deploymentProfileAssignmentDetailedStatus',
            'enrollmentState',
            'remediationState'
        ),

        [Parameter()]
        [string[]]$IgnoreFieldSuffixes = @(
            '@odata.context',
            '@odata.nextLink',
            '@odata.count',
            '@odata.etag',
            '@odata.editLink',
            '@odata.readLink',
            '@odata.deltaLink'
        ),

        [Parameter()]
        [switch]$NoSortArrays,

        [Parameter()]
        [string]$OutputRoot,

        [Parameter()]
        [switch]$PassThru
    )

    foreach ($path in @($ReferencePath, $DifferencePath)) {
        if (-not (Test-Path -Path $path)) {
            throw "Path not found: $path"
        }
    }

    $sortArrays = -not $NoSortArrays.IsPresent

    function Get-CanonicalJsonFromFile {
        param(
            [Parameter(Mandatory)]
            [string]$FilePath
        )

        $raw = Get-Content -Path $FilePath -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return ''
        }

        try {
            $obj = $raw | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $obj) {
                return 'null'
            }
            return (ConvertTo-CanonicalJson -InputObject $obj `
                -IgnoreFields $IgnoreFields `
                -IgnoreFieldSuffixes $IgnoreFieldSuffixes `
                -SortArrays:$sortArrays)
        }
        catch {
            return $raw
        }
    }

    # Build a set of "Workload/ObjectType" names that the DIFFERENCE side failed to fetch.
    # Reference is treated as authoritative; anything missing on the difference side
    # that the difference snapshot couldn't even retrieve is reclassified.
    function Get-FailedExportObjectTypes {
        param([Parameter(Mandatory)] [string]$SnapshotPath)

        $failed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        $logCandidates = @(
            (Join-Path $SnapshotPath 'Logs/backup.log.ndjson'),
            (Join-Path (Split-Path -Path $SnapshotPath -Parent) 'Logs/backup.log.ndjson')
        )

        foreach ($logPath in $logCandidates) {
            if (-not (Test-Path -Path $logPath -PathType Leaf)) { continue }

            foreach ($line in (Get-Content -Path $logPath -ErrorAction SilentlyContinue)) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                try {
                    $entry = $line | ConvertFrom-Json -ErrorAction Stop
                }
                catch { continue }

                $msg = [string]$entry.Message
                if ([string]::IsNullOrWhiteSpace($msg)) { continue }

                # Patterns we know:
                #   "Failed to export Intune object [PolicySets]: ..."
                #   "Failed to export Intune DeviceManagementScripts: ..."
                #   "Failed to export Entra object [B2BManagementPolicy]: ..."
                #   "Skipped Intune object [UserExperienceAnalyticsCategories]..."
                #   "Skipped Defender object [DefenderMachineGroups]..."
                $patterns = @(
                    '^Failed to export\s+(?<workload>[A-Za-z0-9]+)\s+object\s+\[(?<obj>[^\]]+)\]',
                    '^Failed to export\s+(?<workload>[A-Za-z0-9]+)\s+(?<obj>[A-Za-z0-9]+)\s*:',
                    '^Skipped\s+(?<workload>[A-Za-z0-9]+)\s+object\s+\[(?<obj>[^\]]+)\]'
                )

                foreach ($pat in $patterns) {
                    $m = [regex]::Match($msg, $pat)
                    if ($m.Success) {
                        $workload = $m.Groups['workload'].Value
                        $obj = $m.Groups['obj'].Value
                        # Normalize Entra → EntraID folder name used by exporter
                        if ($workload -ieq 'Entra') { $workload = 'EntraID' }
                        [void]$failed.Add("$workload/$obj")
                        break
                    }
                }
            }
        }

        return $failed
    }

    $failedSet = Get-FailedExportObjectTypes -SnapshotPath $DifferencePath

    function Test-FailedExport {
        param(
            [Parameter(Mandatory)] [string]$RelativePath
        )

        $normalized = ($RelativePath -replace '\\', '/')
        $parts = $normalized -split '/'
        if ($parts.Count -lt 2) { return $false }

        $workload = $parts[0]
        $leaf = [System.IO.Path]::GetFileNameWithoutExtension($parts[-1])

        if ($failedSet.Contains("$workload/$leaf")) { return $true }

        # Cascade: per-script metadata files (e.g. Intune/Scripts/<name>/metadata.json)
        # depend on the parent script-list export. If any of the script-list exports
        # failed, treat the entire Intune/Scripts/* subtree as export-failed too.
        if ($workload -ieq 'Intune' -and $parts.Count -ge 2 -and $parts[1] -ieq 'Scripts') {
            $scriptListExports = @(
                'Intune/DeviceManagementScripts',
                'Intune/DeviceHealthScripts',
                'Intune/DeviceComplianceScripts',
                'Intune/ShellScripts'
            )
            foreach ($entry in $scriptListExports) {
                if ($failedSet.Contains($entry)) { return $true }
            }
        }

        return $false
    }

    $referenceFiles = Get-ChildItem -Path $ReferencePath -Filter '*.json' -Recurse -File
    $differenceFiles = Get-ChildItem -Path $DifferencePath -Filter '*.json' -Recurse -File
    $differences = [System.Collections.Generic.List[object]]::new()

    foreach ($referenceFile in $referenceFiles) {
        $relativePath = [System.IO.Path]::GetRelativePath($ReferencePath, $referenceFile.FullName)
        $candidate = Join-Path -Path $DifferencePath -ChildPath $relativePath

        if (-not (Test-Path -Path $candidate)) {
            $referenceJson = Get-CanonicalJsonFromFile -FilePath $referenceFile.FullName
            $status = if (Test-FailedExport -RelativePath $relativePath) {
                'ExportFailedInDifference'
            } else {
                'MissingInDifference'
            }

            $differences.Add([PSCustomObject]@{
                Path             = $relativePath
                Status           = $status
                BackupCanonical  = $referenceJson
                CurrentCanonical = $null
            })
            continue
        }

        $referenceJson = Get-CanonicalJsonFromFile -FilePath $referenceFile.FullName
        $differenceJson = Get-CanonicalJsonFromFile -FilePath $candidate

        if ($referenceJson -ne $differenceJson) {
            $differences.Add([PSCustomObject]@{
                Path             = $relativePath
                Status           = 'Different'
                BackupCanonical  = $referenceJson
                CurrentCanonical = $differenceJson
            })
        }
    }

    foreach ($differenceFile in $differenceFiles) {
        $relativePath = [System.IO.Path]::GetRelativePath($DifferencePath, $differenceFile.FullName)
        $candidate = Join-Path -Path $ReferencePath -ChildPath $relativePath

        if (-not (Test-Path -Path $candidate)) {
            $differenceJson = Get-CanonicalJsonFromFile -FilePath $differenceFile.FullName
            $differences.Add([PSCustomObject]@{
                Path             = $relativePath
                Status           = 'MissingInReference'
                BackupCanonical  = $null
                CurrentCanonical = $differenceJson
            })
        }
    }

    $artifacts = New-CompareReportArtifacts -DifferencePath $DifferencePath -Kind Tenant -OutputRoot $OutputRoot
    $summary = [pscustomobject]@{
        TotalComparisons          = $differences.Count
        Different                 = @($differences | Where-Object { $_.Status -eq 'Different' }).Count
        MissingInDifference       = @($differences | Where-Object { $_.Status -eq 'MissingInDifference' }).Count
        MissingInReference        = @($differences | Where-Object { $_.Status -eq 'MissingInReference' }).Count
        ExportFailedInDifference  = @($differences | Where-Object { $_.Status -eq 'ExportFailedInDifference' }).Count
    }

    $payload = [pscustomobject]@{
        GeneratedUtc        = (Get-Date).ToUniversalTime().ToString('o')
        Kind                = 'Tenant'
        ReferencePath       = $ReferencePath
        DifferencePath      = $DifferencePath
        IgnoreFields        = @($IgnoreFields)
        IgnoreFieldSuffixes = @($IgnoreFieldSuffixes)
        SortArrays          = $sortArrays
        Summary             = $summary
        Items               = $differences.ToArray()
        Output              = [pscustomobject]@{
            RunFolder = $artifacts.RunFolder
            HtmlPath  = $artifacts.HtmlPath
            JsonPath  = $artifacts.JsonPath
            LogPath   = $artifacts.LogPath
        }
    }

    ConvertTo-SafeJson -InputObject $payload -Depth 30 | Set-Content -Path $artifacts.JsonPath -Encoding UTF8
    New-CompareTenantConfigHtmlReport -CompareItems $differences.ToArray() -OutputPath $artifacts.HtmlPath -ReferencePath $ReferencePath -DifferencePath $DifferencePath -Summary $summary
    Write-CompareReportLog -LogPath $artifacts.LogPath -Level Information -Message 'Compare-M365TenantConfig report generated.' -Data ([pscustomobject]@{ HtmlPath = $artifacts.HtmlPath; JsonPath = $artifacts.JsonPath; Summary = $summary })
    Write-Verbose "Compare report (HTML): $($artifacts.HtmlPath)"

    if ($PassThru) {
        return [pscustomobject]@{
            Items          = $differences.ToArray()
            Summary        = $summary
            HtmlReportPath = $artifacts.HtmlPath
            JsonReportPath = $artifacts.JsonPath
            LogPath        = $artifacts.LogPath
        }
    }

    return $differences
}
