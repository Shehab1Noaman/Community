function Resolve-BackupM365Path {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path,

        [Parameter()]
        [string]$DefaultRelativePath
    )

    $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
    $repoRoot = Split-Path -Path $moduleRoot -Parent

    $resolvedPath = $Path
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        $resolvedPath = $DefaultRelativePath
    }

    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return $null
    }

    if ([System.IO.Path]::IsPathRooted($resolvedPath)) {
        return $resolvedPath
    }

    return (Join-Path -Path $repoRoot -ChildPath $resolvedPath)
}

function Get-BackupJsonItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        return @()
    }

    $raw = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return @()
    }

    try {
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return @()
    }

    if ($null -ne $parsed -and -not ($parsed -is [System.Collections.IEnumerable] -and -not ($parsed -is [string])) -and -not ($parsed -is [ValueType]) -and $parsed.PSObject) {
        $propNames = @($parsed.PSObject.Properties | ForEach-Object { $_.Name })
        if ($propNames -contains 'value') {
            return @($parsed.value)
        }
    }

    return @($parsed)
}

function Get-BackupObjectDisplayName {
    [CmdletBinding()]
    param(
        [Parameter()]
        $InputObject
    )

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [ValueType]) { return $null }
    if (-not $InputObject.PSObject) { return $null }

    $propNames = @($InputObject.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($propertyName in @('displayName', 'name', 'userPrincipalName', 'id', 'Identity')) {
        if (($propNames -contains $propertyName) -and -not [string]::IsNullOrWhiteSpace([string]$InputObject.$propertyName)) {
            return [string]$InputObject.$propertyName
        }
    }

    return $null
}

function Get-BackupRelativePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BasePath,

        [Parameter(Mandatory)]
        [string]$ChildPath
    )

    return ([System.IO.Path]::GetRelativePath($BasePath, $ChildPath) -replace '\\', '/')
}

function Get-BackupCatalogEntries {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootPath,

        [Parameter()]
        [string]$TenantName,

        [Parameter()]
        [string[]]$Workloads,

        [Parameter()]
        [switch]$IncludeObjects
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    $tenantFolders = @(Get-ChildItem -Path $RootPath -Directory -ErrorAction SilentlyContinue)
    if (-not [string]::IsNullOrWhiteSpace($TenantName)) {
        $tenantFolders = @($tenantFolders | Where-Object { $_.Name -eq $TenantName })
    }

    foreach ($tenantFolder in $tenantFolders) {
        $snapshotFolders = @(Get-ChildItem -Path $tenantFolder.FullName -Directory -ErrorAction SilentlyContinue)
        foreach ($snapshotFolder in $snapshotFolders) {
            $metadataPath = Join-Path -Path $snapshotFolder.FullName -ChildPath 'metadata.json'
            $metadata = $null
            if (Test-Path -Path $metadataPath -PathType Leaf) {
                try {
                    $metadata = Get-Content -Path $metadataPath -Raw | ConvertFrom-Json -ErrorAction Stop
                }
                catch {
                    $metadata = $null
                }
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
                    $items = @(Get-BackupJsonItems -Path $jsonFile.FullName)
                    $entry = [ordered]@{
                        TenantName      = if ($metadata -and $metadata.TenantName) { [string]$metadata.TenantName } else { $tenantFolder.Name }
                        SnapshotName    = $snapshotFolder.Name
                        BackupTimestamp = $backupTimestamp
                        Workload        = $workloadFolder.Name
                        ObjectType      = [System.IO.Path]::GetFileNameWithoutExtension($jsonFile.Name)
                        FilePath        = $jsonFile.FullName
                        RelativePath    = Get-BackupRelativePath -BasePath $snapshotFolder.FullName -ChildPath $jsonFile.FullName
                        ItemCount       = $items.Count
                        Status          = if ($metadata -and $metadata.Status) { [string]$metadata.Status } else { $null }
                    }

                    if ($IncludeObjects) {
                        $entry.ObjectNames = @($items | ForEach-Object { Get-BackupObjectDisplayName -InputObject $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    }

                    [void]$entries.Add([pscustomobject]$entry)
                }
            }
        }
    }

    return @($entries | Sort-Object TenantName, BackupTimestamp, Workload, ObjectType)
}

function Get-BackupFileFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        return $null
    }

    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash
}

function Compare-BackupSnapshotFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ReferencePath,

        [Parameter(Mandatory)]
        [string]$DifferencePath,

        [Parameter()]
        [string[]]$Workloads
    )

    $referenceFiles = @(Get-ChildItem -Path $ReferencePath -Recurse -Filter '*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne 'metadata.json' -and $_.DirectoryName -notmatch '[\\/]Logs$' })
    $differenceFiles = @(Get-ChildItem -Path $DifferencePath -Recurse -Filter '*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne 'metadata.json' -and $_.DirectoryName -notmatch '[\\/]Logs$' })

    $referenceMap = @{}
    foreach ($file in $referenceFiles) {
        $relativePath = Get-BackupRelativePath -BasePath $ReferencePath -ChildPath $file.FullName
        if ($Workloads -and $Workloads.Count -gt 0) {
            $parts = $relativePath -split '/'
            if ($parts.Count -gt 0 -and $parts[0] -notin $Workloads) { continue }
        }
        $referenceMap[$relativePath] = $file.FullName
    }

    $differenceMap = @{}
    foreach ($file in $differenceFiles) {
        $relativePath = Get-BackupRelativePath -BasePath $DifferencePath -ChildPath $file.FullName
        if ($Workloads -and $Workloads.Count -gt 0) {
            $parts = $relativePath -split '/'
            if ($parts.Count -gt 0 -and $parts[0] -notin $Workloads) { continue }
        }
        $differenceMap[$relativePath] = $file.FullName
    }

    $allKeys = @($referenceMap.Keys + $differenceMap.Keys | Sort-Object -Unique)
    $diffItems = [System.Collections.Generic.List[object]]::new()

    foreach ($key in $allKeys) {
        $inReference = $referenceMap.ContainsKey($key)
        $inDifference = $differenceMap.ContainsKey($key)
        $status = 'Unchanged'
        $referenceHash = $null
        $differenceHash = $null

        if ($inReference) { $referenceHash = Get-BackupFileFingerprint -Path $referenceMap[$key] }
        if ($inDifference) { $differenceHash = Get-BackupFileFingerprint -Path $differenceMap[$key] }

        if ($inReference -and -not $inDifference) {
            $status = 'Removed'
        }
        elseif (-not $inReference -and $inDifference) {
            $status = 'Added'
        }
        elseif ($referenceHash -ne $differenceHash) {
            $status = 'Changed'
        }

        if ($status -eq 'Unchanged') { continue }

        $parts = $key -split '/'
        [void]$diffItems.Add([pscustomobject]@{
            RelativePath    = $key
            Workload        = if ($parts.Count -gt 0) { $parts[0] } else { $null }
            ObjectType      = if ($parts.Count -gt 1) { [System.IO.Path]::GetFileNameWithoutExtension($parts[-1]) } else { $null }
            Status          = $status
            ReferenceHash   = $referenceHash
            DifferenceHash  = $differenceHash
            ReferencePath   = if ($inReference) { $referenceMap[$key] } else { $null }
            DifferencePath  = if ($inDifference) { $differenceMap[$key] } else { $null }
        })
    }

    return @($diffItems)
}

function Resolve-CompareOutputRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DifferencePath,

        [Parameter()]
        [string]$OutputRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($OutputRoot)) {
        return [System.IO.Path]::GetFullPath($OutputRoot)
    }

    $resolvedDifferencePath = [System.IO.Path]::GetFullPath($DifferencePath)
    $snapshotParentPath = Split-Path -Path $resolvedDifferencePath -Parent
    $snapshotContainerName = Split-Path -Path $snapshotParentPath -Leaf

    if ($snapshotContainerName -in @('Backup', 'Restore')) {
        return [System.IO.Path]::GetFullPath((Split-Path -Path $snapshotParentPath -Parent))
    }

    return [System.IO.Path]::GetFullPath($snapshotParentPath)
}

function Get-CompareReportName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DifferencePath,

        [Parameter(Mandatory)]
        [ValidateSet('Snapshot', 'Tenant')]
        [string]$Kind
    )

    $resolvedDifferencePath = [System.IO.Path]::GetFullPath($DifferencePath)
    $snapshotName = Split-Path -Path $resolvedDifferencePath -Leaf
    $snapshotParentPath = Split-Path -Path $resolvedDifferencePath -Parent
    $snapshotContainerName = Split-Path -Path $snapshotParentPath -Leaf

    $reportName = switch ($Kind) {
        'Snapshot' {
            if (-not [string]::IsNullOrWhiteSpace($snapshotName)) { $snapshotName } else { 'snapshot' }
        }
        'Tenant' {
            if ($snapshotContainerName -in @('Backup', 'Restore')) {
                $tenantRoot = Split-Path -Path $snapshotParentPath -Parent
                $tenantName = Split-Path -Path $tenantRoot -Leaf
                if (-not [string]::IsNullOrWhiteSpace($tenantName)) { $tenantName } else { $snapshotName }
            }
            elseif (-not [string]::IsNullOrWhiteSpace($snapshotContainerName)) {
                $snapshotContainerName
            }
            else {
                $snapshotName
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($reportName)) {
        $reportName = 'compare'
    }

    return ($reportName -replace '[<>:"/\\|?*]', '-')
}

function Get-CompareJsonPreview {
    param(
        [Parameter()]
        [string]$Text,

        [Parameter()]
        [int]$MaxLength = 220
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $collapsed = ($Text -replace '\s+', ' ').Trim()
    if ($collapsed.Length -le $MaxLength) { return $collapsed }
    return ($collapsed.Substring(0, $MaxLength) + ' ...')
}

function Convert-CompareCanonicalToPrettyJson {
    param(
        [Parameter()]
        [string]$CanonicalJson
    )

    if ([string]::IsNullOrWhiteSpace($CanonicalJson)) { return '' }
    try {
        $obj = $CanonicalJson | ConvertFrom-Json -ErrorAction Stop
        return ($obj | ConvertTo-Json -Depth 30)
    }
    catch {
        return [string]$CanonicalJson
    }
}

function New-CompareSnapshotHtmlReport {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$CompareItems,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [string]$ReferencePath,

        [Parameter(Mandatory)]
        [string]$DifferencePath,

        [Parameter(Mandatory)]
        [object]$Summary
    )

    $rows = @(foreach ($item in $CompareItems) {
        $relPathEncoded = [System.Net.WebUtility]::HtmlEncode([string]$item.RelativePath)
        $status         = [string]$item.Status
        $statusEncoded  = [System.Net.WebUtility]::HtmlEncode($status)
        $normalized     = ($item.RelativePath -replace '\\', '/')
        $parts          = $normalized -split '/', 2
        $workload       = [System.Net.WebUtility]::HtmlEncode($parts[0])

        @"
<tr class="row-$($status.ToLower())">
    <td><code>$relPathEncoded</code></td>
    <td><span class="badge badge-$($status.ToLower())">$statusEncoded</span></td>
    <td>$workload</td>
</tr>
"@
    })

    if (-not $rows -or $rows.Count -eq 0) {
        $rows = @('<tr><td colspan="3">No differences detected.</td></tr>')
    }

    $generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $html = @"
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>M365 Backup Snapshot Compare</title>
    <style>
        :root { --bg:#f7fafc; --surface:#fff; --line:#d7dee7; --text:#1b2530; --muted:#5c6f82; --accent:#0a6f5a; }
        body { margin:0; font-family:"Segoe UI",Tahoma,sans-serif; background:var(--bg); color:var(--text); }
        .wrap { max-width:1200px; margin:0 auto; padding:24px; }
        h1 { margin:0 0 12px; }
        .meta { background:var(--surface); border:1px solid var(--line); border-radius:10px; padding:14px 16px; margin-bottom:16px; }
        .meta p { margin:6px 0; color:var(--muted); }
        .chips { display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; }
        .chip { border:1px solid var(--line); border-radius:999px; padding:6px 10px; background:#f9fcff; }
        table { width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--line); }
        th,td { border-bottom:1px solid var(--line); padding:10px; vertical-align:top; }
        th { text-align:left; background:#edf5f2; }
        code { font-size:12px; }
        .badge { border-radius:4px; padding:2px 8px; font-size:12px; font-weight:600; }
        .badge-added { background:#d4edda; color:#155724; }
        .badge-removed { background:#f8d7da; color:#721c24; }
        .badge-changed { background:#fff3cd; color:#856404; }
        .row-added td { background:#f0fff4; }
        .row-removed td { background:#fff5f5; }
        .row-changed td { background:#fffef0; }
    </style>
</head>
<body>
<div class="wrap">
    <h1>M365 Backup Snapshot Compare</h1>
    <div class="meta">
        <p><strong>Generated (UTC):</strong> $generatedUtc</p>
        <p><strong>Reference Path:</strong> <code>$([System.Net.WebUtility]::HtmlEncode($ReferencePath))</code></p>
        <p><strong>Difference Path:</strong> <code>$([System.Net.WebUtility]::HtmlEncode($DifferencePath))</code></p>
        <div class="chips">
            <span class="chip">Total: $($Summary.Total)</span>
            <span class="chip">Added: $($Summary.Added)</span>
            <span class="chip">Removed: $($Summary.Removed)</span>
            <span class="chip">Changed: $($Summary.Changed)</span>
        </div>
    </div>
    <table>
        <thead>
            <tr>
                <th>Relative Path</th>
                <th>Status</th>
                <th>Workload</th>
            </tr>
        </thead>
        <tbody>
            $($rows -join "`n")
        </tbody>
    </table>
</div>
</body>
</html>
"@

    Set-Content -Path $OutputPath -Value $html -Encoding UTF8
}

function New-CompareTenantConfigHtmlReport {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$CompareItems,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [string]$ReferencePath,

        [Parameter(Mandatory)]
        [string]$DifferencePath,

        [Parameter(Mandatory)]
        [object]$Summary
    )

    $rows = @(foreach ($item in $CompareItems) {
        $backupRaw      = [string]$item.BackupCanonical
        $currentRaw     = [string]$item.CurrentCanonical
        $backupPreview  = [System.Net.WebUtility]::HtmlEncode((Get-CompareJsonPreview -Text $backupRaw))
        $currentPreview = [System.Net.WebUtility]::HtmlEncode((Get-CompareJsonPreview -Text $currentRaw))
        $pathEncoded    = [System.Net.WebUtility]::HtmlEncode([string]$item.Path)
        $status         = [string]$item.Status
        $statusEncoded  = [System.Net.WebUtility]::HtmlEncode($status)
        $backupPretty   = [System.Net.WebUtility]::HtmlEncode((Convert-CompareCanonicalToPrettyJson -CanonicalJson $backupRaw))
        $currentPretty  = [System.Net.WebUtility]::HtmlEncode((Convert-CompareCanonicalToPrettyJson -CanonicalJson $currentRaw))

        @"
<tr>
    <td><code>$pathEncoded</code></td>
    <td>$statusEncoded</td>
    <td><pre>$backupPreview</pre></td>
    <td><pre>$currentPreview</pre></td>
</tr>
<tr>
    <td colspan="4">
        <details>
            <summary>Full values for <code>$pathEncoded</code></summary>
            <div class="full-grid">
                <div><h4>Backup (Reference)</h4><pre>$backupPretty</pre></div>
                <div><h4>Current Snapshot</h4><pre>$currentPretty</pre></div>
            </div>
        </details>
    </td>
</tr>
"@
    })

    if (-not $rows -or $rows.Count -eq 0) {
        $rows = @('<tr><td colspan="4">No differences detected.</td></tr>')
    }

    $generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $html = @"
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>M365 Tenant Config Compare</title>
    <style>
        :root { --bg:#f7fafc; --surface:#fff; --line:#d7dee7; --text:#1b2530; --muted:#5c6f82; --accent:#0a6f5a; --warn:#9a5a00; }
        body { margin:0; font-family:"Segoe UI",Tahoma,sans-serif; background:linear-gradient(180deg,#f0f5f9 0%,var(--bg) 100%); color:var(--text); }
        .wrap { max-width:1400px; margin:0 auto; padding:24px; }
        h1 { margin:0 0 12px; }
        .meta { background:var(--surface); border:1px solid var(--line); border-radius:10px; padding:14px 16px; margin-bottom:16px; }
        .meta p { margin:6px 0; color:var(--muted); }
        .chips { display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; }
        .chip { border:1px solid var(--line); border-radius:999px; padding:6px 10px; background:#f9fcff; }
        table { width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--line); }
        th,td { border-bottom:1px solid var(--line); padding:10px; vertical-align:top; }
        th { text-align:left; background:#edf5f2; }
        pre { margin:0; white-space:pre-wrap; word-break:break-word; max-height:240px; overflow:auto; }
        details { padding:8px; border:1px solid var(--line); border-radius:8px; background:#fafcff; }
        .full-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:8px; }
        .full-grid h4 { margin:0 0 6px; color:var(--accent); }
        .note { color:var(--warn); margin-top:12px; }
        @media (max-width:900px) { .full-grid { grid-template-columns:1fr; } }
    </style>
</head>
<body>
<div class="wrap">
    <h1>M365 Tenant Config Compare</h1>
    <div class="meta">
        <p><strong>Generated (UTC):</strong> $generatedUtc</p>
        <p><strong>Backup Reference Path:</strong> <code>$([System.Net.WebUtility]::HtmlEncode($ReferencePath))</code></p>
        <p><strong>Current Snapshot Path:</strong> <code>$([System.Net.WebUtility]::HtmlEncode($DifferencePath))</code></p>
        <div class="chips">
            <span class="chip">Total: $($Summary.TotalComparisons)</span>
            <span class="chip">Different: $($Summary.Different)</span>
            <span class="chip">Missing In Difference: $($Summary.MissingInDifference)</span>
            <span class="chip">Missing In Reference: $($Summary.MissingInReference)</span>
            <span class="chip">Export Failed (skipped): $($Summary.ExportFailedInDifference)</span>
        </div>
        <p class="note">"Export Failed (skipped)" rows are items the difference snapshot could not retrieve; they are not counted as true drift.</p>
    </div>
    <table>
        <thead>
            <tr>
                <th>Configuration</th>
                <th>Status</th>
                <th>Backup (Reference)</th>
                <th>Current Snapshot</th>
            </tr>
        </thead>
        <tbody>
            $($rows -join "`n")
        </tbody>
    </table>
</div>
</body>
</html>
"@

    Set-Content -Path $OutputPath -Value $html -Encoding UTF8
}

function New-CompareReportArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DifferencePath,

        [Parameter(Mandatory)]
        [ValidateSet('Snapshot', 'Tenant')]
        [string]$Kind,

        [Parameter()]
        [string]$OutputRoot
    )

    $resolvedOutputRoot = Resolve-CompareOutputRoot -DifferencePath $DifferencePath -OutputRoot $OutputRoot
    $compareRoot = Join-Path -Path $resolvedOutputRoot -ChildPath 'Compare'
    $runFolderName = Get-Date -Format 'yyyyMMdd-HHmmss'
    $runFolder = Join-Path -Path $compareRoot -ChildPath $runFolderName
    $logsFolder = Join-Path -Path $runFolder -ChildPath 'Logs'
    $reportName = Get-CompareReportName -DifferencePath $DifferencePath -Kind $Kind

    New-Item -Path $logsFolder -ItemType Directory -Force | Out-Null

    return [pscustomobject]@{
        OutputRoot  = $resolvedOutputRoot
        CompareRoot = $compareRoot
        RunFolder   = $runFolder
        LogsFolder  = $logsFolder
        ReportName  = $reportName
        HtmlPath    = Join-Path -Path $runFolder -ChildPath ("Compare-$reportName.html")
        JsonPath    = Join-Path -Path $logsFolder -ChildPath 'compare-report.json'
        LogPath     = Join-Path -Path $logsFolder -ChildPath 'compare.log.ndjson'
    }
}

function Write-CompareReportLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogPath,

        [Parameter(Mandatory)]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        $Data
    )

    $entry = [pscustomobject]@{
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        Level     = $Level
        Message   = $Message
        Data      = $Data
    }

    Add-Content -Path $LogPath -Value (ConvertTo-SafeJson -InputObject $entry -Depth 12) -Encoding UTF8
}

function Resolve-BackupRemapConfig {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Config
    )

    $resolved = @{
        ExactValues       = @{}
        Domains           = @{}
        UrlPrefixes       = @{}
        Ids               = @{}
        UserPrincipalNames = @{}
    }

    if ($null -eq $Config) {
        return $resolved
    }

    foreach ($sectionName in @('exactValues', 'domains', 'urlPrefixes', 'ids', 'userPrincipalNames')) {
        if (-not ($Config.PSObject.Properties.Name -contains $sectionName)) { continue }
        $targetMap = switch ($sectionName) {
            'exactValues' { $resolved.ExactValues }
            'domains' { $resolved.Domains }
            'urlPrefixes' { $resolved.UrlPrefixes }
            'ids' { $resolved.Ids }
            'userPrincipalNames' { $resolved.UserPrincipalNames }
        }

        foreach ($property in $Config.$sectionName.PSObject.Properties) {
            if ($property.Name.StartsWith('_')) { continue }
            if ([string]::IsNullOrWhiteSpace([string]$property.Value)) { continue }
            $targetMap[[string]$property.Name] = [string]$property.Value
        }
    }

    return $resolved
}

function Convert-BackupDomainValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value,

        [Parameter(Mandatory)]
        [hashtable]$DomainMap
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $DomainMap.Count -eq 0) {
        return $Value
    }

    foreach ($sourceDomain in @($DomainMap.Keys | Sort-Object { ([string]$_).Length } -Descending)) {
        $sourceText = [string]$sourceDomain
        $targetText = [string]$DomainMap[$sourceDomain]
        if ([string]::IsNullOrWhiteSpace($sourceText) -or [string]::IsNullOrWhiteSpace($targetText)) { continue }

        if ($Value.Equals($sourceText, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $targetText
        }

        if ($Value.Length -gt $sourceText.Length -and $Value.EndsWith('.' + $sourceText, [System.StringComparison]::OrdinalIgnoreCase)) {
            return ($Value.Substring(0, $Value.Length - $sourceText.Length) + $targetText)
        }
    }

    return $Value
}

function Convert-BackupUrlByDomainMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value,

        [Parameter(Mandatory)]
        [hashtable]$DomainMap
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $DomainMap.Count -eq 0) {
        return $Value
    }

    $uri = $null
    if (-not [System.Uri]::TryCreate($Value, [System.UriKind]::Absolute, [ref]$uri)) {
        return $Value
    }

    $mappedHost = Convert-BackupDomainValue -Value $uri.Host -DomainMap $DomainMap
    if ($mappedHost.Equals($uri.Host, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Value
    }

    $builder = [System.UriBuilder]::new($uri)
    $builder.Host = $mappedHost
    return $builder.Uri.AbsoluteUri
}

function Invoke-BackupStringRemap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value,

        [Parameter(Mandatory)]
        [hashtable]$RemapConfig
    )

    if ($RemapConfig.ExactValues.ContainsKey($Value)) {
        return [string]$RemapConfig.ExactValues[$Value]
    }
    if ($RemapConfig.UserPrincipalNames.ContainsKey($Value)) {
        return [string]$RemapConfig.UserPrincipalNames[$Value]
    }
    if ($RemapConfig.Ids.ContainsKey($Value)) {
        return [string]$RemapConfig.Ids[$Value]
    }

    $result = $Value

    foreach ($sourcePrefix in @($RemapConfig.UrlPrefixes.Keys | Sort-Object { ([string]$_).Length } -Descending)) {
        if ($result.StartsWith([string]$sourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return ([string]$RemapConfig.UrlPrefixes[$sourcePrefix] + $result.Substring([string]$sourcePrefix.Length))
        }
    }

    $domainMappedUrl = Convert-BackupUrlByDomainMap -Value $result -DomainMap $RemapConfig.Domains
    if (-not $domainMappedUrl.Equals($result, [System.StringComparison]::Ordinal)) {
        return $domainMappedUrl
    }

    if ($result -match '^[^@\s]+@[^@\s]+$') {
        $parts = $result.Split('@', 2)
        $mappedDomain = Convert-BackupDomainValue -Value $parts[1] -DomainMap $RemapConfig.Domains
        if (-not $mappedDomain.Equals($parts[1], [System.StringComparison]::OrdinalIgnoreCase)) {
            return ($parts[0] + '@' + $mappedDomain)
        }
    }

    $domainMappedValue = Convert-BackupDomainValue -Value $result -DomainMap $RemapConfig.Domains
    if (-not $domainMappedValue.Equals($result, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $domainMappedValue
    }

    return $result
}

function Invoke-BackupRemap {
    [CmdletBinding()]
    param(
        [Parameter()]
        $InputObject,

        [Parameter()]
        [hashtable]$RemapConfig
    )

    if ($null -eq $InputObject -or $null -eq $RemapConfig) {
        return $InputObject
    }

    if ($InputObject -is [string]) {
        return (Invoke-BackupStringRemap -Value $InputObject -RemapConfig $RemapConfig)
    }

    if ($InputObject -is [System.ValueType]) {
        return $InputObject
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $mapped = [ordered]@{}
        foreach ($key in $InputObject.Keys) {
            $mapped[$key] = Invoke-BackupRemap -InputObject $InputObject[$key] -RemapConfig $RemapConfig
        }
        return $mapped
    }

    if (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string])) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) {
            [void]$items.Add((Invoke-BackupRemap -InputObject $item -RemapConfig $RemapConfig))
        }
        return @($items)
    }

    $properties = [ordered]@{}
    foreach ($property in $InputObject.PSObject.Properties) {
        $properties[$property.Name] = Invoke-BackupRemap -InputObject $property.Value -RemapConfig $RemapConfig
    }

    return [pscustomobject]$properties
}

function Get-BackupDependencyReferences {
    [CmdletBinding()]
    param(
        [Parameter()]
        $InputObject,

        [Parameter()]
        [string]$Workload,

        [Parameter()]
        [string]$ObjectType
    )

    $references = [System.Collections.Generic.List[object]]::new()

    function Add-ReferenceIfNeeded {
        param(
            [string]$Kind,
            [string]$Value,
            [string]$Path
        )

        if ([string]::IsNullOrWhiteSpace($Value)) { return }
        [void]$references.Add([pscustomobject]@{
            Workload   = $Workload
            ObjectType = $ObjectType
            Kind       = $Kind
            Value      = $Value
            Path       = $Path
        })
    }

    function Get-PathLeafToken {
        param([string]$Path)

        if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
        $token = ($Path -split '\.')[-1]
        return ($token -replace '\[\d+\]', '')
    }

    function Test-ReferencePathHint {
        param(
            [string]$Path,
            [string]$Kind
        )

        $leaf = (Get-PathLeafToken -Path $Path)
        if ([string]::IsNullOrWhiteSpace($leaf)) { return $false }

        $genericPattern = switch ($Kind) {
            'Id' { '(?i)(^|_|-)(id|guid|objectid|groupid|userid|teamid|siteid|policyid|templateid|environmentid|connectionid|ownerid|memberid|ref|reference)$' }
            'UPNOrEmail' { '(?i)(^|_|-)(upn|email|mail|userprincipalname|owner|member|user|principal|smtp|login|creator|createdby|modifiedby)$' }
            'Url' { '(?i)(^|_|-)(url|uri|weburl|siteurl|hostname|endpoint|resource|portal|adminurl|tenanturl|callbackurl)$' }
            'Domain' { '(?i)(^|_|-)(domain|hostname|fqdn|suffix|issuer|upn|email|mail)$' }
            default { '' }
        }

        $workloadPattern = switch (($Workload ?? '').ToLowerInvariant()) {
            'sharepoint' {
                switch ($Kind) {
                    'Id' { '(?i)(hubsiteid|siteid|groupid|ownerid|webid)' }
                    'UPNOrEmail' { '(?i)(owner|owners|member|members|admins|sitecollectionadmin)' }
                    'Url' { '(?i)(siteurl|weburl|url|hubsiteurl)' }
                    'Domain' { '(?i)(domain|hostname)' }
                    default { '' }
                }
            }
            'teams' {
                switch ($Kind) {
                    'Id' { '(?i)(teamid|groupid|channelid|userid|ownerid)' }
                    'UPNOrEmail' { '(?i)(owner|owners|member|members|primarysmtpaddress|email|upn|user)' }
                    'Url' { '(?i)(url|weburl|meetingurl|recordingurl)' }
                    'Domain' { '(?i)(domain|tenantdomain)' }
                    default { '' }
                }
            }
            'powerplatform' {
                switch ($Kind) {
                    'Id' { '(?i)(environmentid|tenantid|connectionid|ownerid|userid)' }
                    'UPNOrEmail' { '(?i)(owner|admin|user|email|upn)' }
                    'Url' { '(?i)(environmenturl|url|apiurl|portalurl|instanceurl)' }
                    'Domain' { '(?i)(domain|hostname|instance)' }
                    default { '' }
                }
            }
            default { '' }
        }

        if (-not [string]::IsNullOrWhiteSpace($genericPattern) -and $leaf -match $genericPattern) {
            return $true
        }

        return (-not [string]::IsNullOrWhiteSpace($workloadPattern) -and $leaf -match $workloadPattern)
    }

    function Walk-Value {
        param(
            $Value,
            [string]$Path,
            [int]$Depth = 0
        )

        if ($null -eq $Value) { return }
        if ($Depth -gt 50) { return }  # Guard against deeply-nested JSON (e.g. Settings Catalog groupSettingCollectionValue chains)

        if ($Value -is [string]) {
            if ($Value -match '^[0-9a-fA-F-]{36}$') {
                if (Test-ReferencePathHint -Path $Path -Kind 'Id') {
                    Add-ReferenceIfNeeded -Kind 'Id' -Value $Value -Path $Path
                }
            }
            elseif ($Value -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
                if (Test-ReferencePathHint -Path $Path -Kind 'UPNOrEmail') {
                    Add-ReferenceIfNeeded -Kind 'UPNOrEmail' -Value $Value -Path $Path
                }
            }
            elseif ($Value -match '^https?://') {
                if ((Test-ReferencePathHint -Path $Path -Kind 'Url') -or ($Value -match '(?i)\.sharepoint\.com|\.powerapps\.com|\.dynamics\.com|\.teams\.microsoft\.com')) {
                    Add-ReferenceIfNeeded -Kind 'Url' -Value $Value -Path $Path
                }
            }
            elseif ($Value -match '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') {
                if (Test-ReferencePathHint -Path $Path -Kind 'Domain') {
                    Add-ReferenceIfNeeded -Kind 'Domain' -Value $Value -Path $Path
                }
            }
            return
        }

        if ($Value -is [System.Collections.IDictionary]) {
            foreach ($key in $Value.Keys) {
                Walk-Value -Value $Value[$key] -Path ($(if ($Path) { "$Path.$key" } else { [string]$key })) -Depth ($Depth + 1)
            }
            return
        }

        if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
            $index = 0
            foreach ($item in $Value) {
                Walk-Value -Value $item -Path "$Path[$index]" -Depth ($Depth + 1)
                $index++
            }
            return
        }

        foreach ($property in $Value.PSObject.Properties) {
            Walk-Value -Value $property.Value -Path ($(if ($Path) { "$Path.$($property.Name)" } else { $property.Name })) -Depth ($Depth + 1)
        }
    }

    Walk-Value -Value $InputObject -Path ''
    return @($references)
}

function Test-BackupRemapCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$References,

        [Parameter()]
        [hashtable]$RemapConfig
    )

    $unresolved = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $RemapConfig) {
        return @($References)
    }

    foreach ($reference in $References) {
        $resolved = switch ([string]$reference.Kind) {
            'Id' { $RemapConfig.Ids.ContainsKey([string]$reference.Value) -or $RemapConfig.ExactValues.ContainsKey([string]$reference.Value) }
            'UPNOrEmail' {
                $value = [string]$reference.Value
                $domain = if ($value -match '@') { $value.Split('@')[-1] } else { '' }
                $RemapConfig.UserPrincipalNames.ContainsKey($value) -or $RemapConfig.ExactValues.ContainsKey($value) -or ($domain -and $RemapConfig.Domains.ContainsKey($domain))
            }
            'Domain' { $RemapConfig.Domains.ContainsKey([string]$reference.Value) -or $RemapConfig.ExactValues.ContainsKey([string]$reference.Value) }
            'Url' {
                $value = [string]$reference.Value
                if ($RemapConfig.ExactValues.ContainsKey($value)) { $true }
                elseif (@($RemapConfig.UrlPrefixes.Keys | Where-Object { $value.StartsWith([string]$_, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) { $true }
                else {
                    $uri = $null
                    if ([System.Uri]::TryCreate($value, [System.UriKind]::Absolute, [ref]$uri)) {
                        @($RemapConfig.Domains.Keys | Where-Object { $uri.Host.Equals([string]$_, [System.StringComparison]::OrdinalIgnoreCase) -or $uri.Host.EndsWith('.' + [string]$_, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
                    }
                    else {
                        $false
                    }
                }
            }
            default { $true }
        }

        if (-not $resolved) {
            [void]$unresolved.Add($reference)
        }
    }

    return @($unresolved)
}

function New-RestorePlanData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BackupPath,

        [Parameter(Mandatory)]
        [string[]]$Workloads,

        [Parameter()]
        [string[]]$ObjectNames,

        [Parameter()]
        [hashtable]$WorkloadObjectTypes,

        [Parameter()]
        [string]$TargetMode = 'SameTenant',

        [Parameter()]
        [hashtable]$RemapConfig,

        [Parameter()]
        [string]$CurrentSnapshotPath
    )

    $planItems = [System.Collections.Generic.List[object]]::new()

    foreach ($workload in $Workloads) {
        $workloadPath = Join-Path -Path $BackupPath -ChildPath $workload
        if (-not (Test-Path -Path $workloadPath -PathType Container)) { continue }

        $currentLookup = @{}
        if (-not [string]::IsNullOrWhiteSpace($CurrentSnapshotPath)) {
            $currentWorkloadPath = Join-Path -Path $CurrentSnapshotPath -ChildPath $workload
            if (Test-Path -Path $currentWorkloadPath -PathType Container) {
                foreach ($currentFile in @(Get-ChildItem -Path $currentWorkloadPath -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
                    $objectTypeName = [System.IO.Path]::GetFileNameWithoutExtension($currentFile.Name)
                    $currentLookup[$objectTypeName] = @{}
                    foreach ($currentItem in @(Get-BackupJsonItems -Path $currentFile.FullName)) {
                        $currentName = Get-BackupObjectDisplayName -InputObject $currentItem
                        if (-not [string]::IsNullOrWhiteSpace($currentName)) {
                            $currentLookup[$objectTypeName][$currentName] = $true
                        }
                    }
                }
            }
        }

        foreach ($backupFile in @(Get-ChildItem -Path $workloadPath -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
            $objectType = [System.IO.Path]::GetFileNameWithoutExtension($backupFile.Name)
            if ($WorkloadObjectTypes -and $WorkloadObjectTypes.ContainsKey($workload)) {
                $allowedTypes = @($WorkloadObjectTypes[$workload])
                if ($allowedTypes.Count -gt 0 -and $objectType -notin $allowedTypes) {
                    continue
                }
                if ($allowedTypes.Count -eq 0) {
                    continue
                }
            }

            foreach ($item in @(Get-BackupJsonItems -Path $backupFile.FullName)) {
                $name = Get-BackupObjectDisplayName -InputObject $item
                if ($ObjectNames -and $ObjectNames.Count -gt 0 -and $name -notin $ObjectNames) { continue }

                $refs = @(Get-BackupDependencyReferences -InputObject $item -Workload $workload -ObjectType $objectType)
                $unresolvedRefs = @()
                if ($TargetMode -eq 'AnotherTenant') {
                    $unresolvedRefs = @(Test-BackupRemapCoverage -References $refs -RemapConfig $RemapConfig)
                }

                $action = 'Review'
                if ($currentLookup.ContainsKey($objectType) -and $name -and $currentLookup[$objectType].ContainsKey($name)) {
                    $action = 'Update'
                }
                elseif (-not [string]::IsNullOrWhiteSpace($CurrentSnapshotPath)) {
                    $action = 'Create'
                }

                [void]$planItems.Add([pscustomobject]@{
                    Workload                 = $workload
                    ObjectType               = $objectType
                    Name                     = $name
                    Action                   = $action
                    RelativePath             = Get-BackupRelativePath -BasePath $BackupPath -ChildPath $backupFile.FullName
                    DependencyCount          = $refs.Count
                    UnresolvedDependencyCount = @($unresolvedRefs).Count
                    Dependencies             = $refs
                    UnresolvedDependencies   = $unresolvedRefs
                })
            }
        }
    }

    $summary = [pscustomobject]@{
        TotalItems                = $planItems.Count
        Creates                   = @($planItems | Where-Object { $_.Action -eq 'Create' }).Count
        Updates                   = @($planItems | Where-Object { $_.Action -eq 'Update' }).Count
        ReviewOnly                = @($planItems | Where-Object { $_.Action -eq 'Review' }).Count
        ItemsWithDependencies     = @($planItems | Where-Object { $_.DependencyCount -gt 0 }).Count
        ItemsWithUnresolvedLinks  = @($planItems | Where-Object { $_.UnresolvedDependencyCount -gt 0 }).Count
    }

    return [pscustomobject]@{
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
        BackupPath   = $BackupPath
        TargetMode   = $TargetMode
        Summary      = $summary
        Items        = @($planItems)
    }
}

function Get-BackupIntegrityReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BackupPath,

        [Parameter()]
        [object[]]$Summary,

        [Parameter()]
        [string]$LogPath
    )

    $workloadRows = @()
    if ($Summary -and $Summary.Count -gt 0) {
        $workloadRows = @($Summary)
    }
    else {
        foreach ($workloadFolder in @(Get-ChildItem -Path $BackupPath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'Logs' })) {
            $files = @(Get-ChildItem -Path $workloadFolder.FullName -Recurse -File -ErrorAction SilentlyContinue)
            $status = if ($files.Count -gt 0) { 'Success' } else { 'Empty' }
            $workloadRows += [pscustomobject]@{
                Workload = $workloadFolder.Name
                Status   = $status
                Files    = $files.Count
                Warnings = 0
                Errors   = 0
                Reason   = if ($status -eq 'Empty') { 'No exported files found.' } else { $null }
            }
        }
    }

    $score = 100
    foreach ($row in $workloadRows) {
        switch ([string]$row.Status) {
            'Failed' { $score -= 20 }
            'Partial' { $score -= 10 }
            'Empty' { $score -= 5 }
        }
        if ([int]$row.Errors -gt 0) { $score -= [Math]::Min([int]$row.Errors, 10) }
        if ([int]$row.Warnings -gt 0) { $score -= [Math]::Min([int]$row.Warnings, 5) }
    }
    if ($score -lt 0) { $score = 0 }

    return [pscustomobject]@{
        GeneratedUtc      = (Get-Date).ToUniversalTime().ToString('o')
        BackupPath        = $BackupPath
        Score             = $score
        TotalWorkloads    = @($workloadRows).Count
        Successful        = @($workloadRows | Where-Object { $_.Status -eq 'Success' }).Count
        Partial           = @($workloadRows | Where-Object { $_.Status -eq 'Partial' }).Count
        Failed            = @($workloadRows | Where-Object { $_.Status -eq 'Failed' }).Count
        Empty             = @($workloadRows | Where-Object { $_.Status -eq 'Empty' }).Count
        Workloads         = @($workloadRows)
        LogPath           = $LogPath
    }
}

function Invoke-BackupSensitiveDataProcessing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BackupPath,

        [Parameter()]
        [ValidateSet('Keep', 'Audit', 'Redact')]
        [string]$Mode = 'Audit'
    )

    $sensitiveKeys = @('clientSecret', 'secret', 'password', 'accessToken', 'refreshToken', 'token')
    $hits = [System.Collections.Generic.List[object]]::new()

    function Process-Value {
        param($Value, [string]$Path)

        if ($null -eq $Value) { return $Value }
        if ($Value -is [System.Collections.IDictionary]) {
            foreach ($key in @($Value.Keys)) {
                $fullPath = if ($Path) { "$Path.$key" } else { [string]$key }
                if ($key -in $sensitiveKeys) {
                    [void]$hits.Add([pscustomobject]@{ Path = $fullPath; Key = $key })
                    if ($Mode -eq 'Redact') {
                        $Value[$key] = '[REDACTED]'
                        continue
                    }
                }
                $Value[$key] = Process-Value -Value $Value[$key] -Path $fullPath
            }
            return $Value
        }
        if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
            $items = [System.Collections.Generic.List[object]]::new()
            $index = 0
            foreach ($item in $Value) {
                [void]$items.Add((Process-Value -Value $item -Path "$Path[$index]"))
                $index++
            }
            return @($items)
        }
        # Treat as object-with-properties only for non-primitive, non-string values.
        # Under Set-StrictMode -Version Latest, accessing .Count on PSObject.Properties
        # for primitives (int/bool/etc.) can throw "property Count cannot be found",
        # so wrap in @() to coerce to an array.
        $hasProps = $false
        if (-not ($Value -is [string]) -and -not ($Value -is [ValueType]) -and $Value.PSObject) {
            $hasProps = (@($Value.PSObject.Properties).Count -gt 0)
        }
        if ($hasProps) {
            $mapped = [ordered]@{}
            foreach ($property in $Value.PSObject.Properties) {
                $fullPath = if ($Path) { "$Path.$($property.Name)" } else { $property.Name }
                if ($property.Name -in $sensitiveKeys) {
                    [void]$hits.Add([pscustomobject]@{ Path = $fullPath; Key = $property.Name })
                    if ($Mode -eq 'Redact') {
                        $mapped[$property.Name] = '[REDACTED]'
                        continue
                    }
                }
                $mapped[$property.Name] = Process-Value -Value $property.Value -Path $fullPath
            }
            return [pscustomobject]$mapped
        }
        return $Value
    }

    if ($Mode -eq 'Keep') {
        return [pscustomobject]@{ Mode = $Mode; FilesScanned = 0; Hits = @() }
    }

    $jsonFiles = @(Get-ChildItem -Path $BackupPath -Recurse -Filter '*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -notmatch '[\\/]Logs$' -and $_.Name -ne 'metadata.json' })

    foreach ($jsonFile in $jsonFiles) {
        $raw = Get-Content -Path $jsonFile.FullName -Raw -ErrorAction SilentlyContinue
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        try {
            $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            continue
        }

        $processed = Process-Value -Value $parsed -Path ([System.IO.Path]::GetFileNameWithoutExtension($jsonFile.Name))
        if ($Mode -eq 'Redact') {
            $processed | ConvertTo-Json -Depth 50 | Set-Content -Path $jsonFile.FullName -Encoding UTF8
        }
    }

    return [pscustomobject]@{
        Mode         = $Mode
        FilesScanned = @($jsonFiles).Count
        HitCount     = @($hits).Count
        Hits         = @($hits)
    }
}

function Find-PreviousBackupSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BackupRoot
    )

    $currentSnapshotName = Split-Path -Path $BackupRoot -Leaf
    $tenantFolder = Split-Path -Path $BackupRoot -Parent
    if (-not (Test-Path -Path $tenantFolder -PathType Container)) {
        return $null
    }

    $previous = @(Get-ChildItem -Path $tenantFolder -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne $currentSnapshotName } |
        Sort-Object Name -Descending |
        Select-Object -First 1)

    if ($previous.Count -eq 0) {
        return $null
    }

    return $previous[0].FullName
}

function New-BackupPrecheckReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter()]$PrecheckResult,
        [Parameter()]$InitialPrecheckResult,
        [Parameter()][string[]]$Workloads,
        [Parameter()]$InstallActions,
        [Parameter()][bool]$AutoInstallEnabled,
        [Parameter()][string]$ModuleScope = 'CurrentUser',
        [Parameter()][string]$Scope = 'Backup'
    )

    if (-not $PrecheckResult) { return }

    $moduleRows = @($PrecheckResult.Modules)
    $initialMissingModules = @()
    if ($InitialPrecheckResult -and $InitialPrecheckResult.Modules) {
        $initialMissingModules = @($InitialPrecheckResult.Modules | Where-Object { -not $_.Installed } | Select-Object -ExpandProperty Module -Unique)
    }

    $installByModule = @{}
    foreach ($a in @($InstallActions)) { $installByModule[[string]$a.Module] = $a }

    $permissionRows = @()
    if ($PrecheckResult.Permissions -and $PrecheckResult.Permissions.Apps) {
        $permissionRows = @($PrecheckResult.Permissions.Apps)
    }

    $impacted = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($m in @($moduleRows | Where-Object { -not $_.Installed })) {
        foreach ($w in ([string]$m.Workload -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            [void]$impacted.Add($w)
        }
    }
    foreach ($p in @($permissionRows | Where-Object { [int]$_.MissingCount -gt 0 })) {
        if ([string]$p.Resource -eq 'SharePointOnline') {
            [void]$impacted.Add('SharePoint')
            continue
        }
        if ([string]$p.Resource -eq 'MicrosoftGraph') {
            foreach ($w in @($Workloads | Where-Object { $_ -in @('EntraID','Intune','Users','Planner','SharePoint','Teams','Defender') })) {
                [void]$impacted.Add($w)
            }
        }
    }

    $issues = @($PrecheckResult.Issues)
    $warnings = @($PrecheckResult.Warnings)

    function Get-PrecheckWarningCategory {
        param([Parameter(Mandatory)][string]$WarningText)

        # Priority matters: actionable permission gaps should always win over generic patterns.
        if ($WarningText -match '(?i)missing graph application roles|missing sharepoint online application roles|missing\s+\d+\s+required role\(s\)\s+on\s+(microsoftgraph|sharepointonline)|permission precheck:') {
            return 'BlockingPermissionGap'
        }

        if ($WarningText -match '(?i)requires\s+.*license|app-only backups use|will be skipped under app-only auth|inconclusive|read-only|missing metadata\.json|coverage will be partial|optional module missing') {
            return 'ExpectedLimitation'
        }

        return 'Other'
    }

    $blockingPermissionWarnings = New-Object System.Collections.Generic.List[string]
    $expectedLimitationsWarnings = New-Object System.Collections.Generic.List[string]
    $otherWarnings = New-Object System.Collections.Generic.List[string]

    foreach ($w in $warnings) {
        $warningText = [string]$w
        if ([string]::IsNullOrWhiteSpace($warningText)) { continue }

        switch (Get-PrecheckWarningCategory -WarningText $warningText) {
            'BlockingPermissionGap' { [void]$blockingPermissionWarnings.Add($warningText) }
            'ExpectedLimitation'    { [void]$expectedLimitationsWarnings.Add($warningText) }
            default                 { [void]$otherWarnings.Add($warningText) }
        }
    }
    $status = if ($issues.Count -gt 0) { 'Failed' } elseif ($warnings.Count -gt 0) { 'Warning' } else { 'Passed' }

    $html = New-Object System.Text.StringBuilder
    [void]$html.AppendLine('<!DOCTYPE html>')
    [void]$html.AppendLine('<html><head><meta charset="utf-8"><title>BackupM365 Precheck Report</title>')
    [void]$html.AppendLine('<style>')
    [void]$html.AppendLine('body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222} h1{margin:0 0 4px 0} h2{margin-top:24px;border-bottom:1px solid #ddd;padding-bottom:4px}')
    [void]$html.AppendLine('table{border-collapse:collapse;width:100%;margin-top:8px} th,td{border:1px solid #ddd;padding:6px 8px;font-size:12px;vertical-align:top} th{background:#f3f3f3}')
    [void]$html.AppendLine('.ok{color:#155724;background:#d4edda;padding:2px 8px;border-radius:10px;font-weight:600} .warn{color:#856404;background:#fff3cd;padding:2px 8px;border-radius:10px;font-weight:600} .fail{color:#721c24;background:#f8d7da;padding:2px 8px;border-radius:10px;font-weight:600}')
    [void]$html.AppendLine('ul{margin-top:6px} code{background:#f3f3f3;padding:1px 4px;border-radius:3px}')
    [void]$html.AppendLine('</style></head><body>')
    [void]$html.AppendLine('<h1>BackupM365 Precheck Report</h1>')
    [void]$html.AppendLine("<div>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')</div>")
    [void]$html.AppendLine("<div>Scope: $Scope</div>")
    [void]$html.AppendLine("<div>Workloads: $([string]::Join(', ', @($Workloads)))</div>")
    $badgeClass = if ($status -eq 'Passed') { 'ok' } elseif ($status -eq 'Warning') { 'warn' } else { 'fail' }
    [void]$html.AppendLine("<div style='margin-top:8px'>Status: <span class='$badgeClass'>$status</span></div>")
    [void]$html.AppendLine("<div style='margin-top:6px'>Blocking permission gaps: $($blockingPermissionWarnings.Count) | Expected limitations/licensing: $($expectedLimitationsWarnings.Count) | Other warnings: $($otherWarnings.Count)</div>")
    [void]$html.AppendLine("<div style='margin-top:4px'>Note: Expected limitations are informational and usually non-blocking for backup or restore execution.</div>")

    [void]$html.AppendLine('<h2>Impacted Workloads</h2>')
    if ($impacted.Count -eq 0) {
        [void]$html.AppendLine('<div>None identified by precheck.</div>')
    } else {
        [void]$html.AppendLine('<ul>')
        foreach ($w in @($impacted | Sort-Object)) { [void]$html.AppendLine("<li>$w</li>") }
        [void]$html.AppendLine('</ul>')
    }

    [void]$html.AppendLine('<h2>Issues</h2>')
    if ($issues.Count -eq 0) { [void]$html.AppendLine('<div>None.</div>') } else {
        [void]$html.AppendLine('<ul>')
        foreach ($i in $issues) { [void]$html.AppendLine("<li>$i</li>") }
        [void]$html.AppendLine('</ul>')
    }

    [void]$html.AppendLine('<h2>Blocking Permission Gaps</h2>')
    if ($blockingPermissionWarnings.Count -eq 0) {
        [void]$html.AppendLine('<div>None.</div>')
    } else {
        [void]$html.AppendLine('<ul>')
        foreach ($w in $blockingPermissionWarnings) {
            $safeWarning = [System.Security.SecurityElement]::Escape([string]$w)
            [void]$html.AppendLine("<li>$safeWarning</li>")
        }
        [void]$html.AppendLine('</ul>')
    }

    [void]$html.AppendLine('<h2>Expected Limitations And Licensing</h2>')
    if ($expectedLimitationsWarnings.Count -eq 0) {
        [void]$html.AppendLine('<div>None.</div>')
    } else {
        [void]$html.AppendLine('<ul>')
        foreach ($w in $expectedLimitationsWarnings) {
            $safeWarning = [System.Security.SecurityElement]::Escape([string]$w)
            [void]$html.AppendLine("<li>$safeWarning</li>")
        }
        [void]$html.AppendLine('</ul>')
    }

    [void]$html.AppendLine('<h2>Other Warnings</h2>')
    if ($otherWarnings.Count -eq 0) {
        [void]$html.AppendLine('<div>None.</div>')
    } else {
        [void]$html.AppendLine('<ul>')
        foreach ($w in $otherWarnings) {
            $safeWarning = [System.Security.SecurityElement]::Escape([string]$w)
            [void]$html.AppendLine("<li>$safeWarning</li>")
        }
        [void]$html.AppendLine('</ul>')
    }

    [void]$html.AppendLine('<h2>Module Checks</h2>')
    [void]$html.AppendLine('<table><tr><th>Module</th><th>Installed</th><th>Workload</th><th>Action Taken</th><th>Recommendation</th></tr>')
    foreach ($m in $moduleRows) {
        $moduleName = [string]$m.Module
        $installed = [bool]$m.Installed
        $action = 'None'
        if ($installByModule.ContainsKey($moduleName)) {
            $a = $installByModule[$moduleName]
            $action = if ($a.Success) { "Installed automatically ($ModuleScope)" } else { "Install attempt failed: $($a.Error)" }
        }
        elseif (($initialMissingModules -contains $moduleName) -and $installed) {
            $action = "Installed automatically ($ModuleScope)"
        }

        $recommendation = if ($installed) {
            if ($action -like 'Installed automatically*') { 'Corrected by auto-install.' } else { 'No action needed.' }
        } else {
            "Install module: Install-Module $moduleName -Scope $ModuleScope -Force"
        }
        [void]$html.AppendLine("<tr><td>$moduleName</td><td>$installed</td><td>$([string]$m.Workload)</td><td>$action</td><td>$recommendation</td></tr>")
    }
    [void]$html.AppendLine('</table>')

    [void]$html.AppendLine('<h2>Permission Checks</h2>')
    if ($permissionRows.Count -eq 0) {
        [void]$html.AppendLine('<div>No permission check rows returned.</div>')
    } else {
        [void]$html.AppendLine('<table><tr><th>App Role</th><th>Resource</th><th>ClientId</th><th>MissingCount</th><th>Missing Settings/Roles</th><th>Recommendation</th></tr>')
        foreach ($p in $permissionRows) {
            $missing = @($p.Missing)
            $missingText = if ($missing.Count -gt 0) { ($missing -join ', ') } else { '(none)' }
            $rec = if ([int]$p.MissingCount -gt 0) {
                if ([string]$p.Resource -eq 'SharePointOnline') {
                    'Grant missing SharePoint Online Application role(s), then Grant admin consent. Example: Sites.FullControl.All.'
                } elseif ([string]$p.Resource -eq 'MicrosoftGraph') {
                    'Grant missing Microsoft Graph Application role(s), then Grant admin consent.'
                } else {
                    'Grant missing application role(s) and admin-consent.'
                }
            } else { 'No action needed.' }
            [void]$html.AppendLine("<tr><td>$([string]$p.Role)</td><td>$([string]$p.Resource)</td><td><code>$([string]$p.ClientId)</code></td><td>$([int]$p.MissingCount)</td><td>$missingText</td><td>$rec</td></tr>")
        }
        [void]$html.AppendLine('</table>')
    }

    [void]$html.AppendLine('</body></html>')
    $html.ToString() | Set-Content -Path $ReportPath -Encoding UTF8
}

function Write-BackupHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][string]$Title,
        [Parameter()]$Data,
        [Parameter()][string[]]$SummaryLines
    )

    $safeTitle = [System.Security.SecurityElement]::Escape($Title)
    $generated = [System.Security.SecurityElement]::Escape((Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'))

    $jsonText = '{}'
    try {
        $jsonText = ConvertTo-SafeJson -InputObject $Data -Depth 20
    }
    catch {
        $jsonText = '{"error":"failed to render report payload"}'
    }
    $jsonEscaped = [System.Security.SecurityElement]::Escape([string]$jsonText)

    $html = New-Object System.Text.StringBuilder
    [void]$html.AppendLine('<!DOCTYPE html>')
    [void]$html.AppendLine('<html><head><meta charset="utf-8"><title>BackupM365 Report</title>')
    [void]$html.AppendLine('<style>')
    [void]$html.AppendLine('body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222} h1{margin:0 0 6px 0} h2{margin-top:22px;border-bottom:1px solid #ddd;padding-bottom:4px}')
    [void]$html.AppendLine('ul{margin-top:6px} code,pre{background:#f3f3f3;border-radius:4px} code{padding:1px 4px} pre{padding:10px;white-space:pre-wrap;word-break:break-word;border:1px solid #ddd;font-size:12px}')
    [void]$html.AppendLine('</style></head><body>')
    [void]$html.AppendLine("<h1>$safeTitle</h1>")
    [void]$html.AppendLine("<div>Generated: $generated</div>")

    [void]$html.AppendLine('<h2>Summary</h2>')
    if ($SummaryLines -and $SummaryLines.Count -gt 0) {
        [void]$html.AppendLine('<ul>')
        foreach ($line in $SummaryLines) {
            $safeLine = [System.Security.SecurityElement]::Escape([string]$line)
            [void]$html.AppendLine("<li>$safeLine</li>")
        }
        [void]$html.AppendLine('</ul>')
    }
    else {
        [void]$html.AppendLine('<div>No summary details.</div>')
    }

    [void]$html.AppendLine('<h2>Raw Data</h2>')
    [void]$html.AppendLine("<pre>$jsonEscaped</pre>")
    [void]$html.AppendLine('</body></html>')
    $html.ToString() | Set-Content -Path $ReportPath -Encoding UTF8
}