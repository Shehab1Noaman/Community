function Restore-M365TenantConfig {
    <#
    .SYNOPSIS
        Restores M365 tenant configuration from a backup snapshot.

    .DESCRIPTION
        Reads restore.config.json (or the supplied ConfigPath), builds a restore plan,
        and applies backed-up configuration objects back to the tenant using
        Import-M365TenantConfig. Supports dry-run mode (-DryRun), selective apply
        (-ApplyChanges), and confirmation bypass (-Force).

        The restore config defines which backup snapshot to use, which workloads and
        object types to restore, any identifier remapping needed, and the target mode
        (Overwrite / MergeOrSkip).

    .PARAMETER ConfigPath
        Path to restore.config.json. Defaults to config/restore.config.json in the
        repository root.

    .PARAMETER SkipPrechecks
        Skip the prerequisite validation phase.

    .PARAMETER DryRun
        Preview which objects would be changed without applying anything.

    .PARAMETER ApplyChanges
        Confirm that changes should be written to the tenant.
        Without this switch the function runs in preview mode by default.

    .PARAMETER Force
        Suppress confirmation prompts for destructive operations.

    .PARAMETER InstallMissingModules
        Automatically install any missing required or optional PowerShell modules from
        PSGallery before running. Equivalent to setting prechecks.installMissingModules
        to true in restore.config.json.

    .PARAMETER ModuleScope
        Scope for automatic module installation: CurrentUser (default) or AllUsers.
        Only used when -InstallMissingModules is specified or configured.

    .EXAMPLE
        Restore-M365TenantConfig -ConfigPath .\config\restore.config.json -DryRun

    .EXAMPLE
        Restore-M365TenantConfig -ConfigPath .\config\restore.config.json `
                                 -ApplyChanges -Force

    .EXAMPLE
        Restore-M365TenantConfig -ConfigPath .\config\restore.config.json `
                                 -DryRun -InstallMissingModules
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$BackupPath,

        [Parameter()]
        [switch]$SkipPrechecks,

        [Parameter()]
        [switch]$DryRun,

        [Parameter()]
        [switch]$ApplyChanges,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$InstallMissingModules,

        [Parameter()]
        [ValidateSet('CurrentUser', 'AllUsers')]
        [string]$ModuleScope = 'CurrentUser',

        [Parameter()]
        [switch]$NoLog
    )

    $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
    $repoRoot = Split-Path -Path $moduleRoot -Parent

    $effectiveConfigPath = if ($ConfigPath) {
        $ConfigPath
    }
    else {
        Join-Path -Path $repoRoot -ChildPath 'config/restore.config.json'
    }

    if (-not (Test-Path -Path $effectiveConfigPath)) {
        throw "Restore config file not found: $effectiveConfigPath"
    }

    try {
        $config = Get-Content -Path $effectiveConfigPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse restore config [$effectiveConfigPath]. $($_.Exception.Message)"
    }

    if (-not [string]::IsNullOrWhiteSpace($BackupPath)) {
        # -BackupPath parameter takes precedence over config
        $backupPath = $BackupPath
    }
    else {
        $sourceBackupPath = [string]$config.source.backupPath
        if ([string]::IsNullOrWhiteSpace($sourceBackupPath)) {
            throw "restore.config.json is missing source.backupPath"
        }
        if ([System.IO.Path]::IsPathRooted($sourceBackupPath)) {
            $backupPath = $sourceBackupPath
        }
        else {
            $backupPath = Join-Path -Path $repoRoot -ChildPath $sourceBackupPath
        }
    }

    if (-not (Test-Path -Path $backupPath)) {
        throw "Backup source path not found: $backupPath"
    }

    $metadataPath = Join-Path -Path $backupPath -ChildPath 'metadata.json'
    $sourceMetadata = $null
    if (Test-Path -Path $metadataPath) {
        try {
            $sourceMetadata = Get-Content -Path $metadataPath -Raw | ConvertFrom-Json
        }
        catch {
            Write-Warning "Failed to read source metadata [$metadataPath]. $($_.Exception.Message)"
        }
    }

    $targetMode = [string]$config.target.mode
    if ([string]::IsNullOrWhiteSpace($targetMode)) {
        $targetMode = 'SameTenant'
    }

    $targetTenantId = [string]$config.target.tenantId
    $targetTenantName = [string]$config.target.tenantName

    if ([string]::IsNullOrWhiteSpace($targetTenantId) -and $sourceMetadata) {
        $targetTenantId = [string]$sourceMetadata.TenantId
    }
    if ([string]::IsNullOrWhiteSpace($targetTenantName) -and $sourceMetadata) {
        $targetTenantName = [string]$sourceMetadata.TenantName
    }

    if ([string]::IsNullOrWhiteSpace($targetTenantId)) {
        throw "Unable to resolve target tenant id. Set target.tenantId in restore.config.json."
    }

    if ($targetMode -eq 'SameTenant' -and $sourceMetadata -and $sourceMetadata.TenantId -and ($sourceMetadata.TenantId -ne $targetTenantId)) {
        throw "target.mode is SameTenant but target.tenantId [$targetTenantId] does not match source metadata tenant [$($sourceMetadata.TenantId)]"
    }

    if ($targetMode -eq 'AnotherTenant' -and $sourceMetadata -and $sourceMetadata.TenantId -and ($sourceMetadata.TenantId -eq $targetTenantId)) {
        Write-Warning 'target.mode is AnotherTenant but target.tenantId matches the backup source tenant.'
    }

    $allWorkloads = @('EntraID', 'ExchangeOnline', 'Teams', 'SharePoint', 'Intune', 'Compliance', 'Defender', 'PowerPlatform', 'Planner', 'Users')

    function Resolve-WorkloadsFromSwitches {
        param(
            [Parameter()]
            $ScopeObject,

            [Parameter(Mandatory)]
            [string[]]$Allowed
        )

        if (-not $ScopeObject) { return @() }
        if (-not ($ScopeObject.PSObject.Properties.Name -contains 'workloadSwitches')) { return @() }
        if (-not $ScopeObject.workloadSwitches) { return @() }

        $allowedByLower = @{}
        foreach ($w in $Allowed) {
            $allowedByLower[$w.ToLowerInvariant()] = $w
        }

        $selected = [System.Collections.Generic.List[string]]::new()
        foreach ($p in $ScopeObject.workloadSwitches.PSObject.Properties) {
            $nameLower = $p.Name.ToLowerInvariant()
            if (-not $allowedByLower.ContainsKey($nameLower)) { continue }

            $enabled = $false
            try { $enabled = [bool]$p.Value } catch { $enabled = $false }
            if ($enabled) {
                $canonical = $allowedByLower[$nameLower]
                if ($canonical -notin $selected) {
                    $selected.Add($canonical)
                }
            }
        }

        return @($selected)
    }

    function Resolve-ScopedBackupPath {
        param(
            [Parameter(Mandatory)]
            [string]$BasePath,

            [Parameter(Mandatory)]
            [string]$RelativePath,

            [Parameter(Mandatory)]
            [ValidateSet('Leaf', 'Container')]
            [string]$PathType
        )

        if ([string]::IsNullOrWhiteSpace($RelativePath)) {
            throw 'Restore scope path cannot be empty.'
        }

        $normalizedRelativePath = ($RelativePath -replace '\\', '/').Trim()
        if ([System.IO.Path]::IsPathRooted($normalizedRelativePath) -or $normalizedRelativePath.StartsWith('/') -or $normalizedRelativePath.StartsWith('\\')) {
            throw "Restore scope path must be relative to the backup root: $RelativePath"
        }

        $baseFullPath = [System.IO.Path]::GetFullPath($BasePath)
        $candidateFullPath = [System.IO.Path]::GetFullPath((Join-Path -Path $baseFullPath -ChildPath $normalizedRelativePath))
        $basePrefix = if ($baseFullPath.EndsWith([System.IO.Path]::DirectorySeparatorChar) -or $baseFullPath.EndsWith([System.IO.Path]::AltDirectorySeparatorChar)) {
            $baseFullPath
        }
        else {
            $baseFullPath + [System.IO.Path]::DirectorySeparatorChar
        }

        if ($candidateFullPath -ne $baseFullPath -and -not $candidateFullPath.StartsWith($basePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Restore scope path escapes the configured backup root: $RelativePath"
        }

        if (-not (Test-Path -Path $candidateFullPath -PathType $PathType)) {
            throw "Configured restore scope $($PathType.ToLowerInvariant()) was not found: $candidateFullPath"
        }

        return [pscustomobject]@{
            FullPath     = $candidateFullPath
            RelativePath = ([System.IO.Path]::GetRelativePath($baseFullPath, $candidateFullPath) -replace '\\', '/')
        }
    }

    $scopeMode = [string]$config.scope.mode
    if ([string]::IsNullOrWhiteSpace($scopeMode)) {
        $scopeMode = 'Tenant'
    }

    $selectedWorkloads = @()
    switch ($scopeMode) {
        'Tenant' {
            if ($sourceMetadata -and $sourceMetadata.IncludedWorkloads) {
                $selectedWorkloads = @($sourceMetadata.IncludedWorkloads | Where-Object { $_ -in $allWorkloads })
            }
            if (-not $selectedWorkloads -or $selectedWorkloads.Count -eq 0) {
                $selectedWorkloads = @(Get-ChildItem -Path $backupPath -Directory -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Name |
                    Where-Object { $_ -in $allWorkloads })
            }

            $switchSelected = @(Resolve-WorkloadsFromSwitches -ScopeObject $config.scope -Allowed $allWorkloads)
            if ($switchSelected.Count -gt 0) {
                $selectedWorkloads = @($selectedWorkloads | Where-Object { $_ -in $switchSelected })
            }
        }
        'Workload' {
            $switchSelected = @(Resolve-WorkloadsFromSwitches -ScopeObject $config.scope -Allowed $allWorkloads)
            if ($switchSelected.Count -gt 0) {
                $selectedWorkloads = @($switchSelected)
            }
            else {
                $selectedWorkloads = @($config.scope.workloads | Where-Object { $_ -in $allWorkloads })
            }
        }
        'Folder' {
            $folder = [string]$config.scope.relativeFolder
            if ([string]::IsNullOrWhiteSpace($folder)) {
                throw "scope.mode=Folder requires scope.relativeFolder"
            }
            $folderSegments = $folder -split '[\\/]+'
            $selectedWorkloads = @($folderSegments | Where-Object { $_ -in $allWorkloads } | Select-Object -Unique)
            if ($selectedWorkloads.Count -eq 0) {
                throw "Unable to infer workload from scope.relativeFolder [$folder]. Include the workload folder in the path (for example Intune/...)."
            }
        }
        'File' {
            $files = @($config.scope.files)
            if ($files.Count -eq 0) {
                throw "scope.mode=File requires scope.files"
            }
            foreach ($f in $files) {
                $segments = ([string]$f) -split '[\\/]+'
                $selectedWorkloads += @($segments | Where-Object { $_ -in $allWorkloads })
            }
            $selectedWorkloads = @($selectedWorkloads | Select-Object -Unique)
            if ($selectedWorkloads.Count -eq 0) {
                throw "Unable to infer workload from scope.files. Include paths that start with a workload folder."
            }
        }
        'Object' {
            $switchSelected = @(Resolve-WorkloadsFromSwitches -ScopeObject $config.scope -Allowed $allWorkloads)
            if ($switchSelected.Count -gt 0) {
                $selectedWorkloads = @($switchSelected)
            }
            else {
                $selectedWorkloads = @($config.scope.workloads | Where-Object { $_ -in $allWorkloads })
            }
            if ($selectedWorkloads.Count -eq 0) {
                throw "scope.mode=Object requires at least one enabled entry in scope.workloadSwitches or one item in scope.workloads"
            }
        }
        default {
            throw "Unsupported scope.mode [$scopeMode]. Supported values: Tenant, Workload, Folder, File, Object"
        }
    }

    if (-not $selectedWorkloads -or $selectedWorkloads.Count -eq 0) {
        throw "No workloads were resolved for restore"
    }

    $objectNames = @()
    if ($config.scope -and ($config.scope.PSObject.Properties.Name -contains 'objectNames') -and $config.scope.objectNames) {
        $objectNames = @($config.scope.objectNames)
    }

    # Resolve workloadObjectTypes: hashtable of workload -> string[] of enabled object type names.
    # Lookup order per workload:
    #   1. Inline scope.workloadObjectTypes.<Workload> in restore.config.json (if present, wins).
    #   2. External per-workload file at <workloadObjectTypesPath>\<Workload>.json
    #      (default path: <repoRoot>\config\workloadObjectTypes\). Schema is either
    #      a flat { name: bool } map or a wrapped { objectTypes: { name: bool } } object.
    # If a workload is present with no enabled types, it means "none enabled" for that workload.
    $resolvedWorkloadObjectTypes = $null

    # 2a. Resolve external folder
    $wotFolder = $null
    if ($config.scope -and ($config.scope.PSObject.Properties.Name -contains 'workloadObjectTypesPath') `
        -and -not [string]::IsNullOrWhiteSpace([string]$config.scope.workloadObjectTypesPath)) {
        $wotPathCfg = [string]$config.scope.workloadObjectTypesPath
        if ([System.IO.Path]::IsPathRooted($wotPathCfg)) {
            $wotFolder = $wotPathCfg
        }
        else {
            $wotFolder = Join-Path -Path $repoRoot -ChildPath $wotPathCfg
        }
    }
    else {
        $wotFolder = Join-Path -Path $repoRoot -ChildPath 'config/workloadObjectTypes'
    }

    function Get-EnabledTypesFromObject {
        param([Parameter(Mandatory)] $Source)

        $enabledTypes = [System.Collections.Generic.List[string]]::new()
        $iterTarget = $Source
        # Support wrapped { objectTypes: { ... } } schema
        if ($Source.PSObject.Properties.Name -contains 'objectTypes' -and $Source.objectTypes) {
            $iterTarget = $Source.objectTypes
        }
        foreach ($typeProp in $iterTarget.PSObject.Properties) {
            if ($typeProp.Name.StartsWith('_')) { continue }  # skip _comment etc.
            $isEnabled = $false
            try { $isEnabled = [bool]$typeProp.Value } catch { $isEnabled = $false }
            if ($isEnabled) {
                [void]$enabledTypes.Add($typeProp.Name)
            }
        }
        return ,$enabledTypes.ToArray()
    }

    # 2b. Inline block in restore.config.json (wins per workload)
    $inlineWot = $null
    if ($config.scope -and ($config.scope.PSObject.Properties.Name -contains 'workloadObjectTypes') -and $config.scope.workloadObjectTypes) {
        $inlineWot = $config.scope.workloadObjectTypes
    }

    # 2c. Build the merged hashtable
    if ($inlineWot -or (Test-Path -Path $wotFolder)) {
        $resolvedWorkloadObjectTypes = @{}

        # Determine which workloads to consider: union of switches that are on + inline keys
        $candidateWorkloads = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($wl in $selectedWorkloads) { [void]$candidateWorkloads.Add($wl) }
        if ($inlineWot) {
            foreach ($p in $inlineWot.PSObject.Properties) {
                if (-not $p.Name.StartsWith('_')) { [void]$candidateWorkloads.Add($p.Name) }
            }
        }

        foreach ($wlName in $candidateWorkloads) {
            $wlSection = $null
            if ($inlineWot -and ($inlineWot.PSObject.Properties.Name -contains $wlName)) {
                $candidate = $inlineWot.$wlName
                # Treat empty/comment-only inline blocks as "no inline override" so we fall through to file
                if ($candidate) {
                    $hasReal = $false
                    foreach ($p in $candidate.PSObject.Properties) {
                        if (-not $p.Name.StartsWith('_')) { $hasReal = $true; break }
                    }
                    if ($hasReal) { $wlSection = $candidate }
                }
            }

            if (-not $wlSection -and (Test-Path -Path $wotFolder)) {
                $wlFile = Join-Path -Path $wotFolder -ChildPath "$wlName.json"
                if (Test-Path -Path $wlFile) {
                    try {
                        $wlSection = Get-Content -Path $wlFile -Raw | ConvertFrom-Json
                    }
                    catch {
                        Write-Warning "Failed to parse workload object-type file [$wlFile]: $($_.Exception.Message)"
                    }
                }
            }

            if ($wlSection) {
                $resolvedWorkloadObjectTypes[$wlName] = Get-EnabledTypesFromObject -Source $wlSection
            }
        }

        if ($resolvedWorkloadObjectTypes.Count -eq 0) {
            $resolvedWorkloadObjectTypes = $null
        }
    }

    $reportRootCfg = ''
    if ($config.PSObject.Properties.Name -contains 'report' -and $null -ne $config.report -and ($config.report.PSObject.Properties.Name -contains 'outputRoot')) {
        $reportRootCfg = [string]$config.report.outputRoot
    }
    if ([string]::IsNullOrWhiteSpace($reportRootCfg)) {
        throw 'restore.config.json is missing report.outputRoot. Set an explicit output root path for restore reports (for example C:\\backup2904\\Restore).'
    }
    if ([System.IO.Path]::IsPathRooted($reportRootCfg)) {
        $restoreOutputRoot = $reportRootCfg
    }
    else {
        $restoreOutputRoot = Join-Path -Path $repoRoot -ChildPath $reportRootCfg
    }

    # Create folder structure early for precheck reporting
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $targetFolderName = if ([string]::IsNullOrWhiteSpace($targetTenantName)) { $targetTenantId } else { $targetTenantName }
    $restoreRoot = Join-Path -Path $restoreOutputRoot -ChildPath (Join-Path (Join-Path $targetFolderName 'Restore') $timestamp)
    $logFolder = Join-Path -Path $restoreRoot -ChildPath 'Logs'

    $prechecksConfig = $null
    if ($config.PSObject.Properties.Name -contains 'prechecks') {
        $prechecksConfig = $config.prechecks
    }

    $createMissingFolders = $true
    if ($prechecksConfig -and ($prechecksConfig.PSObject.Properties.Name -contains 'createMissingFolders')) {
        $createMissingFolders = [bool]$prechecksConfig.createMissingFolders
    }

    $precheckEnabled = $true
    if ($prechecksConfig -and ($prechecksConfig.PSObject.Properties.Name -contains 'enabled')) {
        $precheckEnabled = [bool]$prechecksConfig.enabled
    }

    $requireAllRequiredModules = $true
    if ($prechecksConfig -and ($prechecksConfig.PSObject.Properties.Name -contains 'requireAllRequiredModules')) {
        $requireAllRequiredModules = [bool]$prechecksConfig.requireAllRequiredModules
    }

    $precheckResult = $null
    $precheckResultInitial = $null
    $precheckWarnings = [System.Collections.Generic.List[string]]::new()
    $moduleInstallActions = [System.Collections.Generic.List[object]]::new()
    $precheckReportPath = Join-Path -Path $logFolder -ChildPath 'restore-precheck-report.html'
    $legacyPrecheckReportPath = Join-Path -Path $logFolder -ChildPath 'precheck-report.html'
    
    if (-not $SkipPrechecks -and $precheckEnabled) {
        if ($createMissingFolders -and -not (Test-Path -Path $restoreOutputRoot)) {
            New-Item -Path $restoreOutputRoot -ItemType Directory -Force | Out-Null
        }
        
        # Create Logs folder for precheck report
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
        
        $precheckResult = Test-M365BackupPrerequisites -OutputPath $restoreOutputRoot -CreateMissingFolders:$false -Config $config -Mode Restore -BackupSourcePath $backupPath
        $precheckResultInitial = $precheckResult
        $missingOptional = @($precheckResult.Modules | Where-Object { -not $_.Required -and -not $_.Installed })
        $missingRequired = @($precheckResult.Modules | Where-Object {       $_.Required -and -not $_.Installed })

        # Honor config.prechecks.installMissingModules as a default for the switch
        $autoInstall = [bool]$InstallMissingModules
        if (-not $autoInstall -and $config -and $config.prechecks -and ($config.prechecks.PSObject.Properties.Name -contains 'installMissingModules')) {
            $autoInstall = [bool]$config.prechecks.installMissingModules
        }

        if ($autoInstall -and (($missingRequired.Count + $missingOptional.Count) -gt 0)) {
            $toInstall = @(($missingRequired + $missingOptional) | Select-Object -ExpandProperty Module -Unique)
            Write-Host "Installing missing PowerShell module(s) ($ModuleScope scope): $($toInstall -join ', ')" -ForegroundColor Cyan

            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                try { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope $ModuleScope | Out-Null } catch { Write-Warning "  NuGet provider bootstrap failed: $($_.Exception.Message)" }
            }
            $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
            if ($psGallery -and $psGallery.InstallationPolicy -ne 'Trusted') {
                try { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted } catch { }
            }

            foreach ($mod in $toInstall) {
                try {
                    Write-Host "  - Install-Module $mod -Scope $ModuleScope" -ForegroundColor DarkGray
                    Install-Module -Name $mod -Scope $ModuleScope -Force -AllowClobber -Repository PSGallery -ErrorAction Stop
                    $moduleInstallActions.Add([pscustomobject]@{ Module = $mod; Success = $true; Error = $null }) | Out-Null
                } catch {
                    Write-Warning "  Failed to install '$mod': $($_.Exception.Message)"
                    $moduleInstallActions.Add([pscustomobject]@{ Module = $mod; Success = $false; Error = $_.Exception.Message }) | Out-Null
                }
            }

            # Re-evaluate after install attempt
            $precheckResult = Test-M365BackupPrerequisites -OutputPath $restoreOutputRoot -CreateMissingFolders:$false -Config $config -Mode Restore -BackupSourcePath $backupPath
            $missingOptional = @($precheckResult.Modules | Where-Object { -not $_.Required -and -not $_.Installed })
            $missingRequired = @($precheckResult.Modules | Where-Object {       $_.Required -and -not $_.Installed })
        }

        foreach ($m in $missingOptional) {
            Write-Warning "Optional module missing: $($m.Module) [Workload: $($m.Workload)] - workload may be skipped."
        }

        # Extract workload list for precheck report
        $reportWorkloads = @()
        if ($config.scope -and $config.scope.workloadSwitches) {
            $reportWorkloads = @($config.scope.workloadSwitches.PSObject.Properties.Name | Where-Object { $config.scope.workloadSwitches.$_ -eq $true })
        }
        if ($reportWorkloads.Count -eq 0) {
            $reportWorkloads = @('EntraID', 'ExchangeOnline', 'Teams', 'SharePoint', 'Intune', 'Compliance', 'Defender', 'PowerPlatform', 'Planner', 'Users')
        }

        # Generate precheck report with install actions and module details
        New-BackupPrecheckReport -ReportPath $precheckReportPath -PrecheckResult $precheckResult -InitialPrecheckResult $precheckResultInitial -Workloads $reportWorkloads -InstallActions $moduleInstallActions.ToArray() -AutoInstallEnabled:$autoInstall -ModuleScope $ModuleScope -Scope 'Restore'
        Copy-Item -Path $precheckReportPath -Destination $legacyPrecheckReportPath -Force -ErrorAction SilentlyContinue

        if (-not $precheckResult.AllRequiredModulesInstalled -and $requireAllRequiredModules) {
            $missing = @($precheckResult.Modules | Where-Object { $_.Required -and -not $_.Installed } | Select-Object -ExpandProperty Module)
            throw "Restore prechecks failed. Missing required modules: $($missing -join ', '). See: $precheckReportPath"
        }
        foreach ($w in @($precheckResult.Warnings)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$w)) {
                [void]$precheckWarnings.Add([string]$w)
                Write-Warning $w
            }
        }
        if (@($precheckResult.Issues).Count -gt 0) {
            $issueList = (@($precheckResult.Issues)) -join "`n  - "
            throw "Restore prechecks failed:`n  - $issueList"
        }
    }
    elseif ($SkipPrechecks) {
        Write-Warning 'Skipping prerequisite checks (-SkipPrechecks).'
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
        $precheckResult = [pscustomobject]@{
            Modules            = @()
            Permissions        = [pscustomobject]@{ Apps = @() }
            Issues             = @()
            Warnings           = @('Prechecks were skipped via -SkipPrechecks.')
            AllChecksPassed    = $true
        }
        New-BackupPrecheckReport -ReportPath $precheckReportPath -PrecheckResult $precheckResult -InitialPrecheckResult $null -Workloads @('Restore') -InstallActions @() -AutoInstallEnabled:$false -ModuleScope $ModuleScope -Scope 'Restore'
        Copy-Item -Path $precheckReportPath -Destination $legacyPrecheckReportPath -Force -ErrorAction SilentlyContinue
    }

    # Ensure Logs folder exists (may have been created by precheck block)
    if (-not (Test-Path -Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    }

    $logPath = if ($NoLog) { $null } else { Join-Path -Path $logFolder -ChildPath 'restore.log.ndjson' }
    $transcriptPath = Join-Path -Path $logFolder -ChildPath 'transcript.log'
    $reportJsonPath = Join-Path -Path $logFolder -ChildPath 'restore-report.json'
    $reportTextPath = Join-Path -Path $logFolder -ChildPath 'restore-report.md'
    $reportHtmlPath = Join-Path -Path $logFolder -ChildPath 'restore-report.html'
    $restorePlanPath = Join-Path -Path $restoreRoot -ChildPath 'restore-plan.json'
    $rollbackManifestPath = Join-Path -Path $restoreRoot -ChildPath 'restore-rollback-manifest.ndjson'
    $resolvedRemapConfig = $null
    if ($config.target -and ($config.target.PSObject.Properties.Name -contains 'remap') -and $config.target.remap) {
        $resolvedRemapConfig = Resolve-BackupRemapConfig -Config $config.target.remap
    }

    # Restore mode is controlled by command switches only.
    $restoreApplyMode = $false

    if ($DryRun -and $ApplyChanges) {
        throw 'Specify either -DryRun or -ApplyChanges, not both.'
    }
    if ($DryRun) {
        $restoreApplyMode = $false
    }
    elseif ($ApplyChanges) {
        $restoreApplyMode = $true
    }

    $warnings = [System.Collections.Generic.List[string]]::new()
    foreach ($w in @($precheckWarnings)) {
        [void]$warnings.Add($w)
    }
    $issues = [System.Collections.Generic.List[string]]::new()
    $restoreStatus = 'Success'
    $connected = $false
    $report = $null
    $importWarnings = @()
    $importVerbose = New-Object System.Collections.Generic.List[string]
    $effectiveImportBackupPath = $backupPath
    $stagedSourcePath = $null
    $compareResults = [System.Collections.Generic.List[object]]::new()
    $compareExportMessages = [System.Collections.Generic.List[object]]::new()
    $compareSummary = [PSCustomObject]@{
            TotalComparisons  = 0
            Different         = 0
            MissingInCurrent  = 0
            ExtraInCurrent    = 0
            ExportFailed      = 0
    }
    $compareSnapshotPath = $null
    $compareReferencePath = $effectiveImportBackupPath
    $compareReportFolder = Join-Path -Path $logFolder -ChildPath 'Compare'
    $compareReportJsonPath = Join-Path -Path $compareReportFolder -ChildPath 'compare-report.json'
    $compareReportHtmlPath = Join-Path -Path $compareReportFolder -ChildPath 'compare-report.html'

        function Convert-CanonicalToPrettyJson {
                param(
                        [Parameter()]
                        [string]$CanonicalJson
                )

                if ([string]::IsNullOrWhiteSpace($CanonicalJson)) {
                        return ''
                }

                try {
                        $obj = $CanonicalJson | ConvertFrom-Json -ErrorAction Stop
                        return ($obj | ConvertTo-Json -Depth 30)
                }
                catch {
                        return [string]$CanonicalJson
                }
        }

        function Get-JsonPreview {
                param(
                        [Parameter()]
                        [string]$Text,

                        [Parameter()]
                        [int]$MaxLength = 220
                )

                if ([string]::IsNullOrWhiteSpace($Text)) {
                        return ''
                }

                $collapsed = ($Text -replace '\s+', ' ').Trim()
                if ($collapsed.Length -le $MaxLength) {
                        return $collapsed
                }

                return ($collapsed.Substring(0, $MaxLength) + ' ...')
        }

    function Get-RestoreToggleHint {
        param(
            [Parameter()]
            [string]$RelativePath
        )

        $normalizedPath = ([string]$RelativePath) -replace '\\', '/'
        $normalizedPath = $normalizedPath.TrimStart('.')
        $normalizedPath = $normalizedPath.TrimStart('/')

        if ([string]::IsNullOrWhiteSpace($normalizedPath)) {
            return [PSCustomObject]@{
                TogglePath = ''
                Supported  = $false
                Note       = 'Unable to infer restore selector for this row.'
            }
        }

        $parts = $normalizedPath -split '/'
        if ($parts.Count -lt 2) {
            return [PSCustomObject]@{
                TogglePath = ''
                Supported  = $false
                Note       = 'This row is not a workload object file; use workload-level selection.'
            }
        }

        $workload = [string]$parts[0]
        $fileName = [System.IO.Path]::GetFileName($normalizedPath)
        if ([string]::IsNullOrWhiteSpace($fileName) -or -not $fileName.EndsWith('.json', [System.StringComparison]::OrdinalIgnoreCase)) {
            return [PSCustomObject]@{
                TogglePath = ''
                Supported  = $false
                Note       = 'This row is not a JSON object export; no object-level toggle is available.'
            }
        }

        $objectType = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
        $togglePath = "scope.workloadObjectTypes.$workload.$objectType"

        $supportedObjectTypes = @{
            Intune = @(
                'CompliancePolicies',
                'ConfigurationProfiles',
                'SettingsCatalogPolicies',
                'UpdateRings',
                'AutopilotProfiles',
                'AssignmentFilters',
                'DeviceManagementComplianceSettings'
            )
        }

        if (-not $supportedObjectTypes.ContainsKey($workload)) {
            return [PSCustomObject]@{
                TogglePath = $togglePath
                Supported  = $false
                Note       = 'Object-level restore is not implemented yet for this workload.'
            }
        }

        if ($objectType -in $supportedObjectTypes[$workload]) {
            return [PSCustomObject]@{
                TogglePath = $togglePath
                Supported  = $true
                Note       = 'Set this key to true to include this item type in apply mode.'
            }
        }

        return [PSCustomObject]@{
            TogglePath = $togglePath
            Supported  = $false
            Note       = 'This Intune item is exported for compare/backup, but apply mapping is not implemented yet.'
        }
    }

        function New-CompareHtmlReport {
                param(
                        [Parameter(Mandatory)]
                        [AllowEmptyCollection()]
                        [object[]]$CompareItems,

                        [Parameter(Mandatory)]
                        [string]$OutputPath,

                        [Parameter(Mandatory)]
                        [string]$ReferencePath,

                        [Parameter(Mandatory)]
                        [string]$CurrentPath,

                        [Parameter(Mandatory)]
                        [object]$Summary
                )

                $rows = @(foreach ($item in $CompareItems) {
                        $backupRaw = [string]$item.BackupCanonical
                        $currentRaw = [string]$item.CurrentCanonical
                        $backupPreview = [System.Net.WebUtility]::HtmlEncode((Get-JsonPreview -Text $backupRaw))
                        $currentPreview = [System.Net.WebUtility]::HtmlEncode((Get-JsonPreview -Text $currentRaw))
                        $pathEncoded = [System.Net.WebUtility]::HtmlEncode([string]$item.Path)
                        $statusEncoded = [System.Net.WebUtility]::HtmlEncode([string]$item.Status)
                        $backupPretty = [System.Net.WebUtility]::HtmlEncode((Convert-CanonicalToPrettyJson -CanonicalJson $backupRaw))
                        $currentPretty = [System.Net.WebUtility]::HtmlEncode((Convert-CanonicalToPrettyJson -CanonicalJson $currentRaw))
                        $toggleHint = Get-RestoreToggleHint -RelativePath ([string]$item.Path)
                        $togglePathEncoded = [System.Net.WebUtility]::HtmlEncode([string]$toggleHint.TogglePath)
                        $toggleNoteEncoded = [System.Net.WebUtility]::HtmlEncode([string]$toggleHint.Note)

                        if ([string]$item.Status -eq 'ExportFailedInDifference') {
                                $togglePathEncoded = ''
                                $toggleNoteEncoded = [System.Net.WebUtility]::HtmlEncode('Skipped: live snapshot could not retrieve this object (permission/license/transient error). Not counted as drift.')
                        }
                        elseif ([string]$item.Status -eq 'MissingInReference') {
                            $togglePathEncoded = ''
                            $toggleNoteEncoded = [System.Net.WebUtility]::HtmlEncode('Informational: object exists only in the current snapshot and not in the backup reference.')
                        }

                        @"
<tr>
    <td><code>$pathEncoded</code></td>
    <td>$statusEncoded</td>
    <td><pre>$backupPreview</pre></td>
    <td><pre>$currentPreview</pre></td>
    <td><code>$togglePathEncoded</code><div class="hint">$toggleNoteEncoded</div></td>
</tr>
<tr>
    <td colspan="5">
        <details>
            <summary>Full values for <code>$pathEncoded</code></summary>
            <div class="full-grid">
                <div>
                    <h4>Backup Value</h4>
                    <pre>$backupPretty</pre>
                </div>
                <div>
                    <h4>Current Tenant Value</h4>
                    <pre>$currentPretty</pre>
                </div>
            </div>
        </details>
    </td>
</tr>
"@
                })

                if (-not $rows -or $rows.Count -eq 0) {
            $rows = @('<tr><td colspan="5">No differences detected for selected scope/workloads.</td></tr>')
                }

                $generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
                $html = @"
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>M365 Restore Compare Report</title>
    <style>
        :root {
            --bg: #f7fafc;
            --surface: #ffffff;
            --line: #d7dee7;
            --text: #1b2530;
            --muted: #5c6f82;
            --accent: #0a6f5a;
            --warn: #9a5a00;
        }
        body { margin: 0; font-family: "Segoe UI", Tahoma, sans-serif; background: linear-gradient(180deg, #f0f5f9 0%, var(--bg) 100%); color: var(--text); }
        .wrap { max-width: 1400px; margin: 0 auto; padding: 24px; }
        h1 { margin: 0 0 12px; }
        .meta { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; margin-bottom: 16px; }
        .meta p { margin: 6px 0; color: var(--muted); }
        .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
        .chip { border: 1px solid var(--line); border-radius: 999px; padding: 6px 10px; background: #f9fcff; }
        table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--line); }
        th, td { border-bottom: 1px solid var(--line); padding: 10px; vertical-align: top; }
        th { text-align: left; background: #edf5f2; }
        pre { margin: 0; white-space: pre-wrap; word-break: break-word; max-height: 240px; overflow: auto; }
        details { padding: 8px; border: 1px solid var(--line); border-radius: 8px; background: #fafcff; }
        .full-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 8px; }
        .full-grid h4 { margin: 0 0 6px; color: var(--accent); }
        .hint { color: var(--muted); margin-top: 6px; font-size: 12px; }
        .note { color: var(--warn); margin-top: 12px; }
        @media (max-width: 900px) { .full-grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="wrap">
        <h1>M365 Restore Compare Report</h1>
        <div class="meta">
            <p><strong>Generated (UTC):</strong> $generatedUtc</p>
            <p><strong>Backup Reference Path:</strong> <code>$([System.Net.WebUtility]::HtmlEncode($ReferencePath))</code></p>
            <p><strong>Current Snapshot Path:</strong> <code>$([System.Net.WebUtility]::HtmlEncode($CurrentPath))</code></p>
            <div class="chips">
                <span class="chip">Total: $($Summary.TotalComparisons)</span>
                <span class="chip">Different: $($Summary.Different)</span>
                <span class="chip">Missing In Current: $($Summary.MissingInCurrent)</span>
                <span class="chip">Extra In Current: $($Summary.ExtraInCurrent)</span>
                <span class="chip">Export Failed (skipped): $($Summary.ExportFailed)</span>
            </div>
            <p class="note">This report is compare-first output. "Export Failed (skipped)" rows are items the live snapshot could not retrieve (permission/license/transient API errors); they are not counted as drift.</p>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Configuration</th>
                    <th>Status</th>
                    <th>Backup (Reference)</th>
                    <th>Current Tenant</th>
                    <th>Restore Toggle (set true)</th>
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

    $transcriptStarted = $false
    if (-not $NoLog) {
        Start-Transcript -Path $transcriptPath -Force | Out-Null
        $transcriptStarted = $true
    }
    try {
        if ($scopeMode -eq 'Folder') {
            $relativeFolder = [string]$config.scope.relativeFolder
            $resolvedFolder = Resolve-ScopedBackupPath -BasePath $backupPath -RelativePath $relativeFolder -PathType Container
            $relativeFolderNormalized = $resolvedFolder.RelativePath
            $sourceFolderPath = $resolvedFolder.FullPath

            $stagedSourcePath = Join-Path -Path $restoreRoot -ChildPath 'StagedSource'
            New-Item -Path $stagedSourcePath -ItemType Directory -Force | Out-Null

            $targetFolderPath = Join-Path -Path $stagedSourcePath -ChildPath $relativeFolderNormalized
            $targetFolderParent = Split-Path -Path $targetFolderPath -Parent
            if (-not (Test-Path -Path $targetFolderParent)) {
                New-Item -Path $targetFolderParent -ItemType Directory -Force | Out-Null
            }

            Copy-Item -Path $sourceFolderPath -Destination $targetFolderPath -Recurse -Force
            $effectiveImportBackupPath = $stagedSourcePath
        }

        if ($scopeMode -eq 'File') {
            $files = @($config.scope.files)
            if ($files.Count -eq 0) {
                throw "scope.mode=File requires scope.files"
            }

            $stagedSourcePath = Join-Path -Path $restoreRoot -ChildPath 'StagedSource'
            New-Item -Path $stagedSourcePath -ItemType Directory -Force | Out-Null

            foreach ($fileRelative in $files) {
                $resolvedFile = Resolve-ScopedBackupPath -BasePath $backupPath -RelativePath ([string]$fileRelative) -PathType Leaf
                $relativePath = $resolvedFile.RelativePath
                $sourceFilePath = $resolvedFile.FullPath

                $targetFilePath = Join-Path -Path $stagedSourcePath -ChildPath $relativePath
                $targetParent = Split-Path -Path $targetFilePath -Parent
                if (-not (Test-Path -Path $targetParent)) {
                    New-Item -Path $targetParent -ItemType Directory -Force | Out-Null
                }

                Copy-Item -Path $sourceFilePath -Destination $targetFilePath -Force
            }

            $effectiveImportBackupPath = $stagedSourcePath
        }

        $authMode = $null
        if ($config.authentication -and ($config.authentication.PSObject.Properties.Name -contains 'mode')) {
            $authMode = [string]$config.authentication.mode
        }
        if ([string]::IsNullOrWhiteSpace($authMode)) {
            $authMode = 'AppCertificate'
        }

        if ($authMode -ne 'AppCertificate') {
            throw "Only authentication.mode='AppCertificate' is supported for Restore-M365TenantConfig"
        }

        $connectParams = @{
            TenantId              = $targetTenantId
            ClientId              = [string]$config.authentication.clientId
            CertificateThumbprint = [string]$config.authentication.certificateThumbprint
            ErrorAction           = 'Stop'
        }

        if ([string]::IsNullOrWhiteSpace($connectParams.ClientId)) {
            throw 'restore.config.json is missing authentication.clientId'
        }
        if ([string]::IsNullOrWhiteSpace($connectParams.CertificateThumbprint)) {
            throw 'restore.config.json is missing authentication.certificateThumbprint'
        }

        # Optional: a separate read-only app for the compare snapshot.
        # If config.compareAuthentication is provided, the compare phase uses it
        # (typically the backup app, which already has Read.All scopes), and the
        # write-capable restore app is used only when the apply phase runs.
        $compareConnectParams = $null
        $compareUsesSeparateAuth = $false
        if ($config.PSObject.Properties.Name -contains 'compareAuthentication' -and $null -ne $config.compareAuthentication) {
            $cmpAuth = $config.compareAuthentication
            $cmpMode = [string]$cmpAuth.mode
            if ([string]::IsNullOrWhiteSpace($cmpMode)) { $cmpMode = 'AppCertificate' }
            if ($cmpMode -ne 'AppCertificate') {
                throw "Only compareAuthentication.mode='AppCertificate' is supported"
            }

            $cmpClientId = [string]$cmpAuth.clientId
            $cmpThumb = [string]$cmpAuth.certificateThumbprint
            if ([string]::IsNullOrWhiteSpace($cmpClientId) -or [string]::IsNullOrWhiteSpace($cmpThumb)) {
                throw 'restore.config.json compareAuthentication is missing clientId or certificateThumbprint'
            }

            if ($cmpClientId -ne $connectParams.ClientId -or $cmpThumb -ne $connectParams.CertificateThumbprint) {
                $compareConnectParams = @{
                    TenantId              = $targetTenantId
                    ClientId              = $cmpClientId
                    CertificateThumbprint = $cmpThumb
                    ErrorAction           = 'Stop'
                }
                $compareUsesSeparateAuth = $true
            }
        }

        Write-BackupLog -Level Information -Message "Restore run mode: $($(if ($restoreApplyMode) { 'Apply' } else { 'DryRun/WhatIf' }))" -LogPath $logPath
        Write-BackupLog -Level Information -Message "Scope mode: $scopeMode" -LogPath $logPath
        Write-BackupLog -Level Information -Message "Resolved workloads: $($selectedWorkloads -join ', ')" -LogPath $logPath
        Write-BackupLog -Level Information -Message "Backup source path: $backupPath" -LogPath $logPath
        Write-BackupLog -Level Information -Message "Effective restore source path: $effectiveImportBackupPath" -LogPath $logPath
        Write-BackupLog -Level Information -Message "Target mode: $targetMode (tenantId=$targetTenantId, tenantName=$targetTenantName)" -LogPath $logPath

        $connectSwitches = @{}
        if ($selectedWorkloads -contains 'ExchangeOnline') { $connectSwitches.ConnectExchange = $true; $connectSwitches.ExchangeOrganization = $targetTenantName }
        if ($selectedWorkloads -contains 'Teams') { $connectSwitches.ConnectTeams = $true }
        if ($selectedWorkloads -contains 'Compliance') { $connectSwitches.ConnectCompliance = $true; $connectSwitches.ExchangeOrganization = $targetTenantName }
        if (($selectedWorkloads -contains 'SharePoint') -and -not [string]::IsNullOrWhiteSpace([string]$config.sharePointAdminUrl)) {
            $connectSwitches.SharePointAdminUrl = [string]$config.sharePointAdminUrl
        }

        $authParams = if ($compareUsesSeparateAuth) { $compareConnectParams } else { $connectParams }
        if ($compareUsesSeparateAuth) {
            Write-BackupLog -Level Information -Message "Compare phase will use separate read-only app (clientId=$($compareConnectParams.ClientId)). Restore app reserved for apply phase." -LogPath $logPath
        }

        # Connect to Microsoft Graph (required — throws if it fails)
        Connect-M365Tenant @authParams
        $connected = $true

        # Try each optional service individually so a single failure does not abort the entire restore.
        # Services that fail to connect are removed from $connectSwitches and $selectedWorkloads.
        if ($connectSwitches.ContainsKey('ConnectExchange')) {
            try {
                Connect-M365Tenant @authParams -ConnectExchange -ExchangeOrganization $targetTenantName
            }
            catch {
                $warnMsg = "Exchange Online connection failed — ExchangeOnline will be excluded from compare/apply: $($_.Exception.Message)"
                Write-Warning $warnMsg
                Write-BackupLog -Level Warning -Message $warnMsg -LogPath $logPath
                [void]$warnings.Add($warnMsg)
                $connectSwitches.Remove('ConnectExchange')
                $selectedWorkloads = @($selectedWorkloads | Where-Object { $_ -ne 'ExchangeOnline' })
            }
        }

        if ($connectSwitches.ContainsKey('ConnectTeams')) {
            try {
                Connect-M365Tenant @authParams -ConnectTeams
            }
            catch {
                $warnMsg = "Teams connection failed — Teams will be excluded from compare/apply: $($_.Exception.Message)"
                Write-Warning $warnMsg
                Write-BackupLog -Level Warning -Message $warnMsg -LogPath $logPath
                [void]$warnings.Add($warnMsg)
                $connectSwitches.Remove('ConnectTeams')
                $selectedWorkloads = @($selectedWorkloads | Where-Object { $_ -ne 'Teams' })
            }
        }

        if ($connectSwitches.ContainsKey('ConnectCompliance')) {
            try {
                Connect-M365Tenant @authParams -ConnectCompliance -ExchangeOrganization $targetTenantName
            }
            catch {
                $warnMsg = "Compliance (IPPS) connection failed — Compliance will be excluded from compare/apply: $($_.Exception.Message)"
                Write-Warning $warnMsg
                Write-BackupLog -Level Warning -Message $warnMsg -LogPath $logPath
                [void]$warnings.Add($warnMsg)
                $connectSwitches.Remove('ConnectCompliance')
                $selectedWorkloads = @($selectedWorkloads | Where-Object { $_ -ne 'Compliance' })
            }
        }

        if ($connectSwitches.ContainsKey('SharePointAdminUrl')) {
            try {
                Connect-M365Tenant @authParams -SharePointAdminUrl $connectSwitches.SharePointAdminUrl
            }
            catch {
                $warnMsg = "SharePoint connection failed — SharePoint will be excluded from compare/apply: $($_.Exception.Message)"
                Write-Warning $warnMsg
                Write-BackupLog -Level Warning -Message $warnMsg -LogPath $logPath
                [void]$warnings.Add($warnMsg)
                $connectSwitches.Remove('SharePointAdminUrl')
                $selectedWorkloads = @($selectedWorkloads | Where-Object { $_ -ne 'SharePoint' })
            }
        }

        $compareAuthParams = if ($compareUsesSeparateAuth) { $compareConnectParams } else { $connectParams }
        $compareExportConfig = [pscustomobject]@{
            tenant = [pscustomobject]@{
                tenantName = $targetTenantName
                tenantId   = $targetTenantId
            }
            authentication = [pscustomobject]@{
                clientId              = [string]$compareAuthParams.ClientId
                certificateThumbprint = [string]$compareAuthParams.CertificateThumbprint
            }
        }
        foreach ($propertyName in @('extendedExports', 'defender', 'intune', 'throttling', 'sensitiveData')) {
            if ($config.PSObject.Properties.Name -contains $propertyName) {
                $compareExportConfig | Add-Member -NotePropertyName $propertyName -NotePropertyValue $config.$propertyName
            }
        }

        New-Item -Path $compareReportFolder -ItemType Directory -Force | Out-Null
        $compareSnapshotRoot = Join-Path -Path $compareReportFolder -ChildPath 'CurrentSnapshot'
        New-Item -Path $compareSnapshotRoot -ItemType Directory -Force | Out-Null

        try {
            $compareReferenceRoot = Join-Path -Path $compareReportFolder -ChildPath 'ReferenceScope'
            New-Item -Path $compareReferenceRoot -ItemType Directory -Force | Out-Null

            foreach ($workload in $selectedWorkloads) {
                $sourceWorkloadPath = Join-Path -Path $effectiveImportBackupPath -ChildPath $workload
                if (-not (Test-Path -Path $sourceWorkloadPath -PathType Container)) {
                    continue
                }

                $targetWorkloadPath = Join-Path -Path $compareReferenceRoot -ChildPath $workload
                Copy-Item -Path $sourceWorkloadPath -Destination $targetWorkloadPath -Recurse -Force
            }

            $compareReferencePath = $compareReferenceRoot

            Write-BackupLog -Level Information -Message "Starting compare-first snapshot export for workloads: $($selectedWorkloads -join ', ')" -LogPath $logPath
            $compareSnapshotPath = Export-M365TenantConfig -TenantName $targetTenantName -TenantId $targetTenantId -Workloads $selectedWorkloads -OutputRoot $compareSnapshotRoot -ConfigObject $compareExportConfig -SkipPrechecks

            $compareBackupLog = Join-Path -Path $compareSnapshotPath -ChildPath 'Logs/backup.log.ndjson'
            if (Test-Path -Path $compareBackupLog -PathType Leaf) {
                foreach ($line in (Get-Content -Path $compareBackupLog -ErrorAction SilentlyContinue)) {
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    try {
                        $entry = $line | ConvertFrom-Json -ErrorAction Stop
                    }
                    catch {
                        continue
                    }

                    if ($entry.Level -in @('Warning', 'Error')) {
                        $message = "Compare export $($entry.Level): $($entry.Message)"
                        [void]$warnings.Add($message)
                        [void]$compareExportMessages.Add([PSCustomObject]@{
                            Timestamp = $entry.Timestamp
                            Level     = $entry.Level
                            Message   = $entry.Message
                        })
                        Write-BackupLog -Level Warning -Message $message -LogPath $logPath
                    }
                }
            }

            $compareItems = @(Compare-M365TenantConfig -ReferencePath $compareReferencePath -DifferencePath $compareSnapshotPath)
            foreach ($item in $compareItems) {
                $compareResults.Add($item)
            }

            $compareSummary = [PSCustomObject]@{
                TotalComparisons = $compareResults.Count
                Different        = @($compareResults | Where-Object { $_.Status -eq 'Different' }).Count
                MissingInCurrent = @($compareResults | Where-Object { $_.Status -eq 'MissingInDifference' }).Count
                ExtraInCurrent   = @($compareResults | Where-Object { $_.Status -eq 'MissingInReference' }).Count
                ExportFailed     = @($compareResults | Where-Object { $_.Status -eq 'ExportFailedInDifference' }).Count
            }

            $comparePayload = [PSCustomObject]@{
                GeneratedUtc        = (Get-Date).ToUniversalTime().ToString('o')
                ReferencePath       = $compareReferencePath
                CurrentSnapshotPath = $compareSnapshotPath
                Summary             = $compareSummary
                ExportMessages      = $compareExportMessages.ToArray()
                Items               = $compareResults.ToArray()
            }

            $comparePayload | ConvertTo-Json -Depth 30 | Set-Content -Path $compareReportJsonPath -Encoding UTF8
            New-CompareHtmlReport -CompareItems $compareResults.ToArray() -OutputPath $compareReportHtmlPath -ReferencePath $compareReferencePath -CurrentPath $compareSnapshotPath -Summary $compareSummary

            Write-BackupLog -Level Information -Message "Compare completed. total=$($compareSummary.TotalComparisons), different=$($compareSummary.Different), missingInCurrent=$($compareSummary.MissingInCurrent), extraInCurrent=$($compareSummary.ExtraInCurrent), exportFailed=$($compareSummary.ExportFailed)" -LogPath $logPath
            Write-BackupLog -Level Information -Message "Compare report (HTML): $compareReportHtmlPath" -LogPath $logPath
        }
        catch {
            $restoreStatus = 'Failed'
            $issues.Add("Compare phase failed: $($_.Exception.Message)")
            Write-BackupLog -Level Error -Message "Compare phase failed: $($_.Exception.Message)" -LogPath $logPath
        }

        try {
            $restorePlan = New-RestorePlanData -BackupPath $effectiveImportBackupPath -Workloads $selectedWorkloads -ObjectNames $objectNames -WorkloadObjectTypes $resolvedWorkloadObjectTypes -TargetMode $targetMode -RemapConfig $resolvedRemapConfig -CurrentSnapshotPath $compareSnapshotPath
            $restorePlan | ConvertTo-Json -Depth 30 | Set-Content -Path $restorePlanPath -Encoding UTF8
            Write-BackupLog -Level Information -Message "Restore plan generated: items=$($restorePlan.Summary.TotalItems), creates=$($restorePlan.Summary.Creates), updates=$($restorePlan.Summary.Updates), unresolvedLinks=$($restorePlan.Summary.ItemsWithUnresolvedLinks)" -LogPath $logPath

            if ($targetMode -eq 'AnotherTenant' -and $restorePlan.Summary.ItemsWithUnresolvedLinks -gt 0) {
                $message = "Restore plan detected $($restorePlan.Summary.ItemsWithUnresolvedLinks) item(s) with unresolved cross-tenant references. Review remap settings or rerun with -Force."
                $warnings.Add($message)
                Write-BackupLog -Level Warning -Message $message -LogPath $logPath
                if ($restoreApplyMode -and -not $Force) {
                    $restoreStatus = 'Failed'
                    $issues.Add($message)
                }
            }
        }
        catch {
            $restoreStatus = 'Failed'
            $issues.Add("Restore plan generation failed: $($_.Exception.Message)")
            Write-BackupLog -Level Error -Message "Restore plan generation failed: $($_.Exception.Message)" -LogPath $logPath
        }

        $importParams = @{
            BackupPath = $effectiveImportBackupPath
            Workloads  = $selectedWorkloads
            OperationLogPath = $rollbackManifestPath
        }
        if ($objectNames.Count -gt 0) {
            $importParams.ObjectNames = $objectNames
        }
        if ($null -ne $resolvedWorkloadObjectTypes) {
            $importParams.WorkloadObjectTypes = $resolvedWorkloadObjectTypes
        }
        if ($null -ne $resolvedRemapConfig) {
            $importParams.RemapConfig = $resolvedRemapConfig
        }
        if (-not $restoreApplyMode) {
            $importParams.WhatIf = $true
        }
        $forceApply = [bool]$Force
        if (-not $forceApply -and ($config.PSObject.Properties.Name -contains 'execution') -and ($config.execution.PSObject.Properties.Name -contains 'force')) {
            $forceApply = [bool]$config.execution.force
        }
        if ($forceApply) {
            $importParams.Confirm = $false
            Write-BackupLog -Level Information -Message 'Force/execution.force=true: confirmation prompts on apply phase will be suppressed.' -LogPath $logPath
        }

        if ($restoreStatus -ne 'Failed') {
            if (-not $restoreApplyMode) {
                Write-BackupLog -Level Information -Message 'DryRun selected. Apply/import phase skipped after compare report generation.' -LogPath $logPath
            }
            elseif (($compareSummary.Different + $compareSummary.MissingInCurrent) -eq 0) {
                Write-BackupLog -Level Information -Message 'No actionable differences detected (export-failed entries excluded). Apply/import phase skipped.' -LogPath $logPath
            }
            else {
                if ($compareUsesSeparateAuth) {
                    try {
                        Write-BackupLog -Level Information -Message "Switching auth context to restore app (clientId=$($connectParams.ClientId)) for apply phase." -LogPath $logPath
                        Disconnect-M365Tenant | Out-Null
                        Connect-M365Tenant @connectParams @connectSwitches
                    }
                    catch {
                        $restoreStatus = 'Failed'
                        $issues.Add("Failed to switch auth to restore app: $($_.Exception.Message)")
                        Write-BackupLog -Level Error -Message "Failed to switch auth to restore app: $($_.Exception.Message)" -LogPath $logPath
                    }
                }

                if ($restoreStatus -ne 'Failed') {
                    try {
                        $importParams.Verbose = $true
                        Import-M365TenantConfig @importParams -WarningVariable importWarnings 4>&1 |
                            ForEach-Object {
                                if ($_ -is [System.Management.Automation.VerboseRecord]) {
                                    [void]$importVerbose.Add([string]$_.Message)
                                }
                                else {
                                    $_
                                }
                            }
                    }
                    catch {
                        $restoreStatus = 'Failed'
                        $issues.Add($_.Exception.Message)
                        Write-BackupLog -Level Error -Message "Restore failed: $($_.Exception.Message)" -LogPath $logPath
                    }
                }
            }
        }

        if ($importWarnings) {
            foreach ($w in @($importWarnings)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$w)) {
                    $warnings.Add([string]$w)
                    Write-BackupLog -Level Warning -Message ([string]$w) -LogPath $logPath
                }
            }
        }

        if ($restoreStatus -eq 'Success' -and $warnings.Count -gt 0) {
            $restoreStatus = 'Partial'
        }
    }
    finally {
        if ($connected) {
            try {
                Disconnect-M365Tenant | Out-Null
            }
            catch {
                $issues.Add("Disconnect warning: $($_.Exception.Message)")
            }
        }

        if ($transcriptStarted) { Stop-Transcript | Out-Null }

        # ----- Build per-object Apply summary by parsing import verbose/warning streams -----
        $applyActions = New-Object System.Collections.Generic.List[object]
        $rxOk = '^\[(?<type>[^\]]+)\]\s+(?<verb>Restored|Created)\s+''(?<name>[^'']+)''\.?\s*$'
        $rxFail = '^\[(?<type>[^\]]+)\]\s+Failed\s+to\s+(?<verb>restore|create|retrieve)\s+''?(?<name>[^'':]+)''?:\s*(?<err>.+)$'
        $rxSkip = '^\[(?<type>[^\]]+)\]\s+(?:Skipping|No match found for|Skipping Microsoft built-in script)\s+''(?<name>[^'']+)''.*$'
        $rxNoItems = '^\[(?<type>[^\]]+)\]\s+No backup items found.*$'
        foreach ($msg in @($importVerbose)) {
            if ($msg -match $rxOk) {
                [void]$applyActions.Add([PSCustomObject]@{ ObjectType = $Matches.type; Name = $Matches.name; Action = $Matches.verb; Status = 'Applied'; Detail = '' })
            }
            elseif ($msg -match $rxSkip) {
                [void]$applyActions.Add([PSCustomObject]@{ ObjectType = $Matches.type; Name = $Matches.name; Action = 'Skip'; Status = 'Skipped'; Detail = $msg })
            }
        }
        foreach ($w in @($importWarnings)) {
            $text = [string]$w
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            if ($text -match $rxFail) {
                [void]$applyActions.Add([PSCustomObject]@{ ObjectType = $Matches.type; Name = $Matches.name; Action = $Matches.verb; Status = 'Failed'; Detail = $Matches.err })
            }
            elseif ($text -match $rxSkip) {
                [void]$applyActions.Add([PSCustomObject]@{ ObjectType = $Matches.type; Name = $Matches.name; Action = 'Skip'; Status = 'Skipped'; Detail = $text })
            }
            elseif ($text -match $rxNoItems) {
                [void]$applyActions.Add([PSCustomObject]@{ ObjectType = $Matches.type; Name = ''; Action = 'NoItems'; Status = 'Skipped'; Detail = $text })
            }
            elseif ($text -match '^\[(?<type>[^\]]+)\]\s+(?<msg>.+)$') {
                [void]$applyActions.Add([PSCustomObject]@{ ObjectType = $Matches.type; Name = ''; Action = 'Warn'; Status = 'Warning'; Detail = $Matches.msg })
            }
        }

        $applyByType = @{}
        foreach ($a in $applyActions) {
            $t = [string]$a.ObjectType
            if (-not $applyByType.ContainsKey($t)) {
                $applyByType[$t] = [PSCustomObject]@{ ObjectType = $t; Applied = 0; Failed = 0; Skipped = 0; Warnings = 0 }
            }
            switch ($a.Status) {
                'Applied' { $applyByType[$t].Applied++ }
                'Failed' { $applyByType[$t].Failed++ }
                'Skipped' { $applyByType[$t].Skipped++ }
                'Warning' { $applyByType[$t].Warnings++ }
            }
        }
        $applySummaryRows = @($applyByType.Values | Sort-Object ObjectType)
        $applySummary = [PSCustomObject]@{
            TotalActions = $applyActions.Count
            AppliedCount = (@($applyActions | Where-Object Status -EQ 'Applied')).Count
            FailedCount  = (@($applyActions | Where-Object Status -EQ 'Failed')).Count
            SkippedCount = (@($applyActions | Where-Object Status -EQ 'Skipped')).Count
            WarningCount = (@($applyActions | Where-Object Status -EQ 'Warning')).Count
            ByObjectType = $applySummaryRows
            Actions      = $applyActions.ToArray()
        }

        $scopeRelativeFolder = ''
        $scopeFiles = @()
        if ($config.scope -and ($config.scope.PSObject.Properties.Name -contains 'relativeFolder')) {
            $scopeRelativeFolder = [string]$config.scope.relativeFolder
        }
        if ($config.scope -and ($config.scope.PSObject.Properties.Name -contains 'files') -and $config.scope.files) {
            $scopeFiles = @($config.scope.files)
        }

        $report = [PSCustomObject]@{
            RestoreTimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
            Status              = $restoreStatus
            AppliedChanges      = [bool]$restoreApplyMode
            Workloads           = @($selectedWorkloads)
            ConfigPath          = $effectiveConfigPath
            SourceBackupPath    = $backupPath
            EffectiveSourcePath = $effectiveImportBackupPath
            ReportPath          = $reportTextPath
            JsonReportPath      = $reportJsonPath
            HtmlReportPath      = $reportHtmlPath
            CompareReportPath   = $compareReportHtmlPath
            SourceTenant        = if ($sourceMetadata) { [PSCustomObject]@{ TenantName = $sourceMetadata.TenantName; TenantId = $sourceMetadata.TenantId } } else { $null }
            Target              = [PSCustomObject]@{ Mode = $targetMode; TenantName = $targetTenantName; TenantId = $targetTenantId }
            Scope               = [PSCustomObject]@{ Mode = $scopeMode; Workloads = $selectedWorkloads; ObjectNames = $objectNames; RelativeFolder = $scopeRelativeFolder; Files = $scopeFiles }
            Precheck            = $precheckResult
            Compare             = [PSCustomObject]@{
                ReferencePath       = $compareReferencePath
                CurrentSnapshotPath = $compareSnapshotPath
                TotalComparisons    = $compareSummary.TotalComparisons
                Different           = $compareSummary.Different
                MissingInCurrent    = $compareSummary.MissingInCurrent
                ExtraInCurrent      = $compareSummary.ExtraInCurrent
                ExportFailed        = $compareSummary.ExportFailed
                ExportMessages      = $compareExportMessages.ToArray()
                JsonReportPath      = $compareReportJsonPath
                HtmlReportPath      = $compareReportHtmlPath
            }
            Warnings            = $warnings.ToArray()
            Issues              = $issues.ToArray()
            Apply               = $applySummary
            Output              = [PSCustomObject]@{ RestoreRoot = $restoreRoot; LogPath = $logPath; TranscriptPath = $transcriptPath; StagedSourcePath = $stagedSourcePath; CompareJsonPath = $compareReportJsonPath; CompareHtmlPath = $compareReportHtmlPath; ReportJsonPath = $reportJsonPath; ReportMarkdownPath = $reportTextPath; ReportHtmlPath = $reportHtmlPath }
        }

        $report | ConvertTo-Json -Depth 12 | Set-Content -Path $reportJsonPath -Encoding UTF8

        $lines = @(
            "# Restore Report",
            "",
            "- Status: $restoreStatus",
            "- AppliedChanges: $restoreApplyMode",
            "- SourceBackupPath: $backupPath",
            "- TargetTenantId: $targetTenantId",
            "- ScopeMode: $scopeMode",
            "- Workloads: $($selectedWorkloads -join ', ')",
            "- CompareTotal: $($compareSummary.TotalComparisons)",
            "- CompareDifferent: $($compareSummary.Different)",
            "- CompareMissingInCurrent: $($compareSummary.MissingInCurrent)",
            "- CompareExtraInCurrent: $($compareSummary.ExtraInCurrent)",
            "- CompareExportFailed: $($compareSummary.ExportFailed)",
            "- ApplyApplied: $($applySummary.AppliedCount)",
            "- ApplyFailed: $($applySummary.FailedCount)",
            "- ApplySkipped: $($applySummary.SkippedCount)",
            "- Warnings: $($warnings.Count)",
            "- Issues: $($issues.Count)",
            "",
            "## Output",
            "",
            "- RestoreRoot: $restoreRoot",
            "- LogPath: $logPath",
            "- TranscriptPath: $transcriptPath",
            "- ReportHtmlPath: $reportHtmlPath",
            "- CompareJsonPath: $compareReportJsonPath",
            "- CompareHtmlPath: $compareReportHtmlPath"
        )

        if ($applySummaryRows.Count -gt 0) {
            $lines += ''
            $lines += '## Apply Results by Object Type'
            $lines += ''
            $lines += '| ObjectType | Applied | Failed | Skipped | Warnings |'
            $lines += '|---|---:|---:|---:|---:|'
            foreach ($row in $applySummaryRows) {
                $lines += "| $($row.ObjectType) | $($row.Applied) | $($row.Failed) | $($row.Skipped) | $($row.Warnings) |"
            }
        }

        if ($applyActions.Count -gt 0) {
            $lines += ''
            $lines += '## Apply Action Detail'
            $lines += ''
            $lines += '| ObjectType | Name | Action | Status | Detail |'
            $lines += '|---|---|---|---|---|'
            foreach ($a in $applyActions) {
                $detail = ([string]$a.Detail) -replace '\|', '\|'
                $lines += "| $($a.ObjectType) | $($a.Name) | $($a.Action) | $($a.Status) | $detail |"
            }
        }

        if ($warnings.Count -gt 0) {
            $lines += ''
            $lines += '## Warning Details'
            $lines += ''
            $lines += ($warnings | ForEach-Object { "- $_" })
        }

        if ($issues.Count -gt 0) {
            $lines += ''
            $lines += '## Issues'
            $lines += ''
            $lines += ($issues | ForEach-Object { "- $_" })
        }

        Set-Content -Path $reportTextPath -Value $lines -Encoding UTF8

        # ----- HTML report -----
        $htmlEnc = { param($s) if ($null -eq $s) { '' } else { [System.Net.WebUtility]::HtmlEncode([string]$s) } }
        $statusClass = switch ($restoreStatus) { 'Success' { 'ok' } 'Partial' { 'warn' } default { 'fail' } }
        $generated = (Get-Date).ToString('u')
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"><title>BackupM365 Restore Report</title>')
        [void]$sb.AppendLine('<style>')
        [void]$sb.AppendLine('body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}')
        [void]$sb.AppendLine('h1{margin:0 0 4px 0}h2{margin-top:28px;border-bottom:1px solid #ddd;padding-bottom:4px}')
        [void]$sb.AppendLine('table{border-collapse:collapse;margin:8px 0;width:100%}th,td{border:1px solid #ddd;padding:6px 10px;text-align:left;vertical-align:top;font-size:13px}')
        [void]$sb.AppendLine('th{background:#f3f3f3}')
        [void]$sb.AppendLine('.kv{display:grid;grid-template-columns:220px 1fr;gap:4px 16px;font-size:14px}')
        [void]$sb.AppendLine('.badge{display:inline-block;padding:2px 10px;border-radius:10px;font-weight:600;font-size:13px}')
        [void]$sb.AppendLine('.ok{background:#d4edda;color:#155724}.warn{background:#fff3cd;color:#856404}.fail{background:#f8d7da;color:#721c24}.muted{color:#666}')
        [void]$sb.AppendLine('td.num{text-align:right;font-variant-numeric:tabular-nums}tr.row-Failed td{background:#fdecec}tr.row-Skipped td{background:#fafafa;color:#555}tr.row-Warning td{background:#fff8e1}')
        [void]$sb.AppendLine('code{background:#f3f3f3;padding:1px 4px;border-radius:3px}')
        [void]$sb.AppendLine('</style></head><body>')
        [void]$sb.AppendLine("<h1>BackupM365 Restore Report</h1>")
        [void]$sb.AppendLine("<div class='muted'>Generated $generated</div>")

        [void]$sb.AppendLine("<h2>Summary</h2>")
        [void]$sb.AppendLine("<div class='kv'>")
        [void]$sb.AppendLine("<div>Status</div><div><span class='badge $statusClass'>$(& $htmlEnc $restoreStatus)</span></div>")
        [void]$sb.AppendLine("<div>Mode</div><div>$(if ($restoreApplyMode) { 'Apply' } else { 'DryRun / WhatIf' })</div>")
        [void]$sb.AppendLine("<div>Source backup</div><div><code>$(& $htmlEnc $backupPath)</code></div>")
        [void]$sb.AppendLine("<div>Target tenant</div><div>$(& $htmlEnc $targetTenantName) (<code>$(& $htmlEnc $targetTenantId)</code>)</div>")
        [void]$sb.AppendLine("<div>Scope mode</div><div>$(& $htmlEnc $scopeMode)</div>")
        [void]$sb.AppendLine("<div>Workloads</div><div>$(& $htmlEnc ($selectedWorkloads -join ', '))</div>")
        [void]$sb.AppendLine("<div>Applied / Failed / Skipped</div><div><span class='badge ok'>$($applySummary.AppliedCount) applied</span> <span class='badge fail'>$($applySummary.FailedCount) failed</span> <span class='badge warn'>$($applySummary.SkippedCount) skipped</span></div>")
        [void]$sb.AppendLine("<div>Compare (total / diff / missing / extra)</div><div>$($compareSummary.TotalComparisons) / $($compareSummary.Different) / $($compareSummary.MissingInCurrent) / $($compareSummary.ExtraInCurrent)</div>")
        [void]$sb.AppendLine("<div>Warnings / Issues</div><div>$($warnings.Count) / $($issues.Count)</div>")
        [void]$sb.AppendLine("</div>")

        [void]$sb.AppendLine("<h2>Apply Results by Object Type</h2>")
        if ($applySummaryRows.Count -eq 0) {
            [void]$sb.AppendLine("<p class='muted'>No apply actions were emitted (DryRun, no differences, or no captured operations).</p>")
        }
        else {
            [void]$sb.AppendLine("<table><thead><tr><th>Object Type</th><th class='num'>Applied</th><th class='num'>Failed</th><th class='num'>Skipped</th><th class='num'>Warnings</th></tr></thead><tbody>")
            foreach ($row in $applySummaryRows) {
                [void]$sb.AppendLine("<tr><td>$(& $htmlEnc $row.ObjectType)</td><td class='num'>$($row.Applied)</td><td class='num'>$($row.Failed)</td><td class='num'>$($row.Skipped)</td><td class='num'>$($row.Warnings)</td></tr>")
            }
            [void]$sb.AppendLine("</tbody></table>")
        }

        if ($applyActions.Count -gt 0) {
            [void]$sb.AppendLine("<h2>Apply Action Detail</h2>")
            [void]$sb.AppendLine("<table><thead><tr><th>Object Type</th><th>Name</th><th>Action</th><th>Status</th><th>Detail</th></tr></thead><tbody>")
            foreach ($a in $applyActions) {
                $cls = "row-$([string]$a.Status)"
                [void]$sb.AppendLine("<tr class='$cls'><td>$(& $htmlEnc $a.ObjectType)</td><td>$(& $htmlEnc $a.Name)</td><td>$(& $htmlEnc $a.Action)</td><td>$(& $htmlEnc $a.Status)</td><td>$(& $htmlEnc $a.Detail)</td></tr>")
            }
            [void]$sb.AppendLine("</tbody></table>")
        }

        [void]$sb.AppendLine("<h2>Compare</h2>")
        [void]$sb.AppendLine("<div class='kv'>")
        [void]$sb.AppendLine("<div>Total comparisons</div><div>$($compareSummary.TotalComparisons)</div>")
        [void]$sb.AppendLine("<div>Different</div><div>$($compareSummary.Different)</div>")
        [void]$sb.AppendLine("<div>Missing in current</div><div>$($compareSummary.MissingInCurrent)</div>")
        [void]$sb.AppendLine("<div>Extra in current</div><div>$($compareSummary.ExtraInCurrent)</div>")
        [void]$sb.AppendLine("<div>Export failed</div><div>$($compareSummary.ExportFailed)</div>")
        if ($compareReportHtmlPath) { [void]$sb.AppendLine("<div>Compare HTML</div><div><code>$(& $htmlEnc $compareReportHtmlPath)</code></div>") }
        [void]$sb.AppendLine("</div>")

        if ($warnings.Count -gt 0) {
            [void]$sb.AppendLine("<h2>Warnings</h2><ul>")
            foreach ($w in $warnings) { [void]$sb.AppendLine("<li>$(& $htmlEnc $w)</li>") }
            [void]$sb.AppendLine("</ul>")
        }
        if ($issues.Count -gt 0) {
            [void]$sb.AppendLine("<h2>Issues</h2><ul>")
            foreach ($i in $issues) { [void]$sb.AppendLine("<li>$(& $htmlEnc $i)</li>") }
            [void]$sb.AppendLine("</ul>")
        }

        $perm = $null
        if ($precheckResult -and ($precheckResult.PSObject.Properties.Name -contains 'Permissions')) {
            $perm = $precheckResult.Permissions
        }
        if ($perm -and $perm.Apps -and @($perm.Apps).Count -gt 0) {
            [void]$sb.AppendLine("<h2>Graph Permission Check</h2>")
            [void]$sb.AppendLine("<table><thead><tr><th>Role</th><th>App</th><th>ClientId</th><th>Missing</th><th>Granted</th><th>Note</th></tr></thead><tbody>")
            foreach ($app in @($perm.Apps)) {
                $missing = if ($app.Missing) { ($app.Missing -join ', ') } else { '' }
                $granted = if ($app.Granted) { ($app.Granted -join ', ') } else { '' }
                $err = if ($app.PSObject.Properties.Name -contains 'Error') { [string]$app.Error } else { '' }
                [void]$sb.AppendLine("<tr><td>$(& $htmlEnc $app.Role)</td><td>$(& $htmlEnc $app.AppDisplayName)</td><td><code>$(& $htmlEnc $app.ClientId)</code></td><td>$(& $htmlEnc $missing)</td><td>$(& $htmlEnc $granted)</td><td>$(& $htmlEnc $err)</td></tr>")
            }
            [void]$sb.AppendLine("</tbody></table>")
        }

        [void]$sb.AppendLine("<h2>Output</h2>")
        [void]$sb.AppendLine("<div class='kv'>")
        [void]$sb.AppendLine("<div>Restore root</div><div><code>$(& $htmlEnc $restoreRoot)</code></div>")
        [void]$sb.AppendLine("<div>Log</div><div><code>$(& $htmlEnc $logPath)</code></div>")
        [void]$sb.AppendLine("<div>Transcript</div><div><code>$(& $htmlEnc $transcriptPath)</code></div>")
        [void]$sb.AppendLine("<div>Report (JSON)</div><div><code>$(& $htmlEnc $reportJsonPath)</code></div>")
        [void]$sb.AppendLine("<div>Report (Markdown)</div><div><code>$(& $htmlEnc $reportTextPath)</code></div>")
        [void]$sb.AppendLine("</div>")

        [void]$sb.AppendLine("</body></html>")
        Set-Content -Path $reportHtmlPath -Value $sb.ToString() -Encoding UTF8

        Write-Host ''
        Write-Host '======================== Restore Summary ========================' -ForegroundColor Cyan
        Write-Host ("Status:         {0}" -f $restoreStatus)
        Write-Host ("Mode:           {0}" -f ($(if ($restoreApplyMode) { 'Apply' } else { 'DryRun/WhatIf' })))
        Write-Host ("Target:         {0} ({1})" -f $targetTenantName, $targetTenantId)
        Write-Host ("Scope:          {0}" -f $scopeMode)
        Write-Host ("Workloads:      {0}" -f ($selectedWorkloads -join ', '))
        Write-Host ("Compare Total:  {0}" -f $compareSummary.TotalComparisons)
        Write-Host ("Compare Diff:   {0}" -f $compareSummary.Different)
        Write-Host ("Compare Miss:   {0}" -f $compareSummary.MissingInCurrent)
        Write-Host ("Compare Extra:  {0}" -f $compareSummary.ExtraInCurrent)
        Write-Host ("Compare Skip:   {0} (export failed in current snapshot)" -f $compareSummary.ExportFailed)
        Write-Host ("Apply Applied:  {0}" -f $applySummary.AppliedCount)
        Write-Host ("Apply Failed:   {0}" -f $applySummary.FailedCount)
        Write-Host ("Apply Skipped:  {0}" -f $applySummary.SkippedCount)
        Write-Host ("Warnings:       {0}" -f $warnings.Count)
        Write-Host ("Issues:         {0}" -f $issues.Count)
        Write-Host '----------------------------------------------------------------' -ForegroundColor Cyan
        Write-Host ("Report (HTML):  {0}" -f $reportHtmlPath)
        Write-Host ("Report (JSON):  {0}" -f $reportJsonPath)
        Write-Host ("Report (Text):  {0}" -f $reportTextPath)
        Write-Host ("Compare (HTML): {0}" -f $compareReportHtmlPath)
        Write-Host ("Log:            {0}" -f $logPath)
        Write-Host ''
    }

    return $report
}
