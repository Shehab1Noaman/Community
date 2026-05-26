function Export-M365TenantConfig {
    <#
    .SYNOPSIS
        Runs a full or partial M365 tenant configuration backup.

    .DESCRIPTION
        Orchestrates a complete backup of Microsoft 365 tenant configuration across
        up to 10 workloads: EntraID, ExchangeOnline, Teams, SharePoint, Intune,
        Compliance, Defender, PowerPlatform, Planner, and Users.

        Each workload is exported to a timestamped folder under OutputRoot. A
        metadata.json, integrity-report.json, delta manifest, and catalog index are
        written automatically after every run.

        Use -Connect for a fully automated single-command backup. When -Connect is
        omitted the caller is responsible for having called Connect-M365Tenant first.

    .PARAMETER TenantName
        Tenant name (e.g. contoso.onmicrosoft.com). Overrides config.tenant.tenantName.

    .PARAMETER TenantId
        Tenant ID GUID. Overrides config.tenant.tenantId.

    .PARAMETER Workloads
        Restrict the backup to specific workloads. Valid values: EntraID, ExchangeOnline,
        Teams, SharePoint, Intune, Compliance, Defender, PowerPlatform, Planner, Users.
        When omitted, uses config.workloads (or a built-in default set).

    .PARAMETER Skip
        Exclude specific workloads from the resolved set. Aliases: -SkipWorkload,
        -SkipWorkloads, -Exclude.

    .PARAMETER OutputRoot
        Root path under which timestamped snapshot folders are created.
        Overrides config.outputRoot.

    .PARAMETER ConfigPath
        Path to backup.config.json. Defaults to config/backup.config.json in the
        repository root.

    .PARAMETER ConfigObject
        Supply a pre-parsed config object instead of reading a file. Takes precedence
        over ConfigPath.

    .PARAMETER Connect
        Automatically connect to every workload required by the resolved scope using
        the credentials in the config file before exporting. Omit if you have already
        called Connect-M365Tenant yourself.

    .PARAMETER SkipPrechecks
        Skip the prerequisite validation phase (module and folder checks).

    .PARAMETER InstallMissingModules
        Automatically install any missing required or optional PowerShell modules from
        PSGallery before running. Equivalent to setting prechecks.installMissingModules
        to true in backup.config.json.

    .PARAMETER ModuleScope
        Scope for automatic module installation: CurrentUser (default) or AllUsers.
        Only used when -InstallMissingModules is specified or configured.

    .PARAMETER SkipAutopilotHardwareHash
        Override config.intune.skipAutopilotHardwareHash for this run.

    .OUTPUTS
        String. The absolute path of the created backup snapshot folder.

    .EXAMPLE
        # Fully automated backup (connect + export)
        Export-M365TenantConfig -ConfigPath .\config\backup.config.json -Connect

    .EXAMPLE
        # Backup only EntraID and Intune, verbose output
        Export-M365TenantConfig -ConfigPath .\config\backup.config.json -Connect `
                                -Workloads EntraID, Intune -Verbose

    .EXAMPLE
        # Exclude SharePoint and Teams from the default set
        Export-M365TenantConfig -ConfigPath .\config\backup.config.json -Connect `
                                -Skip SharePoint, Teams

    .EXAMPLE
        # Auto-install missing modules then backup
        Export-M365TenantConfig -ConfigPath .\config\backup.config.json -Connect `
                                -InstallMissingModules

    .EXAMPLE
        # Run without writing any log files
        Export-M365TenantConfig -ConfigPath .\config\backup.config.json -Connect -NoLog
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$TenantName,

        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [ValidateSet('EntraID', 'ExchangeOnline', 'Teams', 'SharePoint', 'Intune', 'Compliance', 'Defender', 'PowerPlatform', 'Planner', 'Users')]
        [string[]]$Workloads,

        [Parameter()]
        [Alias('SkipWorkload','SkipWorkloads','Exclude')]
        [ValidateSet('EntraID', 'ExchangeOnline', 'Teams', 'SharePoint', 'Intune', 'Compliance', 'Defender', 'PowerPlatform', 'Planner', 'Users')]
        [string[]]$Skip,

        [Parameter()]
        [string]$OutputRoot,

        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [psobject]$ConfigObject,

        [Parameter()]
        [switch]$Connect,

        [Parameter()]
        [switch]$SkipPrechecks,

        [Parameter()]
        [switch]$InstallMissingModules,

        [Parameter()]
        [ValidateSet('CurrentUser','AllUsers')]
        [string]$ModuleScope = 'CurrentUser',

        [Parameter()]
        [Nullable[bool]]$SkipAutopilotHardwareHash,

        [Parameter()]
        [switch]$NoLog
    )

    $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
    $repoRoot = Split-Path -Path $moduleRoot -Parent
    $config = $null
    $effectiveConfigPath = if ($ConfigPath) { $ConfigPath } else { Join-Path -Path $repoRoot -ChildPath 'config/backup.config.json' }

    # Load config (used for throttling, and as a fallback for tenant/output/workloads).
    # A caller-provided ConfigObject wins and avoids implicit fallback to backup.config.json.
    if ($PSBoundParameters.ContainsKey('ConfigObject') -and $null -ne $ConfigObject) {
        $config = $ConfigObject
        $effectiveConfigPath = '[caller-supplied ConfigObject]'
    }
    elseif (Test-Path -Path $effectiveConfigPath) {
        try {
            $config = Get-Content -Path $effectiveConfigPath -Raw | ConvertFrom-Json
        }
        catch {
            Write-Warning "Failed to parse [$effectiveConfigPath]: $($_.Exception.Message)"
        }
    }

    # Apply config-derived defaults when caller did not pass values
    if ([string]::IsNullOrWhiteSpace($TenantName) -and $config -and $config.tenant) {
        $TenantName = [string]$config.tenant.tenantName
    }
    if ([string]::IsNullOrWhiteSpace($TenantId) -and $config -and $config.tenant) {
        $TenantId = [string]$config.tenant.tenantId
    }
    $resolvedWorkloads = if ($Workloads -and $Workloads.Count -gt 0) {
        @($Workloads)
    }
    elseif ($config -and $config.workloads) {
        @($config.workloads | ForEach-Object { [string]$_ })
    }
    else {
        @('EntraID', 'ExchangeOnline', 'Teams', 'SharePoint', 'Intune')
    }

    # Apply -Skip filter (case-insensitive) after workload resolution
    if ($Skip -and $Skip.Count -gt 0) {
        $skipped = @($resolvedWorkloads | Where-Object { $Skip -contains $_ })
        $resolvedWorkloads = @($resolvedWorkloads | Where-Object { $Skip -notcontains $_ })
        if ($skipped.Count -gt 0) {
            Write-Host "Skipping workload(s) per -Skip: $($skipped -join ', ')" -ForegroundColor DarkYellow
        }
    }
    if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
        if ($config -and -not [string]::IsNullOrWhiteSpace($config.outputRoot)) {
            $configuredRoot = [string]$config.outputRoot
            if ([System.IO.Path]::IsPathRooted($configuredRoot)) {
                $OutputRoot = $configuredRoot
            }
            else {
                # Resolve relative paths against the repo root, not the caller's cwd
                $OutputRoot = Join-Path -Path $repoRoot -ChildPath $configuredRoot
            }
        }
        else {
            $OutputRoot = Join-Path -Path $repoRoot -ChildPath 'output/Backups'
        }
    }

    if ([string]::IsNullOrWhiteSpace($TenantName)) {
        throw "TenantName is required (pass -TenantName or set tenant.tenantName in $effectiveConfigPath)"
    }
    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        throw "TenantId is required (pass -TenantId or set tenant.tenantId in $effectiveConfigPath)"
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backupRoot = Join-Path -Path $OutputRoot -ChildPath (Join-Path (Join-Path $TenantName 'Backup') $timestamp)
    $logFolder = Join-Path -Path $backupRoot -ChildPath 'Logs'
    New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    # Resolve to absolute path so downstream commands cannot reinterpret relative paths.
    $backupRoot = (Resolve-Path -LiteralPath $backupRoot).Path
    $logFolder  = (Resolve-Path -LiteralPath $logFolder).Path

    # Note: New-BackupPrecheckReport and Write-BackupHtmlReport helper functions
    # are now sourced from BackupFeatureHelpers.ps1 for shared use by both Export and Restore.

    # Resolve SkipAutopilotHardwareHash: explicit param wins, otherwise read config.intune.skipAutopilotHardwareHash
    $effectiveSkipAutopilotHash = $false
    if ($PSBoundParameters.ContainsKey('SkipAutopilotHardwareHash')) {
        $effectiveSkipAutopilotHash = [bool]$SkipAutopilotHardwareHash
    }
    elseif ($config -and ($config.PSObject.Properties.Name -contains 'intune') -and $config.intune `
        -and ($config.intune.PSObject.Properties.Name -contains 'skipAutopilotHardwareHash')) {
        $effectiveSkipAutopilotHash = [bool]$config.intune.skipAutopilotHardwareHash
    }

    # Extended (per-object) export flags from config.extendedExports
    $exoPerMailbox = $false; $teamsPerTeam = $false; $spoPerSite = $false; $perObjectMax = 0
    if ($config -and ($config.PSObject.Properties.Name -contains 'extendedExports') -and $config.extendedExports) {
        $ext = $config.extendedExports
        if ($ext.PSObject.Properties.Name -contains 'exchangePerMailbox') { $exoPerMailbox = [bool]$ext.exchangePerMailbox }
        if ($ext.PSObject.Properties.Name -contains 'teamsPerTeam')      { $teamsPerTeam  = [bool]$ext.teamsPerTeam }
        if ($ext.PSObject.Properties.Name -contains 'sharePointPerSite') { $spoPerSite    = [bool]$ext.sharePointPerSite }
        if ($ext.PSObject.Properties.Name -contains 'perObjectMaxItems') { $perObjectMax  = [int]$ext.perObjectMaxItems }
    }

    # Defender for Endpoint securitycenter API toggle
    $mdeEnabled = $false
    if ($config -and ($config.PSObject.Properties.Name -contains 'defender') -and $config.defender `
        -and ($config.defender.PSObject.Properties.Name -contains 'endpointSecurityCenterEnabled')) {
        $mdeEnabled = [bool]$config.defender.endpointSecurityCenterEnabled
    }

    # Exchange per-mailbox skip flags (default: skip both, since they require AIP/IRM and add noise)
    $exoSkipIRM = $true
    $exoSkipSystemMailboxes = $true
    if ($config -and ($config.PSObject.Properties.Name -contains 'exchange') -and $config.exchange) {
        if ($config.exchange.PSObject.Properties.Name -contains 'skipMailboxIRMAccess') {
            $exoSkipIRM = [bool]$config.exchange.skipMailboxIRMAccess
        }
        if ($config.exchange.PSObject.Properties.Name -contains 'skipSystemMailboxes') {
            $exoSkipSystemMailboxes = [bool]$config.exchange.skipSystemMailboxes
        }
    }

    $throttleSettings = Get-DefaultBackupThrottleSettings
    if ($config -and ($config.PSObject.Properties.Name -contains 'throttling') -and $config.throttling) {
        try {
            if ($config.throttling.PSObject.Properties.Name -contains 'maxRetries') {
                $throttleSettings.MaxRetries = [int]$config.throttling.maxRetries
            }
            if ($config.throttling.PSObject.Properties.Name -contains 'baseDelaySeconds') {
                $throttleSettings.BaseDelaySeconds = [int]$config.throttling.baseDelaySeconds
            }
            if ($config.throttling.PSObject.Properties.Name -contains 'maxDelaySeconds') {
                $throttleSettings.MaxDelaySeconds = [int]$config.throttling.maxDelaySeconds
            }
            if ($config.throttling.PSObject.Properties.Name -contains 'jitterRatio') {
                $throttleSettings.JitterRatio = [double]$config.throttling.jitterRatio
            }
        }
        catch {
            Write-Warning "Failed to parse throttling settings from [$effectiveConfigPath]. Using defaults. Error: $($_.Exception.Message)"
        }
    }

    # Clamp settings to safe ranges to avoid runtime failures from bad config values.
    $throttleSettings.MaxRetries = [Math]::Max(0, [Math]::Min($throttleSettings.MaxRetries, 20))
    $throttleSettings.BaseDelaySeconds = [Math]::Max(1, [Math]::Min($throttleSettings.BaseDelaySeconds, 300))
    $throttleSettings.MaxDelaySeconds = [Math]::Max(1, [Math]::Min($throttleSettings.MaxDelaySeconds, 600))
    $throttleSettings.JitterRatio = [Math]::Max(0.0, [Math]::Min($throttleSettings.JitterRatio, 1.0))

    Set-BackupThrottleSettings -Settings $throttleSettings
    Initialize-BackupRetryMetrics

    # Prerequisite checks: verify required/optional modules and output folder.
    # Honors config.prechecks.* (enabled, requireAllRequiredModules, createMissingFolders)
    # and the -SkipPrechecks switch.
    $precheckEnabled = $true
    $requireAllRequiredModules = $true
    $createMissingFolders = $true
    if ($config -and ($config.PSObject.Properties.Name -contains 'prechecks') -and $config.prechecks) {
        if ($config.prechecks.PSObject.Properties.Name -contains 'enabled')                  { $precheckEnabled         = [bool]$config.prechecks.enabled }
        if ($config.prechecks.PSObject.Properties.Name -contains 'requireAllRequiredModules') { $requireAllRequiredModules = [bool]$config.prechecks.requireAllRequiredModules }
        if ($config.prechecks.PSObject.Properties.Name -contains 'createMissingFolders')      { $createMissingFolders     = [bool]$config.prechecks.createMissingFolders }
    }
    $precheckResult = $null
    $precheckResultInitial = $null
    $moduleInstallActions = [System.Collections.Generic.List[object]]::new()
    $precheckReportPath = Join-Path -Path $logFolder -ChildPath 'backup-precheck-report.html'
    $legacyPrecheckReportPath = Join-Path -Path $logFolder -ChildPath 'precheck-report.html'

    if (-not $SkipPrechecks -and $precheckEnabled) {
        if ($createMissingFolders -and -not (Test-Path -Path $OutputRoot)) {
            New-Item -Path $OutputRoot -ItemType Directory -Force | Out-Null
        }
        $precheckResult = Test-M365BackupPrerequisites -OutputPath $OutputRoot -CreateMissingFolders:$createMissingFolders -Config $config -Mode Backup
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
            $precheckResult = Test-M365BackupPrerequisites -OutputPath $OutputRoot -CreateMissingFolders:$createMissingFolders -Config $config -Mode Backup
            $missingOptional = @($precheckResult.Modules | Where-Object { -not $_.Required -and -not $_.Installed })
            $missingRequired = @($precheckResult.Modules | Where-Object {       $_.Required -and -not $_.Installed })
        }

        foreach ($m in $missingOptional) {
            Write-Warning "Optional module missing: $($m.Module) [Workload: $($m.Workload)] - workload may be skipped."
        }

        New-BackupPrecheckReport -ReportPath $precheckReportPath -PrecheckResult $precheckResult -InitialPrecheckResult $precheckResultInitial -Workloads $resolvedWorkloads -InstallActions $moduleInstallActions.ToArray() -AutoInstallEnabled:$autoInstall -ModuleScope $ModuleScope -Scope 'Backup'
        Copy-Item -Path $precheckReportPath -Destination $legacyPrecheckReportPath -Force -ErrorAction SilentlyContinue

        if ($missingRequired.Count -gt 0) {
            $reqList = ($missingRequired | Select-Object -ExpandProperty Module) -join ', '
            if ($requireAllRequiredModules) {
                throw "Backup prechecks failed. Missing required modules: $reqList. Install with: Install-Module $reqList -Scope $ModuleScope -Force  (or rerun with -InstallMissingModules)"
            }
            else {
                Write-Warning "Required modules missing (continuing because prechecks.requireAllRequiredModules = false): $reqList"
            }
        }
        foreach ($w in @($precheckResult.Warnings)) { Write-Warning $w }
        if (@($precheckResult.Issues).Count -gt 0) {
            $issueList = (@($precheckResult.Issues)) -join "`n  - "
            throw "Backup prechecks failed:`n  - $issueList"
        }
    }
    elseif ($SkipPrechecks) {
        Write-Warning 'Skipping prerequisite checks (-SkipPrechecks).'
        $precheckResult = [pscustomobject]@{
            Modules            = @()
            Permissions        = [pscustomobject]@{ Apps = @() }
            Issues             = @()
            Warnings           = @('Prechecks were skipped via -SkipPrechecks.')
            AllChecksPassed    = $true
        }
        New-BackupPrecheckReport -ReportPath $precheckReportPath -PrecheckResult $precheckResult -InitialPrecheckResult $null -Workloads $resolvedWorkloads -InstallActions @() -AutoInstallEnabled:$false -ModuleScope $ModuleScope -Scope 'Backup'
        Copy-Item -Path $precheckReportPath -Destination $legacyPrecheckReportPath -Force -ErrorAction SilentlyContinue
    }

    # Optional: connect to all required workloads up front. Lets a single
    # Export-M365TenantConfig -ConfigPath ... call run end-to-end without
    # the caller needing to dot-source a session-init script.
    if ($Connect.IsPresent) {
        if (-not $config) {
            throw "-Connect requires a valid config file. Provided path was: $effectiveConfigPath"
        }
        $rawConnectResult = Connect-WorkloadsForBackup -Config $config -Workloads $resolvedWorkloads
        # Defensive: connect cmdlets (e.g. Connect-MicrosoftTeams) can leak context objects into
        # the pipeline, and a wrapped string[] return can be captured as a single nested array.
        # Flatten everything and keep only valid string workload names.
        $flattened = New-Object System.Collections.Generic.List[string]
        foreach ($item in @($rawConnectResult)) {
            if ($null -eq $item) { continue }
            if ($item -is [string]) {
                if (-not [string]::IsNullOrWhiteSpace($item)) { [void]$flattened.Add($item) }
            }
            elseif ($item -is [System.Collections.IEnumerable]) {
                foreach ($sub in $item) {
                    if ($sub -is [string] -and -not [string]::IsNullOrWhiteSpace($sub)) {
                        [void]$flattened.Add($sub)
                    }
                }
            }
        }
        $resolvedWorkloads = $flattened.ToArray()
        if (-not $resolvedWorkloads -or $resolvedWorkloads.Count -eq 0) {
            throw 'No workloads were successfully connected. Aborting backup.'
        }
    }

    $logPath = if ($NoLog) { $null } else { Join-Path -Path $logFolder -ChildPath 'backup.log.ndjson' }
    $transcript = Join-Path -Path $logFolder -ChildPath 'transcript.log'

    $transcriptStarted = $false
    if (-not $NoLog) {
        Start-Transcript -Path $transcript -Force | Out-Null
        $transcriptStarted = $true
    }
    $status = 'Success'
    $summary = [System.Collections.Generic.List[object]]::new()

    try {
        Write-BackupLog -Level Information -Message "Throttle settings: maxRetries=$($throttleSettings.MaxRetries), baseDelaySeconds=$($throttleSettings.BaseDelaySeconds), maxDelaySeconds=$($throttleSettings.MaxDelaySeconds), jitterRatio=$($throttleSettings.JitterRatio)" -LogPath $logPath

        foreach ($workload in $resolvedWorkloads) {
            $workloadFolder = Join-Path $backupRoot $workload
            $logSizeBefore = if ($logPath -and (Test-Path $logPath)) { (Get-Item $logPath).Length } else { 0 }
            $wlStatus = 'Success'
            $wlReason = ''

            try {
                switch ($workload) {
                    'EntraID'        { Export-EntraConfig         -OutputPath $workloadFolder -LogPath $logPath }
                    'ExchangeOnline' { Export-ExchangeConfig      -OutputPath $workloadFolder -LogPath $logPath -IncludePerMailbox:$exoPerMailbox -PerObjectMaxItems $perObjectMax -SkipMailboxIRMAccess:$exoSkipIRM -SkipSystemMailboxes:$exoSkipSystemMailboxes }
                    'Teams'          { Export-TeamsConfig         -OutputPath $workloadFolder -LogPath $logPath -IncludePerTeam:$teamsPerTeam -PerObjectMaxItems $perObjectMax }
                    'SharePoint'     { Export-SharePointConfig    -OutputPath $workloadFolder -LogPath $logPath -IncludePerSite:$spoPerSite -PerObjectMaxItems $perObjectMax }
                    'Intune'         { Export-IntuneConfig        -OutputPath $workloadFolder -LogPath $logPath -SkipAutopilotHardwareHash:$effectiveSkipAutopilotHash }
                    'Compliance'     { Export-ComplianceConfig    -OutputPath $workloadFolder -LogPath $logPath }
                    'Defender'       { Export-DefenderConfig      -OutputPath $workloadFolder -LogPath $logPath -IncludeEndpointSecurityCenter:$mdeEnabled -TenantId $TenantId -ClientId ([string]$config.authentication.clientId) -CertificateThumbprint ([string]$config.authentication.certificateThumbprint) }
                    'PowerPlatform'  { Export-PowerPlatformConfig -OutputPath $workloadFolder -LogPath $logPath }
                    'Planner'        { Export-PlannerConfig       -OutputPath $workloadFolder -LogPath $logPath -PerObjectMaxItems $perObjectMax }
                    'Users'          { Export-UsersConfig         -OutputPath $workloadFolder -LogPath $logPath -PerObjectMaxItems $perObjectMax }
                    default {
                        New-Item -Path $workloadFolder -ItemType Directory -Force | Out-Null
                        Write-BackupLog -Level Warning -Message "Workload [$workload] export scaffold created; detailed exporter not implemented yet." -LogPath $logPath
                        $wlStatus = 'Skipped'
                        $wlReason = 'Exporter not implemented'
                    }
                }
            }
            catch {
                $wlStatus = 'Failed'
                $wlReason = $_.Exception.Message
                Write-BackupLog -Level Error -Message "[$workload] aborted: $($_.Exception.Message)" -LogPath $logPath
            }

            # Tally artifacts and per-workload log entries
            $fileCount = 0
            if (Test-Path $workloadFolder) {
                $fileCount = @(Get-ChildItem -Path $workloadFolder -Recurse -File -ErrorAction SilentlyContinue).Count
            }

            $warnings = 0; $errors = 0; $firstError = ''
            $warningMessages = [System.Collections.Generic.List[string]]::new()
            if ($logPath -and (Test-Path $logPath) -and ((Get-Item $logPath).Length -gt $logSizeBefore)) {
                $stream = $null
                $reader = $null
                try {
                    $stream = [System.IO.File]::Open($logPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    $null = $stream.Seek($logSizeBefore, [System.IO.SeekOrigin]::Begin)
                    $reader = [System.IO.StreamReader]::new($stream)
                    while (-not $reader.EndOfStream) {
                        $line = $reader.ReadLine()
                        if ([string]::IsNullOrWhiteSpace($line)) { continue }
                        try {
                            $obj = $line | ConvertFrom-Json -ErrorAction Stop
                            if ($obj.Level -eq 'Warning') {
                                $warnings++
                                $warningMessages.Add([string]$obj.Message)
                            }
                            elseif ($obj.Level -eq 'Error') {
                                $errors++
                                if (-not $firstError) { $firstError = $obj.Message }
                            }
                        } catch { }
                    }
                } catch { }
                finally {
                    if ($reader) { try { $reader.Dispose() } catch { } }
                    if ($stream) { try { $stream.Dispose() } catch { } }
                }
            }

            if ($wlStatus -eq 'Success') {
                if ($fileCount -eq 0) {
                    $wlStatus = 'Empty'
                    if (-not $wlReason) { $wlReason = if ($firstError) { $firstError } else { 'No items exported (see log)' } }
                }
                elseif ($errors -gt 0) {
                    $wlStatus = 'Partial'
                    if (-not $wlReason) { $wlReason = $firstError }
                }
            }

            $summary.Add([PSCustomObject]@{
                Workload        = $workload
                Status          = $wlStatus
                Files           = $fileCount
                Warnings        = $warnings
                Errors          = $errors
                Reason          = $wlReason
                WarningMessages = $warningMessages.ToArray()
            })
        }
    }
    catch {
        $status = 'Failed'
        Write-BackupLog -Level Error -Message "Backup execution failed: $($_.Exception.Message)" -LogPath $logPath
        throw
    }
    finally {
        $metrics = Get-BackupRetryMetrics
        Write-BackupLog -Level Information -Message "Throttle summary: totalOperations=$($metrics.TotalOperations), retryAttempts=$($metrics.RetryAttempts), throttledResponses=$($metrics.ThrottledResponses), totalBackoffSeconds=$($metrics.TotalBackoffSeconds)" -LogPath $logPath

        # Clear PnP credential env vars so they don't linger in the process after the export.
        Remove-Item -Path 'Env:_BM365_PNP_TENANTID'   -ErrorAction SilentlyContinue
        Remove-Item -Path 'Env:_BM365_PNP_CLIENTID'   -ErrorAction SilentlyContinue
        Remove-Item -Path 'Env:_BM365_PNP_THUMBPRINT' -ErrorAction SilentlyContinue

        if ($summary.Count -gt 0 -and ($summary | Where-Object { $_.Status -ne 'Success' })) {
            $status = 'Partial'
        }

        $sensitiveDataMode = 'Audit'
        if ($config -and ($config.PSObject.Properties.Name -contains 'sensitiveData') -and $config.sensitiveData `
            -and ($config.sensitiveData.PSObject.Properties.Name -contains 'mode') -and -not [string]::IsNullOrWhiteSpace([string]$config.sensitiveData.mode)) {
            $sensitiveDataMode = [string]$config.sensitiveData.mode
        }

        $sensitiveDataReport = Invoke-BackupSensitiveDataProcessing -BackupPath $backupRoot -Mode $sensitiveDataMode
        $sensitiveReportPath = Join-Path -Path $backupRoot -ChildPath 'sensitive-data-report.json'
        ConvertTo-SafeJson -InputObject $sensitiveDataReport -Depth 20 | Set-Content -Path $sensitiveReportPath -Encoding UTF8

        $integrityReport = Get-BackupIntegrityReport -BackupPath $backupRoot -Summary $summary.ToArray() -LogPath $logPath
        $integrityPath = Join-Path -Path $backupRoot -ChildPath 'integrity-report.json'
        ConvertTo-SafeJson -InputObject $integrityReport -Depth 20 | Set-Content -Path $integrityPath -Encoding UTF8
        $integrityHtmlPath = Join-Path -Path $logFolder -ChildPath 'integrity-report.html'
        Write-BackupHtmlReport -ReportPath $integrityHtmlPath -Title 'Backup Integrity Report' -Data $integrityReport -SummaryLines @(
            "BackupPath: $backupRoot",
            "Score: $($integrityReport.Score)",
            "Status: $status"
        )

        $catalogEntries = @(Get-BackupCatalogEntries -RootPath $OutputRoot -TenantName $TenantName -Workloads $resolvedWorkloads |
            Where-Object { $_.SnapshotName -eq $timestamp })
        $catalogPath = Join-Path -Path $backupRoot -ChildPath 'catalog-index.json'
        $catalogPayload = [pscustomobject]@{
            GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
            BackupPath   = $backupRoot
            Entries      = $catalogEntries
        }
        ConvertTo-SafeJson -InputObject $catalogPayload -Depth 20 | Set-Content -Path $catalogPath -Encoding UTF8
        $catalogHtmlPath = Join-Path -Path $logFolder -ChildPath 'catalog-index.html'
        Write-BackupHtmlReport -ReportPath $catalogHtmlPath -Title 'Backup Catalog Index' -Data $catalogPayload -SummaryLines @(
            "BackupPath: $backupRoot",
            "EntryCount: $(@($catalogEntries).Count)",
            "GeneratedUtc: $($catalogPayload.GeneratedUtc)"
        )

        $previousSnapshot = Find-PreviousBackupSnapshot -BackupRoot $backupRoot
        $deltaPath = Join-Path -Path $backupRoot -ChildPath 'delta.manifest.json'
        $hasDeltaManifest = $false
        if (-not [string]::IsNullOrWhiteSpace($previousSnapshot)) {
            try {
                New-M365BackupDelta -ReferencePath $previousSnapshot -DifferencePath $backupRoot -Workloads $resolvedWorkloads -OutputPath $deltaPath | Out-Null
                $hasDeltaManifest = $true
                Write-BackupLog -Level Information -Message "Delta manifest generated from previous snapshot [$previousSnapshot]." -LogPath $logPath
            }
            catch {
                Write-BackupLog -Level Warning -Message "Delta manifest generation failed: $($_.Exception.Message)" -LogPath $logPath
            }
        }

        Save-BackupMetadata -Path (Join-Path $backupRoot 'metadata.json') -TenantName $TenantName -TenantId $TenantId -Workloads $resolvedWorkloads -Status $status -AdditionalProperties @{
            IntegrityScore     = $integrityReport.Score
            SensitiveDataMode  = $sensitiveDataMode
            SensitiveHits      = if ($sensitiveDataReport.PSObject.Properties.Name -contains 'HitCount') { $sensitiveDataReport.HitCount } else { 0 }
            PreviousSnapshot   = $previousSnapshot
            DeltaManifestPath  = if ($hasDeltaManifest) { $deltaPath } else { $null }
            CatalogIndexPath   = $catalogPath
            IntegrityReportPath = $integrityPath
            PrecheckReportPath = $precheckReportPath
        }

        $metadataPath = Join-Path -Path $backupRoot -ChildPath 'metadata.json'
        if (Test-Path -Path $metadataPath) {
            try {
                $metaObj = Get-Content -Path $metadataPath -Raw | ConvertFrom-Json
                $metadataHtmlPath = Join-Path -Path $logFolder -ChildPath 'metadata-report.html'
                Write-BackupHtmlReport -ReportPath $metadataHtmlPath -Title 'Backup Metadata Report' -Data $metaObj -SummaryLines @(
                    "TenantName: $TenantName",
                    "TenantId: $TenantId",
                    "Status: $status",
                    "Workloads: $([string]::Join(', ', @($resolvedWorkloads)))"
                )
            }
            catch {
                Write-Warning "Failed to generate metadata-report.html: $($_.Exception.Message)"
            }
        }

        $sensitiveHtmlPath = Join-Path -Path $logFolder -ChildPath 'sensitive-data-report.html'
        Write-BackupHtmlReport -ReportPath $sensitiveHtmlPath -Title 'Sensitive Data Report' -Data $sensitiveDataReport -SummaryLines @(
            "BackupPath: $backupRoot",
            "Mode: $sensitiveDataMode",
            "HitCount: $(if ($sensitiveDataReport.PSObject.Properties.Name -contains 'HitCount') { $sensitiveDataReport.HitCount } else { 0 })"
        )

        if ($hasDeltaManifest -and (Test-Path -Path $deltaPath)) {
            try {
                $deltaObj = Get-Content -Path $deltaPath -Raw | ConvertFrom-Json
                $deltaHtmlPath = Join-Path -Path $logFolder -ChildPath 'delta-manifest.html'
                Write-BackupHtmlReport -ReportPath $deltaHtmlPath -Title 'Delta Manifest Report' -Data $deltaObj -SummaryLines @(
                    "ReferenceSnapshot: $previousSnapshot",
                    "DifferenceSnapshot: $backupRoot"
                )
            }
            catch {
                Write-Warning "Failed to generate delta-manifest.html: $($_.Exception.Message)"
            }
        }
        if ($transcriptStarted) { Stop-Transcript | Out-Null }

        if ($summary.Count -gt 0) {
            Write-Host ''
            Write-Host '======================== Backup Summary ========================' -ForegroundColor Cyan
            foreach ($row in $summary) {
                $color = switch ($row.Status) {
                    'Success' { 'Green' }
                    'Partial' { 'Yellow' }
                    'Empty'   { 'Yellow' }
                    'Skipped' { 'DarkGray' }
                    default   { 'Red' }
                }
                $line = "{0,-15} {1,-8} files={2,-5} warn={3,-3} err={4,-3}" -f $row.Workload, $row.Status, $row.Files, $row.Warnings, $row.Errors
                if ($row.Reason) { $line += "  reason: $($row.Reason)" }
                Write-Host $line -ForegroundColor $color

                if ($row.WarningMessages -and $row.WarningMessages.Count -gt 0) {
                    $shown = $row.WarningMessages | Select-Object -First 5
                    foreach ($w in $shown) {
                        Write-Host "    warn> $w" -ForegroundColor DarkYellow
                    }
                    if ($row.WarningMessages.Count -gt 5) {
                        Write-Host "    ... and $($row.WarningMessages.Count - 5) more (see log)" -ForegroundColor DarkYellow
                    }
                }
            }
            Write-Host '================================================================' -ForegroundColor Cyan
            Write-Host "Output: $backupRoot"
            Write-Host "Log:    $logPath"
            Write-Host ''
        }
    }

    return $backupRoot
}
