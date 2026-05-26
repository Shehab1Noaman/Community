function Test-M365BackupPrerequisites {
    <#
    .SYNOPSIS
        Validate prerequisites for Backup/Restore: PowerShell modules, config fields,
        certificate, output writability, backup source folder (restore-only), and Graph
        application permissions (best-effort).

    .DESCRIPTION
        Backward compatible: when called with only -OutputPath / -CreateMissingFolders,
        the legacy module-only result shape (Modules, AllRequiredModulesInstalled,
        OutputPath) is still returned. New checks are additive and only run when
        -Config is provided.

        Per-check toggles map to config.prechecks.*:
          requireValidConfig
          requireValidCertificate
          requireWritableOutput
          requireValidBackupSource    (Restore mode only)
          checkGraphPermissions       (best-effort, warn-only by design)

        All toggles default to $true when their key is absent.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath 'output'),

        [Parameter()]
        [switch]$CreateMissingFolders,

        [Parameter()]
        $Config,

        [Parameter()]
        [ValidateSet('Backup', 'Restore')]
        [string]$Mode = 'Backup',

        [Parameter()]
        [string]$BackupSourcePath
    )

    # ---------------- Modules ----------------
    $requiredModules = @(
        @{ Name = 'Microsoft.Graph.Authentication'; Workload = 'EntraID,Intune,Users,Planner,SharePoint,Teams,Defender' },
        @{ Name = 'ExchangeOnlineManagement'; Workload = 'ExchangeOnline,Compliance' },
        @{ Name = 'MicrosoftTeams'; Workload = 'Teams' },
        @{ Name = 'Microsoft.Online.SharePoint.PowerShell'; Workload = 'SharePoint' },
        @{ Name = 'PnP.PowerShell'; Workload = 'SharePoint' }
    )
    $optionalModules = @(
        @{ Name = 'Microsoft.PowerApps.Administration.PowerShell'; Workload = 'PowerPlatform' }
    )

    $moduleResults = foreach ($entry in $requiredModules) {
        $moduleName = [string]$entry.Name
        $module = Get-Module -ListAvailable -Name $moduleName | Sort-Object Version -Descending | Select-Object -First 1
        [PSCustomObject]@{
            Module    = $moduleName
            Installed = [bool]$module
            Version   = if ($module) { $module.Version.ToString() } else { $null }
            Required  = $true
            Workload  = [string]$entry.Workload
        }
    }
    $optionalResults = foreach ($entry in $optionalModules) {
        $module = Get-Module -ListAvailable -Name $entry.Name | Sort-Object Version -Descending | Select-Object -First 1
        [PSCustomObject]@{
            Module    = $entry.Name
            Installed = [bool]$module
            Version   = if ($module) { $module.Version.ToString() } else { $null }
            Required  = $false
            Workload  = $entry.Workload
        }
    }

    if ($CreateMissingFolders) {
        if (-not (Test-Path -Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }

        # Preserve the legacy no-config contract used by existing callers/tests:
        # a generic output root gets Backups and Logs children. Config-aware calls
        # pass the actual target root (for example ./output/Backups), so do not
        # create nested Backups/Backups or Backups/Logs there.
        if (-not $Config) {
            foreach ($folder in @('Backups', 'Logs')) {
                $target = Join-Path -Path $OutputPath -ChildPath $folder
                if (-not (Test-Path -Path $target)) {
                    New-Item -Path $target -ItemType Directory -Force | Out-Null
                }
            }
        }
    }

    $issues   = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()

    # Legacy call site (no config) returns the original shape with extended fields
    # set to safe defaults so consumers can ignore them.
    if (-not $Config) {
        return [PSCustomObject]@{
            Modules                     = $moduleResults + $optionalResults
            AllRequiredModulesInstalled = ($moduleResults.Installed -notcontains $false)
            OutputPath                  = $OutputPath
            Configuration               = @()
            Certificates                = @()
            Output                      = $null
            Source                      = $null
            Permissions                 = $null
            Issues                      = @($issues)
            Warnings                    = @($warnings)
            AllChecksPassed             = ($moduleResults.Installed -notcontains $false)
        }
    }

    # ---------------- Toggles ----------------
    $pre = $null
    if ($Config.PSObject.Properties.Name -contains 'prechecks') { $pre = $Config.prechecks }
    function Get-PrecheckFlag {
        param($Pre, [string]$Name, [bool]$Default = $true)
        if ($Pre -and ($Pre.PSObject.Properties.Name -contains $Name)) { return [bool]$Pre.$Name }
        return $Default
    }
    $doConfig    = Get-PrecheckFlag $pre 'requireValidConfig'        $true
    $doCert      = Get-PrecheckFlag $pre 'requireValidCertificate'   $true
    $doWritable  = Get-PrecheckFlag $pre 'requireWritableOutput'     $true
    $doSource    = Get-PrecheckFlag $pre 'requireValidBackupSource'  $true
    $doGraphPerm = Get-PrecheckFlag $pre 'checkGraphPermissions'     $true

    # ---------------- Configuration ----------------
    # Backup config exposes tenant under .tenant; restore config exposes it under .target.
    $tenantBlock = $null
    if ($Config.PSObject.Properties.Name -contains 'tenant' -and $Config.tenant) { $tenantBlock = $Config.tenant }
    elseif ($Config.PSObject.Properties.Name -contains 'target' -and $Config.target) { $tenantBlock = $Config.target }

    $configCheckResults = [System.Collections.Generic.List[object]]::new()
    if ($doConfig) {
        $tenant = $tenantBlock
        $authBlocks = @(@{ Name = 'authentication'; Obj = $Config.authentication })
        if ($Mode -eq 'Restore' -and ($Config.PSObject.Properties.Name -contains 'compareAuthentication') -and $Config.compareAuthentication) {
            $authBlocks += @{ Name = 'compareAuthentication'; Obj = $Config.compareAuthentication }
        }

        $tenantId   = if ($tenant) { [string]$tenant.tenantId }   else { '' }
        $tenantName = if ($tenant) { [string]$tenant.tenantName } else { '' }
        $tenantSection = if ($Mode -eq 'Restore' -and -not ($Config.PSObject.Properties.Name -contains 'tenant')) { 'target' } else { 'tenant' }
        $configCheckResults.Add([PSCustomObject]@{ Section=$tenantSection; Field='tenantId';   Present=(-not [string]::IsNullOrWhiteSpace($tenantId));   Detail=$tenantId   }) | Out-Null
        $configCheckResults.Add([PSCustomObject]@{ Section=$tenantSection; Field='tenantName'; Present=(-not [string]::IsNullOrWhiteSpace($tenantName)); Detail=$tenantName }) | Out-Null
        if ([string]::IsNullOrWhiteSpace($tenantId))   { [void]$issues.Add("config.$tenantSection.tenantId is missing.") }
        if ([string]::IsNullOrWhiteSpace($tenantName)) { [void]$warnings.Add("config.$tenantSection.tenantName is empty (folder names will use tenantId).") }

        foreach ($ab in $authBlocks) {
            $name = $ab.Name; $obj = $ab.Obj
            if (-not $obj) {
                [void]$issues.Add("config.$name is missing.")
                $configCheckResults.Add([PSCustomObject]@{ Section=$name; Field='*'; Present=$false; Detail='block missing' }) | Out-Null
                continue
            }
            $clientId = if ($obj.PSObject.Properties.Name -contains 'clientId')              { [string]$obj.clientId }              else { '' }
            $thumb    = if ($obj.PSObject.Properties.Name -contains 'certificateThumbprint') { [string]$obj.certificateThumbprint } else { '' }
            $secret   = if ($obj.PSObject.Properties.Name -contains 'clientSecret')          { [string]$obj.clientSecret }          else { '' }
            $credLabel = if ($thumb) { 'certificateThumbprint' } elseif ($secret) { 'clientSecret' } else { '<none>' }
            $configCheckResults.Add([PSCustomObject]@{ Section=$name; Field='clientId';   Present=(-not [string]::IsNullOrWhiteSpace($clientId)); Detail=$clientId }) | Out-Null
            $configCheckResults.Add([PSCustomObject]@{ Section=$name; Field='credential'; Present=((-not [string]::IsNullOrWhiteSpace($thumb)) -or (-not [string]::IsNullOrWhiteSpace($secret))); Detail=$credLabel }) | Out-Null
            if ([string]::IsNullOrWhiteSpace($clientId)) { [void]$issues.Add("config.$name.clientId is missing.") }
            if ([string]::IsNullOrWhiteSpace($thumb) -and [string]::IsNullOrWhiteSpace($secret)) {
                [void]$issues.Add("config.$name has neither certificateThumbprint nor clientSecret.")
            }
        }
    }

    # ---------------- Certificate ----------------
    $certResults = [System.Collections.Generic.List[object]]::new()
    if ($doCert) {
        $authBlocks = @(@{ Name = 'authentication'; Obj = $Config.authentication })
        if ($Mode -eq 'Restore' -and ($Config.PSObject.Properties.Name -contains 'compareAuthentication') -and $Config.compareAuthentication) {
            $authBlocks += @{ Name = 'compareAuthentication'; Obj = $Config.compareAuthentication }
        }
        foreach ($ab in $authBlocks) {
            $thumb = $null
            if ($ab.Obj -and ($ab.Obj.PSObject.Properties.Name -contains 'certificateThumbprint')) {
                $thumb = [string]$ab.Obj.certificateThumbprint
            }
            if ([string]::IsNullOrWhiteSpace($thumb)) { continue }
            $thumb = $thumb.ToUpperInvariant().Replace(' ', '')

            $found = $null
            foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
                try {
                    $c = Get-ChildItem -Path $store -ErrorAction Stop |
                        Where-Object { $_.Thumbprint.ToUpperInvariant() -eq $thumb } |
                        Select-Object -First 1
                    if ($c) { $found = [PSCustomObject]@{ Cert = $c; Store = $store }; break }
                } catch { }
            }

            if (-not $found) {
                [void]$issues.Add("Certificate thumbprint [$thumb] for config.$($ab.Name) not found in CurrentUser\My or LocalMachine\My.")
                $certResults.Add([PSCustomObject]@{
                    Section=$ab.Name; Thumbprint=$thumb; Found=$false; Store=$null
                    NotBefore=$null; NotAfter=$null; HasPrivateKey=$false; Expired=$null; ExpiringSoon=$null
                }) | Out-Null
                continue
            }

            $cert = $found.Cert
            $now = Get-Date
            $expired      = $cert.NotAfter -lt $now
            $expiringSoon = (-not $expired) -and ($cert.NotAfter -lt $now.AddDays(30))
            $hasKey = $false
            try { $hasKey = [bool]$cert.HasPrivateKey } catch { $hasKey = $false }

            $certResults.Add([PSCustomObject]@{
                Section       = $ab.Name
                Thumbprint    = $thumb
                Found         = $true
                Store         = $found.Store
                NotBefore     = $cert.NotBefore
                NotAfter      = $cert.NotAfter
                HasPrivateKey = $hasKey
                Expired       = $expired
                ExpiringSoon  = $expiringSoon
            }) | Out-Null

            if ($expired)      { [void]$issues.Add("Certificate [$thumb] for config.$($ab.Name) expired on $($cert.NotAfter).") }
            if ($expiringSoon) { [void]$warnings.Add("Certificate [$thumb] for config.$($ab.Name) expires on $($cert.NotAfter) (within 30 days).") }
            if (-not $hasKey)  { [void]$issues.Add("Certificate [$thumb] for config.$($ab.Name) has no accessible private key in $($found.Store).") }
        }
    }

    # ---------------- Output writability ----------------
    $outputCheck = $null
    if ($doWritable) {
        $writable = $false; $outDetail = ''
        try {
            if (-not (Test-Path -Path $OutputPath)) {
                if ($CreateMissingFolders) {
                    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                }
            }
            if (Test-Path -Path $OutputPath) {
                $probe = Join-Path -Path $OutputPath -ChildPath (".precheck-{0}.tmp" -f ([Guid]::NewGuid().ToString('N')))
                'precheck' | Set-Content -LiteralPath $probe -Encoding UTF8 -ErrorAction Stop
                Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
                $writable = $true
            } else {
                $outDetail = 'OutputPath does not exist and createMissingFolders is false.'
            }
        } catch {
            $outDetail = $_.Exception.Message
        }
        $outputCheck = [PSCustomObject]@{ Path = $OutputPath; Writable = $writable; Detail = $outDetail }
        if (-not $writable) { [void]$issues.Add("Output path not writable [$OutputPath]: $outDetail") }
    }

    # ---------------- Backup source (Restore only) ----------------
    $sourceCheck = $null
    if ($Mode -eq 'Restore' -and $doSource) {
        $srcPath = $BackupSourcePath
        if ([string]::IsNullOrWhiteSpace($srcPath) -and ($Config.PSObject.Properties.Name -contains 'source') -and $Config.source) {
            $srcPath = [string]$Config.source.backupPath
        }
        $exists = $false; $hasMeta = $false; $metaPath = $null; $detail = ''
        if (-not [string]::IsNullOrWhiteSpace($srcPath)) {
            $exists = Test-Path -Path $srcPath -PathType Container
            if ($exists) {
                $metaPath = Join-Path -Path $srcPath -ChildPath 'metadata.json'
                $hasMeta  = Test-Path -Path $metaPath -PathType Leaf
                if (-not $hasMeta) { $detail = 'metadata.json missing in backup source.' }
            } else {
                $detail = 'Backup source folder does not exist.'
            }
        } else {
            $detail = 'config.source.backupPath is empty.'
        }
        $sourceCheck = [PSCustomObject]@{ Path=$srcPath; Exists=$exists; HasMetadata=$hasMeta; MetadataPath=$metaPath; Detail=$detail }
        if (-not $exists)       { [void]$issues.Add("Backup source not found [$srcPath]: $detail") }
        elseif (-not $hasMeta)  { [void]$warnings.Add("Backup source missing metadata.json [$srcPath]") }
    }

    # ---------------- Graph permission check (best-effort, warn-only) ----------------
    $permCheck = $null
    if ($doGraphPerm) {
        try {
            $permCheck = Test-M365GraphAppPermissions -Config $Config -Mode $Mode -Warnings $warnings

            if ($permCheck -and $permCheck.PSObject.Properties.Name -contains 'Apps' -and $permCheck.Apps) {
                foreach ($a in @($permCheck.Apps)) {
                    $mc = 0
                    try { $mc = [int]$a.MissingCount } catch { $mc = @($a.Missing).Count }
                    if ($mc -gt 0) {
                        $res = if ($a.PSObject.Properties.Name -contains 'Resource' -and -not [string]::IsNullOrWhiteSpace([string]$a.Resource)) { [string]$a.Resource } else { 'UnknownResource' }
                        $msg = "Permission precheck: app $($a.ClientId) is missing $mc required role(s) on $res."
                        if (-not (@($warnings) -contains $msg)) { [void]$warnings.Add($msg) }
                    }
                }
            }
        } catch {
            [void]$warnings.Add("Graph permission check failed: $($_.Exception.Message)")
        }
    }

    $allChecksPassed = ($moduleResults.Installed -notcontains $false) -and ($issues.Count -eq 0)

    return [PSCustomObject]@{
        Modules                     = $moduleResults + $optionalResults
        AllRequiredModulesInstalled = ($moduleResults.Installed -notcontains $false)
        OutputPath                  = $OutputPath
        Configuration               = @($configCheckResults)
        Certificates                = @($certResults)
        Output                      = $outputCheck
        Source                      = $sourceCheck
        Permissions                 = $permCheck
        Issues                      = @($issues)
        Warnings                    = @($warnings)
        AllChecksPassed             = $allChecksPassed
    }
}

function Test-M365GraphAppPermissions {
    <#
    .SYNOPSIS
        Best-effort check that the configured Graph app(s) have the application roles
        the workloads in scope typically need. Connects to Microsoft Graph using the
        cert from $Config when no compatible Mg context exists. Adds advisory entries
        to $Warnings; never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [ValidateSet('Backup', 'Restore')] [string]$Mode,
        [Parameter()]          $Warnings
    )

    if (-not $Warnings) { $Warnings = [System.Collections.Generic.List[string]]::new() }

    # Required Microsoft Graph application roles per workload.
    # Workloads that don't use Microsoft Graph (Teams via MicrosoftTeams module, Exchange/Compliance
    # via EXO/IPPS PowerShell, Power Platform via its own admin module) are intentionally absent —
    # the precheck silently skips them.
    $readScopes = @{
        EntraID    = @(
            'Directory.Read.All','Policy.Read.All','Application.Read.All',
            'RoleManagement.Read.Directory','AuditLog.Read.All','Group.Read.All',
            'IdentityProvider.Read.All','IdentityRiskyUser.Read.All',
            'EntitlementManagement.Read.All','LifecycleWorkflows.Read.All',
            'Agreement.Read.All','CustomSecAttributeDefinition.Read.All',
            'RoleEligibilitySchedule.Read.Directory','RoleAssignmentSchedule.Read.Directory',
            'IdentityUserFlow.Read.All','APIConnectors.Read.All',
            'CustomAuthenticationExtension.Read.All','VerifiableCredential.Read.All'
        )
        Intune     = @(
            'DeviceManagementConfiguration.Read.All','DeviceManagementApps.Read.All',
            'DeviceManagementManagedDevices.Read.All','DeviceManagementServiceConfig.Read.All',
            'DeviceManagementScripts.Read.All','DeviceManagementRBAC.Read.All',
            'CloudPC.Read.All'
        )
        Users      = @('User.Read.All','Group.Read.All','Directory.Read.All','UserAuthenticationMethod.Read.All')
        Planner    = @('Group.Read.All','Tasks.Read.All')
        SharePoint = @('Sites.FullControl.All')
        Teams      = @(
            'TeamSettings.Read.All','Team.ReadBasic.All','TeamMember.Read.All',
            'Channel.ReadBasic.All','ChannelSettings.Read.All','TeamsTab.Read.All',
            'TeamsAppInstallation.ReadForTeam.All'
        )
        Defender   = @('SecurityEvents.Read.All','ThreatHunting.Read.All','SecurityActions.Read.All','IdentityRiskEvent.Read.All','ThreatSubmission.Read.All')
    }
    $writeScopes = @{
        EntraID    = @('Directory.ReadWrite.All','Policy.ReadWrite.ConditionalAccess','Group.ReadWrite.All','Application.ReadWrite.All')
        Intune     = @(
            'DeviceManagementConfiguration.ReadWrite.All','DeviceManagementApps.ReadWrite.All',
            'DeviceManagementManagedDevices.ReadWrite.All','DeviceManagementServiceConfig.ReadWrite.All',
            'DeviceManagementScripts.ReadWrite.All','DeviceManagementRBAC.ReadWrite.All'
        )
        SharePoint = @('Sites.FullControl.All')
        Planner    = @('Group.ReadWrite.All','Tasks.ReadWrite.All')
        Users      = @('User.ReadWrite.All','Group.ReadWrite.All')
    }
    $resourceReadRoles = @{
        SharePoint = @{
            SharePointOnline = @('Sites.FullControl.All')
        }
    }
    $resourceWriteRoles = @{
        SharePoint = @{
            SharePointOnline = @('Sites.FullControl.All')
        }
    }
    $resourceAppIds = @{
        MicrosoftGraph   = '00000003-0000-0000-c000-000000000000'
        SharePointOnline = '00000003-0000-0ff1-ce00-000000000000'
    }

    function Get-AppGrantedResourceRoles {
        param(
            [string]$ClientId,
            [string]$TenantId,
            [string]$Thumbprint,
            [string]$ResourceAppId
        )
        $result = [PSCustomObject]@{ Roles=@(); Error=$null; Connected=$false; AppDisplayName=$null }
        if ([string]::IsNullOrWhiteSpace($ClientId) -or [string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($Thumbprint)) {
            $result.Error = 'Missing clientId/tenantId/thumbprint.'
            return $result
        }
        if ([string]::IsNullOrWhiteSpace($ResourceAppId)) {
            $result.Error = 'Missing resourceAppId.'
            return $result
        }
        try {
            $ctx = $null
            try { $ctx = Get-MgContext -ErrorAction SilentlyContinue } catch { $ctx = $null }
            $needConnect = $true
            if ($ctx -and $ctx.ClientId -eq $ClientId -and $ctx.TenantId -eq $TenantId) { $needConnect = $false }
            if ($needConnect) {
                Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $Thumbprint -NoWelcome -ErrorAction Stop | Out-Null
            }
            $result.Connected = $true
        } catch {
            $result.Error = "Connect-MgGraph failed: $($_.Exception.Message)"
            return $result
        }
        try {
            $sp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$ClientId')" -ErrorAction Stop
            $result.AppDisplayName = $sp.displayName
            $assignments = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments?`$top=999" -ErrorAction Stop
            $assignList = @($assignments.value)
            $graphSp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$ResourceAppId')?`$select=appRoles" -ErrorAction Stop
            $roleMap = @{}
            foreach ($r in $graphSp.appRoles) { $roleMap[[string]$r.id] = [string]$r.value }
            $roles = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($a in $assignList) {
                if ($roleMap.ContainsKey([string]$a.appRoleId)) { [void]$roles.Add($roleMap[[string]$a.appRoleId]) }
            }
            $result.Roles = @($roles)
        } catch {
            $result.Error = "appRoleAssignments lookup failed (caller may need Application.Read.All): $($_.Exception.Message)"
        }
        return $result
    }

    $tenantId = ''
    if ($Config.PSObject.Properties.Name -contains 'tenant' -and $Config.tenant) {
        $tenantId = [string]$Config.tenant.tenantId
    }
    elseif ($Config.PSObject.Properties.Name -contains 'target' -and $Config.target) {
        $tenantId = [string]$Config.target.tenantId
    }

    # Workloads in scope (union of config.workloads and scope.workloadSwitches).
    $workloads = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    if ($Config.PSObject.Properties.Name -contains 'workloads' -and $Config.workloads) {
        foreach ($w in $Config.workloads) { [void]$workloads.Add([string]$w) }
    }
    if ($Config.PSObject.Properties.Name -contains 'scope' -and $Config.scope -and $Config.scope.workloadSwitches) {
        foreach ($p in $Config.scope.workloadSwitches.PSObject.Properties) {
            if ($p.Name.StartsWith('_')) { continue }
            try { if ([bool]$p.Value) { [void]$workloads.Add($p.Name) } } catch { }
        }
    }

    $checks = [System.Collections.Generic.List[object]]::new()

    # Read app: backup uses authentication; restore uses compareAuthentication when present.
    $readApp = $null
    if ($Config.PSObject.Properties.Name -contains 'authentication') { $readApp = $Config.authentication }
    if ($Mode -eq 'Restore' -and ($Config.PSObject.Properties.Name -contains 'compareAuthentication') -and $Config.compareAuthentication) {
        $readApp = $Config.compareAuthentication
    }
    $readThumb = ''
    if ($readApp -and ($readApp.PSObject.Properties.Name -contains 'certificateThumbprint')) { $readThumb = [string]$readApp.certificateThumbprint }
    $readClientId = ''
    if ($readApp -and ($readApp.PSObject.Properties.Name -contains 'clientId')) { $readClientId = [string]$readApp.clientId }
    if ($readApp -and -not [string]::IsNullOrWhiteSpace($readThumb)) {
        $required = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($w in $workloads) { if ($readScopes.ContainsKey($w)) { foreach ($s in $readScopes[$w]) { [void]$required.Add($s) } } }
        # Allow admins to add/override required Graph scopes via config.precheck.requiredGraphPermissions
        if ($Config.PSObject.Properties.Name -contains 'precheck' -and $Config.precheck `
            -and ($Config.precheck.PSObject.Properties.Name -contains 'requiredGraphPermissions') `
            -and $Config.precheck.requiredGraphPermissions) {
            foreach ($extra in @($Config.precheck.requiredGraphPermissions)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$extra)) { [void]$required.Add([string]$extra) }
            }
        }
        $granted = Get-AppGrantedResourceRoles -ClientId $readClientId -TenantId $tenantId -Thumbprint $readThumb -ResourceAppId $resourceAppIds.MicrosoftGraph
        $missing = @($required | Where-Object { -not ($granted.Roles -contains $_) })
        $checks.Add([PSCustomObject]@{
            Role=if ($Mode -eq 'Restore') { 'CompareApp' } else { 'BackupApp' }
            ClientId=$readClientId; AppDisplayName=$granted.AppDisplayName
            Resource='MicrosoftGraph'
            Granted=@($granted.Roles); Required=@($required); Missing=$missing; MissingCount=@($missing).Count; Error=$granted.Error
        }) | Out-Null
        if ($granted.Error) {
            [void]$Warnings.Add("Graph permission check (read app $readClientId) inconclusive: $($granted.Error)")
        } elseif ($missing.Count -gt 0) {
            [void]$Warnings.Add("Read app $readClientId is missing Graph application roles: $($missing -join ', ')")
        }
        if ($workloads.Contains('SharePoint')) {
            [void]$Warnings.Add('SharePoint app-only backups use PnP.PowerShell. Pure Microsoft.Online.SharePoint.PowerShell Get-SPO* coverage still requires an interactive Connect-SPOService session and will be skipped under app-only auth.')

            $requiredSp = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($w in $workloads) {
                if ($resourceReadRoles.ContainsKey($w)) {
                    foreach ($resName in $resourceReadRoles[$w].Keys) {
                        foreach ($role in @($resourceReadRoles[$w][$resName])) {
                            if ($resName -eq 'SharePointOnline') { [void]$requiredSp.Add($role) }
                        }
                    }
                }
            }
            if ($requiredSp.Count -gt 0) {
                $spGranted = Get-AppGrantedResourceRoles -ClientId $readClientId -TenantId $tenantId -Thumbprint $readThumb -ResourceAppId $resourceAppIds.SharePointOnline
                $spMissing = @($requiredSp | Where-Object { -not ($spGranted.Roles -contains $_) })
                $checks.Add([PSCustomObject]@{
                    Role=if ($Mode -eq 'Restore') { 'CompareApp' } else { 'BackupApp' }
                    ClientId=$readClientId; AppDisplayName=$spGranted.AppDisplayName
                    Resource='SharePointOnline'
                    Granted=@($spGranted.Roles); Required=@($requiredSp); Missing=$spMissing; MissingCount=@($spMissing).Count; Error=$spGranted.Error
                }) | Out-Null
                if ($spGranted.Error) {
                    [void]$Warnings.Add("SharePoint Online permission check (read app $readClientId) inconclusive: $($spGranted.Error)")
                } elseif ($spMissing.Count -gt 0) {
                    [void]$Warnings.Add("Read app $readClientId is missing SharePoint Online application roles: $($spMissing -join ', ')")

                    if (($spGranted.Roles -contains 'Sites.Read.All') -and -not ($spGranted.Roles -contains 'Sites.FullControl.All')) {
                        [void]$Warnings.Add('SharePoint app appears to be read-only (Sites.Read.All without Sites.FullControl.All). Backup can run, but SharePoint coverage will be partial and many tenant/admin exports may fail as unauthorized.')
                    }
                }
            }
        }
        if ($workloads.Contains('Teams')) {
            [void]$Warnings.Add('Teams backups require Microsoft Graph application roles such as TeamSettings.Read.All and ChannelSettings.Read.All. The Teams module also needs the MicrosoftTeams PowerShell module to be installed and importable at runtime.')
        }
    }

    # Write app (Restore only).
    $writeApp = $null
    if ($Mode -eq 'Restore' -and ($Config.PSObject.Properties.Name -contains 'authentication')) { $writeApp = $Config.authentication }
    $writeThumb = ''
    if ($writeApp -and ($writeApp.PSObject.Properties.Name -contains 'certificateThumbprint')) { $writeThumb = [string]$writeApp.certificateThumbprint }
    $writeClientId = ''
    if ($writeApp -and ($writeApp.PSObject.Properties.Name -contains 'clientId')) { $writeClientId = [string]$writeApp.clientId }
    if ($writeApp -and -not [string]::IsNullOrWhiteSpace($writeThumb)) {
        $required = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($w in $workloads) { if ($writeScopes.ContainsKey($w)) { foreach ($s in $writeScopes[$w]) { [void]$required.Add($s) } } }
        if ($required.Count -gt 0) {
            $granted = Get-AppGrantedResourceRoles -ClientId $writeClientId -TenantId $tenantId -Thumbprint $writeThumb -ResourceAppId $resourceAppIds.MicrosoftGraph
            $missing = @($required | Where-Object { -not ($granted.Roles -contains $_) })
            $checks.Add([PSCustomObject]@{
                Role='RestoreApp'; ClientId=$writeClientId; AppDisplayName=$granted.AppDisplayName
                Resource='MicrosoftGraph'
                Granted=@($granted.Roles); Required=@($required); Missing=$missing; MissingCount=@($missing).Count; Error=$granted.Error
            }) | Out-Null
            if ($granted.Error) {
                [void]$Warnings.Add("Graph permission check (write app $writeClientId) inconclusive: $($granted.Error)")
            } elseif ($missing.Count -gt 0) {
                [void]$Warnings.Add("Write app $writeClientId is missing Graph application roles: $($missing -join ', ')")
            }

            if ($workloads.Contains('SharePoint')) {
                $requiredSpWrite = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($w in $workloads) {
                    if ($resourceWriteRoles.ContainsKey($w)) {
                        foreach ($resName in $resourceWriteRoles[$w].Keys) {
                            foreach ($role in @($resourceWriteRoles[$w][$resName])) {
                                if ($resName -eq 'SharePointOnline') { [void]$requiredSpWrite.Add($role) }
                            }
                        }
                    }
                }
                if ($requiredSpWrite.Count -gt 0) {
                    $spGrantedWrite = Get-AppGrantedResourceRoles -ClientId $writeClientId -TenantId $tenantId -Thumbprint $writeThumb -ResourceAppId $resourceAppIds.SharePointOnline
                    $spMissingWrite = @($requiredSpWrite | Where-Object { -not ($spGrantedWrite.Roles -contains $_) })
                    $checks.Add([PSCustomObject]@{
                        Role='RestoreApp'; ClientId=$writeClientId; AppDisplayName=$spGrantedWrite.AppDisplayName
                        Resource='SharePointOnline'
                        Granted=@($spGrantedWrite.Roles); Required=@($requiredSpWrite); Missing=$spMissingWrite; MissingCount=@($spMissingWrite).Count; Error=$spGrantedWrite.Error
                    }) | Out-Null
                    if ($spGrantedWrite.Error) {
                        [void]$Warnings.Add("SharePoint Online permission check (write app $writeClientId) inconclusive: $($spGrantedWrite.Error)")
                    } elseif ($spMissingWrite.Count -gt 0) {
                        [void]$Warnings.Add("Write app $writeClientId is missing SharePoint Online application roles: $($spMissingWrite -join ', ')")
                    }
                }
            }
        }
    }

    foreach ($c in @($checks)) {
        $mc = 0
        try { $mc = [int]$c.MissingCount } catch { $mc = @($c.Missing).Count }
        if ($mc -gt 0) {
            $res = if ($c.PSObject.Properties.Name -contains 'Resource' -and -not [string]::IsNullOrWhiteSpace([string]$c.Resource)) { [string]$c.Resource } else { 'UnknownResource' }
            $msg = "App $($c.ClientId) is missing $mc required role(s) on $res."
            if (-not (@($Warnings) -contains $msg)) { [void]$Warnings.Add($msg) }
        }
    }

    return [PSCustomObject]@{ Apps = @($checks) }
}
