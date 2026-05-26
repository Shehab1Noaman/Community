function Export-SharePointConfig {
    <#
    .SYNOPSIS
        Exports SharePoint Online tenant configuration and optionally per-site settings.

    .DESCRIPTION
        Exports SharePoint Online tenant-level settings using the Microsoft.Online.SharePoint
        .PowerShell module (SPO cmdlets) or PnP.PowerShell as a fallback. Covers tenant
        settings, site collections, CDN, hub sites, and more.

        When -IncludePerSite is specified, per-site details are exported for every site
        collection using PnP app-only certificate authentication. Credentials are read
        from the _BM365_PNP_* environment variables set by Connect-WorkloadsForBackup.

        Requires an active SharePoint Online session (Connect-M365Tenant -SharePointAdminUrl).

    .PARAMETER OutputPath
        Directory where exported JSON files are written.
        Created automatically if it does not exist.

    .PARAMETER LogPath
        Optional. Path to the NDJSON backup log file for structured log entries.

    .PARAMETER IncludePerSite
        When set, exports per-site settings for every site collection.
        Requires PnP.PowerShell and can be slow on tenants with many sites.

    .PARAMETER PerObjectMaxItems
        Maximum number of sites to process during per-site export. 0 means unlimited.

    .EXAMPLE
        Export-SharePointConfig -OutputPath C:\backup\SharePoint

    .EXAMPLE
        Export-SharePointConfig -OutputPath C:\backup\SharePoint -IncludePerSite
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [string]$LogPath,

        [Parameter()]
        [switch]$IncludePerSite,

        [Parameter()]
        [int]$PerObjectMaxItems = 0
    )

    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

    function Export-SpoItem {
        param(
            [string]$Name,
            [scriptblock]$Action,
            [string[]]$RequiredCommands,
            [string]$SkipReason
        )
        try {
            if ($RequiredCommands) {
                $available = @($RequiredCommands | Where-Object { Get-Command -Name $_ -ErrorAction SilentlyContinue })
                if ($available.Count -eq 0) {
                    $detail = if ($SkipReason) { $SkipReason } else { "none of the required cmdlets are available: $($RequiredCommands -join ', ')" }
                    Write-BackupLog -Level Information -Message "Skipped SharePoint object [$Name] ($detail)" -LogPath $LogPath
                    return
                }
            }

            $result = Invoke-WithThrottleRetry -OperationName "SharePoint $Name" -LogPath $LogPath -ScriptBlock $Action
            if ($null -eq $result) {
                $detail = if ($SkipReason) { $SkipReason } else { 'no supported cmdlet path was available' }
                Write-BackupLog -Level Information -Message "Skipped SharePoint object [$Name] ($detail)" -LogPath $LogPath
                return
            }

            ConvertTo-SafeJson -InputObject @($result) -Depth 20 |
                Set-Content -Path (Join-Path $OutputPath "$Name.json") -Encoding UTF8
            Write-BackupLog -Level Information -Message "Exported SharePoint object: $Name" -LogPath $LogPath
        }
        catch {
            Write-BackupLog -Level Warning -Message "Failed to export SharePoint object [$Name]: $($_.Exception.Message)" -LogPath $LogPath
        }
    }

    # Tenant settings
    Export-SpoItem -Name 'TenantSettings' -RequiredCommands @('Get-SPOTenant', 'Get-PnPTenant') -Action {
        if (Get-Command -Name Get-SPOTenant -ErrorAction SilentlyContinue) { Get-SPOTenant }
        elseif (Get-Command -Name Get-PnPTenant -ErrorAction SilentlyContinue) { Get-PnPTenant }
    }

    # Sites
    Export-SpoItem -Name 'Sites' -RequiredCommands @('Get-SPOSite', 'Get-PnPTenantSite') -Action {
        if (Get-Command -Name Get-SPOSite -ErrorAction SilentlyContinue) { Get-SPOSite -Limit All }
        elseif (Get-Command -Name Get-PnPTenantSite -ErrorAction SilentlyContinue) { Get-PnPTenantSite }
    }

    # SPO-only items
    Export-SpoItem -Name 'GeoLocations'           -RequiredCommands @('Get-SPOGeoStorageQuota') -SkipReason 'requires Microsoft.Online.SharePoint.PowerShell with an interactive Connect-SPOService session' -Action { Get-SPOGeoStorageQuota }
    Export-SpoItem -Name 'OrgAssetsLibraries'     -RequiredCommands @('Get-SPOOrgAssetsLibrary') -SkipReason 'requires Microsoft.Online.SharePoint.PowerShell with an interactive Connect-SPOService session' -Action { Get-SPOOrgAssetsLibrary }
    Export-SpoItem -Name 'OrgNewsSite'            -RequiredCommands @('Get-SPOOrgNewsSite') -SkipReason 'requires Microsoft.Online.SharePoint.PowerShell with an interactive Connect-SPOService session' -Action { Get-SPOOrgNewsSite }
    Export-SpoItem -Name 'HomeSite'               -RequiredCommands @('Get-SPOHomeSite') -SkipReason 'requires Microsoft.Online.SharePoint.PowerShell with an interactive Connect-SPOService session' -Action { Get-SPOHomeSite }
    Export-SpoItem -Name 'BrowserIdleSignOut'     -RequiredCommands @('Get-SPOBrowserIdleSignOut') -SkipReason 'requires Microsoft.Online.SharePoint.PowerShell with an interactive Connect-SPOService session' -Action { Get-SPOBrowserIdleSignOut }
    Export-SpoItem -Name 'TenantContentTypeHub'   -RequiredCommands @('Get-SPOTenantCdnEnabled') -SkipReason 'requires Microsoft.Online.SharePoint.PowerShell with an interactive Connect-SPOService session' -Action { Get-SPOTenantCdnEnabled -CdnType Public }
    Export-SpoItem -Name 'TenantSyncClientRestriction' -RequiredCommands @('Get-SPOTenantSyncClientRestriction') -SkipReason 'requires Microsoft.Online.SharePoint.PowerShell with an interactive Connect-SPOService session' -Action { Get-SPOTenantSyncClientRestriction }

    # PnP-based items (site designs, hub sites, themes, app catalog)
    Export-SpoItem -Name 'SiteDesigns'            -RequiredCommands @('Get-PnPSiteDesign') -Action { Get-PnPSiteDesign }
    Export-SpoItem -Name 'SiteScripts'            -RequiredCommands @('Get-PnPSiteScript') -Action { Get-PnPSiteScript }
    Export-SpoItem -Name 'HubSites'               -RequiredCommands @('Get-PnPHubSite') -Action { Get-PnPHubSite }
    Export-SpoItem -Name 'TenantThemes'           -RequiredCommands @('Get-PnPTenantTheme') -Action { Get-PnPTenantTheme }
    Export-SpoItem -Name 'StorageEntities'        -RequiredCommands @('Get-PnPStorageEntity') -Action { Get-PnPStorageEntity }
    Export-SpoItem -Name 'AppCatalogApps'         -RequiredCommands @('Get-PnPApp') -Action { Get-PnPApp -Scope Tenant }

    # Search configuration (tenant-scope)
    Export-SpoItem -Name 'SearchManagedProperties' -RequiredCommands @('Get-PnPSearchConfiguration') -Action { Get-PnPSearchConfiguration -Scope Subscription }
    # Get-PnPSearchSettings has no -Scope parameter; call it bare and let PnP return the
    # tenant-scope search settings for the connected admin endpoint.
    Export-SpoItem -Name 'SearchResultSources'     -RequiredCommands @('Get-PnPSearchSettings') -Action { Get-PnPSearchSettings }

    # Sharing & access control settings (tenant-scope)
    Export-SpoItem -Name 'SharingSettings'        -RequiredCommands @('Get-SPOTenant') -SkipReason 'requires Microsoft.Online.SharePoint.PowerShell with an interactive Connect-SPOService session' -Action {
        if (Get-Command -Name Get-SPOTenant -ErrorAction SilentlyContinue) {
            Get-SPOTenant | Select-Object SharingCapability, DefaultSharingLinkType, RequireAcceptingAccountMatchInvitedAccount, ShowAllUsersClaim, ShowEveryoneClaim, ShowEveryoneExceptExternalUsersClaim, ProvisionSharedWithEveryoneFolder, SignInAccelerationDomain, EnableGuestSignInAcceleration, BccExternalSharingInvitations, BccExternalSharingInvitationsList, RequireAnonymousLinksExpireInDays, SharingAllowedDomainList, SharingBlockedDomainList, SharingDomainRestrictionMode, ExternalServicesEnabled, EmailAttestationRequired, EmailAttestationReAuthDays
        }
    }
    Export-SpoItem -Name 'AccessControlSettings'  -RequiredCommands @('Get-SPOTenant') -SkipReason 'requires Microsoft.Online.SharePoint.PowerShell with an interactive Connect-SPOService session' -Action {
        if (Get-Command -Name Get-SPOTenant -ErrorAction SilentlyContinue) {
            Get-SPOTenant | Select-Object ConditionalAccessPolicy, AllowDownloadingNonWebViewableFiles, AllowEditing, ApplyAppEnforcedRestrictionsToAdHocRecipients, IPAddressAllowList, IPAddressEnforcement, IPAddressWACTokenLifetime, EmailAttestationRequired, EmailAttestationReAuthDays, BlockMacSync, BlockUserInfoVisibility, BlockUserInfoVisibilityInOneDrive, BlockUserInfoVisibilityInSharePoint, DisabledWebPartIds
        }
    }

    # CDN
    Export-SpoItem -Name 'CdnEnabledPublic'   -RequiredCommands @('Get-SPOTenantCdnEnabled') -SkipReason 'requires Microsoft.Online.SharePoint.PowerShell with an interactive Connect-SPOService session' -Action { Get-SPOTenantCdnEnabled -CdnType Public }
    Export-SpoItem -Name 'CdnEnabledPrivate'  -RequiredCommands @('Get-SPOTenantCdnEnabled') -SkipReason 'requires Microsoft.Online.SharePoint.PowerShell with an interactive Connect-SPOService session' -Action { Get-SPOTenantCdnEnabled -CdnType Private }
    Export-SpoItem -Name 'CdnPolicyPublic'    -RequiredCommands @('Get-SPOTenantCdnPolicies') -SkipReason 'requires Microsoft.Online.SharePoint.PowerShell with an interactive Connect-SPOService session' -Action { Get-SPOTenantCdnPolicies -CdnType Public }
    Export-SpoItem -Name 'CdnPolicyPrivate'   -RequiredCommands @('Get-SPOTenantCdnPolicies') -SkipReason 'requires Microsoft.Online.SharePoint.PowerShell with an interactive Connect-SPOService session' -Action { Get-SPOTenantCdnPolicies -CdnType Private }

    # Retention labels (tenant). Newer PnP.PowerShell removed -IncludeSiteCollection; pass it
    # only when the parameter is still defined on the installed version.
    Export-SpoItem -Name 'RetentionLabelsSettings' -RequiredCommands @('Get-PnPLabel') -Action {
        $cmd = Get-Command -Name Get-PnPLabel -ErrorAction SilentlyContinue
        if (-not $cmd) { return }
        if ($cmd.Parameters.ContainsKey('IncludeSiteCollection')) {
            Get-PnPLabel -IncludeSiteCollection
        }
        else {
            Get-PnPLabel
        }
    }

    # ── Per-site exports (opt-in; iterates every site) ────────────────────────
    if (-not $IncludePerSite) {
        Write-BackupLog -Level Information -Message "Skipped per-site SharePoint exports (IncludePerSite not set)" -LogPath $LogPath
        return
    }
    $siteEnumerator = if (Get-Command Get-SPOSite -ErrorAction SilentlyContinue) { 'SPO' } elseif (Get-Command Get-PnPTenantSite -ErrorAction SilentlyContinue) { 'PnP' } else { $null }
    if (-not $siteEnumerator) {
        Write-BackupLog -Level Warning -Message "Neither Get-SPOSite nor Get-PnPTenantSite is available; skipping per-site exports" -LogPath $LogPath
        return
    }

    try {
        $sites = if ($siteEnumerator -eq 'SPO') {
            Invoke-WithThrottleRetry -OperationName 'SharePoint Get-SPOSite (all)' -LogPath $LogPath -ScriptBlock { Get-SPOSite -Limit All }
        }
        else {
            Invoke-WithThrottleRetry -OperationName 'SharePoint Get-PnPTenantSite (all)' -LogPath $LogPath -ScriptBlock { Get-PnPTenantSite }
        }
        $sites = @($sites)
        if ($PerObjectMaxItems -gt 0 -and $sites.Count -gt $PerObjectMaxItems) {
            Write-BackupLog -Level Information -Message "Per-site export capped at $PerObjectMaxItems of $($sites.Count) sites" -LogPath $LogPath
            $sites = $sites | Select-Object -First $PerObjectMaxItems
        }
        Write-BackupLog -Level Information -Message "Per-site export starting for $($sites.Count) site(s)" -LogPath $LogPath

        $perSiteFolder = Join-Path -Path $OutputPath -ChildPath 'PerSite'
        New-Item -Path $perSiteFolder -ItemType Directory -Force | Out-Null

        $allSiteGroups = @()
        $allAuditCfg   = @()
        $allPropBag    = @()
        $i = 0
        foreach ($s in $sites) {
            $i++
            if (($i % 50) -eq 0) {
                Write-BackupLog -Level Information -Message "Per-site progress: $i / $($sites.Count)" -LogPath $LogPath
            }
            try {
                if (-not (Get-Command Get-SPOSiteGroup -ErrorAction SilentlyContinue)) {
                    throw 'Get-SPOSiteGroup not available in the current session'
                }
                $groups = Get-SPOSiteGroup -Site $s.Url -ErrorAction Stop
                foreach ($g in @($groups)) {
                    $allSiteGroups += [pscustomobject]@{
                        SiteUrl      = $s.Url
                        Title        = $g.Title
                        Roles        = ($g.Roles -join ';')
                        OwnerLoginName = $g.OwnerLoginName
                        Users        = ($g.Users -join ';')
                    }
                }
            } catch {
                Write-BackupLog -Level Warning -Message "SiteGroups failed [$($s.Url)]: $($_.Exception.Message)" -LogPath $LogPath
            }

            # Property bag and audit settings require PnP per-site connect — best-effort
            if (Get-Command Connect-PnPOnline -ErrorAction SilentlyContinue) {
                try {
                    Connect-PnPOnline -Url $s.Url -ClientId $env:_BM365_PNP_CLIENTID -Tenant $env:_BM365_PNP_TENANTID -Thumbprint $env:_BM365_PNP_THUMBPRINT -ErrorAction Stop -WarningAction SilentlyContinue
                    if (Get-Command Get-PnPPropertyBag -ErrorAction SilentlyContinue) {
                        try {
                            $pb = Get-PnPPropertyBag -ErrorAction Stop
                            $allPropBag += [pscustomobject]@{ SiteUrl = $s.Url; Properties = $pb }
                        } catch { }
                    }
                    if (Get-Command Get-PnPAuditing -ErrorAction SilentlyContinue) {
                        try {
                            $aud = Get-PnPAuditing -ErrorAction Stop
                            $allAuditCfg += [pscustomobject]@{ SiteUrl = $s.Url; Auditing = $aud }
                        } catch { }
                    }
                } catch {
                    # Per-site PnP connect requires app-cert env vars — silently skip if not set
                }
            }
        }

        ConvertTo-SafeJson -InputObject @($allSiteGroups) -Depth 20 | Set-Content -Path (Join-Path $perSiteFolder 'SiteGroups.json') -Encoding UTF8
        ConvertTo-SafeJson -InputObject @($allPropBag)    -Depth 20 | Set-Content -Path (Join-Path $perSiteFolder 'PropertyBag.json') -Encoding UTF8
        ConvertTo-SafeJson -InputObject @($allAuditCfg)   -Depth 20 | Set-Content -Path (Join-Path $perSiteFolder 'AuditSettings.json') -Encoding UTF8

        Write-BackupLog -Level Information -Message "Per-site export complete: $($sites.Count) sites" -LogPath $LogPath
    }
    catch {
        Write-BackupLog -Level Warning -Message "Per-site export failed: $($_.Exception.Message)" -LogPath $LogPath
    }
    finally {
        # Always close any dangling per-site PnP connection
        if (Get-Command Disconnect-PnPOnline -ErrorAction SilentlyContinue) {
            try { Disconnect-PnPOnline -ErrorAction SilentlyContinue } catch { }
        }
    }
}
