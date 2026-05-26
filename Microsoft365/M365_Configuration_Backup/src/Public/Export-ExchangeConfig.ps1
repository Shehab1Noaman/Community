function Export-ExchangeConfig {
    <#
    .SYNOPSIS
        Exports Exchange Online tenant configuration and optionally per-mailbox settings.

    .DESCRIPTION
        Uses the ExchangeOnlineManagement module to export mail flow rules, connectors,
        accepted domains, retention policies, OWA policies, RBAC, and many other
        Exchange Online settings to JSON files under OutputPath.

        When -IncludePerMailbox is specified, per-mailbox settings (client access, IRM,
        Litigation Hold, etc.) are also exported for every mailbox — this can be slow
        on large tenants.

        Requires an active Exchange Online session (Connect-M365Tenant -ConnectExchange).

    .PARAMETER OutputPath
        Directory where exported JSON files are written.
        Created automatically if it does not exist.

    .PARAMETER LogPath
        Optional. Path to the NDJSON backup log file for structured log entries.

    .PARAMETER IncludePerMailbox
        When set, exports per-mailbox settings in addition to tenant-level settings.

    .PARAMETER PerObjectMaxItems
        Maximum number of per-object items (mailboxes) to export. 0 means unlimited.

    .PARAMETER SkipMailboxIRMAccess
        Suppress Get-MailboxIRMAccess calls (requires AIP/Purview Information Protection).

    .PARAMETER SkipSystemMailboxes
        Exclude system arbitration mailboxes (DiscoverySearchMailbox, HealthMailbox, etc.)
        from per-mailbox exports.

    .EXAMPLE
        Export-ExchangeConfig -OutputPath C:\backup\ExchangeOnline

    .EXAMPLE
        Export-ExchangeConfig -OutputPath C:\backup\ExchangeOnline -IncludePerMailbox `
                              -SkipSystemMailboxes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [string]$LogPath,

        [Parameter()]
        [switch]$IncludePerMailbox,

        [Parameter()]
        [int]$PerObjectMaxItems = 0,

        [Parameter()]
        [switch]$SkipMailboxIRMAccess,

        [Parameter()]
        [switch]$SkipSystemMailboxes
    )

    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

    # Exporter map: name => script returning objects. Each is wrapped in retry/try.
    $map = [ordered]@{
        # Mail flow & domains
        AcceptedDomains              = { Get-AcceptedDomain }
        RemoteDomains                = { Get-RemoteDomain }
        TransportRules               = { Get-TransportRule }
        InboundConnectors            = { Get-InboundConnector }
        OutboundConnectors           = { Get-OutboundConnector }
        TransportConfig              = { Get-TransportConfig }
        JournalRules                 = { Get-JournalRule }
        # Org / mailbox baseline
        OrgConfig                    = { Get-OrganizationConfig }
        MailboxPlans                 = { Get-MailboxPlan }
        CASMailboxPlans              = { Get-CasMailboxPlan }
        AddressLists                 = { Get-AddressList }
        GlobalAddressLists           = { Get-GlobalAddressList }
        OfflineAddressBooks          = { Get-OfflineAddressBook }
        AddressBookPolicies          = { Get-AddressBookPolicy }
        EmailAddressPolicies         = { Get-EmailAddressPolicy }
        # Sharing / external
        SharingPolicies              = { Get-SharingPolicy }
        OrganizationRelationships    = { Get-OrganizationRelationship }
        FederationTrust              = { Get-FederationTrust }
        # Mobile devices
        MobileDeviceMailboxPolicies  = { Get-MobileDeviceMailboxPolicy }
        ActiveSyncOrgSettings        = { Get-ActiveSyncOrganizationSettings }
        # Retention (legacy MRM)
        RetentionPolicies            = { Get-RetentionPolicy }
        RetentionPolicyTags          = { Get-RetentionPolicyTag }
        # Tips & misc
        MailTipsConfig               = { (Get-OrganizationConfig).MailTipsAllTipsEnabled }
        OwaMailboxPolicies           = { Get-OwaMailboxPolicy }
        # RBAC
        RoleGroups                   = { Get-RoleGroup }
        ManagementRoles              = { Get-ManagementRole }
        RoleAssignmentPolicies       = { Get-RoleAssignmentPolicy }
        ManagementRoleAssignments    = { Get-ManagementRoleAssignment }
        ManagementScopes             = { Get-ManagementScope }
        # Distribution / public folders (config only, not membership content)
        DistributionGroups           = { Get-DistributionGroup -ResultSize Unlimited }
        DynamicDistributionGroups    = { Get-DynamicDistributionGroup -ResultSize Unlimited }
        UnifiedGroups                = { Get-UnifiedGroup -ResultSize Unlimited }
        # Public folder root must be specified explicitly to avoid an interactive Identity prompt
        PublicFoldersTopLevel        = { Get-PublicFolder -Identity '\' -Recurse -ResultSize Unlimited -ErrorAction SilentlyContinue }

        # === Defender for Office 365 (anti-spam/phish/malware/safe links/safe attachments) ===
        AntiPhishPolicies            = { Get-AntiPhishPolicy }
        AntiPhishRules               = { Get-AntiPhishRule }
        MalwareFilterPolicies        = { Get-MalwareFilterPolicy }
        MalwareFilterRules           = { Get-MalwareFilterRule }
        HostedContentFilterPolicies  = { Get-HostedContentFilterPolicy }   # anti-spam (inbound)
        HostedContentFilterRules     = { Get-HostedContentFilterRule }
        HostedOutboundSpamFilterPolicies = { Get-HostedOutboundSpamFilterPolicy }
        HostedOutboundSpamFilterRules    = { Get-HostedOutboundSpamFilterRule }
        HostedConnectionFilterPolicies   = { Get-HostedConnectionFilterPolicy }
        SafeAttachmentPolicies       = { Get-SafeAttachmentPolicy }
        SafeAttachmentRules          = { Get-SafeAttachmentRule }
        SafeLinksPolicies            = { Get-SafeLinksPolicy }
        SafeLinksRules               = { Get-SafeLinksRule }
        AtpPolicyForO365             = { Get-AtpPolicyForO365 }
        AtpBuiltInProtectionRule     = { Get-AtpBuiltInProtectionRule }
        EOPProtectionPolicyRule      = { Get-EOPProtectionPolicyRule }
        ATPProtectionPolicyRule      = { Get-ATPProtectionPolicyRule }
        ReportSubmissionPolicies     = { Get-ReportSubmissionPolicy }
        ReportSubmissionRules        = { Get-ReportSubmissionRule }
        # Each ListType call is wrapped individually so a tenant lacking ExchangeConfigUnit doesn't blow the whole entry away
        TenantAllowBlockListItems    = {
            $items = @()
            foreach ($lt in 'Sender','Url','FileHash','IP') {
                try {
                    $items += @(Get-TenantAllowBlockListItems -ListType $lt -ErrorAction Stop)
                } catch { }
            }
            $items
        }
        TenantAllowBlockListSpoofItems = { try { Get-TenantAllowBlockListSpoofItems -ErrorAction Stop } catch { @() } }
        PhishSimOverrideRule         = { Get-PhishSimOverrideRule }
        SecOpsOverrideRule           = { Get-SecOpsOverrideRule }

        # === Authentication / app access ===
        AuthenticationPolicies       = { Get-AuthenticationPolicy }
        AuthenticationPolicyAssignments = { Get-User -ResultSize Unlimited -Filter "AuthenticationPolicy -ne `$null" | Select-Object UserPrincipalName, AuthenticationPolicy }
        ApplicationAccessPolicies    = { Get-ApplicationAccessPolicy -ErrorAction SilentlyContinue 2>$null }
        ServicePrincipals            = { Get-ServicePrincipal }
        PartnerApplications          = { Get-PartnerApplication }

        # === Encryption / IRM / DKIM / DNSSEC / ARC ===
        DkimSigningConfig            = { Get-DkimSigningConfig }
        # Iterate accepted/verified domains explicitly; calling without -DomainName triggers an interactive prompt
        DnssecForVerifiedDomains     = {
            if (-not (Get-Command Get-AcceptedDomain -ErrorAction SilentlyContinue)) { return @() }
            $results = @()
            foreach ($d in @(Get-AcceptedDomain -ErrorAction SilentlyContinue)) {
                try {
                    $results += [pscustomobject]@{
                        DomainName = $d.DomainName
                        Status     = (Get-DnssecStatusForVerifiedDomain -DomainName $d.DomainName -ErrorAction Stop)
                    }
                } catch { }
            }
            $results
        }
        ArcConfig                    = { Get-ArcConfig }
        IRMConfiguration             = { Get-IRMConfiguration }
        OMEConfigurations            = { Get-OMEConfiguration }
        DataAtRestEncryptionPolicies = { Get-DataAtRestEncryptionPolicy }
        DataAtRestEncryptionPolicyAssignments = { Get-DataAtRestEncryptionPolicyAssignment }
        DataEncryptionPolicies       = { Get-DataEncryptionPolicy }
        DataClassifications          = { Get-DataClassification }

        # === Quarantine / submission / external mail tags ===
        QuarantinePolicies           = { Get-QuarantinePolicy }
        ExternalInOutlook            = { Get-ExternalInOutlook }
        # FocusedInbox is a per-mailbox cmdlet; calling without -Identity prompts interactively. Skipped at tenant scope.
        TeamsProtectionPolicy        = { Get-TeamsProtectionPolicy }
        EmailTenantSettings          = { Get-EmailTenantSettings }
        OnPremisesOrganizations      = { Get-OnPremisesOrganization }
        IntraOrganizationConnectors  = { Get-IntraOrganizationConnector }
        AvailabilityAddressSpaces    = { Get-AvailabilityAddressSpace }
        AvailabilityConfig           = { Get-AvailabilityConfig }
        PerimeterConfiguration       = { Get-PerimeterConfig }
        ResourceConfiguration        = { Get-ResourceConfig }
        PolicyTipConfig              = { Get-PolicyTipConfig }
        MessageClassifications       = { Get-MessageClassification }
        SmtpDaneInbound              = { Get-SmtpDaneInbound }

        # === Migration / contacts / places ===
        MailContacts                 = { Get-MailContact -ResultSize Unlimited }
        MigrationEndpoints           = { Get-MigrationEndpoint }
        Migrations                   = { Get-MigrationBatch }
        Places                       = { Get-Place }
        ActiveSyncDeviceAccessRules  = { Get-ActiveSyncDeviceAccessRule }
        ActiveSyncMailboxPolicies    = { Get-ActiveSyncMailboxPolicy }
        AdminAuditLogConfig          = { Get-AdminAuditLogConfig }
    }

    foreach ($name in $map.Keys) {
        $cmd = $map[$name]
        try {
            # Quickly skip cmdlets that don't exist in this session (e.g., feature not licensed)
            $cmdSource = $cmd.ToString()
            $firstCmd = ($cmdSource -split '[\s\|;{}\r\n]+' | Where-Object { $_ -like 'Get-*' } | Select-Object -First 1)
            if ($firstCmd -and -not (Get-Command -Name $firstCmd -ErrorAction SilentlyContinue)) {
                Write-BackupLog -Level Information -Message "Skipped Exchange object [$name] (cmdlet $firstCmd not available)" -LogPath $LogPath
                continue
            }

            $result = Invoke-WithThrottleRetry -OperationName "Exchange $name" -LogPath $LogPath -ScriptBlock $cmd
            $targetPath = Join-Path -Path $OutputPath -ChildPath "$name.json"
            ConvertTo-SafeJson -InputObject @($result) -Depth 20 |
                Set-Content -Path $targetPath -Encoding UTF8
            Write-BackupLog -Level Information -Message "Exported Exchange object: $name" -LogPath $LogPath
        }
        catch {
            Write-BackupLog -Level Warning -Message "Failed to export Exchange object [$name]: $($_.Exception.Message)" -LogPath $LogPath
        }
    }

    # ── Per-mailbox exports (opt-in; iterates every mailbox) ─────────────────
    if (-not $IncludePerMailbox) {
        Write-BackupLog -Level Information -Message "Skipped per-mailbox Exchange exports (IncludePerMailbox not set)" -LogPath $LogPath
        return
    }

    if (-not (Get-Command Get-Mailbox -ErrorAction SilentlyContinue)) {
        Write-BackupLog -Level Warning -Message "Get-Mailbox not available; skipping per-mailbox exports" -LogPath $LogPath
        return
    }

    try {
        $mailboxes = Invoke-WithThrottleRetry -OperationName 'Exchange Get-Mailbox (all)' -LogPath $LogPath -ScriptBlock {
            Get-Mailbox -ResultSize Unlimited
        }
        $mailboxes = @($mailboxes)
        if ($SkipSystemMailboxes) {
            $sysPattern = '^(DiscoverySearchMailbox|HealthMailbox|SystemMailbox|FederatedEmail|Migration\.|SM_)'
            $beforeCount = $mailboxes.Count
            $mailboxes = @($mailboxes | Where-Object {
                $alias = [string]$_.Alias
                $rt    = [string]$_.RecipientTypeDetails
                -not (
                    ($alias -and $alias -match $sysPattern) -or
                    ($rt -in @('DiscoveryMailbox','ArbitrationMailbox','AuditLogMailbox','AuxAuditLogMailbox','SupervisoryReviewPolicyMailbox','MonitoringMailbox','SchedulingMailbox'))
                )
            })
            $skipped = $beforeCount - $mailboxes.Count
            if ($skipped -gt 0) {
                Write-BackupLog -Level Information -Message "Per-mailbox export filtered out $skipped system mailbox(es) (skipSystemMailboxes=true)" -LogPath $LogPath
            }
        }
        if ($PerObjectMaxItems -gt 0 -and $mailboxes.Count -gt $PerObjectMaxItems) {
            Write-BackupLog -Level Information -Message "Per-mailbox export capped at $PerObjectMaxItems of $($mailboxes.Count) mailboxes" -LogPath $LogPath
            $mailboxes = $mailboxes | Select-Object -First $PerObjectMaxItems
        }
        Write-BackupLog -Level Information -Message "Per-mailbox export starting for $($mailboxes.Count) mailbox(es)" -LogPath $LogPath

        $perMbxFolder = Join-Path -Path $OutputPath -ChildPath 'PerMailbox'
        New-Item -Path $perMbxFolder -ItemType Directory -Force | Out-Null

        $aggregates = @{
            CalendarProcessing            = @()
            CalendarConfiguration         = @()
            AutoReplyConfiguration        = @()
            MailboxAuditBypassAssociation = @()
            MailboxIRMAccess              = @()
            MailboxSettings               = @()
            CASMailboxSettings            = @()
            MailboxPermission             = @()
            RecipientPermission           = @()
            SweepRule                     = @()
            MailboxFolderPermission       = @()
        }

        $i = 0
        foreach ($mbx in $mailboxes) {
            $i++
            $upn = [string]$mbx.UserPrincipalName
            if ([string]::IsNullOrWhiteSpace($upn)) { $upn = [string]$mbx.PrimarySmtpAddress }
            if ([string]::IsNullOrWhiteSpace($upn)) { continue }

            if (($i % 50) -eq 0) {
                Write-BackupLog -Level Information -Message "Per-mailbox progress: $i / $($mailboxes.Count)" -LogPath $LogPath
            }

            # Wrap each call individually — keep going on per-mailbox failures
            $tryGet = {
                param($Name, $Block)
                try { & $Block } catch {
                    Write-BackupLog -Level Warning -Message "[$Name] $upn`: $($_.Exception.Message)" -LogPath $LogPath
                    return $null
                }
            }

            if (Get-Command Get-CalendarProcessing -ErrorAction SilentlyContinue) {
                $r = & $tryGet 'CalendarProcessing' { Get-CalendarProcessing -Identity $upn -ErrorAction Stop }
                if ($r) { $aggregates.CalendarProcessing += [pscustomobject]@{ Identity = $upn; Value = $r } }
            }
            if (Get-Command Get-MailboxCalendarConfiguration -ErrorAction SilentlyContinue) {
                $r = & $tryGet 'MailboxCalendarConfiguration' { Get-MailboxCalendarConfiguration -Identity $upn -ErrorAction Stop }
                if ($r) { $aggregates.CalendarConfiguration += [pscustomobject]@{ Identity = $upn; Value = $r } }
            }
            if (Get-Command Get-MailboxAutoReplyConfiguration -ErrorAction SilentlyContinue) {
                $r = & $tryGet 'AutoReplyConfiguration' { Get-MailboxAutoReplyConfiguration -Identity $upn -ErrorAction Stop }
                if ($r) { $aggregates.AutoReplyConfiguration += [pscustomobject]@{ Identity = $upn; Value = $r } }
            }
            if (Get-Command Get-MailboxAuditBypassAssociation -ErrorAction SilentlyContinue) {
                $r = & $tryGet 'MailboxAuditBypassAssociation' { Get-MailboxAuditBypassAssociation -Identity $upn -ErrorAction Stop }
                if ($r) { $aggregates.MailboxAuditBypassAssociation += [pscustomobject]@{ Identity = $upn; Value = $r } }
            }
            if (-not $SkipMailboxIRMAccess -and (Get-Command Get-MailboxIRMAccess -ErrorAction SilentlyContinue)) {
                $r = & $tryGet 'MailboxIRMAccess' { Get-MailboxIRMAccess -Identity $upn -ErrorAction Stop }
                if ($r) { $aggregates.MailboxIRMAccess += [pscustomobject]@{ Identity = $upn; Value = $r } }
            }
            if (Get-Command Get-MailboxRegionalConfiguration -ErrorAction SilentlyContinue) {
                $r = & $tryGet 'MailboxSettings' { Get-MailboxRegionalConfiguration -Identity $upn -ErrorAction Stop }
                if ($r) { $aggregates.MailboxSettings += [pscustomobject]@{ Identity = $upn; Value = $r } }
            }
            if (Get-Command Get-CASMailbox -ErrorAction SilentlyContinue) {
                $r = & $tryGet 'CASMailboxSettings' { Get-CASMailbox -Identity $upn -ErrorAction Stop }
                if ($r) { $aggregates.CASMailboxSettings += [pscustomobject]@{ Identity = $upn; Value = $r } }
            }
            if (Get-Command Get-MailboxPermission -ErrorAction SilentlyContinue) {
                $r = & $tryGet 'MailboxPermission' { Get-MailboxPermission -Identity $upn -ErrorAction Stop | Where-Object { $_.User -notlike 'NT AUTHORITY\*' -and -not $_.IsInherited } }
                if ($r) { $aggregates.MailboxPermission += [pscustomobject]@{ Identity = $upn; Value = @($r) } }
            }
            if (Get-Command Get-RecipientPermission -ErrorAction SilentlyContinue) {
                $r = & $tryGet 'RecipientPermission' { Get-RecipientPermission -Identity $upn -ErrorAction Stop | Where-Object { $_.Trustee -ne 'NT AUTHORITY\SELF' } }
                if ($r) { $aggregates.RecipientPermission += [pscustomobject]@{ Identity = $upn; Value = @($r) } }
            }
            if (Get-Command Get-SweepRule -ErrorAction SilentlyContinue) {
                $r = & $tryGet 'SweepRule' { Get-SweepRule -Mailbox $upn -ErrorAction Stop }
                if ($r) { $aggregates.SweepRule += [pscustomobject]@{ Identity = $upn; Value = @($r) } }
            }
            # Top-level folder permissions only (Calendar, Inbox, Contacts) — recursing all folders is too expensive
            if (Get-Command Get-MailboxFolderPermission -ErrorAction SilentlyContinue) {
                foreach ($folder in @('Calendar','Inbox','Contacts')) {
                    $r = & $tryGet "MailboxFolderPermission:$folder" { Get-MailboxFolderPermission -Identity "${upn}:\$folder" -ErrorAction Stop | Where-Object { $_.User.UserType.Value -ne 'Default' -and $_.User.UserType.Value -ne 'Anonymous' } }
                    if ($r) { $aggregates.MailboxFolderPermission += [pscustomobject]@{ Identity = $upn; Folder = $folder; Value = @($r) } }
                }
            }
        }

        foreach ($key in $aggregates.Keys) {
            $path = Join-Path -Path $perMbxFolder -ChildPath "$key.json"
            ConvertTo-SafeJson -InputObject @($aggregates[$key]) -Depth 20 |
                Set-Content -Path $path -Encoding UTF8
        }
        Write-BackupLog -Level Information -Message "Per-mailbox export complete: $($mailboxes.Count) mailbox(es) into $perMbxFolder" -LogPath $LogPath
    }
    catch {
        Write-BackupLog -Level Warning -Message "Per-mailbox export failed: $($_.Exception.Message)" -LogPath $LogPath
    }
}
