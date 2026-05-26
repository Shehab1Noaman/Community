function Export-TeamsConfig {
    <#
    .SYNOPSIS
        Exports Microsoft Teams tenant configuration and optionally per-team settings.

    .DESCRIPTION
        Uses the MicrosoftTeams module to export Teams tenant baseline settings,
        meeting and messaging policies, calling and voice configuration, app policies,
        and many more settings to JSON files under OutputPath.

        When -IncludePerTeam is specified, per-team membership and channel details are
        exported for every team in the tenant — this can be slow on large tenants.

        Requires an active Microsoft Teams session (Connect-M365Tenant -ConnectTeams).

    .PARAMETER OutputPath
        Directory where exported JSON files are written.
        Created automatically if it does not exist.

    .PARAMETER LogPath
        Optional. Path to the NDJSON backup log file for structured log entries.

    .PARAMETER IncludePerTeam
        When set, exports per-team membership and channel details for all teams.

    .PARAMETER PerObjectMaxItems
        Maximum number of teams to process during per-team export. 0 means unlimited.

    .EXAMPLE
        Export-TeamsConfig -OutputPath C:\backup\Teams

    .EXAMPLE
        Export-TeamsConfig -OutputPath C:\backup\Teams -IncludePerTeam
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [string]$LogPath,

        [Parameter()]
        [switch]$IncludePerTeam,

        [Parameter()]
        [int]$PerObjectMaxItems = 0
    )

    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

    $map = [ordered]@{
        # Tenant baseline
        TenantConfig                       = { Get-CsTenant }
        TenantFederationConfig             = { Get-CsTenantFederationConfiguration }
        TeamsClientConfig                  = { Get-CsTeamsClientConfiguration }

        # Core policies
        MeetingPolicies                    = { Get-CsTeamsMeetingPolicy }
        MeetingConfiguration               = { Get-CsTeamsMeetingConfiguration }
        MeetingBrandingPolicies            = { Get-CsTeamsMeetingBrandingPolicy }
        MeetingTemplatePolicies            = { Get-CsTeamsMeetingTemplatePolicy }
        MessagingPolicies                  = { Get-CsTeamsMessagingPolicy }
        ChannelsPolicies                   = { Get-CsTeamsChannelsPolicy }
        AppSetupPolicies                   = { Get-CsTeamsAppSetupPolicy }
        AppPermissionPolicies              = { Get-CsTeamsAppPermissionPolicy }
        TemplatesPolicies                  = { Get-CsTeamsTemplatePermissionPolicy }
        UpdateManagementPolicies           = { Get-CsTeamsUpdateManagementPolicy }
        EventsPolicies                     = { Get-CsTeamsEventsPolicy }
        ShiftsPolicies                     = { Get-CsTeamsShiftsPolicy }
        FilesPolicies                      = { Get-CsTeamsFilesPolicy }
        FeedbackPolicies                   = { Get-CsTeamsFeedbackPolicy }
        EducationAssignmentsPolicies       = { Get-CsTeamsEducationAssignmentsAppPolicy }

        # External / federation
        ExternalAccessPolicies             = { Get-CsExternalAccessPolicy }
        FederationConfig                   = { Get-CsTeamsFederationConfiguration }

        # Calling / voice
        CallingPolicies                    = { Get-CsTeamsCallingPolicy }
        CallParkPolicies                   = { Get-CsTeamsCallParkPolicy }
        CallHoldPolicies                   = { Get-CsTeamsCallHoldPolicy }
        CallQueuePolicies                  = { Get-CsTeamsCallQueuesPolicy }
        AutoAttendantPolicies              = { Get-CsAutoAttendant }
        CallQueues                         = { Get-CsCallQueue }
        OnlineVoiceRoutingPolicies         = { Get-CsOnlineVoiceRoutingPolicy }
        OnlineVoiceRoutes                  = { Get-CsOnlineVoiceRoute }
        OnlinePstnUsages                   = { Get-CsOnlinePstnUsage }
        OnlinePstnGateways                 = { Get-CsOnlinePstnGateway }
        TenantDialPlans                    = { Get-CsTenantDialPlan }
        EmergencyCallRoutingPolicies       = { Get-CsTeamsEmergencyCallRoutingPolicy }
        EmergencyCallingPolicies           = { Get-CsTeamsEmergencyCallingPolicy }
        OnlineVoicemailPolicies            = { Get-CsOnlineVoicemailPolicy }
        OnlineAudioConferencingRoutingPolicies = { Get-CsOnlineAudioConferencingRoutingPolicy }

        # Live Events / streaming
        LiveEventsPolicies                 = { Get-CsTeamsLiveEventsPolicy }
        LiveEventsConfig                   = { Get-CsTeamsLiveEventsConfiguration }
        StreamingConfig                    = { Get-CsTeamsMeetingBroadcastConfiguration }

        # Inventory (config-only export, not message content)
        Teams                              = { Get-Team }

        # === Additional policies (tenant-wide config) ===
        AIPolicies                         = { Get-CsTeamsAIPolicy }
        AudioConferencingPolicies          = { Get-CsTeamsAudioConferencingPolicy }
        ComplianceRecordingPolicies        = { Get-CsTeamsComplianceRecordingPolicy }
        CortanaPolicies                    = { Get-CsTeamsCortanaPolicy }
        DialInConferencingTenantSettings   = { Get-CsOnlineDialInConferencingTenantSettings }
        EnhancedEncryptionPolicies         = { Get-CsTeamsEnhancedEncryptionPolicy }
        IPPhonePolicies                    = { Get-CsTeamsIPPhonePolicy }
        M365AppPolicies                    = { Get-CsTeamsM365AppPolicy }
        MessagingConfiguration             = { Get-CsTeamsMessagingConfiguration }
        MobilityPolicies                   = { Get-CsTeamsMobilityPolicy }
        NetworkRoamingPolicies             = { Get-CsTeamsNetworkRoamingPolicy }
        OrgWideAppSettings                 = { Get-CsTeamsAcsFederationConfiguration }
        TranslationRules                   = { Get-CsTeamsTranslationRule }
        UnassignedNumberTreatments         = { Get-CsTeamsUnassignedNumberTreatment }
        UpgradeConfiguration               = { Get-CsTeamsUpgradeConfiguration }
        UpgradePolicies                    = { Get-CsTeamsUpgradePolicy }
        VdiPolicies                        = { Get-CsTeamsVdiPolicy }
        WorkloadPolicies                   = { Get-CsTeamsWorkLoadPolicy }
        FeedbackConfiguration              = { Get-CsTeamsFeedbackConfiguration }
        GuestCallingConfiguration          = { Get-CsTeamsGuestCallingConfiguration }
        GuestMeetingConfiguration          = { Get-CsTeamsGuestMeetingConfiguration }
        GuestMessagingConfiguration        = { Get-CsTeamsGuestMessagingConfiguration }
        # NOTE: Get-CsOnlineVoicemailUserSettings is per-user (-Identity required) — not exportable at tenant scope.

        # === Network topology ===
        TenantNetworkRegions               = { Get-CsTenantNetworkRegion }
        TenantNetworkSites                 = { Get-CsTenantNetworkSite }
        TenantNetworkSubnets               = { Get-CsTenantNetworkSubnet }
        TenantTrustedIPAddresses           = { Get-CsTenantTrustedIPAddress }
    }

    foreach ($name in $map.Keys) {
        $cmd = $map[$name]
        try {
            $cmdSource = $cmd.ToString()
            $firstCmd = ($cmdSource -split '[\s\|;{}\r\n]+' | Where-Object { $_ -like 'Get-*' } | Select-Object -First 1)
            if ($firstCmd -and -not (Get-Command -Name $firstCmd -ErrorAction SilentlyContinue)) {
                Write-BackupLog -Level Information -Message "Skipped Teams object [$name] (cmdlet $firstCmd not available)" -LogPath $LogPath
                continue
            }

            $result = Invoke-WithThrottleRetry -OperationName "Teams $name" -LogPath $LogPath -ScriptBlock $cmd
            $targetPath = Join-Path -Path $OutputPath -ChildPath "$name.json"
            ConvertTo-SafeJson -InputObject @($result) -Depth 20 |
                Set-Content -Path $targetPath -Encoding UTF8
            Write-BackupLog -Level Information -Message "Exported Teams object: $name" -LogPath $LogPath
        }
        catch {
            Write-BackupLog -Level Warning -Message "Failed to export Teams object [$name]: $($_.Exception.Message)" -LogPath $LogPath
        }
    }

    # ── Per-team exports (opt-in; iterates every Team) ───────────────────────
    if (-not $IncludePerTeam) {
        Write-BackupLog -Level Information -Message "Skipped per-team Teams exports (IncludePerTeam not set)" -LogPath $LogPath
        return
    }
    if (-not (Get-Command Get-Team -ErrorAction SilentlyContinue)) {
        Write-BackupLog -Level Warning -Message "Get-Team not available; skipping per-team exports" -LogPath $LogPath
        return
    }

    try {
        $teams = Invoke-WithThrottleRetry -OperationName 'Teams Get-Team (all)' -LogPath $LogPath -ScriptBlock { Get-Team }
        $teams = @($teams)
        if ($PerObjectMaxItems -gt 0 -and $teams.Count -gt $PerObjectMaxItems) {
            Write-BackupLog -Level Information -Message "Per-team export capped at $PerObjectMaxItems of $($teams.Count) teams" -LogPath $LogPath
            $teams = $teams | Select-Object -First $PerObjectMaxItems
        }
        Write-BackupLog -Level Information -Message "Per-team export starting for $($teams.Count) team(s)" -LogPath $LogPath

        $perTeamFolder = Join-Path -Path $OutputPath -ChildPath 'PerTeam'
        New-Item -Path $perTeamFolder -ItemType Directory -Force | Out-Null

        $allChannels = @()
        $allTabs     = @()
        $allUsers    = @()

        $i = 0
        foreach ($t in $teams) {
            $i++
            if (($i % 25) -eq 0) {
                Write-BackupLog -Level Information -Message "Per-team progress: $i / $($teams.Count)" -LogPath $LogPath
            }
            $gid = [string]$t.GroupId
            if ([string]::IsNullOrWhiteSpace($gid)) { continue }

            try {
                $channels = Get-TeamChannel -GroupId $gid -ErrorAction Stop
                foreach ($c in @($channels)) {
                    $allChannels += [pscustomobject]@{
                        TeamGroupId  = $gid
                        TeamName     = $t.DisplayName
                        ChannelId    = $c.Id
                        DisplayName  = $c.DisplayName
                        MembershipType = $c.MembershipType
                        Description  = $c.Description
                    }

                    if (Get-Command Get-TeamChannelTab -ErrorAction SilentlyContinue) {
                        try {
                            $tabs = Get-TeamChannelTab -GroupId $gid -DisplayName $c.DisplayName -ErrorAction Stop
                            foreach ($tab in @($tabs)) {
                                $allTabs += [pscustomobject]@{
                                    TeamGroupId = $gid
                                    ChannelName = $c.DisplayName
                                    TabId       = $tab.Id
                                    DisplayName = $tab.DisplayName
                                    TeamsAppId  = $tab.TeamsAppId
                                    Configuration = $tab.Configuration
                                }
                            }
                        } catch {
                            Write-BackupLog -Level Warning -Message "Tabs failed [$($t.DisplayName)/$($c.DisplayName)]: $($_.Exception.Message)" -LogPath $LogPath
                        }
                    }
                }
            } catch {
                Write-BackupLog -Level Warning -Message "Channels failed for team [$($t.DisplayName)]: $($_.Exception.Message)" -LogPath $LogPath
            }

            try {
                $tu = Get-TeamUser -GroupId $gid -ErrorAction Stop
                foreach ($u in @($tu)) {
                    $allUsers += [pscustomobject]@{
                        TeamGroupId = $gid
                        TeamName    = $t.DisplayName
                        User        = $u.User
                        Name        = $u.Name
                        Role        = $u.Role
                    }
                }
            } catch {
                Write-BackupLog -Level Warning -Message "Members failed for team [$($t.DisplayName)]: $($_.Exception.Message)" -LogPath $LogPath
            }
        }

        ConvertTo-SafeJson -InputObject @($allChannels) -Depth 20 | Set-Content -Path (Join-Path $perTeamFolder 'Channels.json') -Encoding UTF8
        ConvertTo-SafeJson -InputObject @($allTabs)     -Depth 20 | Set-Content -Path (Join-Path $perTeamFolder 'ChannelTabs.json') -Encoding UTF8
        ConvertTo-SafeJson -InputObject @($allUsers)    -Depth 20 | Set-Content -Path (Join-Path $perTeamFolder 'TeamMembers.json') -Encoding UTF8

        Write-BackupLog -Level Information -Message "Per-team export complete: $($teams.Count) teams, $($allChannels.Count) channels, $($allTabs.Count) tabs" -LogPath $LogPath
    }
    catch {
        Write-BackupLog -Level Warning -Message "Per-team export failed: $($_.Exception.Message)" -LogPath $LogPath
    }

    # Note: Get-CsOnlineVoiceUser was removed by Microsoft (deprecated; throws on invocation).
    # See https://learn.microsoft.com/powershell/module/skype/get-csonlinevoiceuser. Skip silently.
}
