function Export-EntraConfig {
    <#
    .SYNOPSIS
        Exports Microsoft Entra ID (Azure AD) tenant configuration to JSON files.

    .DESCRIPTION
        Queries Microsoft Graph for all major Entra ID settings and writes each
        object type to a separate JSON file under OutputPath. Covers authentication
        policies, conditional access, groups, roles, enterprise apps, B2B/B2C
        settings, privileged identity management, and more.

        Requires an active Microsoft Graph session (Connect-M365Tenant or
        Connect-MgGraph) with at minimum Directory.Read.All and Policy.Read.All.

    .PARAMETER OutputPath
        Directory where exported JSON files are written.
        Created automatically if it does not exist.

    .PARAMETER LogPath
        Optional. Path to the NDJSON backup log file for structured log entries.

    .EXAMPLE
        Export-EntraConfig -OutputPath C:\backup\EntraID

    .EXAMPLE
        Export-EntraConfig -OutputPath C:\backup\EntraID -LogPath C:\backup\Logs\backup.log.ndjson
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [string]$LogPath
    )

    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

    function Get-EntraCollection {
        param([Parameter(Mandatory)][string]$Uri)
        $all = New-Object System.Collections.Generic.List[object]
        $next = $Uri
        while (-not [string]::IsNullOrWhiteSpace($next)) {
            $resp = Invoke-GraphRequestWithRetry -Uri $next -LogPath $LogPath
            if ($null -eq $resp) { break }
            $batch = @()
            $nextLink = $null
            if ($resp -is [System.Collections.IDictionary]) {
                if ($resp.Contains('value')) { $batch = @($resp['value']) } else { $batch = @($resp) }
                if ($resp.Contains('@odata.nextLink')) { $nextLink = [string]$resp['@odata.nextLink'] }
            }
            elseif ($resp.PSObject.Properties.Name -contains 'value') {
                $batch = @($resp.value)
                if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $nextLink = [string]$resp.'@odata.nextLink' }
            }
            else { $batch = @($resp) }
            foreach ($item in $batch) {
                if ($item -is [System.Collections.IDictionary]) { $all.Add([pscustomobject]$item) | Out-Null }
                else { $all.Add($item) | Out-Null }
            }
            $next = $nextLink
        }
        return ,$all.ToArray()
    }

    # Single-object endpoints (no `value` wrapper) — write the response directly
    $singletons = [ordered]@{
        TenantSettings              = '/v1.0/organization'
        AuthenticationMethods       = '/v1.0/policies/authenticationMethodsPolicy'
        AuthorizationPolicy         = '/v1.0/policies/authorizationPolicy'
        CrossTenantAccessPolicy     = '/beta/policies/crossTenantAccessPolicy'
        IdentitySecurityDefaults    = '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
        AdminConsentRequestPolicy   = '/v1.0/policies/adminConsentRequestPolicy'
        ExternalIdentitiesPolicy    = '/beta/policies/externalIdentitiesPolicy'
        B2BManagementPolicy         = '/beta/policies/b2bManagementPolicy'
        DeviceRegistrationPolicy    = '/beta/policies/deviceRegistrationPolicy'
        CompanyBranding             = '/beta/organization/{tenantId}/branding'
    }

    foreach ($name in $singletons.Keys) {
        try {
            $uri = $singletons[$name]
            if ($uri -like '*{tenantId}*') {
                $org = Invoke-GraphRequestWithRetry -Uri '/v1.0/organization' -LogPath $LogPath
                $tid = $null
                if ($org -is [System.Collections.IDictionary] -and $org.Contains('value')) {
                    $first = @($org['value'])[0]
                    if ($first) { $tid = [string]$first['id'] }
                }
                elseif ($org.PSObject.Properties.Name -contains 'value') {
                    $tid = [string](@($org.value)[0].id)
                }
                if (-not $tid) { throw 'Could not resolve tenant id for branding endpoint.' }
                $uri = $uri.Replace('{tenantId}', $tid)
            }
            $data = Invoke-GraphRequestWithRetry -Uri $uri -MaxRetries 2 -LogPath $LogPath
            if ($data -is [System.Collections.IDictionary]) { $data = [pscustomobject]$data }
            ConvertTo-SafeJson -InputObject $data -Depth 20 |
                Set-Content -Path (Join-Path $OutputPath "$name.json") -Encoding UTF8
            Write-BackupLog -Level Information -Message "Exported Entra object: $name" -LogPath $LogPath
        }
        catch {
            Write-BackupLog -Level Warning -Message "Failed to export Entra object [$name]: $($_.Exception.Message)" -LogPath $LogPath
        }
    }

    # Collection endpoints (paged)
    $collections = [ordered]@{
        Groups                          = '/v1.0/groups?$top=999'
        AdministrativeRoles             = '/v1.0/directoryRoles'
        ConditionalAccess               = '/v1.0/identity/conditionalAccess/policies'
        NamedLocations                  = '/v1.0/identity/conditionalAccess/namedLocations'
        AuthenticationContextClassReferences = '/v1.0/identity/conditionalAccess/authenticationContextClassReferences'
        AppRegistrations                = '/v1.0/applications?$top=999'
        EnterpriseApps                  = '/v1.0/servicePrincipals?$top=999'
        Domains                         = '/v1.0/domains'
        SubscribedSkus                  = '/v1.0/subscribedSkus'
        AuthenticationStrengthPolicies  = '/v1.0/policies/authenticationStrengthPolicies'
        ClaimsMappingPolicies           = '/v1.0/policies/claimsMappingPolicies'
        TokenIssuancePolicies           = '/v1.0/policies/tokenIssuancePolicies'
        TokenLifetimePolicies           = '/v1.0/policies/tokenLifetimePolicies'
        FeatureRolloutPolicies          = '/v1.0/policies/featureRolloutPolicies'
        HomeRealmDiscoveryPolicies      = '/v1.0/policies/homeRealmDiscoveryPolicies'
        ActivityBasedTimeoutPolicies    = '/v1.0/policies/activityBasedTimeoutPolicies'
        PermissionGrantPolicies         = '/v1.0/policies/permissionGrantPolicies'
        DefaultAppManagementPolicy      = '/beta/policies/defaultAppManagementPolicy'
        AppManagementPolicies           = '/v1.0/policies/appManagementPolicies'
        GroupLifecyclePolicies          = '/v1.0/groupLifecyclePolicies'
        CustomSecurityAttributeDefinitions = '/v1.0/directory/customSecurityAttributeDefinitions'
        AttributeSets                   = '/v1.0/directory/attributeSets'
        AdministrativeUnits             = '/v1.0/directory/administrativeUnits'
        DirectoryRoleTemplates          = '/v1.0/directoryRoleTemplates'
        UnifiedRoleDefinitions          = '/v1.0/roleManagement/directory/roleDefinitions'
        UnifiedRoleAssignments          = '/v1.0/roleManagement/directory/roleAssignments'
        # PIM (license-gated; will warn if not eligible)
        PimRoleEligibilitySchedules     = '/v1.0/roleManagement/directory/roleEligibilitySchedules'
        PimRoleEligibilityScheduleRequests = '/v1.0/roleManagement/directory/roleEligibilityScheduleRequests'
        PimRoleManagementPolicies       = '/v1.0/policies/roleManagementPolicies?$filter=scopeId eq ''/'' and scopeType eq ''Directory'''
        PimRoleManagementPolicyAssignments = '/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId eq ''/'' and scopeType eq ''Directory'''
        # Identity Protection
        IdentityProtectionRiskyUsers    = '/v1.0/identityProtection/riskyUsers'

        # Identity Governance — Access Reviews
        AccessReviewDefinitions         = '/beta/identityGovernance/accessReviews/definitions'

        # Identity Governance — Entitlement Management
        EntitlementMgmtAccessPackages              = '/v1.0/identityGovernance/entitlementManagement/accessPackages'
        EntitlementMgmtAccessPackageCatalogs       = '/v1.0/identityGovernance/entitlementManagement/catalogs'
        EntitlementMgmtAssignmentPolicies          = '/v1.0/identityGovernance/entitlementManagement/assignmentPolicies'
        EntitlementMgmtAssignments                 = '/v1.0/identityGovernance/entitlementManagement/assignments'
        EntitlementMgmtConnectedOrganizations      = '/v1.0/identityGovernance/entitlementManagement/connectedOrganizations'
        EntitlementMgmtSettings                    = '/v1.0/identityGovernance/entitlementManagement/settings'

        # Identity Governance — Lifecycle Workflows
        LifecycleWorkflows                         = '/v1.0/identityGovernance/lifecycleWorkflows/workflows'
        LifecycleWorkflowsCustomTaskExtensions     = '/v1.0/identityGovernance/lifecycleWorkflows/customTaskExtensions'
        LifecycleWorkflowsSettings                 = '/v1.0/identityGovernance/lifecycleWorkflows/settings'

        # Terms of Use / Agreements
        Agreements                      = '/v1.0/identityGovernance/termsOfUse/agreements'

        # B2X identity user flows + API connectors
        B2xUserFlows                    = '/beta/identity/b2xUserFlows'
        UserFlowAttributes              = '/beta/identity/userFlowAttributes'
        IdentityApiConnectors           = '/beta/identity/apiConnectors'

        # Custom authentication extensions
        CustomAuthenticationExtensions  = '/beta/identity/customAuthenticationExtensions'

        # Verified ID
        VerifiedIdAuthorities           = '/beta/verifiedIdentity/authorities'

        # Global Secure Access (Network Access) — preview/beta, may 404 if not licensed
        NetworkAccessForwardingProfiles = '/beta/networkAccess/forwardingProfiles'
        NetworkAccessForwardingPolicies = '/beta/networkAccess/forwardingPolicies'
        NetworkAccessFilteringPolicies  = '/beta/networkAccess/filteringPolicies'
        NetworkAccessFilteringProfiles  = '/beta/networkAccess/filteringProfiles'
        NetworkAccessRemoteNetworks     = '/beta/networkAccess/connectivity/remoteNetworks'
        NetworkAccessSettings           = '/beta/networkAccess/settings'
        NetworkAccessConditionalAccessSettings = '/beta/networkAccess/settings/conditionalAccess'
        NetworkAccessCrossTenantAccessSettings = '/beta/networkAccess/settings/crossTenantAccess'

        # Cross-tenant access policy partner configs
        CrossTenantPartnerConfigurations = '/v1.0/policies/crossTenantAccessPolicy/partners'

        # On-premises publishing (App Proxy)
        OnPremisesPublishingProfiles    = '/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups'

        # Multi-tenant org
        MultiTenantOrganization         = '/v1.0/tenantRelationships/multiTenantOrganization'

        # Tenant App Management Policy
        TenantAppManagementPolicy       = '/v1.0/policies/defaultAppManagementPolicy'

        # ── Microsoft 365 admin / org settings (Graph) ────────────────────────
        # External connections (Microsoft Search)
        ExternalConnections             = '/v1.0/external/connections'
        # Search & intelligence — profile card properties
        ProfileCardProperties           = '/v1.0/admin/people/profileCardProperties'
        # Pronouns settings
        PronounsSettings                = '/v1.0/admin/people/pronouns'
        # SharePoint tenant admin settings (OneDrive sync, etc.)
        AdminSharePointSettings         = '/v1.0/admin/sharepoint/settings'
        # Forms admin settings
        AdminFormsSettings              = '/beta/admin/forms/settings'
        # Microsoft 365 Apps install options
        AdminAppsInstallationOptions    = '/v1.0/admin/microsoft365Apps/installationOptions'
        # Service announcements (health overview / messages)
        ServiceAnnouncementHealthOverviews = '/v1.0/admin/serviceAnnouncement/healthOverviews'
        # Copilot admin settings (preview; may 404 if not licensed)
        CopilotAdminSettings            = '/beta/copilot/admin/settings'
    }

    foreach ($name in $collections.Keys) {
        try {
            $data = @(Get-EntraCollection -Uri $collections[$name])
            ConvertTo-SafeJson -InputObject $data -Depth 20 |
                Set-Content -Path (Join-Path $OutputPath "$name.json") -Encoding UTF8
            Write-BackupLog -Level Information -Message "Exported Entra object: $name ($($data.Count) items)" -LogPath $LogPath
        }
        catch {
            Write-BackupLog -Level Warning -Message "Failed to export Entra object [$name]: $($_.Exception.Message)" -LogPath $LogPath
        }
    }
}
