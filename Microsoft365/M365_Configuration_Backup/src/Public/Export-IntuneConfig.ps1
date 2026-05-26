function Export-IntuneConfig {
    <#
    .SYNOPSIS
        Exports Microsoft Intune tenant configuration to JSON files.

    .DESCRIPTION
        Queries Microsoft Graph (deviceManagement endpoints) for all major Intune
        settings and writes each object type to a separate JSON file under OutputPath.
        Covers compliance policies, configuration profiles, settings catalog policies,
        Windows Update rings, Autopilot profiles, assignment filters, scripts, and more.

        Requires an active Microsoft Graph session with
        DeviceManagementConfiguration.Read.All and DeviceManagementManagedDevices.Read.All.

    .PARAMETER OutputPath
        Directory where exported JSON files are written.
        Created automatically if it does not exist.

    .PARAMETER LogPath
        Optional. Path to the NDJSON backup log file for structured log entries.

    .PARAMETER SkipAutopilotHardwareHash
        When set, skips the hardware hash export (large and time-consuming on big fleets).

    .EXAMPLE
        Export-IntuneConfig -OutputPath C:\backup\Intune

    .EXAMPLE
        Export-IntuneConfig -OutputPath C:\backup\Intune -SkipAutopilotHardwareHash
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [string]$LogPath,

        [Parameter()]
        [switch]$SkipAutopilotHardwareHash
    )

    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

    function Get-GraphCollectionItems {
        param(
            [Parameter(Mandatory)]
            [string]$Uri
        )

        $allItems = New-Object System.Collections.Generic.List[object]
        $nextUri = $Uri

        while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
            $response = Invoke-GraphRequestWithRetry -Uri $nextUri -LogPath $LogPath
            if ($null -eq $response) { break }

            $batch = @()
            $next = $null
            if ($response -is [System.Collections.IDictionary]) {
                if ($response.Contains('value')) {
                    $batch = @($response['value'])
                }
                else {
                    $batch = @($response)
                }
                if ($response.Contains('@odata.nextLink')) {
                    $next = [string]$response['@odata.nextLink']
                }
            }
            elseif ($response -is [System.Array]) {
                $batch = @($response)
            }
            elseif ($response.PSObject.Properties.Name -contains 'value') {
                $batch = @($response.value)
                if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
                    $next = [string]$response.'@odata.nextLink'
                }
            }
            else {
                $batch = @($response)
            }

            foreach ($item in $batch) {
                if ($item -is [System.Collections.IDictionary]) {
                    $allItems.Add([pscustomobject]$item) | Out-Null
                }
                else {
                    $allItems.Add($item) | Out-Null
                }
            }

            $nextUri = $next
        }

        return ,$allItems.ToArray()
    }

    function Get-SafeItemName {
        param(
            [Parameter(Mandatory)]
            $Item
        )

        $name = [string]$Item.displayName
        if ([string]::IsNullOrWhiteSpace($name)) {
            $name = [string]$Item.id
        }

        $safe = ($name -replace '[\\/:*?"<>|]', '_').Trim()
        if ([string]::IsNullOrWhiteSpace($safe)) {
            return 'UnnamedScript'
        }

        return $safe
    }

    function Write-Base64File {
        param(
            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [AllowNull()]
            [string]$Base64Content
        )

        if ([string]::IsNullOrWhiteSpace($Base64Content)) {
            return
        }

        $bytes = [System.Convert]::FromBase64String($Base64Content)
        [System.IO.File]::WriteAllBytes($Path, $bytes)
    }

    $updateRingFilter = [uri]::EscapeDataString("isof('microsoft.graph.windowsUpdateForBusinessConfiguration')")
    $espFilter        = [uri]::EscapeDataString("deviceEnrollmentConfigurationType eq 'windows10EnrollmentCompletionPageConfiguration'")
    $admxFilter       = [uri]::EscapeDataString("fileName ne null")

    $collections = [ordered]@{
        # Existing policies (with assignments expanded inline)
        CompliancePolicies          = '/beta/deviceManagement/deviceCompliancePolicies?$expand=assignments'
        ConfigurationProfiles       = '/beta/deviceManagement/deviceConfigurations?$expand=assignments'
        SettingsCatalogPolicies     = '/beta/deviceManagement/configurationPolicies?$expand=assignments,settings'
        AdministrativeTemplates     = '/beta/deviceManagement/groupPolicyConfigurations?$expand=assignments'
        EndpointSecurity            = '/beta/deviceManagement/intents'
        ReusablePolicySettings      = '/beta/deviceManagement/reusablePolicySettings'
        UpdateRings                 = "/beta/deviceManagement/deviceConfigurations?`$filter=$updateRingFilter&`$expand=assignments"
        AutopilotProfiles           = '/beta/deviceManagement/windowsAutopilotDeploymentProfiles?$expand=assignments'

        # Phase A – Enrollment
        EnrollmentConfigurations    = '/beta/deviceManagement/deviceEnrollmentConfigurations?$expand=assignments'
        EnrollmentStatusPageProfiles = "/beta/deviceManagement/deviceEnrollmentConfigurations?`$filter=$espFilter&`$expand=assignments"

        # Phase C – App Protection & Configuration
        AppProtectionPolicies       = '/beta/deviceAppManagement/managedAppPolicies'
        AppConfigurations           = '/beta/deviceAppManagement/targetedManagedAppConfigurations?$expand=assignments'
        WindowsInformationProtection = '/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies?$expand=assignments'

        # Phase D – App Inventory
        MobileApps                  = '/beta/deviceAppManagement/mobileApps?$expand=assignments'
        MobileAppConfigurations     = '/beta/deviceAppManagement/mobileAppConfigurations?$expand=assignments'
        MobileAppCategories         = '/beta/deviceAppManagement/mobileAppCategories'

        # Phase E – RBAC
        RoleDefinitions             = '/beta/deviceManagement/roleDefinitions'
        RoleAssignments             = '/beta/deviceManagement/roleAssignments'
        ScopeTags                   = '/beta/deviceManagement/roleScopeTags'

        # Windows Update extras
        FeatureUpdateProfiles       = '/beta/deviceManagement/windowsFeatureUpdateProfiles?$expand=assignments'
        QualityUpdateProfiles       = '/beta/deviceManagement/windowsQualityUpdateProfiles?$expand=assignments'
        DriverUpdateProfiles        = '/beta/deviceManagement/windowsDriverUpdateProfiles?$expand=assignments'

        # Apple / Android enrollment platforms
        AppleVppTokens              = '/beta/deviceAppManagement/vppTokens'
        AppleDepOnboardingSettings  = '/beta/deviceManagement/depOnboardingSettings'
        AndroidManagedStoreSettings = '/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings'
        AndroidDeviceOwnerEnrollmentProfiles = '/beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles'

        # Updates for macOS / iOS (iOS update policies live under deviceConfigurations)
        IosUpdateConfigurations     = "/beta/deviceManagement/deviceConfigurations?`$filter=$([uri]::EscapeDataString("isof('microsoft.graph.iosUpdateConfiguration')"))&`$expand=assignments"
        MacOSSoftwareUpdateAccountSummaries = '/beta/deviceManagement/macOSSoftwareUpdateAccountSummaries'

        # Co-management & Tenant Attach
        ComanagementEligibleDevices = '/beta/deviceManagement/comanagementEligibleDevices'
        MicrosoftTunnelConfigurations = '/beta/deviceManagement/microsoftTunnelConfigurations'
        MicrosoftTunnelSites        = '/beta/deviceManagement/microsoftTunnelSites'
        # MicrosoftTunnelServers — exported separately (nested under tunnel sites)

        # Branding & ADMX
        BrandingProfiles            = '/beta/deviceManagement/intuneBrandingProfiles'
        GroupPolicyDefinitionFiles  = "/beta/deviceManagement/groupPolicyDefinitionFiles?`$filter=$admxFilter"

        # Endpoint Analytics (optional, may 500/403 if tenant hasn't onboarded) — exported separately with MaxRetries=1

        # Miscellaneous
        AssignmentFilters           = '/beta/deviceManagement/assignmentFilters'
        TermsAndConditions          = '/beta/deviceManagement/termsAndConditions'
        DeviceCategories            = '/beta/deviceManagement/deviceCategories'
        NotificationTemplates       = '/beta/deviceManagement/notificationMessageTemplates'

        # Additional Intune resources
        PolicySets                  = '/beta/deviceAppManagement/policySets?$expand=assignments'
        MobileThreatDefenseConnectors = '/beta/deviceManagement/mobileThreatDefenseConnectors'
        WindowsHelloForBusinessGlobalPolicy = '/beta/deviceManagement/deviceConfigurations?$filter=isof(''microsoft.graph.windowsIdentityProtectionConfiguration'')'
        AppleMDMPushNotificationCertificate = '/beta/deviceManagement/applePushNotificationCertificate'
        CorporateDeviceIdentifiers  = '/beta/deviceManagement/importedDeviceIdentities'
        DeviceManagementComplianceSettings  = '/beta/deviceManagement/settings'
        DeviceCleanupRules          = '/beta/deviceManagement/managedDeviceCleanupRules'
        DerivedCredentials          = '/beta/deviceManagement/derivedCredentials'
        AndroidGooglePlayEnrollment = '/beta/deviceManagement/androidForWorkSettings'

        # ── Cloud PC / Windows 365 (virtualEndpoint) ──────────────────────────
        CloudPcProvisioningPolicies = '/beta/deviceManagement/virtualEndpoint/provisioningPolicies?$expand=assignments'
        CloudPcUserSettings         = '/beta/deviceManagement/virtualEndpoint/userSettings?$expand=assignments'
        CloudPcOnPremisesConnections = '/beta/deviceManagement/virtualEndpoint/onPremisesConnections'
        CloudPcGalleryImages        = '/beta/deviceManagement/virtualEndpoint/galleryImages'
        CloudPcAzureNetworkConnections = '/beta/deviceManagement/virtualEndpoint/onPremisesConnections'
        CloudPcAuditEvents          = '/beta/deviceManagement/virtualEndpoint/auditEvents?$top=100'
        CloudPcAlertRules           = '/beta/deviceManagement/monitoring/alertRules'
        CloudPcReports              = '/beta/deviceManagement/virtualEndpoint/reports'
    }

    foreach ($name in $collections.Keys) {
        try {
            $data = @(Get-GraphCollectionItems -Uri $collections[$name])
            $targetPath = Join-Path -Path $OutputPath -ChildPath "$name.json"
            $json = ConvertTo-SafeJson -InputObject $data -Depth 20
            Set-Content -Path $targetPath -Value $json -Encoding UTF8
            Write-BackupLog -Level Information -Message "Exported Intune object: $name ($($data.Count) items)" -LogPath $LogPath
        }
        catch {
            Write-BackupLog -Level Warning -Message "Failed to export Intune object [$name]: $($_.Exception.Message)" -LogPath $LogPath
        }
    }

    # ── Script exports ────────────────────────────────────────────────────────
    # Each script is saved as individual .ps1 files inside Scripts/<name>/

    $scriptsRoot = Join-Path -Path $OutputPath -ChildPath 'Scripts'

    # DeviceManagementScripts - scriptContent (base64 PowerShell)
    try {
        $mgmtScripts = Get-GraphCollectionItems -Uri '/beta/deviceManagement/deviceManagementScripts'
        $mgmtScriptsAll = New-Object System.Collections.Generic.List[object]
        foreach ($script in $mgmtScripts) {
            $scriptDetails = $script
            if (-not [string]::IsNullOrWhiteSpace($script.id)) {
                $detail = Invoke-GraphRequestWithRetry -Uri "/beta/deviceManagement/deviceManagementScripts/$($script.id)" -LogPath $LogPath
                if ($detail -is [System.Collections.IDictionary]) { $detail = [pscustomobject]$detail }
                $scriptDetails = $detail
            }
            $mgmtScriptsAll.Add($scriptDetails) | Out-Null

            $safeName  = Get-SafeItemName -Item $script
            $scriptDir = Join-Path -Path $scriptsRoot -ChildPath $safeName
            New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null

            # Save metadata (without the large base64 blob)
            $meta = $scriptDetails | Select-Object -Property * -ExcludeProperty scriptContent
            ConvertTo-SafeJson -InputObject $meta -Depth 20 | Set-Content -Path (Join-Path $scriptDir 'metadata.json') -Encoding UTF8

            # Decode and save script body
            Write-Base64File -Path (Join-Path $scriptDir 'Script.ps1') -Base64Content ([string]$scriptDetails.scriptContent)
        }
        # Consolidated JSON at Intune root (full details including base64 content)
        ConvertTo-SafeJson -InputObject @($mgmtScriptsAll.ToArray()) -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'DeviceManagementScripts.json') -Encoding UTF8
        Write-BackupLog -Level Information -Message "Exported Intune Scripts ($(@($mgmtScripts).Count) scripts)" -LogPath $LogPath
    }
    catch {
        Write-BackupLog -Level Warning -Message "Failed to export Intune DeviceManagementScripts: $($_.Exception.Message)" -LogPath $LogPath
    }

    # DeviceHealthScripts - detectionScriptContent + remediationScriptContent (base64)
    try {
        $healthScripts = Get-GraphCollectionItems -Uri '/beta/deviceManagement/deviceHealthScripts'
        $healthScriptsAll = New-Object System.Collections.Generic.List[object]
        foreach ($script in $healthScripts) {
            $scriptDetails = $script
            if (-not [string]::IsNullOrWhiteSpace($script.id)) {
                $detail = Invoke-GraphRequestWithRetry -Uri "/beta/deviceManagement/deviceHealthScripts/$($script.id)" -LogPath $LogPath
                if ($detail -is [System.Collections.IDictionary]) { $detail = [pscustomobject]$detail }
                $scriptDetails = $detail
            }
            $healthScriptsAll.Add($scriptDetails) | Out-Null

            $safeName  = Get-SafeItemName -Item $script
            $scriptDir = Join-Path -Path $scriptsRoot -ChildPath $safeName
            New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null

            $meta = $scriptDetails | Select-Object -Property * -ExcludeProperty detectionScriptContent, remediationScriptContent
            ConvertTo-SafeJson -InputObject $meta -Depth 20 | Set-Content -Path (Join-Path $scriptDir 'metadata.json') -Encoding UTF8

            Write-Base64File -Path (Join-Path $scriptDir 'Detection.ps1') -Base64Content ([string]$scriptDetails.detectionScriptContent)
            Write-Base64File -Path (Join-Path $scriptDir 'Remediation.ps1') -Base64Content ([string]$scriptDetails.remediationScriptContent)
        }
        ConvertTo-SafeJson -InputObject @($healthScriptsAll.ToArray()) -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'DeviceHealthScripts.json') -Encoding UTF8
        Write-BackupLog -Level Information -Message "Exported Intune DeviceHealthScripts ($(@($healthScripts).Count) scripts)" -LogPath $LogPath
    }
    catch {
        Write-BackupLog -Level Warning -Message "Failed to export Intune DeviceHealthScripts: $($_.Exception.Message)" -LogPath $LogPath
    }

    # ShellScripts (macOS) - scriptContent (base64 shell script)
    try {
        $shellScripts = Get-GraphCollectionItems -Uri '/beta/deviceManagement/deviceShellScripts'
        $shellScriptsAll = New-Object System.Collections.Generic.List[object]
        foreach ($script in $shellScripts) {
            $scriptDetails = $script
            if (-not [string]::IsNullOrWhiteSpace($script.id)) {
                $detail = Invoke-GraphRequestWithRetry -Uri "/beta/deviceManagement/deviceShellScripts/$($script.id)" -LogPath $LogPath
                if ($detail -is [System.Collections.IDictionary]) { $detail = [pscustomobject]$detail }
                $scriptDetails = $detail
            }
            $shellScriptsAll.Add($scriptDetails) | Out-Null

            $safeName  = Get-SafeItemName -Item $script
            $scriptDir = Join-Path -Path $scriptsRoot -ChildPath $safeName
            New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null

            $meta = $scriptDetails | Select-Object -Property * -ExcludeProperty scriptContent
            ConvertTo-SafeJson -InputObject $meta -Depth 20 | Set-Content -Path (Join-Path $scriptDir 'metadata.json') -Encoding UTF8

            Write-Base64File -Path (Join-Path $scriptDir 'Script.sh') -Base64Content ([string]$scriptDetails.scriptContent)
        }
        ConvertTo-SafeJson -InputObject @($shellScriptsAll.ToArray()) -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'ShellScripts.json') -Encoding UTF8
        Write-BackupLog -Level Information -Message "Exported Intune ShellScripts ($(@($shellScripts).Count) scripts)" -LogPath $LogPath
    }
    catch {
        Write-BackupLog -Level Warning -Message "Failed to export Intune ShellScripts: $($_.Exception.Message)" -LogPath $LogPath
    }

    # DeviceComplianceScripts (Win/Linux) - detectionScriptContent (base64) + JSON detection rules
    try {
        $complianceScripts = Get-GraphCollectionItems -Uri '/beta/deviceManagement/deviceComplianceScripts'
        $complianceScriptsAll = New-Object System.Collections.Generic.List[object]
        foreach ($script in $complianceScripts) {
            $scriptDetails = $script
            if (-not [string]::IsNullOrWhiteSpace($script.id)) {
                $detail = Invoke-GraphRequestWithRetry -Uri "/beta/deviceManagement/deviceComplianceScripts/$($script.id)" -LogPath $LogPath
                if ($detail -is [System.Collections.IDictionary]) { $detail = [pscustomobject]$detail }
                $scriptDetails = $detail
            }
            $complianceScriptsAll.Add($scriptDetails) | Out-Null

            $safeName  = Get-SafeItemName -Item $script
            $scriptDir = Join-Path -Path $scriptsRoot -ChildPath $safeName
            New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null

            $meta = $scriptDetails | Select-Object -Property * -ExcludeProperty detectionScriptContent
            ConvertTo-SafeJson -InputObject $meta -Depth 20 | Set-Content -Path (Join-Path $scriptDir 'metadata.json') -Encoding UTF8

            Write-Base64File -Path (Join-Path $scriptDir 'Detection.ps1') -Base64Content ([string]$scriptDetails.detectionScriptContent)
        }
        ConvertTo-SafeJson -InputObject @($complianceScriptsAll.ToArray()) -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'DeviceComplianceScripts.json') -Encoding UTF8
        Write-BackupLog -Level Information -Message "Exported Intune DeviceComplianceScripts ($(@($complianceScripts).Count) scripts)" -LogPath $LogPath
    }
    catch {
        Write-BackupLog -Level Warning -Message "Failed to export Intune DeviceComplianceScripts: $($_.Exception.Message)" -LogPath $LogPath
    }

    # ── Windows Autopilot Device Identities (hardware hashes) ─────────────────
    # Saves both full JSON (with all metadata) and a portal-importable CSV.
    # NOTE: hardwareIdentifier is NOT returned by the list endpoint — must GET each device individually.
    try {
        $autopilotDevicesList = Get-GraphCollectionItems -Uri '/beta/deviceManagement/windowsAutopilotDeviceIdentities'
        $autopilotDevicesArr = New-Object System.Collections.Generic.List[object]
        foreach ($d in $autopilotDevicesList) {
            if ([string]::IsNullOrWhiteSpace($d.id)) { continue }
            if ($SkipAutopilotHardwareHash) {
                $autopilotDevicesArr.Add($d) | Out-Null
                continue
            }
            try {
                $detail = Invoke-GraphRequestWithRetry -Uri "/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($d.id)" -LogPath $LogPath
                if ($detail -is [System.Collections.IDictionary]) { $detail = [pscustomobject]$detail }

                # hardwareIdentifier is not returned unless explicitly $select'd. NOTE: Microsoft Graph
                # has made this property write-only on most tenants — the request returns 400/empty even
                # with proper permissions. Hashes can only be re-collected from devices via
                # Get-WindowsAutopilotInfo / OA3Tool. We attempt the call and log info on failure.
                try {
                    $hashResp = Invoke-GraphRequestWithRetry -Uri "/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($d.id)?`$select=hardwareIdentifier" -MaxRetries 1 -LogPath $LogPath
                    $hashValue = $null
                    if ($hashResp -is [System.Collections.IDictionary] -and $hashResp.Contains('hardwareIdentifier')) {
                        $hashValue = [string]$hashResp['hardwareIdentifier']
                    }
                    elseif ($hashResp -and $hashResp.PSObject.Properties['hardwareIdentifier']) {
                        $hashValue = [string]$hashResp.hardwareIdentifier
                    }
                    $detail | Add-Member -MemberType NoteProperty -Name 'hardwareIdentifier' -Value $hashValue -Force
                }
                catch {
                    # Expected on most tenants — Graph returns 400 for hardwareIdentifier reads.
                    $detail | Add-Member -MemberType NoteProperty -Name 'hardwareIdentifier' -Value $null -Force
                }

                $autopilotDevicesArr.Add($detail) | Out-Null
            }
            catch {
                Write-BackupLog -Level Warning -Message "Failed to read Autopilot device [$($d.id)]: $($_.Exception.Message)" -LogPath $LogPath
                $autopilotDevicesArr.Add($d) | Out-Null
            }
        }

        ConvertTo-SafeJson -InputObject @($autopilotDevicesArr.ToArray()) -Depth 20 |
            Set-Content -Path (Join-Path $OutputPath 'AutopilotDevices.json') -Encoding UTF8

        # Intune-portal-compatible CSV: Device Serial Number, Windows Product ID, Hardware Hash, Group Tag
        $csvRows = foreach ($d in $autopilotDevicesArr) {
            $hwHash = ''
            if ($d.PSObject.Properties['hardwareIdentifier']) { $hwHash = [string]$d.hardwareIdentifier }
            [pscustomobject]@{
                'Device Serial Number' = [string]$d.serialNumber
                'Windows Product ID'   = ''
                'Hardware Hash'        = $hwHash
                'Group Tag'            = [string]$d.groupTag
            }
        }
        $csvPath = Join-Path -Path $OutputPath -ChildPath 'AutopilotDevices.csv'
        if ($csvRows) {
            $csvRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        }
        else {
            'Device Serial Number,Windows Product ID,Hardware Hash,Group Tag' |
                Set-Content -Path $csvPath -Encoding UTF8
        }

        Write-BackupLog -Level Information -Message "Exported Intune AutopilotDevices ($($autopilotDevicesArr.Count) devices) [JSON + CSV]" -LogPath $LogPath
        $hashCount = @($autopilotDevicesArr | Where-Object { -not [string]::IsNullOrEmpty([string]$_.hardwareIdentifier) }).Count
        if ($hashCount -eq 0 -and $autopilotDevicesArr.Count -gt 0 -and -not $SkipAutopilotHardwareHash) {
            Write-BackupLog -Level Information -Message "Note: Microsoft Graph does not return hardwareIdentifier for already-registered Autopilot devices. To re-collect hashes, run Get-WindowsAutopilotInfo on each device." -LogPath $LogPath
        }
    }
    catch {
        Write-BackupLog -Level Warning -Message "Failed to export Intune AutopilotDevices: $($_.Exception.Message)" -LogPath $LogPath
    }

    # ── Microsoft Tunnel Servers (nested per site) ────────────────────────────
    try {
        $tunnelSites = Get-GraphCollectionItems -Uri '/beta/deviceManagement/microsoftTunnelSites'
        $tunnelServersAll = New-Object System.Collections.Generic.List[object]
        foreach ($site in $tunnelSites) {
            if ([string]::IsNullOrWhiteSpace($site.id)) { continue }
            try {
                $servers = Get-GraphCollectionItems -Uri "/beta/deviceManagement/microsoftTunnelSites/$($site.id)/microsoftTunnelServers"
                foreach ($s in $servers) {
                    $s | Add-Member -MemberType NoteProperty -Name '_tunnelSiteId' -Value $site.id -Force
                    $tunnelServersAll.Add($s) | Out-Null
                }
            }
            catch {
                Write-BackupLog -Level Warning -Message "Failed to read tunnel servers for site [$($site.id)]: $($_.Exception.Message)" -LogPath $LogPath
            }
        }
        ConvertTo-SafeJson -InputObject @($tunnelServersAll.ToArray()) -Depth 20 |
            Set-Content -Path (Join-Path $OutputPath 'MicrosoftTunnelServers.json') -Encoding UTF8
        Write-BackupLog -Level Information -Message "Exported Intune MicrosoftTunnelServers ($($tunnelServersAll.Count) servers across $(@($tunnelSites).Count) sites)" -LogPath $LogPath
    }
    catch {
        Write-BackupLog -Level Warning -Message "Failed to export Intune MicrosoftTunnelServers: $($_.Exception.Message)" -LogPath $LogPath
    }

    # ── Apple DEP enrollment profiles per token ───────────────────────────────
    try {
        $depTokens = Get-GraphCollectionItems -Uri '/beta/deviceManagement/depOnboardingSettings'
        $depProfilesAll = New-Object System.Collections.Generic.List[object]
        foreach ($token in $depTokens) {
            if ([string]::IsNullOrWhiteSpace($token.id)) { continue }
            try {
                $profiles = Get-GraphCollectionItems -Uri "/beta/deviceManagement/depOnboardingSettings/$($token.id)/enrollmentProfiles"
                foreach ($p in $profiles) {
                    $p | Add-Member -MemberType NoteProperty -Name '_depTokenId' -Value $token.id -Force
                    $depProfilesAll.Add($p) | Out-Null
                }
            }
            catch {
                Write-BackupLog -Level Warning -Message "Failed to read DEP enrollment profiles for token [$($token.id)]: $($_.Exception.Message)" -LogPath $LogPath
            }
        }
        ConvertTo-SafeJson -InputObject @($depProfilesAll.ToArray()) -Depth 20 |
            Set-Content -Path (Join-Path $OutputPath 'AppleDepEnrollmentProfiles.json') -Encoding UTF8
        Write-BackupLog -Level Information -Message "Exported Intune AppleDepEnrollmentProfiles ($($depProfilesAll.Count) profiles across $(@($depTokens).Count) tokens)" -LogPath $LogPath
    }
    catch {
        Write-BackupLog -Level Warning -Message "Failed to export Intune AppleDepEnrollmentProfiles: $($_.Exception.Message)" -LogPath $LogPath
    }

    # ── Endpoint Analytics (best-effort, no retries) ──────────────────────────
    # These return HTTP 500 on tenants that haven't onboarded UEA. Don't waste time retrying.
    $ueaEndpoints = [ordered]@{
        UserExperienceAnalyticsBaselines  = '/beta/deviceManagement/userExperienceAnalyticsBaselines'
        UserExperienceAnalyticsCategories = '/beta/deviceManagement/userExperienceAnalyticsCategories'
    }
    foreach ($name in $ueaEndpoints.Keys) {
        try {
            $response = Invoke-GraphRequestWithRetry -Uri $ueaEndpoints[$name] -MaxRetries 1 -LogPath $LogPath
            $items = @()
            if ($response -is [System.Collections.IDictionary]) {
                if ($response.Contains('value')) { $items = @($response['value']) } else { $items = @($response) }
            }
            elseif ($response.PSObject.Properties.Name -contains 'value') {
                $items = @($response.value)
            }
            $normalized = @(
                foreach ($i in $items) {
                    if ($i -is [System.Collections.IDictionary]) { [pscustomobject]$i } else { $i }
                }
            )
            ConvertTo-SafeJson -InputObject $normalized -Depth 20 |
                Set-Content -Path (Join-Path $OutputPath "$name.json") -Encoding UTF8
            Write-BackupLog -Level Information -Message "Exported Intune object: $name ($($normalized.Count) items)" -LogPath $LogPath
        }
        catch {
            Write-BackupLog -Level Information -Message "Skipped Intune object [$name] (Endpoint Analytics likely not onboarded): $($_.Exception.Message)" -LogPath $LogPath
        }
    }
}
