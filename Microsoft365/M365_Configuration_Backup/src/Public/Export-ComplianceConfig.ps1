function Export-ComplianceConfig {
    <#
    .SYNOPSIS
        Exports Microsoft Purview / Security & Compliance Center configuration.
    .DESCRIPTION
        Requires an active Connect-IPPSSession (Security & Compliance PowerShell).
        Use Connect-M365Tenant -ConnectCompliance to establish that session.
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

    $map = [ordered]@{
        # Sensitivity labels & policies
        SensitivityLabels                = { Get-Label }
        SensitivityLabelPolicies         = { Get-LabelPolicy }
        AutoSensitivityLabelPolicies     = { Get-AutoSensitivityLabelPolicy }
        AutoSensitivityLabelRules        = { Get-AutoSensitivityLabelPolicy | ForEach-Object { Get-AutoSensitivityLabelRule -Policy $_.Name -ErrorAction SilentlyContinue } }

        # Retention
        RetentionCompliancePolicies      = { Get-RetentionCompliancePolicy }
        RetentionComplianceRules         = { Get-RetentionCompliancePolicy | ForEach-Object { Get-RetentionComplianceRule -Policy $_.Name -ErrorAction SilentlyContinue } }
        ComplianceRetentionEvents        = { Get-ComplianceRetentionEvent }
        ComplianceRetentionEventTypes    = { Get-RetentionComplianceEventType }
        ComplianceTags                   = { Get-ComplianceTag }
        FilePlanProperties               = { Get-FilePlanProperty }
        FilePlanPropertyAuthorities      = { Get-FilePlanPropertyAuthority }
        FilePlanPropertyCategories       = { Get-FilePlanPropertyCategory }
        FilePlanPropertyCitations        = { Get-FilePlanPropertyCitation }
        FilePlanPropertyDepartments      = { Get-FilePlanPropertyDepartment }
        FilePlanPropertyReferenceIds     = { Get-FilePlanPropertyReferenceId }
        FilePlanPropertySubCategories    = { Get-FilePlanPropertySubCategory }
        AdaptiveScopes                   = { Get-AdaptiveScope }

        # DLP
        DlpCompliancePolicies            = { Get-DlpCompliancePolicy }
        DlpComplianceRules               = { Get-DlpComplianceRule }
        DlpSensitiveInfoTypes            = { Get-DlpSensitiveInformationType }
        DlpKeywordDictionaries           = { Get-DlpKeywordDictionary }
        DlpEdmSchemas                    = { Get-DlpEdmSchema }

        # Information Barriers
        InformationBarrierPolicies       = { Get-InformationBarrierPolicy }
        InformationBarrierSegments       = { Get-OrganizationSegment }

        # Insider Risk
        InsiderRiskPolicies              = { Get-InsiderRiskPolicy }
        InsiderRiskEntityLists           = {
            # Get-InsiderRiskEntityList requires either -Identity or -Type per call. Iterate the
            # known entity types and aggregate; tenants without IRM licensing simply return empty.
            $entityTypes = @('SensitiveInfoTypes','PriorityUserGroups','PriorityAssetGroups','HighRiskUsers','TrainableClassifiers')
            $items = @()
            foreach ($t in $entityTypes) {
                try { $items += @(Get-InsiderRiskEntityList -Type $t -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Type = $t; Value = $_ } }) }
                catch { }
            }
            $items
        }

        # Communication compliance / supervision
        SupervisoryReviewPolicies        = { Get-SupervisoryReviewPolicyV2 }
        SupervisoryReviewRules           = { Get-SupervisoryReviewPolicyV2 | ForEach-Object { Get-SupervisoryReviewRule -Policy $_.Name -ErrorAction SilentlyContinue } }

        # eDiscovery (metadata only)
        ComplianceCases                  = { Get-ComplianceCase }
        ComplianceSearches               = { Get-ComplianceSearch }
        ComplianceSearchActions          = { Get-ComplianceSearch | ForEach-Object { Get-ComplianceSearchAction -SearchName $_.Name -ErrorAction SilentlyContinue } }

        # Holds
        CaseHoldPolicies                 = { Get-CaseHoldPolicy }
        CaseHoldRules                    = { Get-CaseHoldPolicy | ForEach-Object { Get-CaseHoldRule -Policy $_.Name -ErrorAction SilentlyContinue } }

        # Audit
        AuditConfigurationPolicies       = { Get-AuditConfigurationPolicy }
        UnifiedAuditLogRetentionPolicies = { Get-UnifiedAuditLogRetentionPolicy }

        # Activity alerts
        ActivityAlerts                   = { Get-ActivityAlert }
        ProtectionAlerts                 = { Get-ProtectionAlert }

        # SC RBAC / policy infra / additional
        PolicyConfig                     = { Get-PolicyConfig }
        SCRoleGroups                     = { Get-RoleGroup }
        SCRoleGroupMembers               = { Get-RoleGroup | ForEach-Object { Get-RoleGroupMember -Identity $_.Name | Select-Object @{n='RoleGroup';e={$_.Identity}}, @{n='Member';e={$_.Name}}, RecipientType } }
        SecurityFilters                  = { Get-SecurityFilter }
        RecordReviewNotificationTemplate = { Get-RecordReviewNotificationTemplateConfig }
    }

    foreach ($name in $map.Keys) {
        $cmd = $map[$name]
        try {
            $cmdSource = $cmd.ToString()
            $firstCmd = ($cmdSource -split '[\s\|;{}\r\n]+' | Where-Object { $_ -like 'Get-*' } | Select-Object -First 1)
            if ($firstCmd -and -not (Get-Command -Name $firstCmd -ErrorAction SilentlyContinue)) {
                Write-BackupLog -Level Information -Message "Skipped Compliance object [$name] (cmdlet $firstCmd not available; ensure Connect-IPPSSession is active)" -LogPath $LogPath
                continue
            }

            $result = Invoke-WithThrottleRetry -OperationName "Compliance $name" -LogPath $LogPath -ScriptBlock $cmd
            ConvertTo-SafeJson -InputObject @($result) -Depth 20 |
                Set-Content -Path (Join-Path $OutputPath "$name.json") -Encoding UTF8
            Write-BackupLog -Level Information -Message "Exported Compliance object: $name" -LogPath $LogPath
        }
        catch {
            Write-BackupLog -Level Warning -Message "Failed to export Compliance object [$name]: $($_.Exception.Message)" -LogPath $LogPath
        }
    }
}
