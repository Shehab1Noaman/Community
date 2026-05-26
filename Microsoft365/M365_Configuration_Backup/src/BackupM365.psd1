@{
    RootModule             = 'BackupM365.psm1'
    ModuleVersion          = '1.0.0'
    GUID                   = '2d33707f-e7cb-453f-bbee-2291ccf8fc44'
    Author                 = 'Shehab Noaman'
    CompanyName            = 'SysadminHub.info'
    Copyright              = '(c) 2026 Shehab Noaman / SysadminHub.info. All rights reserved.'
    Description            = 'Tenant configuration backup and restore framework for Microsoft 365. Export, compare, and restore EntraID, Exchange Online, Teams, SharePoint, Intune, Compliance, Defender, Power Platform, Planner, and Users configuration using Microsoft Graph and workload-specific PowerShell modules.'
    PowerShellVersion      = '7.2'
    CompatiblePSEditions   = @('Core')

    FunctionsToExport = @(
        'Connect-M365Tenant',
        'Disconnect-M365Tenant',
        'Test-M365BackupPrerequisites',
        'Export-M365TenantConfig',
        'Import-M365TenantConfig',
        'Restore-M365TenantConfig',
        'Compare-M365TenantConfig',
        'Get-M365BackupCatalog',
        'Test-M365BackupIntegrity',
        'Compare-M365BackupSnapshot',
        'New-M365BackupDelta',
        'New-M365RestorePlan',
        'Invoke-M365DeltaRestore',
        'New-M365RecoveryPack',
        'Export-EntraConfig',
        'Export-ExchangeConfig',
        'Export-TeamsConfig',
        'Export-SharePointConfig',
        'Export-IntuneConfig',
        'Export-ComplianceConfig',
        'Export-DefenderConfig',
        'Export-PowerPlatformConfig',
        'Export-PlannerConfig',
        'Export-UsersConfig',
        'New-M365BackupCertificate',
        'New-M365BackupApp',
        'New-M365RestoreApp'
    )

    PrivateData = @{
        PSData = @{
            Tags       = @(
                'Microsoft365', 'M365', 'Backup', 'Restore', 'PowerShell', 'Automation',
                'EntraID', 'AzureAD', 'Intune', 'ExchangeOnline', 'Teams', 'SharePoint',
                'Compliance', 'Defender', 'Planner', 'Governance', 'Configuration',
                'DisasterRecovery', 'ITAdmin'
            )
            ProjectUri   = 'https://github.com/Shehab1Noaman/BackupM365'
            LicenseUri   = 'https://github.com/Shehab1Noaman/BackupM365/blob/main/LICENSE'
            ReleaseNotes = @'
## 1.0.0 — Initial public release (April 2026)

### New features
- Full tenant backup via `Export-M365TenantConfig` covering 10 workloads:
  EntraID, Exchange Online, Teams, SharePoint, Intune, Compliance (Purview),
  Defender, Power Platform, Planner, and Users.
- Workload-level restore via `Restore-M365TenantConfig` and `Import-M365TenantConfig`.
- Snapshot comparison via `Compare-M365TenantConfig` and `Compare-M365BackupSnapshot`.
- Delta manifest generation via `New-M365BackupDelta` and delta-targeted restore via
  `Invoke-M365DeltaRestore`.
- Recovery pack scenarios (FullTenant, IntuneBaseline, TeamsCore, SharePointTenant,
  IdentityCore) via `New-M365RecoveryPack`.
- Backup catalog and integrity reporting via `Get-M365BackupCatalog` and
  `Test-M365BackupIntegrity`.
- Certificate-based app-only authentication setup cmdlets (`New-M365BackupCertificate` +
  `New-M365BackupApp`) with PFX export and automatic module installation.
- Prerequisite checker (`Test-M365BackupPrerequisites`) with `-InstallMissingModules`
  auto-install support.
- Throttle-aware Graph request helper with exponential back-off and jitter.
'@
            ExternalModuleDependencies = @(
                'Microsoft.Graph.Authentication',
                'Microsoft.Graph.Identity.DirectoryManagement',
                'ExchangeOnlineManagement',
                'MicrosoftTeams',
                'Microsoft.Online.SharePoint.PowerShell',
                'PnP.PowerShell'
            )
        }
    }
}
