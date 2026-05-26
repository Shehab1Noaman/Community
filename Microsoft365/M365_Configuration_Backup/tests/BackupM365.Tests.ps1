Import-Module "$PSScriptRoot/../src/BackupM365.psd1" -Force

Describe 'BackupM365 module surface' {
    It 'exports required public functions' {
        $required = @(
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
            'Export-UsersConfig'
        )

        foreach ($fn in $required) {
            Get-Command -Name $fn -ErrorAction Stop | Should -Not -BeNullOrEmpty
        }
    }

    It 'creates output folders through prerequisite check' {
        $tempRoot = Join-Path -Path $TestDrive -ChildPath 'output'
        $result = Test-M365BackupPrerequisites -OutputPath $tempRoot -CreateMissingFolders

        $result | Should -Not -BeNullOrEmpty
        (Test-Path -Path (Join-Path $tempRoot 'Backups')) | Should -BeTrue
        (Test-Path -Path (Join-Path $tempRoot 'Logs')) | Should -BeTrue
    }
}

Describe 'Test-M365BackupPrerequisites extended checks' {

    It 'returns legacy shape when no -Config supplied' {
        $tempRoot = Join-Path -Path $TestDrive -ChildPath 'legacy'
        $result = Test-M365BackupPrerequisites -OutputPath $tempRoot -CreateMissingFolders
        $result.PSObject.Properties.Name -contains 'Modules'                     | Should -BeTrue
        $result.PSObject.Properties.Name -contains 'AllRequiredModulesInstalled' | Should -BeTrue
        $result.PSObject.Properties.Name -contains 'OutputPath'                  | Should -BeTrue
        @($result.Configuration).Count | Should -Be 0
        @($result.Certificates).Count  | Should -Be 0
        $result.Source                  | Should -BeNullOrEmpty
        $result.Permissions             | Should -BeNullOrEmpty
    }

    It 'flags missing tenantId and missing credential when config is empty' {
        $tempRoot = Join-Path -Path $TestDrive -ChildPath 'cfg-empty'
        New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null
        $cfg = [PSCustomObject]@{
            tenant         = [PSCustomObject]@{ tenantId = ''; tenantName = '' }
            authentication = [PSCustomObject]@{ clientId = '' }
            prechecks      = [PSCustomObject]@{
                checkGraphPermissions   = $false
                requireValidCertificate = $false
                requireWritableOutput   = $false
            }
        }
        $result = Test-M365BackupPrerequisites -OutputPath $tempRoot -Config $cfg -Mode Backup
        ($result.Issues -join ';') | Should -Match 'tenantId is missing'
        ($result.Issues -join ';') | Should -Match 'clientId is missing'
        ($result.Issues -join ';') | Should -Match 'neither certificateThumbprint nor clientSecret'
        $result.AllChecksPassed    | Should -BeFalse
    }

    It 'flags missing certificate by thumbprint' {
        $tempRoot = Join-Path -Path $TestDrive -ChildPath 'cert-missing'
        New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null
        $cfg = [PSCustomObject]@{
            tenant         = [PSCustomObject]@{ tenantId = '00000000-0000-0000-0000-000000000001'; tenantName = 'fake.onmicrosoft.com' }
            authentication = [PSCustomObject]@{ clientId = '11111111-1111-1111-1111-111111111111'; certificateThumbprint = 'DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF' }
            prechecks      = [PSCustomObject]@{ checkGraphPermissions = $false; requireWritableOutput = $false }
        }
        $result = Test-M365BackupPrerequisites -OutputPath $tempRoot -Config $cfg -Mode Backup
        ($result.Issues -join ';') | Should -Match 'Certificate thumbprint \[DEADBEEF.*\] for config\.authentication not found'
    }

    It 'flags missing backup source for Restore mode' {
        $tempRoot = Join-Path -Path $TestDrive -ChildPath 'src-missing'
        New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null
        $cfg = [PSCustomObject]@{
            target         = [PSCustomObject]@{ tenantId = '00000000-0000-0000-0000-000000000001'; tenantName = 'fake.onmicrosoft.com' }
            authentication = [PSCustomObject]@{ clientId = '11111111-1111-1111-1111-111111111111'; clientSecret = 'x' }
            source         = [PSCustomObject]@{ backupPath = (Join-Path $TestDrive 'does-not-exist') }
            prechecks      = [PSCustomObject]@{
                checkGraphPermissions   = $false
                requireValidCertificate = $false
            }
        }
        $result = Test-M365BackupPrerequisites -OutputPath $tempRoot -Config $cfg -Mode Restore
        ($result.Issues -join ';') | Should -Match 'Backup source not found'
    }

    It 'detects writable output directory' {
        $tempRoot = Join-Path -Path $TestDrive -ChildPath 'writable'
        New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null
        $cfg = [PSCustomObject]@{
            tenant         = [PSCustomObject]@{ tenantId = '00000000-0000-0000-0000-000000000001'; tenantName = 'fake.onmicrosoft.com' }
            authentication = [PSCustomObject]@{ clientId = '11111111-1111-1111-1111-111111111111'; clientSecret = 'x' }
            prechecks      = [PSCustomObject]@{
                checkGraphPermissions   = $false
                requireValidCertificate = $false
            }
        }
        $result = Test-M365BackupPrerequisites -OutputPath $tempRoot -Config $cfg -Mode Backup
        $result.Output.Writable | Should -BeTrue
    }

    It 'honors prechecks toggles to disable individual checks' {
        $tempRoot = Join-Path -Path $TestDrive -ChildPath 'toggles-off'
        New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null
        $cfg = [PSCustomObject]@{
            tenant         = [PSCustomObject]@{ tenantId = ''; tenantName = '' }
            authentication = [PSCustomObject]@{ clientId = '' }
            prechecks      = [PSCustomObject]@{
                requireValidConfig      = $false
                requireValidCertificate = $false
                requireWritableOutput   = $false
                checkGraphPermissions   = $false
            }
        }
        $result = Test-M365BackupPrerequisites -OutputPath $tempRoot -Config $cfg -Mode Backup
        @($result.Configuration).Count | Should -Be 0
        @($result.Certificates).Count  | Should -Be 0
        $result.Output      | Should -BeNullOrEmpty
        $result.Permissions | Should -BeNullOrEmpty
    }
}

Describe 'Backup feature behavior' {
    BeforeAll {
        function script:New-TestSnapshot {
            param(
                [Parameter(Mandatory)] [string]$Root,
                [Parameter(Mandatory)] [string]$Tenant,
                [Parameter(Mandatory)] [string]$Snapshot,
                [Parameter(Mandatory)] [string]$Workload,
                [Parameter(Mandatory)] [string]$ObjectType,
                [Parameter(Mandatory)] [object[]]$Items,
                [string]$Status = 'Success'
            )

            $snapshotPath = Join-Path -Path (Join-Path -Path $Root -ChildPath $Tenant) -ChildPath $Snapshot
            $workloadPath = Join-Path -Path $snapshotPath -ChildPath $Workload
            New-Item -Path $workloadPath -ItemType Directory -Force | Out-Null

            [pscustomobject]@{
                TenantName      = $Tenant
                TenantId        = '00000000-0000-0000-0000-000000000001'
                BackupTimestamp = (Get-Date).ToString('o')
                IncludedWorkloads = @($Workload)
                Status          = $Status
            } | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $snapshotPath 'metadata.json') -Encoding UTF8

            [pscustomobject]@{ value = @($Items) } | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $workloadPath "$ObjectType.json") -Encoding UTF8
            return $snapshotPath
        }
    }

    AfterAll {
        Remove-Item -Path Function:\New-TestSnapshot -ErrorAction SilentlyContinue
    }

    It 'returns catalog entries and object names' {
        $root = Join-Path -Path $TestDrive -ChildPath 'Backups'
        New-TestSnapshot -Root $root -Tenant 'contoso.onmicrosoft.com' -Snapshot '20260101-010101' -Workload 'Users' -ObjectType 'Users' -Items @(
            [pscustomobject]@{ displayName = 'User One'; userPrincipalName = 'one@contoso.com' }
            [pscustomobject]@{ displayName = 'User Two'; userPrincipalName = 'two@contoso.com' }
        ) | Out-Null

        $catalog = Get-M365BackupCatalog -RootPath $root -TenantName 'contoso.onmicrosoft.com' -IncludeObjects
        $catalog | Should -Not -BeNullOrEmpty
        @($catalog).Count | Should -Be 1
        $catalog[0].Workload | Should -Be 'Users'
        $catalog[0].ObjectType | Should -Be 'Users'
        $catalog[0].ItemCount | Should -Be 2
        @($catalog[0].ObjectNames).Count | Should -Be 2
    }

    It 'detects added changed and removed files between snapshots' {
        $reference = Join-Path -Path $TestDrive -ChildPath 'ref'
        $difference = Join-Path -Path $TestDrive -ChildPath 'diff'

        New-Item -Path (Join-Path $reference 'EntraID') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $reference 'Teams') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $difference 'EntraID') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $difference 'SharePoint') -ItemType Directory -Force | Out-Null

        '[{"id":"1","displayName":"A"}]'.Replace('\"','"') | Set-Content -Path (Join-Path $reference 'EntraID/Users.json') -Encoding UTF8
        '[{"id":"1","displayName":"B"}]'.Replace('\"','"') | Set-Content -Path (Join-Path $difference 'EntraID/Users.json') -Encoding UTF8
        '[{"id":"t1"}]' | Set-Content -Path (Join-Path $reference 'Teams/MeetingPolicies.json') -Encoding UTF8
        '[{"id":"s1"}]' | Set-Content -Path (Join-Path $difference 'SharePoint/Sites.json') -Encoding UTF8

        $result = Compare-M365BackupSnapshot -ReferencePath $reference -DifferencePath $difference

        @($result | Where-Object { $_.Status -eq 'Changed' }).Count | Should -Be 1
        @($result | Where-Object { $_.Status -eq 'Removed' }).Count | Should -Be 1
        @($result | Where-Object { $_.Status -eq 'Added' }).Count | Should -Be 1
    }

    It 'creates compare snapshot HTML output under the derived tenant Compare folder' {
        $tenantRoot = Join-Path -Path $TestDrive -ChildPath 'contoso.onmicrosoft.com'
        $reference = Join-Path -Path $tenantRoot -ChildPath 'Backup/20260101-010101'
        $difference = Join-Path -Path $tenantRoot -ChildPath 'Backup/20260102-020202'

        New-Item -Path (Join-Path $reference 'EntraID') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $difference 'EntraID') -ItemType Directory -Force | Out-Null

        '[{"id":"1","displayName":"A"}]' | Set-Content -Path (Join-Path $reference 'EntraID/Users.json') -Encoding UTF8
        '[{"id":"1","displayName":"B"}]' | Set-Content -Path (Join-Path $difference 'EntraID/Users.json') -Encoding UTF8

        $result = @(Compare-M365BackupSnapshot -ReferencePath $reference -DifferencePath $difference)

        $compareRoot = Join-Path -Path $tenantRoot -ChildPath 'Compare'
        $runFolder = Get-ChildItem -Path $compareRoot -Directory | Select-Object -First 1

        $result.Count | Should -Be 1
        $runFolder | Should -Not -BeNullOrEmpty
        (Test-Path -Path (Join-Path $runFolder.FullName 'Compare-20260102-020202.html')) | Should -BeTrue
        (Test-Path -Path (Join-Path $runFolder.FullName 'Logs/compare-report.json')) | Should -BeTrue
        (Test-Path -Path (Join-Path $runFolder.FullName 'Logs/compare.log.ndjson')) | Should -BeTrue

        $htmlContent = Get-Content -Path (Join-Path $runFolder.FullName 'Compare-20260102-020202.html') -Raw
        $htmlContent | Should -Match '<table'
        $htmlContent | Should -Match '<th>Relative Path</th>'
        $htmlContent | Should -Match 'badge-changed'
    }

    It 'returns a PassThru object with artifact paths for Compare-M365BackupSnapshot' {
        $tenantRoot = Join-Path -Path $TestDrive -ChildPath 'snap-passthru.onmicrosoft.com'
        $reference = Join-Path -Path $tenantRoot -ChildPath 'Backup/20260101-010101'
        $difference = Join-Path -Path $tenantRoot -ChildPath 'Backup/20260102-020202'

        New-Item -Path (Join-Path $reference 'EntraID') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $difference 'EntraID') -ItemType Directory -Force | Out-Null

        '[{"id":"1","displayName":"A"}]' | Set-Content -Path (Join-Path $reference 'EntraID/Users.json') -Encoding UTF8
        '[{"id":"1","displayName":"B"}]' | Set-Content -Path (Join-Path $difference 'EntraID/Users.json') -Encoding UTF8

        $result = Compare-M365BackupSnapshot -ReferencePath $reference -DifferencePath $difference -PassThru

        $result | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties.Name | Should -Contain 'Items'
        $result.PSObject.Properties.Name | Should -Contain 'HtmlReportPath'
        $result.PSObject.Properties.Name | Should -Contain 'JsonReportPath'
        $result.PSObject.Properties.Name | Should -Contain 'LogPath'
        $result.PSObject.Properties.Name | Should -Contain 'Summary'
        $result.Items.Count | Should -Be 1
        $result.Summary.Changed | Should -Be 1
        (Test-Path -Path $result.HtmlReportPath) | Should -BeTrue
        (Test-Path -Path $result.JsonReportPath) | Should -BeTrue
    }

    It 'creates a delta manifest with summary counts' {
        $reference = Join-Path -Path $TestDrive -ChildPath 'ref2'
        $difference = Join-Path -Path $TestDrive -ChildPath 'diff2'
        $deltaPath = Join-Path -Path $TestDrive -ChildPath 'delta.manifest.json'

        New-Item -Path (Join-Path $reference 'EntraID') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $difference 'EntraID') -ItemType Directory -Force | Out-Null
        '[{"id":"1","displayName":"A"}]' | Set-Content -Path (Join-Path $reference 'EntraID/Users.json') -Encoding UTF8
        '[{"id":"1","displayName":"C"}]' | Set-Content -Path (Join-Path $difference 'EntraID/Users.json') -Encoding UTF8

        $delta = New-M365BackupDelta -ReferencePath $reference -DifferencePath $difference -OutputPath $deltaPath
        (Test-Path -Path $deltaPath) | Should -BeTrue
        $delta.Summary.Total | Should -BeGreaterThan 0
        $delta.Summary.Changed | Should -Be 1
    }

    It 'detects files that exist only in the current snapshot' {
        $reference = Join-Path -Path $TestDrive -ChildPath 'compare-ref-extra'
        $difference = Join-Path -Path $TestDrive -ChildPath 'compare-diff-extra'

        New-Item -Path (Join-Path $reference 'EntraID') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $difference 'EntraID') -ItemType Directory -Force | Out-Null

        '[{"id":"1"}]' | Set-Content -Path (Join-Path $reference 'EntraID/Users.json') -Encoding UTF8
        '[{"id":"1"}]' | Set-Content -Path (Join-Path $difference 'EntraID/Users.json') -Encoding UTF8
        '[{"id":"2"}]' | Set-Content -Path (Join-Path $difference 'EntraID/Groups.json') -Encoding UTF8

        $result = Compare-M365TenantConfig -ReferencePath $reference -DifferencePath $difference

        @($result | Where-Object { $_.Status -eq 'MissingInReference' -and $_.Path -eq 'EntraID\Groups.json' }).Count | Should -Be 1
    }

    It 'creates tenant compare HTML output and keeps returning diff objects' {
        $tenantRoot = Join-Path -Path $TestDrive -ChildPath 'tenant-compare-root/contoso.onmicrosoft.com'
        $reference = Join-Path -Path $tenantRoot -ChildPath 'Backup/20260101-010101'
        $difference = Join-Path -Path $tenantRoot -ChildPath 'Backup/20260102-020202'
        $outputRoot = Join-Path -Path $TestDrive -ChildPath 'custom-compare-output'

        New-Item -Path (Join-Path $reference 'EntraID') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $difference 'EntraID') -ItemType Directory -Force | Out-Null

        '{"value":[{"id":"1","displayName":"A"}]}'.Replace('\"','"') | Set-Content -Path (Join-Path $reference 'EntraID/Users.json') -Encoding UTF8
        '{"value":[{"id":"1","displayName":"B"}]}'.Replace('\"','"') | Set-Content -Path (Join-Path $difference 'EntraID/Users.json') -Encoding UTF8

        $result = @(Compare-M365TenantConfig -ReferencePath $reference -DifferencePath $difference -OutputRoot $outputRoot)

        $compareRoot = Join-Path -Path $outputRoot -ChildPath 'Compare'
        $runFolder = Get-ChildItem -Path $compareRoot -Directory | Select-Object -First 1

        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Different'
        $runFolder | Should -Not -BeNullOrEmpty
        (Test-Path -Path (Join-Path $runFolder.FullName 'Compare-contoso.onmicrosoft.com.html')) | Should -BeTrue
        (Test-Path -Path (Join-Path $runFolder.FullName 'Logs/compare-report.json')) | Should -BeTrue
        (Test-Path -Path (Join-Path $runFolder.FullName 'Logs/compare.log.ndjson')) | Should -BeTrue

        $htmlContent = Get-Content -Path (Join-Path $runFolder.FullName 'Compare-contoso.onmicrosoft.com.html') -Raw
        $htmlContent | Should -Match '<table'
        $htmlContent | Should -Match '<th>Configuration</th>'
        $htmlContent | Should -Match 'Backup \(Reference\)'
        $htmlContent | Should -Match 'full-grid'
    }

    It 'returns a PassThru object with artifact paths for Compare-M365TenantConfig' {
        $tenantRoot = Join-Path -Path $TestDrive -ChildPath 'tenant-passthru/contoso.onmicrosoft.com'
        $reference = Join-Path -Path $tenantRoot -ChildPath 'Backup/20260101-010101'
        $difference = Join-Path -Path $tenantRoot -ChildPath 'Backup/20260102-020202'

        New-Item -Path (Join-Path $reference 'EntraID') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $difference 'EntraID') -ItemType Directory -Force | Out-Null

        '{"value":[{"id":"1","displayName":"A"}]}' | Set-Content -Path (Join-Path $reference 'EntraID/Users.json') -Encoding UTF8
        '{"value":[{"id":"1","displayName":"B"}]}' | Set-Content -Path (Join-Path $difference 'EntraID/Users.json') -Encoding UTF8

        $result = Compare-M365TenantConfig -ReferencePath $reference -DifferencePath $difference -PassThru

        $result | Should -Not -BeNullOrEmpty
        $result.PSObject.Properties.Name | Should -Contain 'Items'
        $result.PSObject.Properties.Name | Should -Contain 'HtmlReportPath'
        $result.PSObject.Properties.Name | Should -Contain 'JsonReportPath'
        $result.PSObject.Properties.Name | Should -Contain 'LogPath'
        $result.PSObject.Properties.Name | Should -Contain 'Summary'
        $result.Items.Count | Should -Be 1
        $result.Summary.Different | Should -Be 1
        (Test-Path -Path $result.HtmlReportPath) | Should -BeTrue
        (Test-Path -Path $result.JsonReportPath) | Should -BeTrue
    }

    It 'builds a restore plan and flags unresolved remap references for cross-tenant restore' {
        $backupRoot = Join-Path -Path $TestDrive -ChildPath 'planBackup'
        $currentRoot = Join-Path -Path $TestDrive -ChildPath 'planCurrent'

        New-Item -Path (Join-Path $backupRoot 'SharePoint') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $currentRoot 'SharePoint') -ItemType Directory -Force | Out-Null

        [pscustomobject]@{ value = @(
            [pscustomobject]@{
                displayName = 'Site Policy A'
                siteUrl = 'https://contoso.sharepoint.com/sites/alpha'
                owner = 'owner@contoso.com'
            }
        ) } | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $backupRoot 'SharePoint/Sites.json') -Encoding UTF8

        [pscustomobject]@{ value = @(
            [pscustomobject]@{ displayName = 'Site Policy A' }
        ) } | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $currentRoot 'SharePoint/Sites.json') -Encoding UTF8

        $planWithoutRemap = New-M365RestorePlan -BackupPath $backupRoot -Workloads @('SharePoint') -TargetMode AnotherTenant -CurrentSnapshotPath $currentRoot
        $planWithoutRemap.Summary.Updates | Should -Be 1
        $planWithoutRemap.Summary.ItemsWithUnresolvedLinks | Should -BeGreaterThan 0

        $remap = @{
            Domains = @{ 'contoso.com' = 'fabrikam.com' }
            UrlPrefixes = @{ 'https://contoso.sharepoint.com' = 'https://fabrikam.sharepoint.com' }
            ExactValues = @{}
            Ids = @{}
            UserPrincipalNames = @{}
        }

        $planWithRemap = New-M365RestorePlan -BackupPath $backupRoot -Workloads @('SharePoint') -TargetMode AnotherTenant -CurrentSnapshotPath $currentRoot -RemapConfig $remap
        $planWithRemap.Summary.ItemsWithUnresolvedLinks | Should -Be 0
    }

    It 'treats domain-only mapping as sufficient for URL dependency remap coverage' {
        $backupRoot = Join-Path -Path $TestDrive -ChildPath 'planBackupDomainOnly'
        $currentRoot = Join-Path -Path $TestDrive -ChildPath 'planCurrentDomainOnly'

        New-Item -Path (Join-Path $backupRoot 'SharePoint') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $currentRoot 'SharePoint') -ItemType Directory -Force | Out-Null

        [pscustomobject]@{ value = @(
            [pscustomobject]@{
                displayName = 'Site Policy B'
                siteUrl = 'https://contoso.sharepoint.com/sites/bravo'
            }
        ) } | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $backupRoot 'SharePoint/Sites.json') -Encoding UTF8

        [pscustomobject]@{ value = @(
            [pscustomobject]@{ displayName = 'Site Policy B' }
        ) } | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $currentRoot 'SharePoint/Sites.json') -Encoding UTF8

        $domainOnlyRemap = @{
            Domains = @{ 'contoso.sharepoint.com' = 'fabrikam.sharepoint.com' }
            UrlPrefixes = @{}
            ExactValues = @{}
            Ids = @{}
            UserPrincipalNames = @{}
        }

        $plan = New-M365RestorePlan -BackupPath $backupRoot -Workloads @('SharePoint') -TargetMode AnotherTenant -CurrentSnapshotPath $currentRoot -RemapConfig $domainOnlyRemap
        $plan.Summary.ItemsWithUnresolvedLinks | Should -Be 0
    }

    It 'produces integrity score that drops for empty workloads' {
        $backupRoot = Join-Path -Path $TestDrive -ChildPath 'integrityBackup'
        New-Item -Path (Join-Path $backupRoot 'EntraID') -ItemType Directory -Force | Out-Null

        $result = Test-M365BackupIntegrity -BackupPath $backupRoot
        $result.Score | Should -BeLessThan 100
        $result.Empty | Should -BeGreaterThan 0
    }

    It 'creates scenario recovery pack config' {
        $backupRoot = Join-Path -Path $TestDrive -ChildPath 'rpBackup'
        New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null
        $packPath = New-M365RecoveryPack -Scenario IntuneBaseline -BackupPath $backupRoot

        (Test-Path -Path $packPath) | Should -BeTrue
        $pack = Get-Content -Path $packPath -Raw | ConvertFrom-Json
        $pack.scope.workloadSwitches.Intune | Should -BeTrue
        $pack.scope.mode | Should -Be 'Workload'
    }

    It 'uses config workloads without revalidating the parameter variable' {
        $tempRoot = Join-Path -Path $TestDrive -ChildPath 'config-workloads'
        $outputRoot = Join-Path -Path $tempRoot -ChildPath 'out'
        $configPath = Join-Path -Path $tempRoot -ChildPath 'backup.config.json'

        New-Item -Path $outputRoot -ItemType Directory -Force | Out-Null
        @{
            tenant = @{ tenantName = 'contoso.onmicrosoft.com'; tenantId = '00000000-0000-0000-0000-000000000001' }
            authentication = @{ clientId = '11111111-1111-1111-1111-111111111111'; certificateThumbprint = 'ABCDEF1234567890ABCDEF1234567890ABCDEF12' }
            workloads = @('EntraID', 'Users')
            outputRoot = $outputRoot
            throttling = @{ maxRetries = 1; baseDelaySeconds = 1; maxDelaySeconds = 1; jitterRatio = 0.0 }
        } | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath -Encoding UTF8

        Mock Get-DefaultBackupThrottleSettings -ModuleName BackupM365 {
            @{ MaxRetries = 3; BaseDelaySeconds = 1; MaxDelaySeconds = 2; JitterRatio = 0.0 }
        }
        Mock Set-BackupThrottleSettings -ModuleName BackupM365 {}
        Mock Initialize-BackupRetryMetrics -ModuleName BackupM365 {}
        Mock Get-BackupRetryMetrics -ModuleName BackupM365 {
            [pscustomobject]@{ TotalOperations = 0; RetryAttempts = 0; ThrottledResponses = 0; TotalBackoffSeconds = 0 }
        }
        Mock Write-BackupLog -ModuleName BackupM365 {}
        Mock Start-Transcript -ModuleName BackupM365 { 'started' }
        Mock Stop-Transcript -ModuleName BackupM365 { 'stopped' }
        Mock Invoke-BackupSensitiveDataProcessing -ModuleName BackupM365 { [pscustomobject]@{ HitCount = 0 } }
        Mock Get-BackupIntegrityReport -ModuleName BackupM365 { [pscustomobject]@{ Score = 100 } }
        Mock Get-BackupCatalogEntries -ModuleName BackupM365 { @() }
        Mock Find-PreviousBackupSnapshot -ModuleName BackupM365 { $null }
        Mock Save-BackupMetadata -ModuleName BackupM365 {}
        Mock Export-EntraConfig -ModuleName BackupM365 {
            param($OutputPath, $LogPath)

            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            '{"value":[{"id":"1"}]}' | Set-Content -Path (Join-Path -Path $OutputPath -ChildPath 'TenantSettings.json') -Encoding UTF8
        }
        Mock Export-UsersConfig -ModuleName BackupM365 {
            param($OutputPath, $LogPath, $PerObjectMaxItems)

            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            '{"value":[{"id":"1"}]}' | Set-Content -Path (Join-Path -Path $OutputPath -ChildPath 'Users.json') -Encoding UTF8
        }

        $result = Export-M365TenantConfig -ConfigPath $configPath -SkipPrechecks

        $result | Should -Not -BeNullOrEmpty
        $result | Should -BeLike '*contoso.onmicrosoft.com*'
    }

    It 'prefers ConfigObject over the repo backup config and audits sensitive data by default' {
        $outputRoot = Join-Path -Path $TestDrive -ChildPath 'config-object-export'
        $sensitiveModes = [System.Collections.Generic.List[string]]::new()

        Mock Get-DefaultBackupThrottleSettings -ModuleName BackupM365 {
            @{ MaxRetries = 3; BaseDelaySeconds = 1; MaxDelaySeconds = 2; JitterRatio = 0.0 }
        }
        Mock Set-BackupThrottleSettings -ModuleName BackupM365 {}
        Mock Initialize-BackupRetryMetrics -ModuleName BackupM365 {}
        Mock Get-BackupRetryMetrics -ModuleName BackupM365 {
            [pscustomobject]@{ TotalOperations = 0; RetryAttempts = 0; ThrottledResponses = 0; TotalBackoffSeconds = 0 }
        }
        Mock Write-BackupLog -ModuleName BackupM365 {}
        Mock Start-Transcript -ModuleName BackupM365 { 'started' }
        Mock Stop-Transcript -ModuleName BackupM365 { 'stopped' }
        Mock Invoke-BackupSensitiveDataProcessing -ModuleName BackupM365 {
            param($BackupPath, $Mode)
            $sensitiveModes.Add([string]$Mode) | Out-Null
            [pscustomobject]@{ HitCount = 0; Mode = $Mode }
        }
        Mock Get-BackupIntegrityReport -ModuleName BackupM365 { [pscustomobject]@{ Score = 100 } }
        Mock Get-BackupCatalogEntries -ModuleName BackupM365 { @() }
        Mock Find-PreviousBackupSnapshot -ModuleName BackupM365 { $null }
        Mock Save-BackupMetadata -ModuleName BackupM365 {}
        Mock Export-EntraConfig -ModuleName BackupM365 {
            param($OutputPath, $LogPath)
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            '{"value":[{"id":"1"}]}' | Set-Content -Path (Join-Path -Path $OutputPath -ChildPath 'TenantSettings.json') -Encoding UTF8
        }

        $configObject = [pscustomobject]@{
            tenant = [pscustomobject]@{ tenantName = 'config-object.onmicrosoft.com'; tenantId = '00000000-0000-0000-0000-000000000099' }
            workloads = @('EntraID')
            outputRoot = $outputRoot
        }

        $result = Export-M365TenantConfig -ConfigObject $configObject -SkipPrechecks

        $result | Should -BeLike '*config-object.onmicrosoft.com*'
        $sensitiveModes | Should -Contain 'Audit'
    }

    It 'throws when restore scope paths escape the backup root' {
        $backupRoot = Join-Path -Path $TestDrive -ChildPath 'restore-source'
        $configPath = Join-Path -Path $TestDrive -ChildPath 'restore.config.json'

        New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null
        [pscustomobject]@{
            source = [pscustomobject]@{ backupPath = $backupRoot }
            target = [pscustomobject]@{ mode = 'SameTenant'; tenantId = '00000000-0000-0000-0000-000000000001'; tenantName = 'contoso.onmicrosoft.com' }
            authentication = [pscustomobject]@{ clientId = '11111111-1111-1111-1111-111111111111'; certificateThumbprint = 'ABCDEF1234567890ABCDEF1234567890ABCDEF12' }
            scope = [pscustomobject]@{ mode = 'File'; files = @('EntraID/../../outside.json') }
            report = [pscustomobject]@{ outputRoot = (Join-Path -Path $TestDrive -ChildPath 'restore-out') }
        } | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath -Encoding UTF8

        { Restore-M365TenantConfig -ConfigPath $configPath -SkipPrechecks } | Should -Throw '*escapes the configured backup root*'
    }

    It 'returns top-level report paths and workloads for restore dry-run results' {
        $backupRoot = Join-Path -Path $TestDrive -ChildPath 'restore-contract-source'
        $reportRoot = Join-Path -Path $TestDrive -ChildPath 'restore-contract-out'
        $configPath = Join-Path -Path $TestDrive -ChildPath 'restore-contract.config.json'
        $currentSnapshot = Join-Path -Path $TestDrive -ChildPath 'restore-contract-current'

        New-Item -Path (Join-Path $backupRoot 'Users') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $currentSnapshot 'Users') -ItemType Directory -Force | Out-Null

        [pscustomobject]@{
            TenantName       = 'contoso.onmicrosoft.com'
            TenantId         = '00000000-0000-0000-0000-000000000001'
            BackupTimestamp  = (Get-Date).ToString('o')
            IncludedWorkloads = @('Users')
            Status           = 'Success'
        } | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $backupRoot 'metadata.json') -Encoding UTF8

        [pscustomobject]@{ value = @([pscustomobject]@{ id = '1'; userPrincipalName = 'one@contoso.com' }) } |
            ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $backupRoot 'Users/Users.json') -Encoding UTF8

        [pscustomobject]@{
            source = [pscustomobject]@{ backupPath = $backupRoot }
            target = [pscustomobject]@{ mode = 'SameTenant'; tenantId = '00000000-0000-0000-0000-000000000001'; tenantName = 'contoso.onmicrosoft.com' }
            authentication = [pscustomobject]@{ mode = 'AppCertificate'; clientId = '11111111-1111-1111-1111-111111111111'; certificateThumbprint = 'ABCDEF1234567890ABCDEF1234567890ABCDEF12' }
            scope = [pscustomobject]@{
                mode = 'Workload'
                workloads = @('Users')
            }
            report = [pscustomobject]@{ outputRoot = $reportRoot }
        } | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath -Encoding UTF8

        Mock Write-BackupLog -ModuleName BackupM365 {}
        Mock Connect-M365Tenant -ModuleName BackupM365 {}
        Mock Disconnect-M365Tenant -ModuleName BackupM365 {}
        Mock Export-M365TenantConfig -ModuleName BackupM365 {
            param($TenantName, $TenantId, $Workloads, $OutputRoot)

            New-Item -Path $currentSnapshot -ItemType Directory -Force | Out-Null
            New-Item -Path (Join-Path $currentSnapshot 'Users') -ItemType Directory -Force | Out-Null
            [pscustomobject]@{ value = @([pscustomobject]@{ id = '1'; userPrincipalName = 'one@contoso.com' }) } |
                ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $currentSnapshot 'Users/Users.json') -Encoding UTF8
            return $currentSnapshot
        }
        Mock Compare-M365TenantConfig -ModuleName BackupM365 { @() }
        Mock New-RestorePlanData -ModuleName BackupM365 {
            [pscustomobject]@{
                Summary = [pscustomobject]@{
                    TotalItems = 0
                    Creates = 0
                    Updates = 0
                    ItemsWithUnresolvedLinks = 0
                }
            }
        }

        $result = Restore-M365TenantConfig -ConfigPath $configPath -DryRun -SkipPrechecks -NoLog

        $result.Status | Should -Be 'Success'
        $result.Workloads | Should -Contain 'Users'
        $result.ReportPath | Should -Not -BeNullOrEmpty
        $result.JsonReportPath | Should -Not -BeNullOrEmpty
        $result.HtmlReportPath | Should -Not -BeNullOrEmpty
        $result.CompareReportPath | Should -Not -BeNullOrEmpty
        (Test-Path -Path $result.ReportPath) | Should -BeTrue
        (Test-Path -Path $result.JsonReportPath) | Should -BeTrue
        (Test-Path -Path $result.HtmlReportPath) | Should -BeTrue
        (Test-Path -Path $result.CompareReportPath) | Should -BeTrue
        $result.Output.ReportMarkdownPath | Should -Be $result.ReportPath
        $result.Output.ReportJsonPath | Should -Be $result.JsonReportPath
        $result.Output.ReportHtmlPath | Should -Be $result.HtmlReportPath
    }

    It 'throws when apply operations fail during import' {
        $backupRoot = Join-Path -Path $TestDrive -ChildPath 'import-failure'
        $workloadPath = Join-Path -Path $backupRoot -ChildPath 'ExchangeOnline'
        New-Item -Path $workloadPath -ItemType Directory -Force | Out-Null

        @(
            [pscustomobject]@{ Name = 'contoso.com'; DomainName = 'contoso.com'; DomainType = 'Authoritative' }
        ) | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path -Path $workloadPath -ChildPath 'AcceptedDomains.json') -Encoding UTF8

        function global:Get-AcceptedDomain { $null }
        function global:New-AcceptedDomain { throw 'create failed' }

        { Import-M365TenantConfig -BackupPath $backupRoot -Workloads @('ExchangeOnline') -Confirm:$false } | Should -Throw '*Restore apply completed with 1 failure(s).*'

        Remove-Item -Path Function:\Get-AcceptedDomain -ErrorAction SilentlyContinue
        Remove-Item -Path Function:\New-AcceptedDomain -ErrorAction SilentlyContinue
    }

    It 'does not request SharePoint-backed profile fields in the bulk users query' {
        $outputRoot = Join-Path -Path $TestDrive -ChildPath 'users-export'
        $capturedUris = [System.Collections.Generic.List[string]]::new()

        Mock Invoke-GraphRequestWithRetry -ModuleName BackupM365 {
            param($Uri, $Method, $Body, $MaxRetries, $BaseDelaySeconds, $TransientErrorPattern, $LogPath)

            $capturedUris.Add([string]$Uri) | Out-Null
            if ($Uri -like '/v1.0/users?*') {
                return @{
                    value = @(
                        [pscustomobject]@{
                            id = '00000000-0000-0000-0000-000000000001'
                            userPrincipalName = 'one@contoso.com'
                            displayName = 'User One'
                        }
                    )
                }
            }

            return @{ value = @() }
        }
        Mock Write-BackupLog -ModuleName BackupM365 {}

        Export-UsersConfig -OutputPath $outputRoot

        $listUri = $capturedUris | Where-Object { $_ -like '/v1.0/users?*' } | Select-Object -First 1
        $listUri | Should -Not -BeNullOrEmpty
        $listUri | Should -Not -Match '(?<![A-Za-z])(aboutMe|birthday|hireDate|interests|mySite|pastProjects|preferredName|responsibilities|schools|skills)(?![A-Za-z])'
        (Test-Path -Path (Join-Path -Path $outputRoot -ChildPath 'Users.json')) | Should -BeTrue
    }
}
