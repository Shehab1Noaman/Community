function Connect-WorkloadsForBackup {
    <#
    .SYNOPSIS
        Connects to every workload required by the requested backup scope.
        Returns the list of workloads that were successfully connected.

    .DESCRIPTION
        Internal helper used by Export-M365TenantConfig when invoked with -Connect.
        Mirrors the orchestration that historically lived in samples\Initialize-BackupSession.ps1
        so a single Export-M365TenantConfig call can do the entire backup end-to-end.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Config,

        [Parameter(Mandatory)]
        [string[]]$Workloads
    )

    if (-not $Config -or -not $Config.tenant) {
        throw 'Connect-WorkloadsForBackup requires a parsed backup.config.json with a "tenant" block.'
    }
    if ([string]::IsNullOrWhiteSpace($Config.authentication.clientId) -or
        [string]::IsNullOrWhiteSpace($Config.authentication.certificateThumbprint)) {
        throw 'backup.config.json is missing authentication.clientId or authentication.certificateThumbprint'
    }

    $tenantId   = [string]$Config.tenant.tenantId
    $tenantName = [string]$Config.tenant.tenantName

    $baseConnectParams = @{
        TenantId              = $tenantId
        ClientId              = [string]$Config.authentication.clientId
        CertificateThumbprint = [string]$Config.authentication.certificateThumbprint
        ErrorAction           = 'Stop'
    }

    # Expose app-only auth details for per-site PnP connections inside Export-SharePointConfig.
    $env:_BM365_PNP_TENANTID   = $tenantId
    $env:_BM365_PNP_CLIENTID   = $baseConnectParams.ClientId
    $env:_BM365_PNP_THUMBPRINT = $baseConnectParams.CertificateThumbprint

    $connected = [System.Collections.Generic.List[string]]::new()

    Write-Host 'Connecting to Microsoft Graph (required)...'
    Connect-M365Tenant @baseConnectParams | Out-Null
    if ($Workloads -contains 'EntraID')  { [void]$connected.Add('EntraID') }
    if ($Workloads -contains 'Intune')   { [void]$connected.Add('Intune') }
    if ($Workloads -contains 'Defender') { [void]$connected.Add('Defender') }
    if ($Workloads -contains 'Planner')  { [void]$connected.Add('Planner') }
    if ($Workloads -contains 'Users')    { [void]$connected.Add('Users') }

    if ($Workloads -contains 'ExchangeOnline') {
        if (Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue) {
            try {
                Write-Host "Connecting to Exchange Online [$tenantName]..."
                Connect-M365Tenant @baseConnectParams -ConnectExchange -ExchangeOrganization $tenantName | Out-Null
                [void]$connected.Add('ExchangeOnline')
            }
            catch { Write-Warning "Exchange Online connection skipped: $($_.Exception.Message)" }
        }
        else { Write-Warning 'ExchangeOnlineManagement module not available. Exchange workload will be skipped.' }
    }

    if ($Workloads -contains 'Teams') {
        if (-not (Get-Command Connect-MicrosoftTeams -ErrorAction SilentlyContinue)) {
            try {
                Import-Module MicrosoftTeams -ErrorAction Stop | Out-Null
            }
            catch { }
        }
        if (Get-Command Connect-MicrosoftTeams -ErrorAction SilentlyContinue) {
            try {
                Write-Host 'Connecting to Microsoft Teams...'
                Connect-M365Tenant @baseConnectParams -ConnectTeams | Out-Null
                [void]$connected.Add('Teams')
            }
            catch { Write-Warning "Teams connection skipped: $($_.Exception.Message)" }
        }
        else { Write-Warning 'MicrosoftTeams module not available. Teams workload will be skipped.' }
    }

    if ($Workloads -contains 'SharePoint') {
        $spoUrl = [string]$Config.sharePointAdminUrl
        if ([string]::IsNullOrWhiteSpace($spoUrl)) {
            Write-Warning 'SharePoint workload requested but config.sharePointAdminUrl is empty. Skipping.'
        }
        elseif (-not (Get-Command Connect-PnPOnline -ErrorAction SilentlyContinue)) {
            try {
                $env:PNPPOWERSHELL_UPDATECHECK = 'Off'
                Import-Module PnP.PowerShell -ErrorAction Stop
            }
            catch {
                Write-Warning "SharePoint app-only export requires PnP.PowerShell. Install with: Install-Module PnP.PowerShell -Scope CurrentUser. Skipping."
                $spoUrl = $null
            }
        }
        if ($spoUrl) {
            try {
                Write-Host "Connecting to SharePoint admin endpoint [$spoUrl]..."
                Connect-M365Tenant @baseConnectParams -SharePointAdminUrl $spoUrl | Out-Null
                if ((Get-Module -ListAvailable -Name 'Microsoft.Online.SharePoint.PowerShell') -and -not (Get-Module -Name 'Microsoft.Online.SharePoint.PowerShell')) {
                    try { Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop | Out-Null } catch { }
                }
                [void]$connected.Add('SharePoint')
            }
            catch { Write-Warning "SharePoint connection skipped: $($_.Exception.Message)" }
        }
    }

    if ($Workloads -contains 'Compliance') {
        if (Get-Command Connect-IPPSSession -ErrorAction SilentlyContinue) {
            try {
                Write-Host "Connecting to Security & Compliance (Purview) [$tenantName]..."
                Connect-M365Tenant @baseConnectParams -ConnectCompliance -ExchangeOrganization $tenantName | Out-Null
                [void]$connected.Add('Compliance')
            }
            catch { Write-Warning "Compliance/Purview connection skipped: $($_.Exception.Message)" }
        }
        else { Write-Warning 'Connect-IPPSSession not available. Compliance workload will be skipped.' }
    }

    if ($Workloads -contains 'PowerPlatform') {
        $ppEnabled = $false
        if ($Config.PSObject.Properties.Name -contains 'powerPlatform' -and $Config.powerPlatform `
            -and $Config.powerPlatform.PSObject.Properties.Name -contains 'enabled') {
            $ppEnabled = [bool]$Config.powerPlatform.enabled
        }
        if (-not $ppEnabled) {
            Write-Warning 'PowerPlatform requested but config.powerPlatform.enabled = false. Skipping.'
        }
        elseif (-not (Get-Command Add-PowerAppsAccount -ErrorAction SilentlyContinue)) {
            Write-Warning 'Microsoft.PowerApps.Administration.PowerShell not installed. Power Platform workload skipped.'
        }
        elseif ([string]::IsNullOrWhiteSpace([string]$Config.powerPlatform.clientSecret)) {
            Write-Warning 'config.powerPlatform.clientSecret is required for app-only Power Platform connection. Skipping.'
        }
        else {
            try {
                Write-Host 'Connecting to Power Platform...'
                Connect-M365Tenant @baseConnectParams -ConnectPowerPlatform -PowerPlatformClientSecret $Config.powerPlatform.clientSecret | Out-Null
                [void]$connected.Add('PowerPlatform')
            }
            catch { Write-Warning "Power Platform connection skipped: $($_.Exception.Message)" }
        }
    }

    Write-Host "Connected workloads for export: $($connected -join ', ')"
    # Emit each workload name individually as a string so the caller's @(...) capture
    # produces a flat string array (no nested [string[]] wrapping). Using Write-Output
    # also avoids any chance of pipeline pollution from upstream connect cmdlets.
    Write-Output -InputObject ([string[]]$connected.ToArray()) -NoEnumerate:$false
}
