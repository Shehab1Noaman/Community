function Connect-M365Tenant {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph and optionally to Exchange, Teams, SharePoint,
        Compliance, and Power Platform.

    .DESCRIPTION
        Establishes authenticated sessions to each Microsoft 365 service required
        for a backup run. Supports certificate-based app-only authentication
        (recommended for automation), Managed Identity, and Interactive login.

        When used as part of Export-M365TenantConfig -Connect, this function is
        called automatically via the internal Connect-WorkloadsForBackup helper.
        Call it directly only when managing sessions manually.

    .PARAMETER TenantId
        Azure AD tenant ID (GUID or .onmicrosoft.com domain).

    .PARAMETER ClientId
        App registration client ID for certificate-based authentication.

    .PARAMETER CertificateThumbprint
        Thumbprint of the certificate installed in the local certificate store
        (Cert:\CurrentUser\My or Cert:\LocalMachine\My).

    .PARAMETER ManagedIdentity
        Use system-assigned or user-assigned Managed Identity instead of a certificate.

    .PARAMETER Interactive
        Use interactive browser-based login (useful for ad-hoc runs).

    .PARAMETER GraphScopes
        Microsoft Graph delegated or application scopes to request.
        Only relevant for Interactive login; app-only auth uses the app's granted roles.

    .PARAMETER ConnectExchange
        Also connect to Exchange Online (ExchangeOnlineManagement module required).

    .PARAMETER ExchangeOrganization
        Exchange organisation name (e.g. contoso.onmicrosoft.com).
        Required when -ConnectExchange or -ConnectCompliance is specified.

    .PARAMETER ConnectTeams
        Also connect to Microsoft Teams (MicrosoftTeams module required).

    .PARAMETER ConnectCompliance
        Also connect to Security and Compliance / Purview
        (ExchangeOnlineManagement module required).

    .PARAMETER ConnectPowerPlatform
        Also connect to Power Platform
        (Microsoft.PowerApps.Administration.PowerShell module required).

    .PARAMETER PowerPlatformClientSecret
        Client secret for Power Platform connection (certificate auth is not
        supported by the Power Platform module).

    .PARAMETER SharePointAdminUrl
        SharePoint admin centre URL (e.g. https://contoso-admin.sharepoint.com/).
        Required when SharePoint workload backups are needed.

    .EXAMPLE
        # App-only certificate login (recommended for automation)
        Connect-M365Tenant -TenantId '...' -ClientId '...' -CertificateThumbprint '...'

    .EXAMPLE
        # Full stack connection for a complete backup
        Connect-M365Tenant -TenantId $tid -ClientId $cid -CertificateThumbprint $thumb `
            -ConnectExchange -ExchangeOrganization contoso.onmicrosoft.com `
            -ConnectTeams -SharePointAdminUrl https://contoso-admin.sharepoint.com/
    #>
    [CmdletBinding(DefaultParameterSetName = 'AppCertificate')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'AppCertificate', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(ParameterSetName = 'AppCertificate', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'ManagedIdentity', Mandatory)]
        [switch]$ManagedIdentity,

        [Parameter(ParameterSetName = 'Interactive', Mandatory)]
        [switch]$Interactive,

        [Parameter()]
        [string[]]$GraphScopes = @(
            'Directory.Read.All',
            'Policy.Read.All',
            'Group.Read.All',
            'Application.Read.All',
            'Organization.Read.All',
            'Sites.Read.All',
            'DeviceManagementConfiguration.Read.All'
        ),

        [Parameter()]
        [switch]$ConnectExchange,

        [Parameter()]
        [string]$ExchangeOrganization,

        [Parameter()]
        [switch]$ConnectTeams,

        [Parameter()]
        [switch]$ConnectCompliance,

        [Parameter()]
        [switch]$ConnectPowerPlatform,

        [Parameter()]
        [string]$PowerPlatformClientSecret,

        [Parameter()]
        [string]$SharePointAdminUrl
    )

    $certificate = $null

    if ($PSCmdlet.ParameterSetName -eq 'AppCertificate' -and $ConnectTeams) {
        $certificateStores = @(
            "Cert:\CurrentUser\My\$CertificateThumbprint",
            "Cert:\LocalMachine\My\$CertificateThumbprint"
        )

        foreach ($certificatePath in $certificateStores) {
            if (Test-Path -Path $certificatePath) {
                $certificate = Get-Item -Path $certificatePath
                break
            }
        }

        if (-not $certificate) {
            throw "Failed to resolve certificate [$CertificateThumbprint] from CurrentUser or LocalMachine personal stores for Microsoft Teams app authentication."
        }
    }

    try {
        if ($PSCmdlet.ParameterSetName -eq 'AppCertificate') {
            $null = Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'ManagedIdentity') {
            $null = Connect-MgGraph -TenantId $TenantId -Identity -NoWelcome
        }
        else {
            $null = Connect-MgGraph -TenantId $TenantId -Scopes $GraphScopes -NoWelcome
        }
    }
    catch {
        throw "Failed to connect to Microsoft Graph for tenant [$TenantId]. $($_.Exception.Message)"
    }

    if ($ConnectExchange) {
        $exchangeOrganization = if ($ExchangeOrganization) { $ExchangeOrganization } else { $TenantId }

        try {
            if ($PSCmdlet.ParameterSetName -eq 'AppCertificate') {
                $null = Connect-ExchangeOnline -Organization $exchangeOrganization -AppId $ClientId -CertificateThumbprint $CertificateThumbprint -ShowBanner:$false
            }
            else {
                $null = Connect-ExchangeOnline -Organization $exchangeOrganization -ShowBanner:$false
            }
        }
        catch {
            throw "Failed to connect to Exchange Online for organization [$exchangeOrganization]. $($_.Exception.Message)"
        }
    }

    if ($ConnectTeams) {
        if (-not (Get-Command -Name Connect-MicrosoftTeams -ErrorAction SilentlyContinue)) {
            try {
                Import-Module MicrosoftTeams -ErrorAction Stop | Out-Null
            }
            catch {
                throw 'MicrosoftTeams module is required for Teams connections. Install-Module MicrosoftTeams -Scope CurrentUser'
            }
        }
        # After import, verify the binary cmdlet actually loaded (the PS-script cmdlets load even
        # if the required .NET assembly fails silently, so we must check explicitly).
        if (-not (Get-Command -Name Connect-MicrosoftTeams -ErrorAction SilentlyContinue)) {
            throw 'Connect-MicrosoftTeams cmdlet is not available after importing MicrosoftTeams. The module binary assembly may have failed to load (check .NET runtime compatibility). Try: Import-Module MicrosoftTeams -Verbose to see load errors.'
        }
        try {
            # Connect-MicrosoftTeams returns a PSAzureContext object on success. Suppress it explicitly
            # so it doesn't leak into the caller's pipeline (e.g., into the resolved workload list).
            if ($PSCmdlet.ParameterSetName -eq 'AppCertificate') {
                $null = Connect-MicrosoftTeams -TenantId $TenantId -ApplicationId $ClientId -Certificate $certificate
            }
            else {
                $null = Connect-MicrosoftTeams -TenantId $TenantId
            }
        }
        catch {
            throw "Failed to connect to Microsoft Teams for tenant [$TenantId]. $($_.Exception.Message)"
        }
    }

    if ($ConnectCompliance) {
        # Security & Compliance PowerShell session (Connect-IPPSSession). Lives in ExchangeOnlineManagement module.
        if (-not (Get-Command -Name Connect-IPPSSession -ErrorAction SilentlyContinue)) {
            throw 'Connect-IPPSSession not available. Install/import ExchangeOnlineManagement module.'
        }

        $ippsOrganization = if ($ExchangeOrganization) { $ExchangeOrganization } else { $TenantId }
        try {
            if ($PSCmdlet.ParameterSetName -eq 'AppCertificate') {
                $null = Connect-IPPSSession -Organization $ippsOrganization -AppId $ClientId -CertificateThumbprint $CertificateThumbprint -ShowBanner:$false
            }
            else {
                $null = Connect-IPPSSession -Organization $ippsOrganization -ShowBanner:$false
            }
        }
        catch {
            throw "Failed to connect to Security & Compliance (IPPSSession) for organization [$ippsOrganization]. $($_.Exception.Message)"
        }
    }

    if ($ConnectPowerPlatform) {
        if (-not (Get-Command -Name Add-PowerAppsAccount -ErrorAction SilentlyContinue)) {
            throw 'Add-PowerAppsAccount not available. Install Microsoft.PowerApps.Administration.PowerShell module.'
        }
        try {
            if ($PSCmdlet.ParameterSetName -eq 'AppCertificate') {
                if ([string]::IsNullOrWhiteSpace($PowerPlatformClientSecret)) {
                    throw 'Power Platform service-principal authentication requires a client secret (-PowerPlatformClientSecret). Certificate auth is not currently supported by the Microsoft.PowerApps.Administration.PowerShell module.'
                }
                Add-PowerAppsAccount -Endpoint prod -TenantID $TenantId -ApplicationId $ClientId -ClientSecret $PowerPlatformClientSecret | Out-Null
            }
            else {
                Add-PowerAppsAccount -Endpoint prod | Out-Null
            }
        }
        catch {
            throw "Failed to connect to Power Platform for tenant [$TenantId]. $($_.Exception.Message)"
        }
    }

    if ($SharePointAdminUrl) {
        if ($PSCmdlet.ParameterSetName -eq 'AppCertificate') {
            if (-not (Get-Command -Name Connect-PnPOnline -ErrorAction SilentlyContinue)) {
                try {
                    Import-Module PnP.PowerShell -ErrorAction Stop | Out-Null
                }
                catch {
                    throw 'PnP.PowerShell module is required for non-interactive SharePoint app-only connection. Install-Module PnP.PowerShell -Scope CurrentUser'
                }
            }

            try {
                $null = Connect-PnPOnline -Url $SharePointAdminUrl -ClientId $ClientId -Tenant $TenantId -Thumbprint $CertificateThumbprint
            }
            catch {
                throw "Failed to connect to SharePoint Online app-only endpoint [$SharePointAdminUrl]. $($_.Exception.Message)"
            }
        }
        else {
            if (-not (Get-Command -Name Connect-SPOService -ErrorAction SilentlyContinue)) {
                try {
                    Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop | Out-Null
                }
                catch {
                    throw 'Microsoft.Online.SharePoint.PowerShell is required for interactive SharePoint admin connections. Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser'
                }
            }
            try {
                $null = Connect-SPOService -Url $SharePointAdminUrl
            }
            catch {
                throw "Failed to connect to SharePoint Online admin endpoint [$SharePointAdminUrl]. $($_.Exception.Message)"
            }
        }
    }

    Write-Verbose 'Successfully connected to Microsoft 365 services.'
}
