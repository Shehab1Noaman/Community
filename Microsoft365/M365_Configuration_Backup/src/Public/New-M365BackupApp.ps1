function New-M365BackupApp {
    <#
    .SYNOPSIS
        Creates the BackupM365 Entra app registration, uploads the signing
        certificate, assigns API app-role permissions, grants admin consent,
        and writes the resulting IDs to a JSON file.

    .DESCRIPTION
        Run this AFTER creating the certificate (New-M365BackupCertificate).
        The admin running this cmdlet must hold a role that can:
          * create app registrations          (e.g. Application Administrator)
          * grant admin consent for app roles (e.g. Privileged Role Administrator
            or Global Administrator)

        The cmdlet:
          1. Connects to Microsoft Graph interactively as the admin.
          2. Creates the app registration (or reuses one if -DisplayName matches).
          3. Uploads the public certificate from the .cer file.
          4. Resolves the requested permission bundles and adds matching app roles.
          5. Creates the service principal in the tenant.
          6. Grants admin consent for every requested app role.
          7. Optionally assigns directory roles required by Exchange/Compliance.
          8. Writes app-output.json containing TenantId, ClientId, Thumbprint,
             and a copy/paste block ready for backup.config.json.

    .PARAMETER DisplayName
        The app registration display name. Defaults to 'BackupM365'.

    .PARAMETER CertificateThumbprint
        Thumbprint of the certificate created by New-M365BackupCertificate.

    .PARAMETER CertificatePath
        Override the .cer file location explicitly. If omitted, the newest
        .cer file in the output folder is used automatically.

    .PARAMETER Bundles
        Permission bundles to grant. Use 'Full' for everything (default), or any
        combination of 'Entra','Users','Intune','Exchange','SharePoint','Teams',
        'Compliance','Defender','Planner'.

    .PARAMETER AssignDirectoryRoles
        If set, also assigns the directory roles listed under each bundle's
        'directoryRoles'. Requires Privileged Role Administrator or Global Administrator.

    .PARAMETER TenantId
        Optional tenant id / domain to connect to.

    .PARAMETER OutputFolder
        Folder where app-output.json is written.
        Defaults to an 'output' folder in the current working directory.

    .PARAMETER InstallMissingModules
        If set, automatically installs any required Microsoft.Graph.* modules
        that are missing from PSGallery instead of failing.

    .PARAMETER ModuleScope
        Scope used when installing modules with -InstallMissingModules. Defaults
        to 'CurrentUser'. Use 'AllUsers' from an elevated session.

    .EXAMPLE
        New-M365BackupApp -CertificateThumbprint 944C33C8EE589FAB873DB3B3834F43618FB7B8E5

    .EXAMPLE
        New-M365BackupApp -CertificateThumbprint <thumb> -Bundles Entra,Intune,Users -AssignDirectoryRoles

    .EXAMPLE
        New-M365BackupApp -CertificateThumbprint <thumb> -Bundles Full -TenantId contoso.onmicrosoft.com -InstallMissingModules
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName = 'BackupM365',

        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9A-Fa-f]{40}$')]
        [string]$CertificateThumbprint,

        [Parameter()]
        [string]$CertificatePath,

        [Parameter()]
        [ValidateSet('Full','Entra','Users','Intune','Exchange','SharePoint','Teams','Compliance','Defender','Planner')]
        [string[]]$Bundles = @('Full'),

        [Parameter()]
        [switch]$AssignDirectoryRoles,

        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [string]$OutputFolder,

        [Parameter()]
        [switch]$InstallMissingModules,

        [Parameter()]
        [ValidateSet('CurrentUser','AllUsers')]
        [string]$ModuleScope = 'CurrentUser'
    )

    if (-not $OutputFolder) {
        $OutputFolder = Join-Path (Get-Location).Path 'output'
    }

    # Resolve bundle JSON from the repository config folder.
    $moduleRoot = Split-Path $PSScriptRoot -Parent
    $repoRoot = Split-Path $moduleRoot -Parent
    $bundleFile = Join-Path $repoRoot 'config/permissions/backup-permissions-bundles.json'
    if (-not (Test-Path $bundleFile)) {
        throw "backup-permissions-bundles.json not found: $bundleFile"
    }
    $bundleConfig = Get-Content $bundleFile -Raw | ConvertFrom-Json

    # ─── Module checks ───────────────────────────────────────────────────────
    $requiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Applications',
        'Microsoft.Graph.Identity.DirectoryManagement'
    )

    $missingModules = @($requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
    if ($missingModules.Count -gt 0) {
        if ($InstallMissingModules) {
            Write-Host "Installing missing modules ($ModuleScope scope): $($missingModules -join ', ')" -ForegroundColor Cyan

            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Write-Host '  - Bootstrapping NuGet package provider...' -ForegroundColor DarkGray
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope $ModuleScope | Out-Null
            }

            $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
            if ($psGallery -and $psGallery.InstallationPolicy -ne 'Trusted') {
                Write-Host '  - Trusting PSGallery for this session...' -ForegroundColor DarkGray
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            }

            foreach ($m in $missingModules) {
                Write-Host "  - Install-Module $m -Scope $ModuleScope" -ForegroundColor DarkGray
                Install-Module -Name $m -Scope $ModuleScope -Force -AllowClobber -Repository PSGallery
            }
        }
        else {
            $installCmd = ($missingModules | ForEach-Object { "Install-Module $_ -Scope $ModuleScope -Force" }) -join '; '
            throw "Required module(s) not installed: $($missingModules -join ', '). Re-run with -InstallMissingModules, or install manually: $installCmd"
        }
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null
    Import-Module Microsoft.Graph.Applications -ErrorAction Stop | Out-Null
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop | Out-Null

    # ─── Resolve certificate ─────────────────────────────────────────────────
    if (-not $CertificatePath) {
        $candidate = Get-ChildItem -Path $OutputFolder -Filter '*.cer' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($candidate) { $CertificatePath = $candidate.FullName }
    }
    if (-not $CertificatePath -or -not (Test-Path $CertificatePath)) {
        throw "Public-key (.cer) file not found. Run New-M365BackupCertificate first or pass -CertificatePath."
    }

    $certInStore = Get-Item -Path "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
    if (-not $certInStore) {
        Write-Warning "Certificate $CertificateThumbprint not found in CurrentUser\My. Backups will fail at runtime unless the cert is installed on the machine that runs them."
    }

    $cerBytes = [System.IO.File]::ReadAllBytes($CertificatePath)

    # ─── Resolve bundles → flat list ─────────────────────────────────────────
    function Resolve-Bundles {
        param([string[]]$Names)
        $all = @()
        foreach ($n in $Names) {
            if ($n -eq 'Full') {
                $all += $bundleConfig.bundles.Full.includes
            } else {
                $all += $n
            }
        }
        $all | Select-Object -Unique
    }

    $bundleNames = Resolve-Bundles -Names $Bundles
    Write-Host ("Bundles resolved: {0}" -f ($bundleNames -join ', ')) -ForegroundColor Cyan

    $wantedPerms = @()
    $wantedRoles = @()
    foreach ($n in $bundleNames) {
        $b = $bundleConfig.bundles.$n
        if (-not $b) { Write-Warning "Bundle '$n' not found in backup-permissions-bundles.json"; continue }
        if ($b.permissions)    { $wantedPerms += $b.permissions }
        if ($b.directoryRoles) { $wantedRoles += $b.directoryRoles }
    }
    $wantedRoles = $wantedRoles | Select-Object -Unique

    # Normalize permissions and group by API
    $wantedPerms = $wantedPerms | ForEach-Object {
        $t = if ($_.type) { $_.type } else { 'Application' }
        [pscustomobject]@{ api = $_.api; role = $_.role; type = $t }
    } | Sort-Object api, type, role -Unique

    $permsByApi = $wantedPerms | Group-Object -Property api

    # ─── Connect ─────────────────────────────────────────────────────────────
    $connectArgs = @{
        Scopes   = @(
            'Application.ReadWrite.All',
            'AppRoleAssignment.ReadWrite.All',
            'DelegatedPermissionGrant.ReadWrite.All',
            'Directory.ReadWrite.All',
            'RoleManagement.ReadWrite.Directory'
        )
        NoWelcome = $true
    }
    if ($TenantId) { $connectArgs.TenantId = $TenantId }
    Write-Host 'Connecting to Microsoft Graph (interactive)...' -ForegroundColor Cyan
    Connect-MgGraph @connectArgs | Out-Null
    $ctx = Get-MgContext
    if (-not $ctx) { throw 'Connect-MgGraph did not establish a session.' }
    Write-Host ("Connected to tenant {0} as {1}" -f $ctx.TenantId, $ctx.Account) -ForegroundColor Green

    # ─── Build RequiredResourceAccess ────────────────────────────────────────
    $rraList     = @()
    $grantsByApi = @{}
    foreach ($grp in $permsByApi) {
        $apiName  = $grp.Name
        $apiAppId = $bundleConfig.apis.$apiName
        if (-not $apiAppId) {
            Write-Warning "API '$apiName' not mapped in backup-permissions-bundles.json apis section. Skipping its $($grp.Count) permissions."
            continue
        }

        $sp = Get-MgServicePrincipal -Filter "appId eq '$apiAppId'" -ErrorAction SilentlyContinue
        if (-not $sp) {
            Write-Warning "Service principal for API '$apiName' (appId $apiAppId) not present in tenant. Skipping."
            continue
        }

        $resAccess = @(); $appRoleGrants = @(); $scopeGrants = @()
        $appCount = 0; $delegCount = 0

        foreach ($p in $grp.Group) {
            if ($p.type -eq 'Delegated') {
                $oauth2 = $sp.Oauth2PermissionScopes | Where-Object { $_.Value -eq $p.role } | Select-Object -First 1
                if (-not $oauth2) {
                    Write-Warning ("[{0}] Delegated scope '{1}' not found on resource SP. Skipping." -f $apiName, $p.role)
                    continue
                }
                $resAccess   += @{ id = $oauth2.Id; type = 'Scope' }
                $scopeGrants += [pscustomobject]@{ Id = $oauth2.Id; Value = $p.role }
                $delegCount++
            }
            else {
                $appRole = $sp.AppRoles | Where-Object { $_.Value -eq $p.role -and $_.AllowedMemberTypes -contains 'Application' } | Select-Object -First 1
                if (-not $appRole) {
                    Write-Warning ("[{0}] AppRole '{1}' not found on resource SP. Skipping." -f $apiName, $p.role)
                    continue
                }
                $resAccess      += @{ id = $appRole.Id; type = 'Role' }
                $appRoleGrants  += [pscustomobject]@{ Id = $appRole.Id; Value = $p.role }
                $appCount++
            }
        }

        if ($resAccess.Count -gt 0) {
            $rraList += @{ resourceAppId = $apiAppId; resourceAccess = $resAccess }
            $grantsByApi[$apiName] = [pscustomobject]@{
                ResourceSpId = $sp.Id
                AppRoles     = $appRoleGrants
                Scopes       = $scopeGrants
            }
            Write-Host ("  {0,-20} -> {1} app-role(s), {2} delegated scope(s)" -f $apiName, $appCount, $delegCount)
        }
    }

    # ─── Create or reuse the application ─────────────────────────────────────
    $existingApp = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    if ($existingApp) {
        Write-Host ("Reusing existing app registration '{0}' (appId={1})" -f $DisplayName, $existingApp.AppId) -ForegroundColor Yellow
        $app = $existingApp
    } else {
        Write-Host ("Creating app registration '{0}'..." -f $DisplayName) -ForegroundColor Cyan
        $app = New-MgApplication -DisplayName $DisplayName -SignInAudience AzureADMyOrg
        if (-not $app -or [string]::IsNullOrWhiteSpace($app.AppId)) {
            throw "App registration was not created. Graph authentication failed before an AppId was returned."
        }
        Write-Host ("  appId = {0}" -f $app.AppId)
    }

    Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $rraList | Out-Null
    Write-Host '  RequiredResourceAccess updated' -ForegroundColor Green

    # ─── Upload certificate ───────────────────────────────────────────────────
    $certAlreadyUploaded = $false
    if ($app.KeyCredentials) {
        foreach ($k in $app.KeyCredentials) {
            if ($k.CustomKeyIdentifier) {
                $thumb = ([System.BitConverter]::ToString($k.CustomKeyIdentifier) -replace '-','').ToUpper()
                if ($thumb -eq $CertificateThumbprint.ToUpper()) { $certAlreadyUploaded = $true; break }
            }
        }
    }
    if (-not $certAlreadyUploaded) {
        Write-Host '  Uploading certificate...' -ForegroundColor Cyan
        $existing = @()
        if ($app.KeyCredentials) { $existing = @($app.KeyCredentials) }
        $newKey = @{
            type        = 'AsymmetricX509Cert'
            usage       = 'Verify'
            displayName = "BackupM365-$CertificateThumbprint"
            key         = $cerBytes
        }
        Update-MgApplication -ApplicationId $app.Id -KeyCredentials ($existing + $newKey) | Out-Null
        Write-Host '  Certificate attached' -ForegroundColor Green
    } else {
        Write-Host '  Certificate already attached to this app' -ForegroundColor Yellow
    }

    # ─── Ensure service principal ─────────────────────────────────────────────
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
    if (-not $sp) {
        Write-Host '  Creating service principal in tenant...' -ForegroundColor Cyan
        $sp = New-MgServicePrincipal -AppId $app.AppId
    }
    Write-Host ("  servicePrincipalId = {0}" -f $sp.Id)

    # ─── Grant admin consent (app roles) ──────────────────────────────────────
    Write-Host 'Granting admin consent (app role assignments)...' -ForegroundColor Cyan
    $grantedCount = 0; $skippedCount = 0
    foreach ($apiName in $grantsByApi.Keys) {
        $g = $grantsByApi[$apiName]
        foreach ($ar in $g.AppRoles) {
            $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue |
                Where-Object { $_.ResourceId -eq $g.ResourceSpId -and $_.AppRoleId -eq $ar.Id }
            if ($existing) { $skippedCount++; continue }
            try {
                New-MgServicePrincipalAppRoleAssignment `
                    -ServicePrincipalId $sp.Id `
                    -PrincipalId        $sp.Id `
                    -ResourceId         $g.ResourceSpId `
                    -AppRoleId          $ar.Id | Out-Null
                $grantedCount++
            } catch {
                Write-Warning ("  Failed to grant app role {0} on {1}: {2}" -f $ar.Value, $apiName, $_.Exception.Message)
            }
        }
    }
    Write-Host ("  App roles  -> Granted: {0}   Already present: {1}" -f $grantedCount, $skippedCount) -ForegroundColor Green

    # ─── Grant admin consent (delegated scopes) ────────────────────────────────
    Write-Host 'Granting admin consent (delegated scopes, tenant-wide)...' -ForegroundColor Cyan
    $delegGranted = 0; $delegSkipped = 0
    foreach ($apiName in $grantsByApi.Keys) {
        $g = $grantsByApi[$apiName]
        if (-not $g.Scopes -or $g.Scopes.Count -eq 0) { continue }

        $existingGrant = Get-MgOauth2PermissionGrant -All -ErrorAction SilentlyContinue |
            Where-Object { $_.ClientId -eq $sp.Id -and $_.ResourceId -eq $g.ResourceSpId -and $_.ConsentType -eq 'AllPrincipals' } |
            Select-Object -First 1

        $desiredScopes  = ($g.Scopes.Value | Sort-Object -Unique) -join ' '
        $existingScopes = if ($existingGrant) { ($existingGrant.Scope -split '\s+' | Where-Object { $_ } | Sort-Object -Unique) } else { @() }
        $mergedScopes   = (@($existingScopes) + ($g.Scopes.Value)) | Sort-Object -Unique
        $mergedString   = $mergedScopes -join ' '

        try {
            if (-not $existingGrant) {
                New-MgOauth2PermissionGrant -BodyParameter @{
                    clientId    = $sp.Id
                    consentType = 'AllPrincipals'
                    resourceId  = $g.ResourceSpId
                    scope       = $desiredScopes
                } | Out-Null
                $delegGranted += $g.Scopes.Count
            }
            elseif ($mergedString -ne ($existingScopes -join ' ')) {
                Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $existingGrant.Id -BodyParameter @{ scope = $mergedString } | Out-Null
                $delegGranted += ($mergedScopes.Count - $existingScopes.Count)
                $delegSkipped += $existingScopes.Count
            }
            else {
                $delegSkipped += $g.Scopes.Count
            }
        } catch {
            Write-Warning ("  Failed to grant delegated scopes on {0}: {1}" -f $apiName, $_.Exception.Message)
        }
    }
    Write-Host ("  Delegated  -> Granted: {0}   Already present: {1}" -f $delegGranted, $delegSkipped) -ForegroundColor Green

    # ─── Optional directory role assignments ───────────────────────────────────
    if ($AssignDirectoryRoles -and $wantedRoles.Count -gt 0) {
        Write-Host 'Assigning directory roles to service principal...' -ForegroundColor Cyan
        foreach ($roleName in $wantedRoles) {
            try {
                $template = Get-MgDirectoryRoleTemplate -All | Where-Object { $_.DisplayName -eq $roleName } | Select-Object -First 1
                if (-not $template) { Write-Warning "  Role template '$roleName' not found."; continue }

                $role = Get-MgDirectoryRole -All | Where-Object { $_.RoleTemplateId -eq $template.Id } | Select-Object -First 1
                if (-not $role) {
                    $role = New-MgDirectoryRole -BodyParameter @{ roleTemplateId = $template.Id } -ErrorAction SilentlyContinue
                    if (-not $role) { $role = Get-MgDirectoryRole -All | Where-Object { $_.RoleTemplateId -eq $template.Id } | Select-Object -First 1 }
                }
                if (-not $role) { Write-Warning "  Could not activate directory role '$roleName'."; continue }

                $alreadyMember = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue |
                    Where-Object { $_.Id -eq $sp.Id }
                if ($alreadyMember) {
                    Write-Host ("  {0,-30} already assigned" -f $roleName) -ForegroundColor Yellow
                    continue
                }
                New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -BodyParameter @{
                    '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($sp.Id)"
                }
                Write-Host ("  {0,-30} assigned" -f $roleName) -ForegroundColor Green
            } catch {
                Write-Warning ("  Failed to assign role '{0}': {1}" -f $roleName, $_.Exception.Message)
            }
        }
    } elseif ($wantedRoles.Count -gt 0) {
        Write-Host ''
        Write-Host 'NOTE: One or more bundles require directory-role assignments:' -ForegroundColor Yellow
        foreach ($r in $wantedRoles) { Write-Host ("    - {0}" -f $r) -ForegroundColor Yellow }
        Write-Host ('Assign them in portal, or rerun with -AssignDirectoryRoles.') -ForegroundColor Yellow
    }

    # ─── Write output JSON ────────────────────────────────────────────────────
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
    $outFile = Join-Path $OutputFolder 'app-output.json'

    $tenantDomain = $null
    try {
        $org = Get-MgOrganization -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($org) { $tenantDomain = ($org.VerifiedDomains | Where-Object IsInitial | Select-Object -First 1).Name }
    } catch { }

    $result = [pscustomobject]@{
        TenantId                = $ctx.TenantId
        TenantDomain            = $tenantDomain
        ApplicationId           = $app.AppId
        ObjectId                = $app.Id
        ServicePrincipalId      = $sp.Id
        DisplayName             = $DisplayName
        CertificateThumbprint   = $CertificateThumbprint
        Bundles                 = $bundleNames
        DirectoryRolesRequested = $wantedRoles
        DirectoryRolesAssigned  = [bool]$AssignDirectoryRoles
        CreatedUtc              = (Get-Date).ToUniversalTime().ToString('o')
        ConfigSnippet           = [ordered]@{
            tenant         = [ordered]@{ tenantName = $tenantDomain; tenantId = $ctx.TenantId }
            authentication = [ordered]@{
                mode                  = 'AppCertificate'
                clientId              = $app.AppId
                certificateThumbprint = $CertificateThumbprint
            }
        }
    }

    $result | ConvertTo-Json -Depth 10 | Set-Content -Path $outFile -Encoding UTF8

    Write-Host ''
    Write-Host '=== Done ===' -ForegroundColor Green
    Write-Host ('Output written to: {0}' -f $outFile)
    Write-Host ''
    Write-Host 'Paste the following into config\backup.config.json:' -ForegroundColor Cyan
    $result.ConfigSnippet | ConvertTo-Json -Depth 5
}
