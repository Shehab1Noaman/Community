function Export-UsersConfig {
    <#
    .SYNOPSIS
        Backs up the full user inventory: profile properties, permissions/access,
        license assignments, group + role memberships, owned objects and devices,
        authentication methods, and (when Exchange is connected) mailbox
        signatures + delegate permissions.

    .DESCRIPTION
        Files written to $OutputPath:
            Users.json                          — full Graph user objects (extended properties: jobTitle, department, manager, phones, address, etc.)
            UserManagers.json                   — user → manager mapping
            UserDirectReports.json              — user → direct reports
            UserMemberOf.json                   — group + role memberships per user
            UserAppRoleAssignments.json         — app role assignments granted to each user
            UserDirectoryRoleMemberships.json   — admin (directory) role memberships
            UserLicenseDetails.json             — assigned license SKUs and service plans per user
            UserAuthenticationMethods.json      — auth methods registered (sign-in/MFA)
            UserOwnedObjects.json               — apps/groups owned by each user
            UserOwnedDevices.json               — registered devices per user

        When Exchange Online is connected:
            MailboxSignatures.json              — Get-MailboxMessageConfiguration (signature HTML/text + auto-add settings)
            MailboxFullAccessPermissions.json   — Get-MailboxPermission (delegates with Full Access)
            MailboxSendAsPermissions.json       — Get-RecipientPermission (Send As)
            MailboxSendOnBehalfPermissions.json — derived from mailbox.GrantSendOnBehalfTo

    .PARAMETER PerObjectMaxItems
        Cap user iteration to N users (0 = no cap). Useful for smoke tests.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [string]$LogPath,

        [Parameter()]
        [int]$PerObjectMaxItems = 0
    )

    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

    # Reuse the same Graph paginator pattern used elsewhere.
    function Get-UsersGraphCollection {
        param(
            [Parameter(Mandatory)][string]$Uri,
            [int]$MaxRetries = 4
        )
        $all = New-Object System.Collections.Generic.List[object]
        $next = $Uri
        while (-not [string]::IsNullOrWhiteSpace($next)) {
            $resp = Invoke-GraphRequestWithRetry -Uri $next -MaxRetries $MaxRetries -LogPath $LogPath
            if ($null -eq $resp) { break }
            $batch = @(); $nextLink = $null
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
        return $all
    }

    # ── 1. Full user list with extended profile properties ──────────────────
    # Properties beyond the default set must be requested explicitly with $select.
    # Keep the collection query to fields the /users endpoint can materialize in bulk.
    # Profile-heavy fields such as aboutMe/interests/schools/skills trigger a backend
    # InvalidClientQueryException on larger tenants and would abort the entire Users export.
    $userSelect = @(
        'id','userPrincipalName','displayName','givenName','surname','mail','otherMails',
        'mailNickname','accountEnabled','userType','createdDateTime','lastPasswordChangeDateTime',
        'jobTitle','department','companyName','employeeId','employeeType','employeeHireDate',
        'officeLocation','streetAddress','city','state','postalCode','country','usageLocation',
        'preferredLanguage','businessPhones','mobilePhone','faxNumber',
        'proxyAddresses','onPremisesSyncEnabled','onPremisesImmutableId','onPremisesSamAccountName',
        'onPremisesUserPrincipalName','onPremisesDistinguishedName','onPremisesDomainName',
        'onPremisesSecurityIdentifier','externalUserState','externalUserStateChangeDateTime',
        'creationType','identities','signInSessionsValidFromDateTime',
        'assignedLicenses','assignedPlans','provisionedPlans',
        'authorizationInfo','imAddresses','isResourceAccount','showInAddressList',
        'ageGroup','consentProvidedForMinor','legalAgeGroupClassification'
    ) -join ','

    $users = @()
    try {
        $users = @(Get-UsersGraphCollection -Uri "/v1.0/users?`$top=999&`$select=$userSelect")
        ConvertTo-SafeJson -InputObject $users -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'Users.json') -Encoding UTF8
        Write-BackupLog -Level Information -Message "Users: $($users.Count) exported" -LogPath $LogPath
    }
    catch {
        Write-BackupLog -Level Error -Message "Users (list) failed: $($_.Exception.Message)" -LogPath $LogPath
        return
    }

    if ($PerObjectMaxItems -gt 0 -and $users.Count -gt $PerObjectMaxItems) {
        Write-BackupLog -Level Information -Message "Per-user expansion capped at $PerObjectMaxItems of $($users.Count) users" -LogPath $LogPath
        $users = $users | Select-Object -First $PerObjectMaxItems
    }

    # ── 2. Per-user expansions via Graph (manager / memberOf / app roles / etc.) ──
    $managers          = @()
    $directReports     = @()
    $memberOf          = @()
    $appRoleAssign     = @()
    $licenseDetails    = @()
    $authMethods       = @()
    $ownedObjects      = @()
    $ownedDevices      = @()

    $i = 0
    foreach ($u in $users) {
        $i++
        $uid = [string]$u.id
        $upn = [string]$u.userPrincipalName
        if ([string]::IsNullOrWhiteSpace($uid)) { continue }
        if (($i % 100) -eq 0) {
            Write-BackupLog -Level Information -Message "Per-user expansion progress: $i / $($users.Count)" -LogPath $LogPath
        }

        # Manager (single object; 404 when none assigned — silently ignore)
        try {
            $mgr = Invoke-GraphRequestWithRetry -Uri "/v1.0/users/$uid/manager" -MaxRetries 1 -LogPath $LogPath
            if ($mgr) {
                $managers += [pscustomobject]@{
                    UserId            = $uid
                    UserPrincipalName = $upn
                    Manager           = $mgr
                }
            }
        } catch { }

        # Direct reports
        try {
            $dr = @(Get-UsersGraphCollection -Uri "/v1.0/users/$uid/directReports" -MaxRetries 1)
            if ($dr.Count -gt 0) {
                $directReports += [pscustomobject]@{
                    UserId            = $uid
                    UserPrincipalName = $upn
                    DirectReports     = $dr
                }
            }
        } catch { }

        # memberOf — groups + directory roles (transitive variant captures nested)
        try {
            $mo = @(Get-UsersGraphCollection -Uri "/v1.0/users/$uid/transitiveMemberOf" -MaxRetries 1)
            if ($mo.Count -gt 0) {
                $memberOf += [pscustomobject]@{
                    UserId            = $uid
                    UserPrincipalName = $upn
                    MemberOf          = $mo
                }
            }
        } catch { }

        # App role assignments (which apps + which app role)
        try {
            $ara = @(Get-UsersGraphCollection -Uri "/v1.0/users/$uid/appRoleAssignments" -MaxRetries 1)
            if ($ara.Count -gt 0) {
                $appRoleAssign += [pscustomobject]@{
                    UserId            = $uid
                    UserPrincipalName = $upn
                    Assignments       = $ara
                }
            }
        } catch { }

        # License details
        try {
            $ld = @(Get-UsersGraphCollection -Uri "/v1.0/users/$uid/licenseDetails" -MaxRetries 1)
            if ($ld.Count -gt 0) {
                $licenseDetails += [pscustomobject]@{
                    UserId            = $uid
                    UserPrincipalName = $upn
                    Licenses          = $ld
                }
            }
        } catch { }

        # Authentication methods (MFA / passwordless registration)
        try {
            $am = @(Get-UsersGraphCollection -Uri "/v1.0/users/$uid/authentication/methods" -MaxRetries 1)
            if ($am.Count -gt 0) {
                $authMethods += [pscustomobject]@{
                    UserId            = $uid
                    UserPrincipalName = $upn
                    Methods           = $am
                }
            }
        } catch { }

        # Owned objects (apps / groups)
        try {
            $oo = @(Get-UsersGraphCollection -Uri "/v1.0/users/$uid/ownedObjects" -MaxRetries 1)
            if ($oo.Count -gt 0) {
                $ownedObjects += [pscustomobject]@{
                    UserId            = $uid
                    UserPrincipalName = $upn
                    OwnedObjects      = $oo
                }
            }
        } catch { }

        # Owned (registered) devices
        try {
            $od = @(Get-UsersGraphCollection -Uri "/v1.0/users/$uid/ownedDevices" -MaxRetries 1)
            if ($od.Count -gt 0) {
                $ownedDevices += [pscustomobject]@{
                    UserId            = $uid
                    UserPrincipalName = $upn
                    OwnedDevices      = $od
                }
            }
        } catch { }
    }

    ConvertTo-SafeJson -InputObject @($managers)       -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'UserManagers.json')                 -Encoding UTF8
    ConvertTo-SafeJson -InputObject @($directReports)  -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'UserDirectReports.json')            -Encoding UTF8
    ConvertTo-SafeJson -InputObject @($memberOf)       -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'UserMemberOf.json')                 -Encoding UTF8
    ConvertTo-SafeJson -InputObject @($appRoleAssign)  -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'UserAppRoleAssignments.json')       -Encoding UTF8
    ConvertTo-SafeJson -InputObject @($licenseDetails) -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'UserLicenseDetails.json')           -Encoding UTF8
    ConvertTo-SafeJson -InputObject @($authMethods)    -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'UserAuthenticationMethods.json')    -Encoding UTF8
    ConvertTo-SafeJson -InputObject @($ownedObjects)   -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'UserOwnedObjects.json')             -Encoding UTF8
    ConvertTo-SafeJson -InputObject @($ownedDevices)   -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'UserOwnedDevices.json')             -Encoding UTF8

    # Directory role memberships from the role side (faster than per-user when many users have no admin roles)
    try {
        $dirRoles = @(Get-UsersGraphCollection -Uri '/v1.0/directoryRoles')
        $dirRoleMembers = @()
        foreach ($r in $dirRoles) {
            $rid = [string]$r.id
            try {
                $members = @(Get-UsersGraphCollection -Uri "/v1.0/directoryRoles/$rid/members" -MaxRetries 1)
                $dirRoleMembers += [pscustomobject]@{
                    RoleId          = $rid
                    RoleDisplayName = $r.displayName
                    RoleTemplateId  = $r.roleTemplateId
                    Members         = $members
                }
            } catch { }
        }
        ConvertTo-SafeJson -InputObject @($dirRoleMembers) -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'UserDirectoryRoleMemberships.json') -Encoding UTF8
    }
    catch {
        Write-BackupLog -Level Warning -Message "Directory role memberships failed: $($_.Exception.Message)" -LogPath $LogPath
    }

    # ── 3. Exchange Online: signatures + delegate permissions (best-effort) ──
    if (-not (Get-Command Get-Mailbox -ErrorAction SilentlyContinue)) {
        Write-BackupLog -Level Information -Message "Exchange Online not connected; skipping mailbox signatures + permissions" -LogPath $LogPath
        return
    }

    try {
        $mailboxes = Invoke-WithThrottleRetry -OperationName 'Users Get-Mailbox (all)' -LogPath $LogPath -ScriptBlock {
            Get-Mailbox -ResultSize Unlimited
        }
        $mailboxes = @($mailboxes)
        if ($PerObjectMaxItems -gt 0 -and $mailboxes.Count -gt $PerObjectMaxItems) {
            Write-BackupLog -Level Information -Message "Per-mailbox signature/perm export capped at $PerObjectMaxItems of $($mailboxes.Count) mailboxes" -LogPath $LogPath
            $mailboxes = $mailboxes | Select-Object -First $PerObjectMaxItems
        }
        Write-BackupLog -Level Information -Message "Mailbox signatures + permissions starting for $($mailboxes.Count) mailbox(es)" -LogPath $LogPath

        $signatures   = @()
        $fullAccess   = @()
        $sendAs       = @()
        $sendOnBehalf = @()

        $j = 0
        foreach ($mbx in $mailboxes) {
            $j++
            $upn = [string]$mbx.UserPrincipalName
            if ([string]::IsNullOrWhiteSpace($upn)) { $upn = [string]$mbx.PrimarySmtpAddress }
            if ([string]::IsNullOrWhiteSpace($upn)) { continue }
            if (($j % 100) -eq 0) {
                Write-BackupLog -Level Information -Message "Mailbox signature/perm progress: $j / $($mailboxes.Count)" -LogPath $LogPath
            }

            # Signature (and "auto-add to outgoing" behavior)
            if (Get-Command Get-MailboxMessageConfiguration -ErrorAction SilentlyContinue) {
                try {
                    $sig = Get-MailboxMessageConfiguration -Identity $upn -ErrorAction Stop
                    $signatures += [pscustomobject]@{
                        Identity                       = $upn
                        SignatureHtml                  = [string]$sig.SignatureHtml
                        SignatureText                  = [string]$sig.SignatureText
                        AutoAddSignature               = [bool]$sig.AutoAddSignature
                        AutoAddSignatureOnReply        = [bool]$sig.AutoAddSignatureOnReply
                        AutoAddSignatureOnMobile       = [bool]$sig.AutoAddSignatureOnMobile
                        UseDefaultSignatureOnMobile    = [bool]$sig.UseDefaultSignatureOnMobile
                        AlwaysShowBcc                  = [bool]$sig.AlwaysShowBcc
                        AlwaysShowFrom                 = [bool]$sig.AlwaysShowFrom
                        DefaultFontName                = [string]$sig.DefaultFontName
                        DefaultFontSize                = [string]$sig.DefaultFontSize
                        DefaultFontColor               = [string]$sig.DefaultFontColor
                        DefaultFontFlags               = [string]$sig.DefaultFontFlags
                    }
                } catch {
                    Write-BackupLog -Level Warning -Message "[Signature] $upn`: $($_.Exception.Message)" -LogPath $LogPath
                }
            }

            # Full Access delegates
            if (Get-Command Get-MailboxPermission -ErrorAction SilentlyContinue) {
                try {
                    $perms = @(Get-MailboxPermission -Identity $upn -ErrorAction Stop |
                        Where-Object { $_.User -and -not $_.IsInherited -and $_.User -notlike 'NT AUTHORITY\SELF' -and $_.User -notlike 'S-1-5-*' })
                    if ($perms.Count -gt 0) {
                        $fullAccess += [pscustomobject]@{
                            Identity    = $upn
                            Permissions = $perms | Select-Object User, AccessRights, Deny, InheritanceType
                        }
                    }
                } catch {
                    Write-BackupLog -Level Warning -Message "[MailboxPermission] $upn`: $($_.Exception.Message)" -LogPath $LogPath
                }
            }

            # Send As
            if (Get-Command Get-RecipientPermission -ErrorAction SilentlyContinue) {
                try {
                    $rperms = @(Get-RecipientPermission -Identity $upn -ErrorAction Stop |
                        Where-Object { $_.Trustee -and $_.Trustee -ne 'NT AUTHORITY\SELF' })
                    if ($rperms.Count -gt 0) {
                        $sendAs += [pscustomobject]@{
                            Identity    = $upn
                            Permissions = $rperms | Select-Object Trustee, AccessRights, AccessControlType
                        }
                    }
                } catch {
                    Write-BackupLog -Level Warning -Message "[RecipientPermission] $upn`: $($_.Exception.Message)" -LogPath $LogPath
                }
            }

            # Send on Behalf — read directly from the mailbox object
            if ($mbx.GrantSendOnBehalfTo -and @($mbx.GrantSendOnBehalfTo).Count -gt 0) {
                $sendOnBehalf += [pscustomobject]@{
                    Identity            = $upn
                    GrantSendOnBehalfTo = @($mbx.GrantSendOnBehalfTo | ForEach-Object { [string]$_ })
                }
            }
        }

        ConvertTo-SafeJson -InputObject @($signatures)   -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'MailboxSignatures.json')             -Encoding UTF8
        ConvertTo-SafeJson -InputObject @($fullAccess)   -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'MailboxFullAccessPermissions.json') -Encoding UTF8
        ConvertTo-SafeJson -InputObject @($sendAs)       -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'MailboxSendAsPermissions.json')     -Encoding UTF8
        ConvertTo-SafeJson -InputObject @($sendOnBehalf) -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'MailboxSendOnBehalfPermissions.json') -Encoding UTF8

        Write-BackupLog -Level Information -Message "Mailbox signatures + permissions complete: $($mailboxes.Count) mailboxes" -LogPath $LogPath
    }
    catch {
        Write-BackupLog -Level Warning -Message "Mailbox signatures/permissions failed: $($_.Exception.Message)" -LogPath $LogPath
    }
}
