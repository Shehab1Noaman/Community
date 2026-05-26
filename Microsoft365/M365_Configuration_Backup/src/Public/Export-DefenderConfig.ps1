function Export-DefenderConfig {
    <#
    .SYNOPSIS
        Exports Microsoft Defender configuration via Microsoft Graph (security namespace)
        and (optionally) Defender for Endpoint Security Center API.
    .DESCRIPTION
        Most Defender for Office policies are exported via Export-ExchangeConfig
        (anti-phish, anti-spam, anti-malware, safe links, safe attachments).
        This exporter focuses on cross-Defender items exposed via Microsoft Graph,
        plus optional Defender for Endpoint config from api.securitycenter.microsoft.com.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [string]$LogPath,

        [Parameter()]
        [switch]$IncludeEndpointSecurityCenter,

        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [string]$ClientId,

        [Parameter()]
        [string]$CertificateThumbprint
    )

    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

    function Get-DefenderCollection {
        param([Parameter(Mandatory)][string]$Uri)
        $all = New-Object System.Collections.Generic.List[object]
        $next = $Uri
        while (-not [string]::IsNullOrWhiteSpace($next)) {
            $resp = Invoke-GraphRequestWithRetry -Uri $next -MaxRetries 2 -LogPath $LogPath
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

    $collections = [ordered]@{
        SecureScores                  = '/v1.0/security/secureScores?$top=50'
        SecureScoreControlProfiles    = '/v1.0/security/secureScoreControlProfiles'
        ThreatSubmissionEmails        = '/v1.0/security/threatSubmission/emailThreats?$top=100'
        ThreatSubmissionUrls          = '/v1.0/security/threatSubmission/urlThreats?$top=100'
        ThreatSubmissionFiles         = '/v1.0/security/threatSubmission/fileThreats?$top=100'
        ThreatSubmissionPolicies      = '/v1.0/security/threatSubmission/emailThreatSubmissionPolicies'
        # Identity protection (Defender for Identity)
        IdentityRiskDetections        = '/v1.0/identityProtection/riskDetections?$top=100'
    }

    foreach ($name in $collections.Keys) {
        try {
            $data = @(Get-DefenderCollection -Uri $collections[$name])
            ConvertTo-SafeJson -InputObject $data -Depth 20 |
                Set-Content -Path (Join-Path $OutputPath "$name.json") -Encoding UTF8
            Write-BackupLog -Level Information -Message "Exported Defender object: $name ($($data.Count) items)" -LogPath $LogPath
        }
        catch {
            Write-BackupLog -Level Information -Message "Skipped Defender object [$name] (likely not licensed or insufficient permissions): $($_.Exception.Message)" -LogPath $LogPath
        }
    }

    Write-BackupLog -Level Information -Message "Note: Defender for Office policies (anti-phish/spam/malware/safe links/safe attachments) are exported via the ExchangeOnline workload. Defender for Endpoint configuration uses a separate API (api.securitycenter.microsoft.com) and is not yet automated here." -LogPath $LogPath

    # ── Defender for Endpoint (api.securitycenter.microsoft.com) — opt-in ────
    if (-not $IncludeEndpointSecurityCenter) {
        return
    }
    if ([string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($ClientId) -or [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        Write-BackupLog -Level Warning -Message "Defender for Endpoint: TenantId/ClientId/CertificateThumbprint not provided; skipping securitycenter API exports" -LogPath $LogPath
        return
    }

    try {
        # Acquire access token using client certificate (no extra modules; uses MSAL.PS if available, else manual JWT)
        $cert = Get-ChildItem -Path "Cert:\CurrentUser\My\$CertificateThumbprint","Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $cert) { throw "Certificate $CertificateThumbprint not found in CurrentUser\My or LocalMachine\My" }

        # Build self-signed JWT client assertion
        $now    = [DateTimeOffset]::UtcNow
        $exp    = $now.AddMinutes(10)
        $jwtHeader = @{ alg='RS256'; typ='JWT'; x5t = [Convert]::ToBase64String($cert.GetCertHash()) -replace '\+','-' -replace '/','_' -replace '=','' }
        $jwtPayload = @{
            aud = "https://login.microsoftonline.com/$TenantId/v2.0"
            iss = $ClientId
            sub = $ClientId
            jti = [guid]::NewGuid().ToString()
            nbf = $now.ToUnixTimeSeconds()
            exp = $exp.ToUnixTimeSeconds()
        }
        function ConvertTo-Base64Url([byte[]]$Bytes) { ([Convert]::ToBase64String($Bytes) -replace '\+','-' -replace '/','_' -replace '=','') }
        $headerB64  = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($jwtHeader  | ConvertTo-Json -Compress)))
        $payloadB64 = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($jwtPayload | ConvertTo-Json -Compress)))
        $unsigned   = "$headerB64.$payloadB64"
        $rsa        = $cert.PrivateKey
        if (-not $rsa) { $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert) }
        $sigBytes   = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($unsigned), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $assertion  = "$unsigned." + (ConvertTo-Base64Url $sigBytes)

        $body = @{
            grant_type            = 'client_credentials'
            client_id             = $ClientId
            scope                 = 'https://api.securitycenter.microsoft.com/.default'
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $assertion
        }
        $tok = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body -ContentType 'application/x-www-form-urlencoded'
        $headers = @{ Authorization = "Bearer $($tok.access_token)" }

        $mdeEndpoints = [ordered]@{
            DeviceAuthenticatedScanDefinitions = 'https://api.securitycenter.microsoft.com/api/DeviceAuthenticatedScanDefinitions'
            DefenderRoleDefinitions            = 'https://api.securitycenter.microsoft.com/api/Roles'
            DefenderMachineGroups              = 'https://api.securitycenter.microsoft.com/api/machineGroups'
            DefenderIndicators                 = 'https://api.securitycenter.microsoft.com/api/indicators'
            DefenderRecommendations            = 'https://api.securitycenter.microsoft.com/api/recommendations'
            DefenderConfigurations             = 'https://api.securitycenter.microsoft.com/api/configurations'
            DefenderSubscriptionPlan           = 'https://api.securitycenter.microsoft.com/api/configuration/subscriptionPlan'
        }
        foreach ($name in $mdeEndpoints.Keys) {
            try {
                $r = Invoke-RestMethod -Method Get -Uri $mdeEndpoints[$name] -Headers $headers -ErrorAction Stop
                $items = if ($null -ne $r.value) { @($r.value) } else { @($r) }
                ConvertTo-SafeJson -InputObject $items -Depth 20 |
                    Set-Content -Path (Join-Path $OutputPath "$name.json") -Encoding UTF8
                Write-BackupLog -Level Information -Message "Exported Defender object: $name ($($items.Count) items)" -LogPath $LogPath
            } catch {
                Write-BackupLog -Level Information -Message "Skipped Defender object [$name] (likely not licensed or insufficient WindowsDefenderATP API permissions): $($_.Exception.Message)" -LogPath $LogPath
            }
        }
    }
    catch {
        Write-BackupLog -Level Warning -Message "Defender for Endpoint securitycenter export failed: $($_.Exception.Message)" -LogPath $LogPath
    }
}
