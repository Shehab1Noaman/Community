# ==========================================
# Zoho OAuth Configuration
# ==========================================

# https://api-console.zoho.eu/client/xxxx

# Operation Type    Scope Example              Description
# ALL               SDPOnDemand.assets.ALL     To access Asset module related all APIs
# CREATE            SDPOnDemand.assets.CREATE  To create Asset module related records
# READ              SDPOnDemand.assets.READ    To read Asset module related records
# UPDATE            SDPOnDemand.assets.UPDATE  To update Asset module related records
# DELETE            SDPOnDemand.assets.DELETE  To delete Asset module related records

$ClientId       = "xxx"
$ClientSecret   = "xxx"
$AccountsUrl    = "https://accounts.zoho.uk"  ## Adjust the domain to match your Zoho region (.com / .eu / .uk / .in / .com.au / .jp)
$ZohoApiBaseUrl = "https://servicedeskplus.uk/app/itdesk/api/v3" ## Adjust the domain to match your Zoho region (.com / .eu / .uk / .in / .com.au / .jp)

# File to store tokens locally (adjust path as needed)
# For production use, store secrets in a secure location such as
# Windows Credential Manager, Azure Key Vault, or another secret store.
$TokenFile = "$env:LOCALAPPDATA\ZohoTokens.json"


# ==========================================
# Function: Save Tokens
# ==========================================
function Save-Tokens {
    param (
        [Parameter(Mandatory = $true)]
        $tokens
    )

    $tokens | ConvertTo-Json | Set-Content -Path $TokenFile
}


# ==========================================
# Function: Load Tokens
# ==========================================
function Load-Tokens {
    if (Test-Path $TokenFile) {
        return Get-Content $TokenFile | ConvertFrom-Json
    }
    return $null
}


# ==========================================
# 1. First-time Authorization (Run Once)
# ==========================================
function Get-InitialToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AuthCode
    )

    # First you need to generate an OAuth access token using your Client ID and Client Secret.
    # The authorization code is obtained after the user authorizes your application.

    $url = "$AccountsUrl/oauth/v2/token"

    $body = @{
        code          = $AuthCode
        grant_type    = "authorization_code"
        client_id     = $ClientId
        client_secret = $ClientSecret
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Post `
            -Body $body -ContentType "application/x-www-form-urlencoded"

        # You can use the authorization code flow to obtain an access token.
        # Make sure to save the refresh token for later use.

        $tokens = @{
            access_token  = $response.access_token
            refresh_token = $response.refresh_token
            api_domain    = $response.api_domain
            created_on    = (Get-Date)
        }

        Save-Tokens $tokens

        Write-Host "Initial tokens acquired and saved."
        return $tokens
    }
    catch {
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            Write-Error "Status: $($_.Exception.Response.StatusCode)"
            Write-Error "Body: $($reader.ReadToEnd())"
        }
        else {
            Write-Error $_.Exception.Message
        }
    }
}


# ==========================================
# 2. Refresh Access Token (Used Ongoing)
# ==========================================
function Refresh-AccessToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$refreshToken
    )

    # The refresh token is used to obtain a new access token without requiring user re-authorization.

    $url = "$AccountsUrl/oauth/v2/token"

    $body = @{
        refresh_token = $refreshToken
        grant_type    = "refresh_token"
        client_id     = $ClientId
        client_secret = $ClientSecret
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Post `
            -Body $body -ContentType "application/x-www-form-urlencoded"

        $tokens = @{
            access_token  = $response.access_token
            refresh_token = $refreshToken
            api_domain    = $response.api_domain
            created_on    = (Get-Date)
        }

        Save-Tokens $tokens

        Write-Host "Access token refreshed."
        return $tokens
    }
    catch {
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            Write-Error "Status: $($_.Exception.Response.StatusCode)"
            Write-Error "Body: $($reader.ReadToEnd())"
        }
        else {
            Write-Error $_.Exception.Message
        }
    }
}


# ==========================================
# 3. Get Valid Access Token (Auto Handles Expiry)
# ==========================================
function Get-ValidAccessToken {
    $tokens = Load-Tokens

    if (-not $tokens) {
        throw "No tokens found. Run Get-InitialToken first."
    }

    # Access token typically expires in 1 hour
    $age = (New-TimeSpan -Start $tokens.created_on -End (Get-Date)).TotalMinutes

    if ($age -gt 50) {
        # If expired or close to expiry → refresh
        return Refresh-AccessToken -refreshToken $tokens.refresh_token
    }

    return $tokens
}


# ==========================================
# 4. Example API Call (Assets Module)
# ==========================================
function Get-ZohoAssets {

    # The access token will be used to authenticate your API requests.

    $tokens = Get-ValidAccessToken

    $headers = @{
        Authorization = "Zoho-oauthtoken $($tokens.access_token)"
        Accept        = "application/vnd.manageengine.sdp.v3+json"
    }

    $url = "$ZohoApiBaseUrl/assets"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
        return $response
    }
    catch {
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            Write-Error "Status: $($_.Exception.Response.StatusCode)"
            Write-Error "Body: $($reader.ReadToEnd())"
        }
        else {
            Write-Error $_.Exception.Message
        }
    }
}


# ==========================================
# Usage Instructions
# ==========================================

# STEP 1 (Run once only):
# Get-InitialToken -AuthCode "paste_your_authorization_code_here"

# STEP 2 (Normal usage after that):
# Get-ZohoAssets
