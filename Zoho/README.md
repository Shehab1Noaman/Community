# Zoho ServiceDesk Plus OAuth PowerShell

Simple PowerShell helper for authenticating to Zoho ServiceDesk Plus with OAuth 2.0 and calling the API with automatic token refresh.

## Features

- One-time authorization code exchange
- Local token save/load helper
- Automatic access-token refresh
- Example ServiceDesk Plus Assets API call
- Clear structure for reuse in other scripts

## Files

- `Zoho-ServiceDeskPlus-OAuth.ps1` - main PowerShell script
- `.gitignore` - ignores local token files and editor clutter
- `LICENSE` - MIT license

## Prerequisites

- PowerShell 5.1 or later
- A Zoho Self Client created in the Zoho API Console
- Client ID
- Client Secret
- Authorization code for the first run
- Correct regional URLs for your Zoho tenant

## Scope format

Zoho uses this format for scopes:

```text
SDPOnDemand.<module>.<operation>
```

Examples:

- `SDPOnDemand.assets.ALL`
- `SDPOnDemand.assets.READ`
- `SDPOnDemand.assets.CREATE`

Use the minimum scope your automation needs.

## Configuration

Open `Zoho-ServiceDeskPlus-OAuth.ps1` and update these values:

```powershell
$ClientId       = "xxx"
$ClientSecret   = "xxx"
$AccountsUrl    = "https://accounts.zoho.uk"
$ZohoApiBaseUrl = "https://servicedeskplus.uk/app/itdesk/api/v3"
```

## How it works

### Step 1 - Run once to get tokens

Generate an authorization code in the Zoho API Console, then run:

```powershell
Get-InitialToken -AuthCode "paste_your_authorization_code_here"
```

This saves the access token, refresh token, API domain, and timestamp to:

```text
%LOCALAPPDATA%\ZohoTokens.json
```

### Step 2 - Use the script normally

After the first run, call:

```powershell
Get-ZohoAssets
```

The script will:

1. Load saved tokens
2. Check token age
3. Refresh the access token when needed
4. Call the ServiceDesk Plus Assets endpoint

## Region examples

Update the URLs to match your region.

| Region | Accounts URL | ServiceDesk Plus API base |
|---|---|---|
| UK | `https://accounts.zoho.uk` | `https://servicedeskplus.uk/app/itdesk/api/v3` |
| EU | `https://accounts.zoho.eu` | `https://servicedeskplus.eu/app/itdesk/api/v3` |
| US | `https://accounts.zoho.com` | `https://servicedeskplus.com/app/itdesk/api/v3` |
| IN | `https://accounts.zoho.in` | `https://servicedeskplus.in/app/itdesk/api/v3` |
| AU | `https://accounts.zoho.com.au` | `https://servicedeskplus.com.au/app/itdesk/api/v3` |

## Security note

The example stores tokens in a local JSON file for simplicity. That is convenient, but not a secure secret store.

For production use, prefer one of these:

- Azure Key Vault
- Windows Credential Manager
- Environment variables managed by your automation platform
- Another dedicated secret-management solution

## Common next steps

You can extend the script for other endpoints by replacing:

```powershell
$url = "$ZohoApiBaseUrl/assets"
```

Examples:

- `/solutions`
- `/requests`
- `/problems`
- `/changes`

## License

MIT
