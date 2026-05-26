# M365_Configuration_Backup

A PowerShell module for Microsoft 365 tenant configuration backup, drift detection, and controlled restore. Supports EntraID, Exchange Online, Teams, SharePoint, Intune, Compliance, Defender, Power Platform, Planner, and Users.

---

## Getting Started

### Prerequisites

- PowerShell 7.2 or later (`winget install Microsoft.PowerShell`)
- An Azure/Entra admin account with **Application Administrator** and **Privileged Role Administrator** roles (for one-time app registration only)
- Required PowerShell modules installed on the machine that runs backups:
  ```powershell
  Install-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement,
                MicrosoftTeams, Microsoft.Online.SharePoint.PowerShell,
                PnP.PowerShell -Scope CurrentUser -Force
  ```
  Or let the module install them for you by passing `-InstallMissingModules` on the first run.

---

### Step 1 — Create a certificate

The module uses **app-only certificate authentication** (no passwords, no interactive sign-in at runtime).

```powershell
Import-Module .\src\BackupM365.psd1 -Force

# Creates a self-signed cert in Cert:\CurrentUser\My and exports BackupM365.cer + BackupM365.pfx
New-M365BackupCertificate -Subject 'CN=BackupM365' -YearsValid 2 -OutputFolder C:\M365Backup\certs
```

Note the **Thumbprint** printed at the end — you will need it in Steps 2 and 3.

---

### Step 2 — Register the Entra app (backup app)

```powershell
# Connects interactively (browser popup), creates the app, uploads your cert, and grants admin consent
New-M365BackupApp `
	-CertificateThumbprint <THUMBPRINT_FROM_STEP_1> `
	-Bundles               Full `
	-AssignDirectoryRoles `
	-InstallMissingModules
```

**Parameter explanations:**

- **`-Bundles Full`**: Grants permission bundles for all 9 supported workloads (Entra, Users, Intune, Exchange, SharePoint, Teams, Compliance, Defender, Planner).
  - If you only backup specific workloads, use a selective list: `-Bundles 'Entra,Users,Intune'` (grants only permissions needed for those three).
  - See `config/permissions/backup-permissions-bundles.json` for the full list of permission bundles.

- **`-AssignDirectoryRoles`**: Assigns Entra directory roles required by some workloads (e.g., "Attribute Definition Reader" for Entra Config).
  - Required for full backup coverage; omit if your account doesn't have Privileged Role Administrator.
  - Requires: Privileged Role Administrator or Global Administrator role.

- **`-InstallMissingModules`**: Auto-installs any required PowerShell modules (Microsoft.Graph.*, ExchangeOnlineManagement, etc.) from PSGallery.
  - Omit if modules are already installed or if you prefer to install them manually.

**Output**: The **Client ID (appId)** printed at the end — save this for Step 3.

For restore you can reuse the same app or create a separate restore-only app with narrower write permissions:
```powershell
# Restore app with read-write permissions
New-M365RestoreApp `
	-CertificateThumbprint <THUMBPRINT> `
	-Bundles Full `
	-AssignDirectoryRoles `
	-InstallMissingModules
```

---

### Step 3 — Create your config files

Edit the template files in `config/templates/` and save them as your runtime configs. You can either:

**Option A — Edit templates directly:**
```powershell
# Edit the template files with your tenant/app/path values
notepad config\templates\backup.config.json
notepad config\templates\restore.config.json
```

**Option B — Copy templates to runtime location (if you prefer keeping templates separate):**
```powershell
Copy-Item config\templates\backup.config.json  config\backup.config.json
Copy-Item config\templates\restore.config.json config\restore.config.json
# Then edit your runtime copies
notepad config\backup.config.json
notepad config\restore.config.json
```

Either way, both `backup.config.json` and `restore.config.json` are **gitignored** and must never be committed.

#### backup.config.json — key fields to fill in

| Field | Where to find it | Example |
|---|---|---|
| `tenant.tenantName` | Microsoft 365 admin center → Settings → Org settings | `contoso.onmicrosoft.com` |
| `tenant.tenantId` | Entra ID portal → Overview | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `authentication.clientId` | Entra ID → App registrations → your app → Overview | `yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy` |
| `authentication.certificateThumbprint` | Output of Step 1, or `Get-ChildItem Cert:\CurrentUser\My` | `AABB...EEFF` |
| `sharePointAdminUrl` | Your tenant name + `-admin.sharepoint.com` | `https://contoso-admin.sharepoint.com/` |
| `outputRoot` | Any local or UNC path where backups are written | `C:\M365Backup\output` |

Everything else (throttling, prechecks, per-workload flags) has sensible defaults — leave them as-is for the first run.

#### restore.config.json — key fields to fill in

| Field | Notes |
|---|---|
| `source.backupPath` | Path to a specific backup snapshot folder (contains `metadata.json`) |
| `target.tenantName` / `target.tenantId` | Same as backup for same-tenant restore; different tenant for cross-tenant |
| `authentication.clientId` | Client ID of your **restore** app (needs ReadWrite permissions) |
| `compareAuthentication.clientId` | Client ID of your **backup** app (read-only, used for the compare phase) |
| `authentication.certificateThumbprint` | Same thumbprint works for both apps if you reused the cert |
| `report.outputRoot` | Required. Where restore reports are written; restore now fails fast if this is empty/missing |

---

### Step 4 — Run a backup

```powershell
Import-Module .\src\BackupM365.psd1 -Force

Export-M365TenantConfig -ConfigPath .\config\backup.config.json -Connect -Verbose
```

`-Connect` auto-connects to every workload using the credentials in `backup.config.json`. Omit it if you have already called `Connect-M365Tenant` yourself.

**Common variations:**
```powershell
# Backup only specific workloads
Export-M365TenantConfig -ConfigPath .\config\backup.config.json -Connect -Workloads EntraID,Intune -Verbose

# Skip workloads you don't need
Export-M365TenantConfig -ConfigPath .\config\backup.config.json -Connect -Skip SharePoint,Teams -Verbose

# Auto-install any missing modules first
Export-M365TenantConfig -ConfigPath .\config\backup.config.json -Connect -InstallMissingModules -Verbose

# Skip pre-flight checks (faster, for scheduled/CI runs after first success)
Export-M365TenantConfig -ConfigPath .\config\backup.config.json -Connect -SkipPrechecks -Verbose

# Skip logging (no transcript or NDJSON logs)
Export-M365TenantConfig -ConfigPath .\config\backup.config.json -Connect -NoLog -Verbose
```

---

### Step 5 — Run a restore

**Always dry-run first** to see what would change before applying anything:

```powershell
# Compare only — no changes written, no logs by default
Restore-M365TenantConfig -ConfigPath .\config\restore.config.json -DryRun -Verbose

# Apply changes (prompts [Y/N] per object by default)
Restore-M365TenantConfig -ConfigPath .\config\restore.config.json -ApplyChanges -Verbose

# Apply without prompts (CI / unattended)
Restore-M365TenantConfig -ConfigPath .\config\restore.config.json -ApplyChanges -Force -Verbose

# Enable logging during restore
Restore-M365TenantConfig -ConfigPath .\config\restore.config.json -ApplyChanges -NoLog:$false -Verbose
```

---

## App Registration Setup — Manual Alternative

If you prefer to create and configure app registrations **manually without the setup scripts**, follow this guide. You'll need **two apps**: one for backup (read-only) and one for restore (read-write).

### Authentication Methods Summary

| Workload | Auth Method | Backup App | Restore App |
|---|---|---|---|
| **Entra ID** | Microsoft Graph (certificate or secret) | ✓ Certificate | ✓ Certificate |
| **Users** | Microsoft Graph (certificate or secret) | ✓ Certificate | ✓ Certificate |
| **Intune** | Microsoft Graph (certificate or secret) | ✓ Certificate | ✓ Certificate |
| **Planner** | Microsoft Graph (certificate or secret) | ✓ Certificate | ✓ Certificate |
| **Exchange Online** | ExchangeOnlineManagement (`Exchange.ManageAsApp`) | ✓ Certificate | ✓ Certificate |
| **Teams** | MicrosoftTeams module app-only or interactive | ✓ Certificate | ✓ Certificate |
| **SharePoint** | PnP.PowerShell app-only for supported items; `Get-SPO*` remains interactive | ✓ Certificate (partial) | ✓ Certificate (partial/export-first) |
| **Compliance/Purview** | ExchangeOnlineManagement / `Connect-IPPSSession` (`Exchange.ManageAsApp`) | ✓ Certificate | ✓ Certificate |
| **Defender** | Microsoft Graph (certificate or secret) | ✓ Certificate | ✓ Certificate |
| **Power Platform** | Power Platform admin module (client secret only) | ✓ Client Secret | ✓ Client Secret |

**Key Points:**
- **Most workloads use certificate authentication** (recommended for security)
- **Power Platform requires a Client Secret** (the admin module does not support certificate auth)
- **Exchange and Compliance require `Exchange.ManageAsApp`** and the right directory role assignments on the service principal
- **Teams uses the MicrosoftTeams module with app-only certificate auth** and still needs the Graph Teams application roles
- **SharePoint app-only is partial**: PnP-backed items work with certificate auth, but pure `Get-SPO*` coverage still needs an interactive `Connect-SPOService` session
- Backup app needs **read-only Graph permissions**
- Restore app needs **read-write Graph permissions** for its assigned workloads

### Step 1 — Create a Self-Signed Certificate

First, generate a certificate for authentication (required for Graph API):

```powershell
# Create certificate (valid for 2 years)
$cert = New-SelfSignedCertificate -Type Custom `
  -Subject "CN=BackupM365" `
  -KeyUsage DigitalSignature `
  -FriendlyName "BackupM365" `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyExportPolicy Exportable `
  -NotAfter (Get-Date).AddYears(2)

# Export to .cer (for app registration) and .pfx (for backup)
$cert | Export-Certificate -FilePath "$env:USERPROFILE\Desktop\BackupM365.cer" -Force
Export-PfxCertificate -Cert $cert -FilePath "$env:USERPROFILE\Desktop\BackupM365.pfx" `
  -Password (ConvertTo-SecureString -String "YourPassword123!" -AsPlainText -Force) -Force

Write-Host "Certificate Thumbprint: $($cert.Thumbprint)"
Write-Host "Exported .cer to: $env:USERPROFILE\Desktop\BackupM365.cer"
Write-Host "Exported .pfx to: $env:USERPROFILE\Desktop\BackupM365.pfx"
```

**Save the thumbprint** — you'll need it for both app registrations and config files.

### Step 2 — Create Backup App (Read-Only)

Create the app registration in Entra ID:

1. Go to **Entra ID Portal** → **App registrations** → **New registration**
2. **Name**: `BackupM365-Backup`
3. **Supported account types**: `Accounts in this organizational directory only`
4. **Register** → Copy the **Application (client) ID**

**Add certificate:**
1. Go to **Certificates & secrets** → **Certificates** → **Upload certificate**
2. Upload the **BackupM365.cer** file from Step 1
3. Verify the thumbprint matches

**Add API permissions** (backup / read path):

| Workload | Required permissions / roles |
|---|---|
| Entra ID | Microsoft Graph: `Directory.Read.All`, `Policy.Read.All`, `Application.Read.All`, `RoleManagement.Read.Directory`, `AuditLog.Read.All`, `Group.Read.All` plus the extra Entra/Governance read roles defined in `config/permissions/backup-permissions-bundles.json` |
| Users | Microsoft Graph: `User.Read.All`, `Group.Read.All`, `Directory.Read.All`, `UserAuthenticationMethod.Read.All` |
| Intune | Microsoft Graph: `DeviceManagementConfiguration.Read.All`, `DeviceManagementApps.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementServiceConfig.Read.All`, `DeviceManagementScripts.Read.All`, `DeviceManagementRBAC.Read.All`, `CloudPC.Read.All` |
| Exchange Online | Office 365 Exchange Online: `Exchange.ManageAsApp` and assign the service principal a suitable Entra directory role such as `Global Reader` |
| SharePoint | SharePoint Online: `Sites.FullControl.All`; Microsoft Graph: `Sites.FullControl.All` |
| Teams | Microsoft Graph: `TeamSettings.Read.All`, `Team.ReadBasic.All`, `TeamMember.Read.All`, `Channel.ReadBasic.All`, `ChannelSettings.Read.All`, `TeamsTab.Read.All`, `TeamsAppInstallation.ReadForTeam.All` |
| Compliance / Purview | Office 365 Exchange Online: `Exchange.ManageAsApp` and assign the service principal `Compliance Administrator` |
| Defender | Microsoft Graph: `SecurityEvents.Read.All`, `SecurityActions.Read.All`, `ThreatHunting.Read.All`, `ThreatSubmission.Read.All`; WindowsDefenderATP: `Machine.Read.All`, `AdvancedQuery.Read.All`, `SecurityRecommendation.Read.All`, `Vulnerability.Read.All`, `Score.Read.All`, `SecurityBaselinesAssessment.Read.All` |
| Planner | Microsoft Graph: `Tasks.Read.All`, `Group.Read.All` |

`config/permissions/backup-permissions-bundles.json` is the authoritative source for the full backup-app permission list. The helper cmdlet already grants these bundles correctly; no code change was needed in the app-creation cmdlet.

Then **Grant admin consent** (your account needs Global Admin or Privileged Role Admin).

### Step 3 — Create Restore App (Read-Write)

Repeat the process for the restore app:

1. **Entra ID Portal** → **App registrations** → **New registration**
2. **Name**: `BackupM365-Restore`
3. **Register** → Copy the **Application (client) ID**
4. **Add the same certificate** as Step 2
5. **Add API permissions**. Start with the same read permissions as the backup app, then add these restore-specific write roles where restore supports write-back:

| Workload | Additional restore permissions / roles |
|---|---|
| Entra ID | Microsoft Graph: `Directory.ReadWrite.All`, `Policy.ReadWrite.ConditionalAccess`, `Group.ReadWrite.All`, `Application.ReadWrite.All` |
| Users | Microsoft Graph: `User.ReadWrite.All`, `Group.ReadWrite.All` |
| Intune | Microsoft Graph: `DeviceManagementConfiguration.ReadWrite.All`, `DeviceManagementApps.ReadWrite.All`, `DeviceManagementManagedDevices.ReadWrite.All`, `DeviceManagementServiceConfig.ReadWrite.All`, `DeviceManagementScripts.ReadWrite.All`, `DeviceManagementRBAC.ReadWrite.All` |
| SharePoint | SharePoint Online: `Sites.FullControl.All`; Microsoft Graph: `Sites.FullControl.All` |
| Teams | Microsoft Graph: `TeamSettings.ReadWrite.All`, `ChannelSettings.ReadWrite.All`, `TeamsAppInstallation.ReadWriteForTeam.All` in addition to the read roles |
| Planner | Microsoft Graph: `Tasks.ReadWrite.All` and `Group.Read.All` |

`config/permissions/restore-permissions-bundles.json` is the authoritative source for the full restore-app permission list. The helper cmdlet already grants these bundles correctly; no code change was needed in the app-creation cmdlet.

Then **Grant admin consent**.

### Step 4 — Fill in Config Files

Use the credentials from your app registrations:

**config/backup.config.json:**
```json
{
  "tenant": {
    "tenantName": "yourtenant.onmicrosoft.com",
    "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  },
  "authentication": {
    "mode": "AppCertificate",
    "clientId": "your-backup-app-client-id",
    "certificateThumbprint": "your-certificate-thumbprint"
  },
  "sharePointAdminUrl": "https://yourtenant-admin.sharepoint.com/",
  "outputRoot": "C:\\M365Backup"
}
```

**config/restore.config.json:**
```json
{
  "source": {
    "backupPath": "C:\\M365Backup\\yourtenant.onmicrosoft.com\\20260429-120000"
  },
  "target": {
    "mode": "SameTenant",
    "tenantName": "yourtenant.onmicrosoft.com",
    "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  },
  "authentication": {
    "mode": "AppCertificate",
    "clientId": "your-restore-app-client-id",
    "certificateThumbprint": "your-certificate-thumbprint"
  },
  "compareAuthentication": {
    "mode": "AppCertificate",
    "clientId": "your-backup-app-client-id",
    "certificateThumbprint": "your-certificate-thumbprint"
  },
  "report": {
    "outputRoot": "C:\\M365Backup"
  }
}
```

### Comparison: Automatic vs. Manual Setup

| Aspect | Automatic (`New-M365BackupApp`) | Manual |
|---|---|---|
| **Time** | ~2 minutes | ~15 minutes |
| **User interaction** | 1 browser login | Portal clicks for each app |
| **Error handling** | Built-in validation | Manual verification |
| **Permission accuracy** | 100% (by bundle) | Requires checklist |
| **Preferred for** | Quick setup, CI/CD | Audited setups, manual control |
| **When to use** | First-time setup | Recreating after removal, specific requirements |

---

```powershell
# List all snapshots in the backup catalog
Get-M365BackupCatalog -RootPath C:\M365Backup\output

# Verify a snapshot is not corrupted
Test-M365BackupIntegrity -BackupPath C:\M365Backup\output\contoso\20260428-120000

# See what changed between two snapshots
Compare-M365BackupSnapshot -ReferencePath .\snap-old -DifferencePath .\snap-new

# Check that all required modules are installed
Test-M365BackupPrerequisites -OutputPath C:\M365Backup\output -CreateMissingFolders

# Disconnect all workload sessions when done
Disconnect-M365Tenant
```

---

## 1) Brief architecture summary

BackupM365 is a modular PowerShell framework for Microsoft 365 configuration backup, drift detection, and controlled restore. The module separates:

- **Authentication and session management** (`Connect-M365Tenant`, `Disconnect-M365Tenant`)
- **Prerequisite validation** (`Test-M365BackupPrerequisites`)
- **Export orchestration** (`Export-M365TenantConfig`) and workload-specific exporters
- **Import orchestration** with safety guards (`Import-M365TenantConfig`, `-WhatIf`, workload/object filtering)
- **Drift detection** (`Compare-M365TenantConfig`)
- **Cross-cutting services** (`Write-BackupLog`, `Invoke-GraphRequestWithRetry`, `Save-BackupMetadata`)

Primary data format is JSON with backup metadata and transcript/log capture for auditability.

Backups include throttle-aware retries and emit a run summary in logs (total operations, retry attempts, throttled responses, and total backoff time).

## 2) Workload support matrix

| Workload | Status | Export | Restore |
|---|---|---|---|
| Entra ID / Azure AD | Partially supported | Yes | Partial/manual-first |
| Exchange Online | Partially supported | Yes | Partial |
| Microsoft Teams | Partially supported | Yes | Partial |
| SharePoint Online / OneDrive | Export only | Yes | Not automated |
| Intune / Endpoint Manager | Export only | Yes | Not automated |
| Purview / Compliance | Export only | Yes | Not automated |
| Defender | Export only | Yes | Not automated |
| Power Platform | Export only | Yes | Not automated |
| Planner | Export only | Yes | Not automated |
| Users | Export only | Yes | Not automated |

See `docs/WorkloadSupport.md` for details.

## 3) Repository folder structure

```text
.
├── .github/workflows/backup-m365-example.yml
├── config/backup.config.json
├── config/restore.config.json
├── docs/WorkloadSupport.md
├── output/
│   ├── Backups/
│   └── Logs/
├── samples/Example.Commands.ps1
├── samples/Restore.Example.Commands.ps1
├── src/
│   ├── BackupM365.psd1
│   ├── BackupM365.psm1
│   ├── Private/
│   │   ├── ConvertTo-CanonicalJson.ps1
│   │   ├── Invoke-GraphRequestWithRetry.ps1
│   │   ├── Invoke-WithThrottleRetry.ps1
│   │   ├── Save-BackupMetadata.ps1
│   │   └── Write-BackupLog.ps1
│   └── Public/
│       ├── Compare-M365TenantConfig.ps1
│       ├── Connect-M365Tenant.ps1
│       ├── Disconnect-M365Tenant.ps1
│       ├── Export-ComplianceConfig.ps1
│       ├── Export-DefenderConfig.ps1
│       ├── Export-EntraConfig.ps1
│       ├── Export-ExchangeConfig.ps1
│       ├── Export-IntuneConfig.ps1
│       ├── Export-M365TenantConfig.ps1
│       ├── Export-PlannerConfig.ps1
│       ├── Export-PowerPlatformConfig.ps1
│       ├── Export-SharePointConfig.ps1
│       ├── Export-TeamsConfig.ps1
│       ├── Export-UsersConfig.ps1
│       ├── Import-M365TenantConfig.ps1
│       ├── Restore-M365TenantConfig.ps1
│       └── Test-M365BackupPrerequisites.ps1
└── tests/BackupM365.Tests.ps1
```

## 4) PowerShell code files with contents

All code is included in the `src/` folder as a reusable module and dot-sourced function files.

## 5) Sample configuration file

See `config/backup.config.json`.

`throttling` settings in config:

- `maxRetries`: Maximum retry attempts for throttled/transient API errors.
- `baseDelaySeconds`: Base delay used for exponential backoff.
- `maxDelaySeconds`: Upper cap for backoff delay.
- `jitterRatio`: Random jitter added to reduce synchronized retry spikes.

`prechecks` settings in config (used by both `Export-M365TenantConfig` and `Restore-M365TenantConfig`; pass `-SkipPrechecks` on the command line to bypass for one run):

- `enabled`: master switch for the precheck phase.
- `requireAllRequiredModules`: throw when any required PowerShell module is missing (warn-only when `false`).
- `requireValidConfig`: validate `tenant`/`target` and `authentication`/`compareAuthentication` (clientId + credential) blocks.
- `requireValidCertificate`: confirm `certificateThumbprint` exists in `Cert:\CurrentUser\My` or `Cert:\LocalMachine\My`, has a private key, is not expired, and warn 30 days before expiry.
- `requireWritableOutput`: probe-write a temp file to the output root.
- `requireValidBackupSource` (Restore only): confirm `source.backupPath` exists and contains `metadata.json`.
- `checkGraphPermissions`: best-effort, **warn-only** audit that the configured Graph app(s) have the application roles each in-scope workload typically needs (per-workload table baked into `Test-M365GraphAppPermissions`). Requires `Application.Read.All` on the calling app to enumerate `appRoleAssignments`; if missing, the check returns "inconclusive" rather than failing.
- `createMissingFolders`: create `Backups`/`Logs` under the output root when missing.

When prechecks run as part of `Export-M365TenantConfig`, the module writes a precheck HTML report to the run log folder:

- `outputRoot/<tenant>/<timestamp>/Logs/precheck-report.html`

The report includes:

- Missing modules and impacted workloads.
- Missing app permissions (Graph and non-Graph resources like SharePoint Online).
- Recommended fixes (for example, install module commands or app permission grants).
- Auto-correction notes when `-InstallMissingModules` (or `prechecks.installMissingModules=true`) installed missing modules successfully.

Required Graph **application** permissions per workload (apply scope is the union of read + write for restore, read-only for backup/compare):

| Workload | Read (Backup / Compare app) | ReadWrite (Restore app) |
|---|---|---|
| EntraID | `Directory.Read.All`, `Policy.Read.All`, `Application.Read.All`, `RoleManagement.Read.Directory`, `AuditLog.Read.All`, `Group.Read.All`, `IdentityProvider.Read.All`, `IdentityRiskyUser.Read.All`, `EntitlementManagement.Read.All`, `LifecycleWorkflows.Read.All`, `Agreement.Read.All`, `CustomSecAttributeDefinition.Read.All` | `Directory.ReadWrite.All`, `Policy.ReadWrite.ConditionalAccess`, `Group.ReadWrite.All`, `Application.ReadWrite.All` |
| Intune | `DeviceManagementConfiguration.Read.All`, `DeviceManagementApps.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementServiceConfig.Read.All`, `DeviceManagementScripts.Read.All`, `DeviceManagementRBAC.Read.All` | `DeviceManagementConfiguration.ReadWrite.All`, `DeviceManagementApps.ReadWrite.All`, `DeviceManagementManagedDevices.ReadWrite.All`, `DeviceManagementServiceConfig.ReadWrite.All`, `DeviceManagementScripts.ReadWrite.All`, `DeviceManagementRBAC.ReadWrite.All` |
| Users | `User.Read.All`, `Group.Read.All`, `Directory.Read.All`, `UserAuthenticationMethod.Read.All` | `User.ReadWrite.All`, `Group.ReadWrite.All` |
| Planner | `Group.Read.All`, `Tasks.Read.All` | `Group.ReadWrite.All`, `Tasks.ReadWrite.All` |
| SharePoint (Graph portion) | `Sites.FullControl.All` | `Sites.FullControl.All` |
| Defender | `SecurityEvents.Read.All`, `ThreatHunting.Read.All`, `SecurityActions.Read.All`, `IdentityRiskEvent.Read.All`, `ThreatSubmission.Read.All` | (no automated restore today) |
| Teams | `TeamSettings.Read.All`, `Team.ReadBasic.All`, `TeamMember.Read.All`, `Channel.ReadBasic.All`, `ChannelSettings.Read.All`, `TeamsTab.Read.All`, `TeamsAppInstallation.ReadForTeam.All` | `TeamSettings.ReadWrite.All`, `ChannelSettings.ReadWrite.All`, `TeamsAppInstallation.ReadWriteForTeam.All` |
| ExchangeOnline / Compliance / PowerPlatform | Authenticate via their own PowerShell modules / non-Graph resources — not fully audited by `checkGraphPermissions` | — |

For SharePoint, `checkGraphPermissions` only audits the Microsoft Graph side. It does **not** verify the SharePoint Online resource permission `Sites.FullControl.All`, which is also required for app-only PnP export.

Per-workload object-type apply toggles live in `config/workloadObjectTypes/<Workload>.json`. The path is set by `scope.workloadObjectTypesPath` in `restore.config.json` (default `./config/workloadObjectTypes`). An inline `scope.workloadObjectTypes.<Workload>` block in `restore.config.json` overrides the per-workload file. Schema: flat `{ "Name": true|false }` or wrapped `{ "objectTypes": { "Name": true|false } }`. Keys starting with `_` are ignored.

## 6) Example backup commands

```powershell
Import-Module ./src/BackupM365.psd1 -Force
Connect-M365Tenant -TenantId '<tenant-guid>' -ClientId '<app-guid>' -CertificateThumbprint '<thumbprint>' -ConnectExchange -ConnectTeams -SharePointAdminUrl 'https://contoso-admin.sharepoint.com'
$backup = Export-M365TenantConfig -TenantName 'contoso' -TenantId '<tenant-guid>' -Workloads EntraID,ExchangeOnline,Teams,SharePoint,Intune,Compliance,Defender,PowerPlatform,Planner,Users -Verbose
```

## 7) Example restore commands

```powershell
# Config-driven restore (mode is controlled by -DryRun or -ApplyChanges)
Restore-M365TenantConfig -ConfigPath .\config\restore.config.json -Verbose

# Explicit dry-run override from CLI
Restore-M365TenantConfig -ConfigPath .\config\restore.config.json -DryRun -Verbose

# Explicit apply override from CLI
Restore-M365TenantConfig -ConfigPath .\config\restore.config.json -ApplyChanges -Verbose

# Apply without per-object [Y/N] confirmation prompts (CI / unattended runs)
Restore-M365TenantConfig -ConfigPath .\config\restore.config.json -ApplyChanges -Force -Verbose

# Legacy direct import usage (still available)
Import-M365TenantConfig -BackupPath $backup -Workloads ExchangeOnline,Teams -WhatIf
```

`Import-M365TenantConfig` declares `ConfirmImpact = 'High'`, so the apply phase prompts `[Y] Yes [A] Yes to All [N] No ...` for every object by default. To suppress those prompts, either pass `-Force` to `Restore-M365TenantConfig` or set `execution.force = true` in `restore.config.json`. Both translate to `-Confirm:$false` on the inner import call.

### 7.1) Backup intelligence and recovery commands

```powershell
# Inspect backup catalog (tenant/snapshot/workload/object type rows)
Get-M365BackupCatalog -RootPath .\output\Backups -TenantName 'contoso.onmicrosoft.com' -IncludeObjects

# Compare two snapshots (Added/Removed/Changed at file level)
Compare-M365BackupSnapshot -ReferencePath .\output\Backups\contoso.onmicrosoft.com\20260422-154335 -DifferencePath .\output\Backups\contoso.onmicrosoft.com\20260422-193544

# Generate a reusable delta manifest
New-M365BackupDelta -ReferencePath .\output\Backups\contoso.onmicrosoft.com\20260422-154335 -DifferencePath .\output\Backups\contoso.onmicrosoft.com\20260422-193544

# Build a restore plan (supports config-driven and explicit arguments)
New-M365RestorePlan -ConfigPath .\config\restore.config.json -OutputPath .\output\Restore\contoso.onmicrosoft.com\restore-plan.json

# Run delta-scoped restore (dry-run by default)
Invoke-M365DeltaRestore -DeltaPath .\output\Backups\contoso.onmicrosoft.com\20260422-193544\delta.manifest.json -RestoreConfigPath .\config\restore.config.json

# Validate backup integrity score and workload completeness
Test-M365BackupIntegrity -BackupPath .\output\Backups\contoso.onmicrosoft.com\20260422-193544

# Generate scenario-based recovery pack config
New-M365RecoveryPack -Scenario IntuneBaseline -BackupPath .\output\Backups\contoso.onmicrosoft.com\20260422-193544
```

### 7.2) Cross-tenant remap schema (`target.remap`)

When `target.mode` is `AnotherTenant`, define `target.remap` in `restore.config.json` to rewrite tenant-specific identifiers.

```json
{
	"target": {
		"mode": "AnotherTenant",
		"tenantName": "fabrikam.onmicrosoft.com",
		"tenantId": "00000000-0000-0000-0000-000000000000",
		"remap": {
			"exactValues": {
				"old-value": "new-value"
			},
			"ids": {
				"11111111-1111-1111-1111-111111111111": "22222222-2222-2222-2222-222222222222"
			},
			"userPrincipalNames": {
				"admin@contoso.com": "admin@fabrikam.com"
			},
			"domains": {
				"contoso.com": "fabrikam.com",
				"contoso.sharepoint.com": "fabrikam.sharepoint.com"
			},
			"urlPrefixes": {
				"https://contoso.sharepoint.com": "https://fabrikam.sharepoint.com"
			}
		}
	}
}
```

Remap behavior notes:

- `exactValues` and `ids` are strict one-to-one rewrites.
- `userPrincipalNames` rewrites complete UPN/email values.
- `domains` rewrites plain domains, subdomains, email suffixes, and URL hosts.
- `urlPrefixes` performs highest-priority URL prefix substitution (longest prefix wins).

### 7.3) Generated artifacts

Backup snapshot root (`output/Backups/<tenant>/<timestamp>`) now includes:

- `metadata.json`: run metadata, workload status, retry/throttle telemetry.
- `catalog-index.json`: flattened inventory of workload/object files and counts.
- `integrity-report.json`: integrity score and workload completeness summary.
- `sensitive-data-report.json`: discovered sensitive-field summary from snapshot scan.
- `delta.manifest.json`: emitted when prior snapshot is available for diffing.

Human-readable HTML report copies are written under the backup run `Logs` folder:

- `Logs/precheck-report.html`
- `Logs/metadata-report.html`
- `Logs/integrity-report.html`
- `Logs/catalog-index.html`
- `Logs/sensitive-data-report.html`
- `Logs/delta-manifest.html` (when delta exists)

JSON files remain in the backup snapshot root for automation and machine parsing.

Restore run root (`output/Restore/<tenant>/<timestamp>`) includes:

- `restore-plan.json`: pre-apply plan with action summary and unresolved links.
- `restore-rollback-manifest.ndjson`: append-only operation log for applied changes.

Backup run log folder also includes:

- `precheck-report.html`: pre-run prerequisite validation report with fix recommendations and auto-install correction status.

## 8) Drift detection approach

`Compare-M365TenantConfig` recursively compares JSON backup files between two snapshots using canonical JSON serialization, then reports missing/different file-level drift markers.

### Comparison command overview

| | `Compare-M365BackupSnapshot` | `Compare-M365TenantConfig` | `Restore-M365TenantConfig -DryRun` |
|---|---|---|---|
| **Purpose** | File-level diff between two saved snapshots | Deep JSON field diff between two saved snapshots | Full restore simulation against the live tenant |
| **Live tenant involved?** | No | No | Yes — takes a live snapshot of the tenant at runtime |
| **What it compares** | Which JSON files were Added/Removed/Changed | Which JSON fields changed inside those files | Backup snapshot vs. live tenant state right now |
| **Output** | List of changed file paths with status + `Compare\<timestamp>\Compare-<snapshot>.html` | List of changed field values + `Compare\<timestamp>\Compare-<tenant>.html` | Full restore report: what would be created/updated + `restore-report.html`, `compare-report.html`, `restore-report.json` |
| **Side effects** | None | None | Creates output folder and generates report files |
| **Use case** | "What changed between two old snapshots?" | "What exact settings changed between two old snapshots?" | "If I restore this backup, what would change on my live tenant?" |

**In short:**
- `Compare-M365BackupSnapshot` / `Compare-M365TenantConfig` — **offline**, compare two already-saved backup snapshots against each other.
- `Restore-M365TenantConfig -DryRun` — **online**, connects to the live tenant and exports a current snapshot at runtime before comparing.

## 9) GitHub Actions workflow example

See `.github/workflows/backup-m365-example.yml`. It:

- installs required modules
- authenticates via app+certificate secrets
- runs backup
- uploads backup artifacts

## 10) README content

This file documents architecture, support, usage, restore strategy, and limitations.

## 11) Limitations and restore caveats

- Not all workloads are reliably restorable through a generic automation flow.
- Some APIs (especially Intune) rely on Graph beta endpoints and may change.
- Some objects have dependency ordering and tenant-specific constraints.
- Restore is intentionally conservative; unsupported objects are export-first.
- Always run restore with `-WhatIf` and approval gates before apply.

## 12) Suggested future enhancements

- Expand restore coverage for Entra/Intune/SharePoint with dependency graph resolution.
- Add schema versioning and migration handlers for backup format changes.
- Add object-level checksums and signed manifests.
- Add policy-level compliance reports and drift severity scoring.
- Add automated pull request diff reporting from scheduled backups.
