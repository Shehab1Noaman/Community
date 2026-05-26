# Changelog

All notable changes to **BackupM365** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-04-28

### Added
- **10-workload backup engine** via `Export-M365TenantConfig`:
  EntraID, Exchange Online, Teams, SharePoint, Intune, Compliance (Purview),
  Defender for Endpoint, Power Platform, Planner, and Users.
- **Restore pipeline**: `Restore-M365TenantConfig`, `Import-M365TenantConfig`,
  `New-M365RestorePlan`, `Invoke-M365DeltaRestore`.
- **Snapshot comparison**: `Compare-M365TenantConfig` (deep JSON diff with
  configurable ignore fields) and `Compare-M365BackupSnapshot` (file-level diff).
- **Delta backups**: `New-M365BackupDelta` generates a delta manifest between two
  snapshots; `Invoke-M365DeltaRestore` applies only the changed files.
- **Recovery packs**: `New-M365RecoveryPack` bundles a subset of a snapshot into a
  named recovery scenario (FullTenant, IntuneBaseline, TeamsCore, SharePointTenant,
  IdentityCore).
- **Catalog and integrity**: `Get-M365BackupCatalog` lists all snapshots with
  metadata; `Test-M365BackupIntegrity` validates snapshot completeness.
- **Prerequisite checker**: `Test-M365BackupPrerequisites` with `-InstallMissingModules`
  flag to auto-install required PowerShell modules from PSGallery.
- **Auto-install in config**: `prechecks.installMissingModules: true` in
  `backup.config.json` triggers automatic module installation on the first run.
- **Setup cmdlets** (module public functions):
  - `New-M365BackupCertificate` — creates self-signed cert, exports `.cer` for
    Entra upload and `.pfx` for machine import.
  - `New-M365BackupApp` — creates Entra app registration, uploads cert,
    assigns both Application and Delegated Microsoft Graph permissions, grants
    admin consent, supports `-InstallMissingModules`.
  - `New-M365RestoreApp` — creates restore-scoped app registration.
- **Throttle-aware Graph helper**: exponential back-off with jitter for all
  Microsoft Graph calls.
- **Workload object type filtering**: per-workload JSON definitions
  (`config/workloadObjectTypes/`) allow fine-grained control over what is exported.
- **Sensitive data audit**: post-backup scan for common sensitive patterns with
  configurable `sensitiveData.mode` (Audit / Redact).

[1.0.0]: https://github.com/Shehab1Noaman/BackupM365/releases/tag/v1.0.0
