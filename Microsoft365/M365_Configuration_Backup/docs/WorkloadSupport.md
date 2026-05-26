# Workload Support Matrix

| Workload | Export | Restore | Status | Notes |
|---|---|---|---|---|
| Entra ID | Yes | Partial | Partially supported | Highly dependent objects (CA, apps, auth methods) are exported; restore is intentionally guarded/manual first. |
| Exchange Online | Yes | Partial | Partially supported | Accepted domains and selected policy objects are restorable. |
| Microsoft Teams | Yes | Partial | Partially supported | App-only certificate auth is supported through the MicrosoftTeams module; export coverage is broad once the module is installed/importable. Restore starts with meeting policy sample flow. |
| SharePoint Online / OneDrive | Yes | No (automated) | Export only | App-only certificate auth covers PnP-backed items. Pure `Get-SPO*` admin cmdlets still require an interactive `Connect-SPOService` session, so app-only coverage is partial by design. |
| Intune | Yes | No (automated) | Export only | Exported via Graph beta endpoints; restore is tenant-specific and approval-led. Covers: compliance policies, configuration profiles, administrative templates, endpoint security intents, update rings, Autopilot profiles (all with assignments), enrollment configurations, device management scripts, device health scripts (proactive remediations), shell scripts, app protection policies, app configurations, mobile apps, mobile app configurations, role definitions, role assignments, scope tags, feature/quality/driver update profiles, assignment filters, terms & conditions, device categories, and notification templates. |
| Purview / Compliance | Yes | No | Export only | Exports Purview and Security & Compliance configuration objects such as labels, retention, DLP, information barriers, insider risk, eDiscovery metadata, audit, alerts, and policy infrastructure. Restore is not automated. |
| Defender | Yes | No | Export only | Exports Graph security objects such as secure score and threat submission data, plus optional Defender for Endpoint securitycenter API objects when enabled. Restore is not automated. |
| Power Platform | Yes | No | Export only | Exports environments, DLP policies, tenant settings, isolation and URL patterns, managed environments, apps, flows, connectors, and environment locations. Restore is not automated. |
| Planner | Yes | No | Export only | Exports Planner plans, buckets, and tasks across Microsoft 365 groups. Restore is not automated. |
| Users | Yes | No | Export only | Exports user inventory, profile data, licenses, auth methods, memberships, owned objects/devices, and Exchange mailbox settings where available. Restore is intentionally limited today. |

## Cross-Tenant Restore Notes

- `New-M365RestorePlan` and `Restore-M365TenantConfig` can evaluate unresolved cross-tenant references when `target.mode` is `AnotherTenant`.
- `target.remap.domains` now covers domain/subdomain, email suffix, and URL host remap patterns, while `target.remap.urlPrefixes` remains the highest-priority URL rewrite mechanism.
- Dependency detection is workload-aware for SharePoint, Teams, and Power Platform reference patterns to reduce false positives in plan warnings.
