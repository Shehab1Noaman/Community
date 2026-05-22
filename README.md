# Community

A PowerShell toolkit repository for IT administration and automation, with practical scripts and utilities for Microsoft Intune, SharePoint migration, Windows shortcut packaging, and Zoho ServiceDesk Plus integration.

## Overview

This repository contains a collection of PowerShell-based tools built to support common endpoint management, migration, and service automation tasks. The projects are organized by solution area and are intended to help IT administrators streamline repetitive work, package deployable assets, and integrate with external platforms.

The repository currently focuses on:

- **Microsoft Intune automation**
- **SharePoint migration tooling**
- **Windows shortcut and file packaging for Intune Win32 deployment**
- **Zoho ServiceDesk Plus OAuth and API access**

## Repository Structure

### `Intune/`
PowerShell tools related to Microsoft Intune and endpoint administration.

Current solution areas include:

- **Category**
- **Device Renaming Automation**
- **Intune Devices Primary Users**
- **MDE**
- **RenameDevice-IntuneV2**
- **SecureBoot**

These scripts are aimed at simplifying device management, identity alignment, security-related tasks, and operational automation in Microsoft-managed environments.

### `SharePoint/`
Contains tools for SharePoint content migration.

Notable item:

- **SharePointDriveMigrator.ps1** — a PowerShell-based migration utility with a GUI for moving content between SharePoint locations using Microsoft Graph.

This area is intended for administrators managing SharePoint document movement, migration planning, and operational transfers between sites or libraries.

### `ShortCut_Creator/`
Contains a PowerShell-based utility for generating Intune Win32 packages that deploy desktop shortcuts or files/folders.

Primary capabilities include:

- Creating Windows shortcuts
- Packaging apps for Intune deployment
- Generating install, uninstall, and detection scripts
- Supporting URL, file path, and Microsoft Store app shortcut targets

### `ShortCut_CreatorV2/`
An expanded version of the shortcut packaging workflow with additional script revisions and packaging assets.

Includes:

- `ShortCut_CreatorV2.ps1`
- `ShortCut_CreatorV3.ps1`
- `ShortCut_CreatorV3.1.ps1`
- `IntuneWinAppUtil.exe`

This area is useful for administrators who need repeatable packaging workflows for desktop shortcuts and file delivery through Microsoft Intune.

### `Zoho/`
Contains a PowerShell helper for authenticating to Zoho ServiceDesk Plus using OAuth 2.0 and making authenticated API calls.

Notable item:

- **Zoho-ServiceDeskPlus-OAuth.ps1**

This module is intended for admins and automation engineers integrating Zoho ServiceDesk Plus into their operational scripts.

## Key Use Cases

This repository is useful for teams and administrators who need to:

- Automate **Microsoft Intune** management tasks
- Package **Win32 apps** for deployment through Intune
- Create and deploy **desktop shortcuts** at scale
- Migrate content between **SharePoint** locations
- Integrate PowerShell automation with **Zoho ServiceDesk Plus**
- Build reusable admin tooling for Windows-centric enterprise environments

## Technology

- **Language:** PowerShell
- **Primary audience:** IT administrators, endpoint engineers, automation engineers, and Microsoft 365 administrators

## Requirements

Requirements vary by project, but depending on the tool you use, you may need:

- **PowerShell 5.1 or later**
- Windows environment for GUI-based scripts
- Appropriate administrative permissions
- Microsoft Graph access for SharePoint and Intune-related automation
- Intune packaging tools for Win32 app creation
- Zoho API credentials for Zoho-related automation

## How to Use

1. Browse to the relevant solution folder.
2. Review the script or project-specific documentation.
3. Update configuration values, credentials, paths, or tenant-specific settings as needed.
4. Run the script in an appropriate PowerShell environment.
5. Validate results in a test environment before production use.

## Notes

- Some scripts include GUI components and are designed for interactive use on Windows.
- Some projects may require tenant-specific configuration before they can run successfully.
- External tools and credentials should be handled securely and never hardcoded in production workflows.
- Test all migration and deployment scripts in a non-production environment first.

## Contributing

Contributions, suggestions, and improvements are welcome. If you want to enhance an existing script or add a new automation workflow, feel free to open an issue or submit a pull request.

When contributing:

- Keep scripts organized by solution area
- Document required inputs and prerequisites
- Avoid committing secrets, tokens, or credentials
- Include usage notes where possible

## License

Please review the license information included in individual project folders where applicable.

## Disclaimer

These tools are provided as-is for administrative and automation purposes. Always review scripts before use and confirm they meet your organization’s security, compliance, and operational requirements.
