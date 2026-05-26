<#
.SYNOPSIS
    Publishes the BackupM365 module to the PowerShell Gallery.

.DESCRIPTION
    Stages the module from src/ into a temporary build folder, then publishes
    it to PSGallery using Publish-Module.  The script validates the manifest and
    runs Pester tests before publishing.

.PARAMETER NuGetApiKey
    Your PSGallery API key (https://www.powershellgallery.com/account/apikeys).

.PARAMETER SkipTests
    Skip the Pester test run before publishing.

.PARAMETER WhatIf
    Perform a dry-run: stage and validate without publishing.

.EXAMPLE
    .\Publish-BackupM365.ps1 -NuGetApiKey 'oy2...'

.EXAMPLE
    .\Publish-BackupM365.ps1 -NuGetApiKey 'oy2...' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$NuGetApiKey,

    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot  = $PSScriptRoot
$srcPath   = Join-Path $repoRoot 'src'
$stagePath = Join-Path ([System.IO.Path]::GetTempPath()) 'BackupM365-publish'

# ── 1. Run tests ─────────────────────────────────────────────────────────────
if (-not $SkipTests) {
    Write-Host '[1/4] Running Pester tests...' -ForegroundColor Cyan
    if (-not (Get-Module -ListAvailable Pester | Where-Object { $_.Version -ge '5.0' })) {
        Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck
    }
    $result = Invoke-Pester -Path (Join-Path $repoRoot 'tests') -PassThru
    if ($result.FailedCount -gt 0) {
        throw "Pester: $($result.FailedCount) test(s) failed. Fix them before publishing."
    }
    Write-Host "  All $($result.PassedCount) test(s) passed." -ForegroundColor Green
}

# ── 2. Stage module ───────────────────────────────────────────────────────────
Write-Host '[2/4] Staging module...' -ForegroundColor Cyan
if (Test-Path $stagePath) { Remove-Item $stagePath -Recurse -Force }
Copy-Item -Path $srcPath -Destination $stagePath -Recurse
Write-Host "  Staged to: $stagePath"

# ── 3. Validate manifest ──────────────────────────────────────────────────────
Write-Host '[3/4] Validating manifest...' -ForegroundColor Cyan
$manifestPath = Join-Path $stagePath 'BackupM365.psd1'
$null = Test-ModuleManifest -Path $manifestPath
Write-Host '  Manifest is valid.' -ForegroundColor Green

# ── 4. Publish ────────────────────────────────────────────────────────────────
if ($PSCmdlet.ShouldProcess('PowerShell Gallery', 'Publish-Module BackupM365')) {
    Write-Host '[4/4] Publishing to PSGallery...' -ForegroundColor Cyan
    Publish-Module -Path $stagePath -NuGetApiKey $NuGetApiKey -Repository PSGallery -Verbose
    Write-Host 'Published successfully.' -ForegroundColor Green
}
else {
    Write-Host '[4/4] WhatIf: skipping Publish-Module.' -ForegroundColor Yellow
}
