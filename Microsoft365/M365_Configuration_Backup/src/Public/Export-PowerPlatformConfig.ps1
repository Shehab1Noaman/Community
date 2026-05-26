function Export-PowerPlatformConfig {
    <#
    .SYNOPSIS
        Exports Power Platform tenant configuration: environments, DLP policies,
        tenant settings, and (optionally) inventory of apps/flows.
    .DESCRIPTION
        Requires Microsoft.PowerApps.Administration.PowerShell module and an active
        Add-PowerAppsAccount session. The session must have Power Platform admin rights.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [string]$LogPath
    )

    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

    $map = [ordered]@{
        Environments         = { Get-AdminPowerAppEnvironment }
        DlpPolicies          = { Get-DlpPolicy }
        DlpPolicyConnectorConfigurations = { Get-DlpPolicy | ForEach-Object { Get-PowerAppDlpPolicyConnectorConfigurations -PolicyName $_.PolicyName -ErrorAction SilentlyContinue } }
        TenantSettings       = { Get-TenantSettings }
        TenantIsolation      = { Get-PowerAppTenantIsolationPolicy }
        TenantUrlPatterns    = { Get-PowerAppTenantUrlPatterns }
        ManagedEnvironments  = { Get-AdminPowerAppEnvironment | Where-Object { $_.EnvironmentType -eq 'Managed' } }
        PowerApps            = { Get-AdminPowerApp }
        Flows                = { Get-AdminFlow }
        Connectors           = { Get-AdminPowerAppConnector }
        ConnectorPermissions = { Get-AdminPowerAppConnectorRoleAssignment }
        EnvironmentLocations = { Get-AdminPowerAppEnvironmentLocation }
    }

    foreach ($name in $map.Keys) {
        $cmd = $map[$name]
        try {
            $cmdSource = $cmd.ToString()
            $firstCmd = ($cmdSource -split '[\s\|;{}\r\n]+' | Where-Object { $_ -like 'Get-*' } | Select-Object -First 1)
            if ($firstCmd -and -not (Get-Command -Name $firstCmd -ErrorAction SilentlyContinue)) {
                Write-BackupLog -Level Information -Message "Skipped PowerPlatform object [$name] (cmdlet $firstCmd not available; install Microsoft.PowerApps.Administration.PowerShell)" -LogPath $LogPath
                continue
            }

            $result = Invoke-WithThrottleRetry -OperationName "PowerPlatform $name" -LogPath $LogPath -ScriptBlock $cmd
            ConvertTo-SafeJson -InputObject @($result) -Depth 20 |
                Set-Content -Path (Join-Path $OutputPath "$name.json") -Encoding UTF8
            Write-BackupLog -Level Information -Message "Exported PowerPlatform object: $name" -LogPath $LogPath
        }
        catch {
            Write-BackupLog -Level Warning -Message "Failed to export PowerPlatform object [$name]: $($_.Exception.Message)" -LogPath $LogPath
        }
    }
}
