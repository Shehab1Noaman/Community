function Disconnect-M365Tenant {
    <#
    .SYNOPSIS
        Disconnects from all Microsoft 365 services connected during a backup session.

    .DESCRIPTION
        Calls the disconnect/sign-out cmdlet for each service that may have been
        connected: Microsoft Graph, Exchange Online, Security and Compliance (Purview),
        Microsoft Teams, SharePoint (PnP), and Power Platform. Non-fatal errors from
        services that were not connected are silently discarded and surfaced only at
        the -Verbose level.

    .EXAMPLE
        Disconnect-M365Tenant

    .EXAMPLE
        Disconnect-M365Tenant -Verbose
    #>
    [CmdletBinding()]
    param()

    $errors = [System.Collections.Generic.List[string]]::new()

    foreach ($step in @(
        { Disconnect-MgGraph -ErrorAction Stop },
        { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop },
        { if (Get-Command -Name Disconnect-IPPSSession -ErrorAction SilentlyContinue) { Disconnect-IPPSSession -ErrorAction Stop } },
        { if (Get-Command -Name Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue) { Disconnect-MicrosoftTeams -ErrorAction Stop } },
        { if (Get-Command -Name Disconnect-PnPOnline -ErrorAction SilentlyContinue) { Disconnect-PnPOnline -ErrorAction Stop } },
        { if (Get-Command -Name Remove-PowerAppsAccount -ErrorAction SilentlyContinue) { Remove-PowerAppsAccount -ErrorAction Stop } }
    )) {
        try {
            & $step
        }
        catch {
            $errors.Add($_.Exception.Message)
        }
    }

    if ($errors.Count -gt 0) {
        Write-Verbose ("Disconnect notices: {0}" -f ($errors -join ' | '))
    }
}
