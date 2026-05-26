function Save-BackupMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Workloads,

        [Parameter()]
        [ValidateSet('Success', 'Failed', 'Partial')]
        [string]$Status = 'Success',

        [Parameter()]
        [string[]]$RequiredModules = @(
            'Microsoft.Graph.Authentication',
            'ExchangeOnlineManagement',
            'MicrosoftTeams',
            'Microsoft.Online.SharePoint.PowerShell'
        ),

        [Parameter()]
        [hashtable]$AdditionalProperties
    )

    $installedModules = foreach ($moduleName in $RequiredModules) {
        $module = Get-Module -ListAvailable -Name $moduleName | Sort-Object Version -Descending | Select-Object -First 1
        [PSCustomObject]@{
            Name      = $moduleName
            Installed = [bool]$module
            Version   = if ($module) { $module.Version.ToString() } else { $null }
        }
    }

    $metadata = [ordered]@{
        TenantName        = $TenantName
        TenantId          = $TenantId
        BackupTimestamp   = (Get-Date).ToString('o')
        IncludedWorkloads = $Workloads
        ModuleVersions    = $installedModules
        Status            = $Status
    }

    if ($AdditionalProperties) {
        foreach ($key in $AdditionalProperties.Keys) {
            $metadata[$key] = $AdditionalProperties[$key]
        }
    }

    ([pscustomobject]$metadata) | ConvertTo-Json -Depth 20 | Set-Content -Path $Path -Encoding UTF8
}
