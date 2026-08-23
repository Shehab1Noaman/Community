<#
.SYNOPSIS
    Grants Microsoft Graph API app role assignments to a System Assigned Managed Identity.

.DESCRIPTION
    Assigns the required Microsoft Graph application permissions to an Azure Automation
    Managed Identity using direct REST calls via the Microsoft Graph API.
    No Microsoft.Graph module required — runs directly in Azure Cloud Shell.

    The following app roles are assigned:
        - DeviceManagementManagedDevices.ReadWrite.All
        - User.Read.All
        - Mail.Send

    Prerequisites:
    - Azure Cloud Shell (PowerShell)
    - Logged in as Global Admin or Privileged Role Administrator
    - Object ID of the Managed Identity

.EXAMPLE
    Run directly in Azure Cloud Shell after updating $miObjectId.
#>

Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All","Application.Read.All"

$miObjectId = "<ObjectId of the Managed Identity>"  # Automation Account → Identity → Object ID
$graphAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph (known GUID)

$graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"

$roles = @(
    "DeviceManagementManagedDevices.ReadWrite.All",
    "User.Read.All",
    "Mail.Send"
)

foreach ($roleName in $roles) {
    $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $roleName }
    New-MgServicePrincipalAppRoleAssignment `
        -ServicePrincipalId $miObjectId `
        -PrincipalId        $miObjectId `
        -ResourceId         $graphSp.Id `
        -AppRoleId          $role.Id
    Write-Host "✓ $roleName assigned"
}
