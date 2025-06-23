<#
.SYNOPSIS
    Automates the update of Intune Windows device primary users based on the "last logged on user" using Microsoft Graph API,
    and generates comprehensive reports including a CSV export and an HTML summary embedded in an email.

.DESCRIPTION
    This script is designed for Azure Automation and leverages a System Assigned Managed Identity for secure authentication with Azure Key Vault
    to retrieve an Azure AD Application Registration client secret. It then uses this secret to authenticate with Microsoft Graph API
    via the Client Credentials Flow.

    The script performs the following actions:
    1.  Authenticates securely with Azure Key Vault using Managed Identity.
    2.  Retrieves the Azure AD Application Registration client secret from Key Vault.
    3.  Authenticates with Microsoft Graph API using the client secret, tenant ID, and application ID.
    4.  Fetches all Windows company-owned devices from Intune using the Microsoft Graph beta endpoint to access 'usersLoggedOn' property.
    5.  Iterates through each device, identifies the last logged-on user.
    6.  Compares the current Intune primary user with the last logged-on user.
    7.  If a discrepancy is found, it updates the Intune primary user to the last logged-on user via a Graph API POST request.
    8.  Generates a detailed CSV report of all processed devices, highlighting original and new primary users.
    9.  Generates an HTML summary of the automation run.
    10. Sends an email notification with the HTML summary and the CSV report as an attachment.
    11. Cleans up temporary report files.

.NOTES
    Author: Shehab Noaman
    Version: 1.1
    Date: 2025-06-15

    Prerequisites:
    - Azure Automation Account with System Assigned Managed Identity enabled.
    - Az.KeyVault, Az.Accounts, Microsoft.Graph.Authentication, Microsoft.Graph.Intune, Microsoft.Graph.Users, Microsoft.Graph.Devices.CloudPrint modules installed in Automation Account.
    - Azure AD Application Registration with the following Microsoft Graph API permissions (Application type):
        - DeviceManagementManagedDevices.ReadWrite.All
        - User.Read.All
        - Mail.Send (if email notifications are desired)
    - Client secret for the Azure AD Application Registration stored securely in Azure Key Vault.
    - Azure Key Vault access policy configured to allow the Automation Account's Managed Identity to "Get" secrets.

.PARAMETERS
    None directly, but relies on Azure Automation variables or hardcoded values for configuration (e.g., Key Vault name, App ID).
#>

#region Configuration Variables
# --- Update these variables for your environment ---

# Authenticate and obtain an access token using client credentials flow,
# securely fetching credentials from Azure Key Vault.

#To create MulitLine Secret Key check https://github.com/Shehab1Noaman/Community/blob/main/Intune/Intune_Devices_Primary_Users/Create%20a%20multiline.ps1

# Import the Values form Azure Key Vault


$MLSecretName = "<your Secret Name>"    # e.g., "MyIntuneSecretsKV"
$VaultName = "<Your Vault Name>"        # Name of the secret storing your Client Secret in Key Vault

try {
    Enable-AzContextAutosave -Scope Process
    Connect-AzAccount -Identity
    Write-Output "Successfully connected with managed identity"

    $ReturnedMLSecret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $MLSecretName -AsPlainText

    $secretParts = $ReturnedMLSecret.Split()
    if ($secretParts.Count -lt 3) {
        throw "Secret format is incorrect. Expected format: 'ClientSecretValue TenantIDValue ClientIDValue'"
    }
    
    $ClientSecret = $secretParts[0]
    $TenantID     = $secretParts[1]
    $clientId     = $secretParts[2]

    Write-Output "Application Client ID is $clientId"
    Write-Output "Tenant ID is $TenantID"
    Write-Output "Client Secret is (hidden for security)"

    if ([string]::IsNullOrEmpty($clientSecret)) {
        throw "Failed to retrieve client secret from Key Vault"
    }
    Write-Output "Successfully retrieved client secret"
}
catch {
    Write-Error "Failed to authenticate or retrieve secret: $($_.Exception.Message)"
    exit 1
}


# You uncommon the parmeters below if you don't want to use Azure Vault
#$ClientSecret = "<Your Clinet Secret>" # Placeholder: Replace with a secure method
#$TenantID = "<Your Tenant ID>"
#$clientId = "<Appliaction ID"

#

#Create the Access Token
Write-Output "Attempting to get access token..."
try {
    $tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Body @{
        client_id = $clientId
        scope = "https://graph.microsoft.com/.default"
        client_secret = $clientSecret
        grant_type = "client_credentials"
    } -ErrorAction Stop
    $accessToken = $tokenResponse.access_token
    $Headers = @{Authorization = "Bearer $accessToken"}
    Write-Output "Access token obtained successfully."
}
catch {
    Write-Output "Error obtaining access token: $($_.Exception.Message)"
    Write-Output "Please check your Client ID, Client Secret, Tenant ID, and network connectivity."
    exit 1
}

# Define the export paths for the CSV files
$tempPath = "$($env:TEMP)\AllDevicesReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

$PrimaryUserChangeReport = "$($env:TEMP)\PrimaryUserChangeReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

# Define the email parameters
$fromEmail = 'Sender@email.com' # Ensure this sender has Mail.Send permission
$toEmails = @(
    'user1@email.com',
    'user2@email.com'
)
$subject = "Devices Primary Users Vs Last Logon Users Report - $(Get-Date -Format 'yyyy-MM-dd')"
$body = "Please find attached the report for more details."

$toRecipients = foreach ($email in $toEmails) {
    @{
        emailAddress = @{
            address = $email
        }
    }
}

# Add this line to define users to exclude from being set as primary user
$UsersToExclude = @("admin@yourdomain.com", "svc_account@yourdomain.com") # <--- New line: Add UPNs of users to exclude here

#endregion

#region Functions

# Reporting Function
function New-DeviceInfoObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$DeviceIntuneID,

        [Parameter(Mandatory=$false)]
        [string]$DeviceAzureADDeviceId,

        [Parameter(Mandatory=$true)]
        [string]$DeviceName,

        [Parameter(Mandatory=$false)]
        [string]$DeviceEnrolledByUserPrincipalName,

        [Parameter(Mandatory=$false)]
        [string]$PrimaryuserId,

        [Parameter(Mandatory=$false)]
        [string]$PrimaryuserUPN,

        [Parameter(Mandatory=$false)]
        [string]$PrimaryuserDisplayName,

        [Parameter(Mandatory=$false)]
        [string]$PrimaryuserEmail,

        [Parameter(Mandatory=$false)]
        [string]$LastloginUserId, 

        [Parameter(Mandatory=$false)]
        [string]$UserLoggedon_Dispalyname,

        [Parameter(Mandatory=$false)]
        [string]$UserLoggedon_UserPrincipalName,

        [Parameter(Mandatory=$false)]
        [string]$LastloginTime,

        [Parameter(Mandatory=$false)]
        [string]$ChangeStatus,

        [Parameter(Mandatory=$false)]
        [string]$MorethanOneLogin
    )

    # Create and return the PSCustomObject
    [PSCustomObject]@{
        DeviceIntuneID                  = $DeviceIntuneID
        DeviceAzureId                   = $DeviceAzureADDeviceId
        DeviceName                      = $DeviceName
        DeviceEnrolledByUserPrincipalName = $DeviceEnrolledByUserPrincipalName
        PrimaryuserId                   = $PrimaryuserId
        UPN_Primary                     = $PrimaryuserUPN
        DisplayName_Primary             = $PrimaryuserDisplayName
        Email_Primary                   = $PrimaryuserEmail
        LastusersLoggedOn_ID            = $LastloginUserId
        LastUserLoggedon_Dispalyname    = $UserLoggedon_Dispalyname
        LastUserLoggedon_UPN            = $UserLoggedon_UserPrincipalName
        lastLogOnDateTime               = $LastloginTime
        PrimaryChangeStatus             = $ChangeStatus
        MorethanOneLogin                = $JsonOutput
    }
}

#endregion

$PrimarVsLogonUsers = 0
$PrimarUserChangeSuccess = 0
$PrimarUserChangeFailed = 0
$TotalDevices = 0

# NOTE: 'usersLoggedOn' property is currently only available in the /beta endpoint.
$Devicesuri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows' and managedDeviceOwnerType eq 'company'&`$select=id,deviceName,userDisplayName,userPrincipalName,usersLoggedOn,azureADDeviceId,enrolledByUserPrincipalName,emailAddress"

#region Main Script Logic

$allDevices = @()
$currentUri = $Devicesuri

Write-Output "Fetching managed devices with pagination.."
try {
    do{
        Write-Output "Fetching devices from URI: $currentUri"
        $Devices = Invoke-RestMethod -Method GET `
            -Uri $currentUri `
            -Headers $Headers `
            -ContentType 'application/json' `
            -ErrorAction Stop

        # Append the current page of devices to the allDevices array
        $allDevices += $Devices.value
        Write-Output "  Retrieved $($response.value.Count) devices from current page. Total collected: $($allDevices.Count)"
     

        # Check if there is a next page
        if ($Devices.'@odata.nextLink' -eq $null) {
            Write-Output "No more pages to fetch."
            break
        }else {
            # Update the current URI to the next page link
            $currentUri = $Devices.'@odata.nextLink'
            Write-Output "Next page found, updating URI to: $currentUri"

            #Optional: Add a small delay to avoid hitting Graph API throttling limits on very large tenants
            Start-Sleep -Milliseconds 100
   
        }
    } while ($currentUri) # Continue until there are no more pages
        
    write-Output "All devices fetched successfully."
    Write-Output "Total devices fetched: $($allDevices.Count)"

}
catch {
    Write-Output "Error fetching devices: $($_.Exception.Message)"
    Write-Output "Please check Graph API permissions and URI." 
    exit 1
}

# Initialize arrays to store report data
$allDevicesReportData = @()
$primaryUserChangeReportData = @()
#$primaryVsLogonUsersReportData = @()


Foreach($Device in $allDevices){
     $TotalDevices ++
     Write-Output $TotalDevices
    # Get the last logged on user information for each device
    # Fetching full device details, including usersLoggedOn (beta endpoint specific)
    $Uri2 ="https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($Device.id)')"
    Write-Output "Fetching details for device $($Device.deviceName) ($($Device.id))..."
    try {
        $DMSUri2 = Invoke-RestMethod -Method GET `
            -Uri $Uri2 `
            -Headers $Headers `
            -ContentType 'application/json' `
            -ErrorAction Stop
    }
    catch {
        Write-Output "Error fetching details for device $($Device.deviceName): $($_.Exception.Message)"
        continue # Skip to the next device
    }

    # Current primary user details from Intune (may be null if not set)
    $PrimaryuserId= $DMSUri2.userId
    $PrimaryuserDisplayName = $DMSUri2.userDisplayName
    $PrimaryuserUPN = $DMSUri2.userPrincipalName
    $PrimaryuserEmail = $DMSUri2.emailAddress

    # Device details
    $DeviceName = $DMSUri2.deviceName
    $DeviceId = $DMSUri2.id # Intune Device ID
    $DeviceAzureADDeviceId = $DMSUri2.azureADDeviceId # Microsoft Entra Device ID
    $DeviceEnrolledByUserPrincipalName = $DMSUri2.enrolledByUserPrincipalName

    # Last logged on user details
    # Check if usersLoggedOn exists and has entries
    if ($DMSUri2.usersLoggedOn -and $DMSUri2.usersLoggedOn.Count -gt 0) {
        # Get the last entry in the usersLoggedOn array.
        $JsonOutput = $DMSUri2.usersLoggedOn | Sort-Object lastLogOnDateTime  | ConvertTo-Json -Depth 5
        
        $lastLoginEntry = $DMSUri2.usersLoggedOn | Sort-Object lastLogOnDateTime | Select-Object -Last 1
        $LastloginUserId = $lastLoginEntry.userId
        $LastloginTime = $lastLoginEntry.lastLogOnDateTime

        # Get detailed user info for the last logged-on user
        Write-Output "Fetching details for last logged on user $($LastloginUserId)..."
        try {
            $UserLoggedonDetails = Invoke-RestMethod -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/users/$LastloginUserId" `
                -Headers $Headers `
                -ContentType 'application/json' `
                -ErrorAction Stop

            $UserLoggedon_Dispalyname = $UserLoggedonDetails.DisplayName
            $UserLoggedon_UserPrincipalName= $UserLoggedonDetails.UserPrincipalName
        }
        catch {
            Write-Output "Error fetching details for last logged on user $($LastloginUserId): $($_.Exception.Message)"
            $UserLoggedon_Dispalyname = "Unknown"
            $UserLoggedon_UserPrincipalName = "Unknown"
            # Set values to empty/unknown if user details cannot be retrieved
        }
    } else {
        Write-Output "No last logged on user data for device $($DeviceName)."
        $LastloginUserId = "N/A"
        $LastloginTime = "N/A"
        $UserLoggedon_Dispalyname = "N/A"
        $UserLoggedon_UserPrincipalName = "N/A"
        $MorethanOneLogin = "N/A"
    }

    # Create a custom object to hold the device and user information for the main report
   $allDevicesReportData += (New-DeviceInfoObject `
    -DeviceIntuneID $DeviceId `
    -DeviceAzureADDeviceId $DeviceAzureADDeviceId `
    -DeviceName $DeviceName `
    -DeviceEnrolledByUserPrincipalName $DeviceEnrolledByUserPrincipalName `
    -PrimaryuserId $PrimaryuserId `
    -PrimaryuserUPN $PrimaryuserUPN `
    -PrimaryuserDisplayName $PrimaryuserDisplayName `
    -PrimaryuserEmail $PrimaryuserEmail `
    -LastloginUserId $LastloginUserId `
    -UserLoggedon_Dispalyname $UserLoggedon_Dispalyname `
    -UserLoggedon_UserPrincipalName $UserLoggedon_UserPrincipalName `
    -LastloginTime $LastloginTime `
    -MorethanOneLogin $JsonOutput )


    # List Devices with different primary user and last logged on user
    if ($PrimaryuserId -ne $LastloginUserId -and $LastloginUserId -ne $null -and $LastloginUserId -ne "N/A") {
        if ($UsersToExclude -notcontains $UserLoggedon_UserPrincipalName) { # <--- New line: Exclude specified users from primary user change
            $PrimarVsLogonUsers ++

            Write-Output "Device: $($DeviceName), Primary User: $($PrimaryuserDisplayName) ($($PrimaryuserUPN)), Last Logged On User: $($UserLoggedon_Dispalyname) ($($UserLoggedon_UserPrincipalName)), Last Login Time: $($LastloginTime)"

            # Update Device Primary user with last logon user
            $UpdatePrimaryUseruri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($DeviceId)')/users/`$ref"
            $UpdatePrimaryUserBody = @{
                "@odata.id" = "https://graph.microsoft.com/beta/users/$LastloginUserId"
            } | ConvertTo-Json

            $currentUpdateHeaders = @{ # Re-use the existing $Headers to avoid re-defining token
                "Authorization" = "Bearer $accessToken"
                "Content-Type"  = "application/json"
            }

            try {
                Write-Output "Attempting to associate user $($LastloginUserId) with device $($DeviceId)..."
                $Response = Invoke-RestMethod -Method POST `
                    -Uri $UpdatePrimaryUseruri `
                    -Body $UpdatePrimaryUserBody `
                    -Headers $currentUpdateHeaders `
                    -ContentType 'application/json' `
                    -ErrorAction Stop

                # Check if the response indicates success

                
                Write-Output "User successfully associated with device (204 No Content expected)."
                $PrimarUserChangeSuccess ++
                $primaryUserChangeReportData += (New-DeviceInfoObject `
                    -DeviceIntuneID $DeviceId `
                    -DeviceAzureADDeviceId $DeviceAzureADDeviceId `
                    -DeviceName $DeviceName `
                    -DeviceEnrolledByUserPrincipalName $DeviceEnrolledByUserPrincipalName `
                    -PrimaryuserId $PrimaryuserId `
                    -PrimaryuserUPN $PrimaryuserUPN `
                    -PrimaryuserDisplayName $PrimaryuserDisplayName `
                    -PrimaryuserEmail $PrimaryuserEmail `
                    -LastloginUserId $LastloginUserId `
                    -UserLoggedon_Dispalyname $UserLoggedon_Dispalyname `
                    -UserLoggedon_UserPrincipalName $UserLoggedon_UserPrincipalName `
                    -LastloginTime $LastloginTime `
                    -ChangeStatus "Success")
            }
            catch { # Error handling for the update attempt
                

                Write-Output "Error associating user with device:"
                Write-Output "Status Code: $($_.Exception.Response.StatusCode)" 

                $graphErrorMessage = ""

                if ($_.Exception.Response -and $_.Exception.Response.Content){ #($_.Exception.Response -and $_.Exception.Response.GetResponseStream()) {
                        
                    try {

                        # ReadAsStringAsync() returns a Task, .Result waits for it synchronously
                        $graphErrorMessage = $_.Exception.Response.Content.ReadAsStringAsync().Result
                        Write-Output "Graph API Error Details: $($graphErrorMessage)"

                        #$reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                       # $graphErrorMessage = $reader.ReadToEnd()
                       # $reader.Close()
                       # Write-Output "Graph API Error Details: $($graphErrorMessage)"
                    }
                    catch {
                        Write-Output "Could not read detailed error message from Graph API response."
                    }
                } else {
                    Write-Output "No detailed error response stream available from Graph API."
                    # Sometimes the simple message is enough, or if the Response object isn't fully populated.
                    $graphErrorMessage = $_.ErrorDetails.Message
                }

                $PrimarUserChangeFailed ++
                $primaryUserChangeReportData += (New-DeviceInfoObject `
                    -DeviceIntuneID $DeviceId `
                    -DeviceAzureADDeviceId $DeviceAzureADDeviceId `
                    -DeviceName $DeviceName `
                    -DeviceEnrolledByUserPrincipalName $DeviceEnrolledByUserPrincipalName `
                    -PrimaryuserId $PrimaryuserId `
                    -PrimaryuserUPN $PrimaryuserUPN `
                    -PrimaryuserDisplayName $PrimaryuserDisplayName `
                    -PrimaryuserEmail $PrimaryuserEmail `
                    -LastloginUserId $LastloginUserId `
                    -UserLoggedon_Dispalyname $UserLoggedon_Dispalyname `
                    -UserLoggedon_UserPrincipalName $UserLoggedon_UserPrincipalName `
                    -LastloginTime $LastloginTime `
                    -ChangeStatus "Failed - $($graphErrorMessage | Select-Object -First 100)" # Truncate for report if needed
                )

                Write-Output "Request URI: $($UpdatePrimaryUseruri)"
                Write-Output "Request Body: $($UpdatePrimaryUserBody)"
            }
        } else { # <--- New line: Else for exclusion
            Write-Output "Skipping primary user update for device $($DeviceName) because last logged on user '$($UserLoggedon_UserPrincipalName)' is in the exclusion list." # <--- New line: Exclusion message
        } # <--- New line: End of exclusion if
    } else {
        Write-Output "Device: $($DeviceName), Primary User and Last Logged On User are the same: $($UserLoggedon_Dispalyname) ($($UserLoggedon_UserPrincipalName)), Last Login Time: $($LastloginTime)"
    }
}

# Export all collected data to CSVs
Write-Output "Exporting all devices report to $tempPath..."
$allDevicesReportData | Export-Csv -Path $tempPath -NoTypeInformation -Force

Write-Output "Exporting primary user change report to $PrimaryUserChangeReport..."
$primaryUserChangeReportData | Export-Csv -Path $PrimaryUserChangeReport -NoTypeInformation -Force


Write-Output "Summary Counts:"
Write-Output "Total Devices: $TotalDevices"
Write-Output "Devices with Primary user different from Last Logon user: $PrimarVsLogonUsers"
Write-Output "Primary User Change Success: $PrimarUserChangeSuccess"
Write-Output "Primary User Change Failed: $PrimarUserChangeFailed"

$PrimarVsLogonUsersReportSummary = @(
    [PSCustomObject]@{
        'Report' = 'Total Devices'
        'Count'= $TotalDevices
    },
    [PSCustomObject]@{
        'Report' = 'Devices with a Mismatch Between Primary and Last Logged-On User '
        'Count' = $PrimarVsLogonUsers
    }
    ,[PSCustomObject]@{
        'Report' = 'Primary User  - Change Success'
        'Count' = $PrimarUserChangeSuccess
    }
    ,[PSCustomObject]@{
        'Report' = 'Primary User  - Change Failed'
        'Count' = $PrimarUserChangeFailed
    }
)

$PrimarVsLogonUsersHtmlBody = $PrimarVsLogonUsersReportSummary | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Devices Primary User Vs Last Logged-On Users - Summary</h2>" | Out-String

# Send an email with the CSV attachments
$emailContent = @"
<html>
<head>
<style>
    body { font-family: Arial, sans-serif; margin: 20px; color: #333; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; margin-bottom: 30px; background-color: #ffffff; box-shadow: 0 0 10px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }
    th, td { border: 1px solid #e0e0e0; padding: 12px 15px; text-align: left; }
    th { background-color: #0078d4; color: #ffffff; font-weight: bold; text-transform: uppercase; }
    tr:nth-child(even) { background-color: #f8f8f8; }
    h1 { color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 10px; margin-bottom: 20px; }
    h2 { color: #333; border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 40px; }
    .summary { background-color: #e6f2fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; border: 1px solid #b3d9ff; }
    p { line-height: 1.6; }
</style>
</head>
<body>
<div class="summary">
    <h1>Devices Primary Users Vs Last Logon Users Report - $(Get-Date -Format 'yyyy-MM-dd')</h1>
    <p>Please find attached reports for devices managed by Intune.</p>
</div>

$PrimarVsLogonUsersHtmlBody

$body
</body>
</html>
"@

$messageBody = @{
    message = @{
        subject = $subject
        body = @{
            contentType = 'html'
            content = $emailContent
        }
        toRecipients = $toRecipients

        attachments = @(
            @{
                '@odata.type' = '#microsoft.graph.fileAttachment'
                name = "AllDevicesReport_$(Get-Date -Format 'yyyy-MM-dd').csv"
                contentBytes = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($tempPath))
            },
            @{
                '@odata.type' = '#microsoft.graph.fileAttachment'
                name = "PrimaryUserChangeReport_$(Get-Date -Format 'yyyy-MM-dd').csv"
                contentBytes = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($PrimaryUserChangeReport))
            }
        )
    }
    saveToSentItems = $true
}

Write-Output "Sending email to $toEmail..."
try {
    $emailResponse = Invoke-RestMethod -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/users/$fromEmail/sendMail" `
        -Headers $Headers `
        -Body ($messageBody | ConvertTo-Json -Depth 10) `
        -ContentType 'application/json' `
        -ErrorAction Stop

    Write-Output "Email sent successfully!"
}
catch {
    Write-Output "Email sending failed: $($_.Exception.Message)"
    Write-Output "Please check Mail.Send permission for the sending user/application ($fromEmail)."
}

# Clean up the temporary files
Write-Output "Cleaning up temporary files..."
try {
    Remove-Item -Path $tempPath -ErrorAction SilentlyContinue
    Remove-Item -Path $PrimaryUserChangeReport -ErrorAction SilentlyContinue
    Write-Output "Temporary files cleaned up."
}
catch {
    Write-Output "Error cleaning up temporary files: $($_.Exception.Message)"
}

Write-Output "Script execution finished."

#endregion
