<#
.SYNOPSIS
    Automates the update of Intune Windows device primary users based on the "last logged on user" using Microsoft Graph API,
    and generates comprehensive reports including a CSV export and an HTML summary embedded in an email.

.DESCRIPTION
    Authenticates via System Assigned Managed Identity.
    The Managed Identity requires the following Graph API App Roles:
        - DeviceManagementManagedDevices.ReadWrite.All
        - User.Read.All
        - Mail.Send
#>

#region Authentication via Managed Identity

Connect-AzAccount -Identity | Out-Null

$tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
$token    = $tokenObj.Token

$Headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

Write-Output "Token opgehaald. Expires: $($tokenObj.ExpiresOn)"

#endregion

#region Configuration

$fromEmail      = "AzureAutomation@contoso.com"
$toEmail        = "IT@contoso.com"
$UsersToExclude = @("user1@contoso.com", "user2@contoso.com", "user3@contoso.com")

$AllDevicesReportPath        = "$($env:TEMP)\AllDevicesReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$PrimaryUserChangeReportPath = "$($env:TEMP)\PrimaryUserChangeReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

#endregion

#region Functions

function New-DeviceInfoObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]  [string]$DeviceIntuneID,
        [Parameter(Mandatory=$false)] [string]$DeviceAzureADDeviceId,
        [Parameter(Mandatory=$true)]  [string]$DeviceName,
        [Parameter(Mandatory=$false)] [string]$DeviceEnrolledByUserPrincipalName,
        [Parameter(Mandatory=$false)] [string]$PrimaryuserId,
        [Parameter(Mandatory=$false)] [string]$PrimaryuserUPN,
        [Parameter(Mandatory=$false)] [string]$PrimaryuserDisplayName,
        [Parameter(Mandatory=$false)] [string]$PrimaryuserEmail,
        [Parameter(Mandatory=$false)] [string]$LastloginUserId,
        [Parameter(Mandatory=$false)] [string]$UserLoggedon_DisplayName,
        [Parameter(Mandatory=$false)] [string]$UserLoggedon_UserPrincipalName,
        [Parameter(Mandatory=$false)] [string]$LastloginTime,
        [Parameter(Mandatory=$false)] [string]$ChangeStatus,
        [Parameter(Mandatory=$false)] [string]$MorethanOneLogin
    )

    [PSCustomObject]@{
        DeviceIntuneID                    = $DeviceIntuneID
        DeviceAzureId                     = $DeviceAzureADDeviceId
        DeviceName                        = $DeviceName
        DeviceEnrolledByUserPrincipalName = $DeviceEnrolledByUserPrincipalName
        PrimaryuserId                     = $PrimaryuserId
        UPN_Primary                       = $PrimaryuserUPN
        DisplayName_Primary               = $PrimaryuserDisplayName
        Email_Primary                     = $PrimaryuserEmail
        LastusersLoggedOn_ID              = $LastloginUserId
        LastUserLoggedon_Displayname      = $UserLoggedon_DisplayName
        LastUserLoggedon_UPN              = $UserLoggedon_UserPrincipalName
        lastLogOnDateTime                 = $LastloginTime
        PrimaryChangeStatus               = $ChangeStatus
        MorethanOneLogin                  = $MorethanOneLogin
    }
}

#endregion

#region Fetch Devices

$PrimarVsLogonUsers      = 0
$PrimarUserChangeSuccess = 0
$PrimarUserChangeFailed  = 0
$TotalDevices            = 0

$Devicesuri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows' and managedDeviceOwnerType eq 'company'&`$select=id,deviceName,userDisplayName,userPrincipalName,usersLoggedOn,azureADDeviceId,enrolledByUserPrincipalName,emailAddress"

$allDevices  = @()
$currentUri  = $Devicesuri

Write-Output "Fetching managed devices with pagination..."

try {
    do {
        $Devices     = Invoke-RestMethod -Method GET -Uri $currentUri -Headers $Headers -ContentType 'application/json' -ErrorAction Stop
        $allDevices += $Devices.value
        Write-Output "  Pagina opgehaald. Totaal tot nu toe: $($allDevices.Count)"

        if ($null -eq $Devices.'@odata.nextLink') {
            Write-Output "Geen volgende pagina."
            break
        }
        $currentUri = $Devices.'@odata.nextLink'
        Start-Sleep -Milliseconds 100

    } while ($currentUri)

    Write-Output "Alle apparaten opgehaald. Totaal: $($allDevices.Count)"
}
catch {
    Write-Output "Fout bij ophalen apparaten: $($_.ErrorDetails.Message ?? $_.Exception.Message)"
    exit 1
}

#endregion

#region Process Devices

$allDevicesReportData        = @()
$primaryUserChangeReportData = @()

foreach ($Device in $allDevices) {
    $TotalDevices++
    Write-Output "[$TotalDevices] Verwerken: $($Device.deviceName)"

    try {
        $DMSUri2 = Invoke-RestMethod -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($Device.id)')" `
            -Headers $Headers -ContentType 'application/json' -ErrorAction Stop
    }
    catch {
        Write-Output "Fout bij ophalen details voor $($Device.deviceName): $($_.ErrorDetails.Message ?? $_.Exception.Message)"
        continue
    }

    $PrimaryuserId                    = $DMSUri2.userId
    $PrimaryuserDisplayName           = $DMSUri2.userDisplayName
    $PrimaryuserUPN                   = $DMSUri2.userPrincipalName
    $PrimaryuserEmail                 = $DMSUri2.emailAddress
    $DeviceName                       = $DMSUri2.deviceName
    $DeviceId                         = $DMSUri2.id
    $DeviceAzureADDeviceId            = $DMSUri2.azureADDeviceId
    $DeviceEnrolledByUserPrincipalName= $DMSUri2.enrolledByUserPrincipalName

    if ($DMSUri2.usersLoggedOn -and $DMSUri2.usersLoggedOn.Count -gt 0) {
        $JsonOutput      = $DMSUri2.usersLoggedOn | Sort-Object lastLogOnDateTime | ConvertTo-Json -Depth 5
        $lastLoginEntry  = $DMSUri2.usersLoggedOn | Sort-Object lastLogOnDateTime | Select-Object -Last 1
        $LastloginUserId = $lastLoginEntry.userId
        $LastloginTime   = $lastLoginEntry.lastLogOnDateTime

        try {
            $UserLoggedonDetails           = Invoke-RestMethod -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/users/$LastloginUserId" `
                -Headers $Headers -ContentType 'application/json' -ErrorAction Stop
            $UserLoggedon_DisplayName      = $UserLoggedonDetails.displayName
            $UserLoggedon_UserPrincipalName= $UserLoggedonDetails.userPrincipalName
        }
        catch {
            Write-Output "Fout bij ophalen gebruiker $LastloginUserId : $($_.ErrorDetails.Message ?? $_.Exception.Message)"
            $UserLoggedon_DisplayName       = "Unknown"
            $UserLoggedon_UserPrincipalName = "Unknown"
        }
    }
    else {
        Write-Output "Geen inloggeschiedenis voor $DeviceName."
        $LastloginUserId                = "N/A"
        $LastloginTime                  = "N/A"
        $UserLoggedon_DisplayName       = "N/A"
        $UserLoggedon_UserPrincipalName = "N/A"
        $JsonOutput                     = "N/A"
    }

    $allDevicesReportData += New-DeviceInfoObject `
        -DeviceIntuneID $DeviceId `
        -DeviceAzureADDeviceId $DeviceAzureADDeviceId `
        -DeviceName $DeviceName `
        -DeviceEnrolledByUserPrincipalName $DeviceEnrolledByUserPrincipalName `
        -PrimaryuserId $PrimaryuserId `
        -PrimaryuserUPN $PrimaryuserUPN `
        -PrimaryuserDisplayName $PrimaryuserDisplayName `
        -PrimaryuserEmail $PrimaryuserEmail `
        -LastloginUserId $LastloginUserId `
        -UserLoggedon_DisplayName $UserLoggedon_DisplayName `
        -UserLoggedon_UserPrincipalName $UserLoggedon_UserPrincipalName `
        -LastloginTime $LastloginTime `
        -MorethanOneLogin $JsonOutput

    if ($PrimaryuserId -ne $LastloginUserId -and $LastloginUserId -notin @($null, "N/A")) {

        if ($UserLoggedon_UserPrincipalName -notin $UsersToExclude) {
            $PrimarVsLogonUsers++
            Write-Output "Verschil gevonden - $DeviceName | Huidig: $PrimaryuserUPN | Nieuw: $UserLoggedon_UserPrincipalName"

            $UpdatePrimaryUseruri  = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$DeviceId')/users/`$ref"
            $UpdatePrimaryUserBody = @{ "@odata.id" = "https://graph.microsoft.com/beta/users/$LastloginUserId" } | ConvertTo-Json

            try {
                Invoke-RestMethod -Method POST `
                    -Uri $UpdatePrimaryUseruri `
                    -Body $UpdatePrimaryUserBody `
                    -Headers $Headers `
                    -ContentType 'application/json' `
                    -ErrorAction Stop

                Write-Output "Hoofdgebruiker succesvol bijgewerkt."
                $PrimarUserChangeSuccess++

                $primaryUserChangeReportData += New-DeviceInfoObject `
                    -DeviceIntuneID $DeviceId `
                    -DeviceAzureADDeviceId $DeviceAzureADDeviceId `
                    -DeviceName $DeviceName `
                    -DeviceEnrolledByUserPrincipalName $DeviceEnrolledByUserPrincipalName `
                    -PrimaryuserId $PrimaryuserId `
                    -PrimaryuserUPN $PrimaryuserUPN `
                    -PrimaryuserDisplayName $PrimaryuserDisplayName `
                    -PrimaryuserEmail $PrimaryuserEmail `
                    -LastloginUserId $LastloginUserId `
                    -UserLoggedon_DisplayName $UserLoggedon_DisplayName `
                    -UserLoggedon_UserPrincipalName $UserLoggedon_UserPrincipalName `
                    -LastloginTime $LastloginTime `
                    -ChangeStatus "Success"
            }
            catch {
                $graphError = $_.ErrorDetails.Message ?? $_.Exception.Message
                Write-Output "Fout bij bijwerken hoofdgebruiker: $graphError"
                $PrimarUserChangeFailed++

                $primaryUserChangeReportData += New-DeviceInfoObject `
                    -DeviceIntuneID $DeviceId `
                    -DeviceAzureADDeviceId $DeviceAzureADDeviceId `
                    -DeviceName $DeviceName `
                    -DeviceEnrolledByUserPrincipalName $DeviceEnrolledByUserPrincipalName `
                    -PrimaryuserId $PrimaryuserId `
                    -PrimaryuserUPN $PrimaryuserUPN `
                    -PrimaryuserDisplayName $PrimaryuserDisplayName `
                    -PrimaryuserEmail $PrimaryuserEmail `
                    -LastloginUserId $LastloginUserId `
                    -UserLoggedon_DisplayName $UserLoggedon_DisplayName `
                    -UserLoggedon_UserPrincipalName $UserLoggedon_UserPrincipalName `
                    -LastloginTime $LastloginTime `
                    -ChangeStatus "Failed - $($graphError.Substring(0, [Math]::Min(100, $graphError.Length)))"
            }
        }
        else {
            Write-Output "Overgeslagen (exclusielijst): $DeviceName | $UserLoggedon_UserPrincipalName"
        }
    }
    else {
        Write-Output "Geen wijziging nodig: $DeviceName | $UserLoggedon_UserPrincipalName"
    }
}

#endregion

#region Export CSV

Write-Output "Exporteren rapporten..."
$allDevicesReportData        | Export-Csv -Path $AllDevicesReportPath        -NoTypeInformation -Force -Delimiter ';'
$primaryUserChangeReportData | Export-Csv -Path $PrimaryUserChangeReportPath -NoTypeInformation -Force -Delimiter ';'

Write-Output "Totaal apparaten        : $TotalDevices"
Write-Output "Verschillen gevonden    : $PrimarVsLogonUsers"
Write-Output "Succesvol bijgewerkt    : $PrimarUserChangeSuccess"
Write-Output "Mislukt                 : $PrimarUserChangeFailed"

#endregion

#region Build & Send Email

$tableStyle = "border-collapse:collapse;border:1px solid #b3d9ff;background:#ffffff;"
$thStyle    = "border:1px solid #b3d9ff;background:#e6f2fa;color:#0078d4;padding:6px;text-align:left;"
$tdStyle    = "border:1px solid #b3d9ff;padding:6px;"

$PrimarVsLogonUsersReportSummary = @(
    [PSCustomObject]@{ 'Rapport' = 'Aantal apparaten';                                                              'Aantal' = $TotalDevices }
    [PSCustomObject]@{ 'Rapport' = 'Apparaten met verschil in Hoofdgebruiker en Laatst aangemelde gebruiker';       'Aantal' = $PrimarVsLogonUsers }
    [PSCustomObject]@{ 'Rapport' = 'Hoofdgebruiker - Succesvol aangepast';                                         'Aantal' = $PrimarUserChangeSuccess }
    [PSCustomObject]@{ 'Rapport' = 'Hoofdgebruiker - Aanpassing gefaald';                                          'Aantal' = $PrimarUserChangeFailed }
)

$summaryHtml = ($PrimarVsLogonUsersReportSummary | ConvertTo-Html -Fragment -As Table -PreContent "<h3 style='color:#0078d4;'>Samenvatting</h3>" | Out-String) `
    -replace '<table>',  "<table style='$tableStyle'>" `
    -replace '<th>',     "<th style='$thStyle'>" `
    -replace '<td>',     "<td style='$tdStyle'>"

$urgent     = $PrimarVsLogonUsers -gt 0
$reportDate = Get-Date -Format "dd/MM/yyyy HH:mm"
$runbookName= "UpdateIntuneDevicesPrimaryUser"
$runbookUrl = "https://portal.azure.com/#@erpe-mere.be/asset/Microsoft_Azure_Automation/Runbook/subscriptions/fb2ffe08-3411-4919-b710-3886ae6fdade/resourceGroups/Resource_group_Erpe-Mere/providers/Microsoft.Automation/automationAccounts/Automation01-Erpe-Mere/runbooks/UpdateIntuneDevicesPrimaryUser"

$emailContent = @"
<html><body style="font-family:Arial,sans-serif;color:#333;">
<table border="0" cellpadding="0" cellspacing="0">
<tr><td>
  <table border="0" cellpadding="12" cellspacing="0" style="border:1px solid #b3d9ff;background:#e6f2fa;">
  <tr><td>
    <h1 style="color:#0078d4;font-size:20px;margin:0 0 6px 0;">Intune Apparaten Rapport</h1>
    <p style="margin:4px 0;"><strong>Runbook:</strong> <a href="$runbookUrl" style="color:#0078d4;text-decoration:none;">$runbookName</a></p>
    <p style="margin:4px 0;"><strong>Datum &amp; Tijd:</strong> $reportDate</p>
    <p style="margin:4px 0;">Alleen bedrijfseigen Windows-apparaten verwerkt. Zie bijgevoegde CSV voor details.</p>
  </td></tr>
  </table>
  $summaryHtml
</td></tr>
</table>
</body></html>
"@

$attachments = @(
    @{
        '@odata.type' = '#microsoft.graph.fileAttachment'
        name          = [System.IO.Path]::GetFileName($AllDevicesReportPath)
        contentType   = 'text/csv'
        contentBytes  = [Convert]::ToBase64String([IO.File]::ReadAllBytes($AllDevicesReportPath))
    },
    @{
        '@odata.type' = '#microsoft.graph.fileAttachment'
        name          = [System.IO.Path]::GetFileName($PrimaryUserChangeReportPath)
        contentType   = 'text/csv'
        contentBytes  = [Convert]::ToBase64String([IO.File]::ReadAllBytes($PrimaryUserChangeReportPath))
    }
)

$messageBody = @{
    message = @{
        subject    = "Intune Devices Rapport - $reportDate"
        importance = if ($urgent) { "high" } else { "normal" }
        body       = @{ contentType = 'HTML'; content = $emailContent }
        from       = @{ emailAddress = @{ address = $fromEmail } }
        toRecipients = @( @{ emailAddress = @{ address = $toEmail } } )
        attachments  = $attachments
    }
    saveToSentItems = $true
} | ConvertTo-Json -Depth 10

try {
    Write-Output "Mail versturen..."
    Invoke-RestMethod -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/users/$fromEmail/sendMail" `
        -Headers $Headers `
        -Body $messageBody
    Write-Output "Mail succesvol verstuurd."
}
catch {
    Write-Output "Mail versturen mislukt."
    Write-Output ($_.ErrorDetails.Message ?? $_.Exception.Message)
}

#endregion

#region Cleanup

Write-Output "Tijdelijke bestanden verwijderen..."
Remove-Item -Path $AllDevicesReportPath        -ErrorAction SilentlyContinue
Remove-Item -Path $PrimaryUserChangeReportPath -ErrorAction SilentlyContinue
Write-Output "Klaar."

#endregion