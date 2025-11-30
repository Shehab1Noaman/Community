    <#
        .SYNOPSIS
            Aligns Intune Managed Device Categories with the primary user's Department or Company Name.

        .DESCRIPTION
            Before running this script, make sure you have created the relevant device categories in Intune:

                Endpoint Manager Admin Center > Devices > Device Categories > Create Device Category

            Create the categories according to how you want to classify devices. For example:

                - By department: HR, Finance, IT, Marketing, etc.
                - By brand / company name: Company A, Company B, etc.

            This script:
                - Gets all Windows, Corporate-owned managed devices from Intune.
                - For each device, gets the primary user from Microsoft Graph.
                - Compares the device's current category with the chosen user attribute
                (Department or CompanyName).
                - If a matching category exists in Intune, updates the device category (unless -ReadOnly is specified).
                - If not, it writes a warning so you can create the category first.

        .PARAMETER CategorySource
            Specifies which user attribute to use for categorization: 'Department' or 'CompanyName'

        .PARAMETER ReportPath
            Custom path for the CSV report. If not specified, generates a timestamped file.

        .PARAMETER ReadOnly
            When specified, the script only generates a report without making any changes to device categories.

        .PARAMETER ExcludeCategories
            Array of category names to exclude. Devices already in these categories will be skipped.

        .EXAMPLE
            .\Sync-IntuneDeviceCategories.ps1 -ReadOnly -CategorySource CompanyName
            Generates a report only, no changes made.

        .EXAMPLE
            .\Sync-IntuneDeviceCategories.ps1 -CategorySource Department -ExcludeCategories "Test","IT"
            Updates device categories based on Department, excluding devices already in "Test" or "IT" categories.

        .EXAMPLE
            .\Sync-IntuneDeviceCategories.ps1 -ReadOnly -CategorySource CompanyName -ExcludeCategories "Test","IT"
            Report only mode, excluding devices in "Test" or "IT" categories.
        #>

        param(
            [Parameter(Mandatory = $false)]
            [ValidateSet('Department', 'CompanyName')]
            [string]$CategorySource = 'Department',

            [Parameter(Mandatory = $false)]
            [string]$ReportPath,

            [Parameter(Mandatory = $false)]
            [switch]$ReadOnly,

            [Parameter(Mandatory = $false)]
            [string[]]$ExcludeCategories = @()
        )

        # Graph modules must be installed and authenticated prior to running this script
        Import-Module Microsoft.Graph.Users -ErrorAction Stop
        Import-Module Microsoft.Graph.DeviceManagement -ErrorAction Stop

        # Generate report path with timestamp if not provided
        if (-not $ReportPath) {
            $timestamp = Get-Date -Format 'ddMMyyyy_HHmmss'
            $mode = if ($ReadOnly) { "ReadOnly" } else { "Update" }
            $ReportPath = Join-Path -Path (Get-Location) -ChildPath "IntuneDeviceCategoryReport_${mode}_$timestamp.csv"
        }

        Write-Output "=========================================="
        if ($ReadOnly) {
            Write-Output "RUNNING IN READ-ONLY MODE - No changes will be made"
        } else {
            Write-Output "RUNNING IN UPDATE MODE - Device categories will be updated"
        }
        Write-Output "=========================================="

        if ($ExcludeCategories.Count -gt 0) {
            Write-Output "Excluding devices in categories: $($ExcludeCategories -join ', ')"
        }

        Write-Output "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes "User.Read.All", "DeviceManagementManagedDevices.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All"

        Write-Output "Retrieving Intune device categories..."
        $DeviceCategories = Get-MgDeviceManagementDeviceCategory -All
        $DeviceCategoryNames = @($DeviceCategories.DisplayName)

        Write-Output "Retrieving Windows corporate-owned managed devices..."
        $Devices = Get-MgDeviceManagementManagedDevice -All -Filter "managedDeviceOwnerType eq 'company' and operatingSystem eq 'Windows'"

        # Initialize report array
        $Report = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($Device in $Devices) {
            Write-Output "------------------------------------------------------------"
            Write-Output "Device Name      : $($Device.DeviceName)"
            Write-Output "Device ID        : $($Device.Id)"
            Write-Output "Operating System : $($Device.OperatingSystem)"
            Write-Output "Ownership        : $($Device.ManagedDeviceOwnerType)"
            Write-Output "Primary User ID  : $($Device.UserId)"

            $PrimaryUserId = $Device.UserId
            $PrimaryUser = $null
            $PrimaryUserDepartment = $null
            $PrimaryUserCompanyName = $null
            $TargetCategoryName = $null
            $DeviceCategoryDisplayName = $Device.DeviceCategoryDisplayName
            $Action = 'Unknown'
            $Notes = ''

            if (-not $PrimaryUserId) {
                Write-Output "No primary user assigned to this device. Skipping..."
                $Action = 'Skipped - No Primary User'
                $Notes = 'No primary user assigned to this device.'
                
                $ReportRow = [PSCustomObject]@{
                    DeviceName             = $Device.DeviceName
                    DeviceId               = $Device.Id
                    SerialNumber           = $Device.SerialNumber
                    OperatingSystem        = $Device.OperatingSystem
                    OSVersion              = $Device.OSVersion
                    Ownership              = $Device.ManagedDeviceOwnerType
                    EnrollmentDate         = $Device.EnrolledDateTime
                    LastSyncDateTime       = $Device.LastSyncDateTime
                    PrimaryUserId          = $PrimaryUserId
                    PrimaryUserDisplayName = $null
                    PrimaryUserDepartment  = $PrimaryUserDepartment
                    PrimaryUserCompanyName = $PrimaryUserCompanyName
                    CurrentCategory        = $DeviceCategoryDisplayName
                    TargetCategorySource   = $CategorySource
                    TargetCategoryName     = $TargetCategoryName
                    Action                 = $Action
                    Notes                  = $Notes
                    ProcessedDateTime      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                }
                $Report.Add($ReportRow)
                continue
            }

            # Get primary user details with required properties explicitly specified
            $PrimaryUser = Get-MgUser -UserId $PrimaryUserId -Property "Id,DisplayName,Department,CompanyName" -ErrorAction SilentlyContinue | 
                        Select-Object Id, DisplayName, Department, CompanyName
            if (-not $PrimaryUser) {
                Write-Output "WARNING: Could not retrieve primary user object for ID $PrimaryUserId. Skipping..."
                $Action = 'Error - Get User Failed'
                $Notes = "Could not retrieve primary user object for ID $PrimaryUserId."
                
                $ReportRow = [PSCustomObject]@{
                    DeviceName             = $Device.DeviceName
                    DeviceId               = $Device.Id
                    SerialNumber           = $Device.SerialNumber
                    OperatingSystem        = $Device.OperatingSystem
                    OSVersion              = $Device.OSVersion
                    Ownership              = $Device.ManagedDeviceOwnerType
                    EnrollmentDate         = $Device.EnrolledDateTime
                    LastSyncDateTime       = $Device.LastSyncDateTime
                    PrimaryUserId          = $PrimaryUserId
                    PrimaryUserDisplayName = $null
                    PrimaryUserDepartment  = $PrimaryUserDepartment
                    PrimaryUserCompanyName = $PrimaryUserCompanyName
                    CurrentCategory        = $DeviceCategoryDisplayName
                    TargetCategorySource   = $CategorySource
                    TargetCategoryName     = $TargetCategoryName
                    Action                 = $Action
                    Notes                  = $Notes
                    ProcessedDateTime      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                }
                $Report.Add($ReportRow)
                continue
            }

            $PrimaryUserDepartment = $PrimaryUser.Department
            $PrimaryUserCompanyName = $PrimaryUser.CompanyName

            Write-Output "Primary User Name       : $($PrimaryUser.DisplayName)"
            Write-Output "Primary User Department : $PrimaryUserDepartment"
            Write-Output "Primary User Company    : $PrimaryUserCompanyName"

            # Decide which user attribute to use for categorisation
            switch ($CategorySource) {
                'Department'  { $TargetCategoryName = $PrimaryUserDepartment }
                'CompanyName' { $TargetCategoryName = $PrimaryUserCompanyName }
            }

            if ($TargetCategoryName) {
                $TargetCategoryName = $TargetCategoryName.Trim()
            }

            # Current device category (display name)
            $DeviceCategoryDisplayName = $Device.DeviceCategoryDisplayName
            Write-Output "Current Device Category : $DeviceCategoryDisplayName"

            if ([string]::IsNullOrWhiteSpace($TargetCategoryName)) {
                Write-Output "WARNING: User $($PrimaryUser.DisplayName) has no value for $CategorySource. Cannot categorise device."
                $Action = "Skipped - No $CategorySource"
                $Notes = "User has no value in $CategorySource; cannot categorise device."
                
                $ReportRow = [PSCustomObject]@{
                    DeviceName             = $Device.DeviceName
                    DeviceId               = $Device.Id
                    SerialNumber           = $Device.SerialNumber
                    OperatingSystem        = $Device.OperatingSystem
                    OSVersion              = $Device.OSVersion
                    Ownership              = $Device.ManagedDeviceOwnerType
                    EnrollmentDate         = $Device.EnrolledDateTime
                    LastSyncDateTime       = $Device.LastSyncDateTime
                    PrimaryUserId          = $PrimaryUserId
                    PrimaryUserDisplayName = $PrimaryUser.DisplayName
                    PrimaryUserDepartment  = $PrimaryUserDepartment
                    PrimaryUserCompanyName = $PrimaryUserCompanyName
                    CurrentCategory        = $DeviceCategoryDisplayName
                    TargetCategorySource   = $CategorySource
                    TargetCategoryName     = $TargetCategoryName
                    Action                 = $Action
                    Notes                  = $Notes
                    ProcessedDateTime      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                }
                $Report.Add($ReportRow)
                continue
            }

            # Check if device category should be excluded
            if ($ExcludeCategories.Count -gt 0 -and $DeviceCategoryDisplayName -in $ExcludeCategories) {
                Write-Output "Device is in excluded category '$DeviceCategoryDisplayName'. Skipping..."
                $Action = 'Skipped - Excluded Category'
                $Notes = "Device category '$DeviceCategoryDisplayName' is in the exclusion list."
                
                $ReportRow = [PSCustomObject]@{
                    DeviceName             = $Device.DeviceName
                    DeviceId               = $Device.Id
                    SerialNumber           = $Device.SerialNumber
                    OperatingSystem        = $Device.OperatingSystem
                    OSVersion              = $Device.OSVersion
                    Ownership              = $Device.ManagedDeviceOwnerType
                    EnrollmentDate         = $Device.EnrolledDateTime
                    LastSyncDateTime       = $Device.LastSyncDateTime
                    PrimaryUserId          = $PrimaryUserId
                    PrimaryUserDisplayName = $PrimaryUser.DisplayName
                    PrimaryUserDepartment  = $PrimaryUserDepartment
                    PrimaryUserCompanyName = $PrimaryUserCompanyName
                    CurrentCategory        = $DeviceCategoryDisplayName
                    TargetCategorySource   = $CategorySource
                    TargetCategoryName     = $TargetCategoryName
                    Action                 = $Action
                    Notes                  = $Notes
                    ProcessedDateTime      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                }
                $Report.Add($ReportRow)
                continue
            }

            if ($DeviceCategoryDisplayName -eq $TargetCategoryName) {
                Write-Output "Device is already in the correct category: '$TargetCategoryName'."
                $Action = 'No Change'
                $Notes = "Device already in correct category '$TargetCategoryName'."
                
                $ReportRow = [PSCustomObject]@{
                    DeviceName             = $Device.DeviceName
                    DeviceId               = $Device.Id
                    SerialNumber           = $Device.SerialNumber
                    OperatingSystem        = $Device.OperatingSystem
                    OSVersion              = $Device.OSVersion
                    Ownership              = $Device.ManagedDeviceOwnerType
                    EnrollmentDate         = $Device.EnrolledDateTime
                    LastSyncDateTime       = $Device.LastSyncDateTime
                    PrimaryUserId          = $PrimaryUserId
                    PrimaryUserDisplayName = $PrimaryUser.DisplayName
                    PrimaryUserDepartment  = $PrimaryUserDepartment
                    PrimaryUserCompanyName = $PrimaryUserCompanyName
                    CurrentCategory        = $DeviceCategoryDisplayName
                    TargetCategorySource   = $CategorySource
                    TargetCategoryName     = $TargetCategoryName
                    Action                 = $Action
                    Notes                  = $Notes
                    ProcessedDateTime      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                }
                $Report.Add($ReportRow)
                continue
            }

            # Check if a matching device category exists in Intune
            if ($DeviceCategoryNames -contains $TargetCategoryName) {
                $CategoryId = ($DeviceCategories | Where-Object { $_.DisplayName -eq $TargetCategoryName }).Id

                if ($ReadOnly) {
                    # Read-Only Mode - Report what would be changed
                    Write-Output "[READ-ONLY] Would update device category to '$TargetCategoryName'..."
                    Write-Output "  Category ID: $CategoryId"
                    $Action = 'Would Update'
                    $Notes = "Device category would be updated from '$DeviceCategoryDisplayName' to '$TargetCategoryName'."
                }
                else {
                    # Update Mode - Actually make the change
                    Write-Output "Updating device category to '$TargetCategoryName'..."
                    Write-Output "  Category ID: $CategoryId"

                    try {
                        # Use BodyParameter to set the category
                        $body = @{
                            "@odata.id" = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCategories/$CategoryId"
                        }
                        Invoke-MgGraphRequest -Method PUT -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$($Device.Id)')/deviceCategory/`$ref" -Body $body -ErrorAction Stop
                        
                        Write-Output "SUCCESS: Device '$($Device.DeviceName)' category updated to '$TargetCategoryName'."
                        $Action = 'Updated'
                        $Notes = "Device category updated from '$DeviceCategoryDisplayName' to '$TargetCategoryName'."
                    }
                    catch {
                        Write-Output "ERROR: Failed to update device category for '$($Device.DeviceName)': $($_.Exception.Message)"
                        $Action = 'Error - Update Failed'
                        $Notes = "Failed to update device category: $($_.Exception.Message)"
                    }
                }
            }
            else {
                Write-Output "ERROR: Device Category '$TargetCategoryName' does not exist in Intune."
                Write-Output "       Please create this category first in Endpoint Manager."
                $Action = 'Error - Category Missing'
                $Notes = "Device category '$TargetCategoryName' does not exist in Intune."
            }

            # Build report row for this device
            $ReportRow = [PSCustomObject]@{
                DeviceName             = $Device.DeviceName
                DeviceId               = $Device.Id
                SerialNumber           = $Device.SerialNumber
                OperatingSystem        = $Device.OperatingSystem
                OSVersion              = $Device.OSVersion
                Ownership              = $Device.ManagedDeviceOwnerType
                EnrollmentDate         = $Device.EnrolledDateTime
                LastSyncDateTime       = $Device.LastSyncDateTime
                PrimaryUserId          = $PrimaryUserId
                PrimaryUserDisplayName = $PrimaryUser.DisplayName
                PrimaryUserDepartment  = $PrimaryUserDepartment
                PrimaryUserCompanyName = $PrimaryUserCompanyName
                CurrentCategory        = $DeviceCategoryDisplayName
                TargetCategorySource   = $CategorySource
                TargetCategoryName     = $TargetCategoryName
                Action                 = $Action
                Notes                  = $Notes
                ProcessedDateTime      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            }

            $Report.Add($ReportRow)
        }

        Write-Output "------------------------------------------------------------"
        Write-Output "Exporting report to: $ReportPath"
        $Report | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
        Write-Output "Report exported successfully."

        # Display summary
        $Summary = [ordered]@{
            'Mode'                 = if ($ReadOnly) { 'READ-ONLY' } else { 'UPDATE' }
            'Total Devices'        = $Report.Count
            'Updated'              = ($Report | Where-Object { $_.Action -eq 'Updated' }).Count
            'Would Update'         = ($Report | Where-Object { $_.Action -eq 'Would Update' }).Count
            'No Change'            = ($Report | Where-Object { $_.Action -eq 'No Change' }).Count
            'Skipped - No User'    = ($Report | Where-Object { $_.Action -eq 'Skipped - No Primary User' }).Count
            "Skipped - No $CategorySource" = ($Report | Where-Object { $_.Action -eq "Skipped - No $CategorySource" }).Count
            'Skipped - Excluded'   = ($Report | Where-Object { $_.Action -eq 'Skipped - Excluded Category' }).Count
            'Category Missing'     = ($Report | Where-Object { $_.Action -eq 'Error - Category Missing' }).Count
            'Update Failed'        = ($Report | Where-Object { $_.Action -eq 'Error - Update Failed' }).Count
            'User Retrieval Error' = ($Report | Where-Object { $_.Action -eq 'Error - Get User Failed' }).Count
        }

        Write-Output "`n=========================================="
        Write-Output "SUMMARY:"
        Write-Output "=========================================="
        $Summary.GetEnumerator() | ForEach-Object { 
            Write-Output "$($_.Key): $($_.Value)" 
        }
        
        if ($ReadOnly) {
            Write-Output "`nTo apply these changes, run the script again WITHOUT the -ReadOnly parameter."
        }
        
        Write-Output "Processing complete."
        Disconnect-MgGraph
