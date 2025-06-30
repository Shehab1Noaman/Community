# Requires PowerShell 5.1 or later for System.Windows.Forms.
# PowerShell 7.x is recommended for better performance and modern features,
# but this version is adjusted for broader compatibility.

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# region --- Global Variables for Script State (Accessible throughout) ---
# These variables store configuration and runtime state.
$global:g_tenantId = ""
$global:g_applicationId = "" 
$global:g_clientSecret = "" 

$global:g_sourceSiteSpecifier = ""
$global:g_destSiteSpecifier = ""
$global:g_sourceFolderPath = ""
$global:g_destinationFolderPath = ""
$global:g_resumeOperation = $false
$global:g_preMigrationScan = $false
$global:g_copyAllVersions = $false # Graph API's direct copy support for all versions is limited.
$global:g_maxConcurrentCopies = 5
$global:g_initialRetryPauseSeconds = 5
$global:g_excludeFileExtensions = @("tmp", "bak", "DS_Store", "ini")
$global:g_excludeFolderNames = @("$recycle") # SharePoint Recycle Bin folder name

$global:g_accessToken = $null
$global:g_headers = $null
$global:g_sourceSiteID = $null
$global:g_sourceSitedriveId = $null
$global:g_destSiteID = $null
$global:g_destSitedriveId = $null
$global:g_processedPaths = @{} # Stores paths marked as 'Completed' or 'Skipped' for resume functionality
$global:g_semaphore = $null # Initialized after UI input to control concurrency

# Logging Paths (initialized after UI input for consistent timestamping)
$global:g_logBaseDirPath = "C:\SharePointMigrationLogs"
$global:g_scriptStartTime = ""
$global:g_logFolderpath = ""
$global:g_logFilePath = ""
$global:g_recordFilePath = ""
$global:g_scanReportPath = ""

# Progress Tracking for UI
$global:g_totalItemsToProcess = 0 # Estimated total items (files + folders), dynamically updated
$global:g_itemsProcessedCount = 0 # Number of items processed so far

# Define log levels for granular output control
$global:LogLevels = @{
    "CRITICAL" = 5
    "ERROR"    = 4
    "WARNING"  = 3
    "INFO"     = 2
    "DEBUG"    = 1
    "VERBOSE"  = 0
}
$global:MinLogLevel = $global:LogLevels.INFO # Default minimum log level for console/file output

# UI Controls (made global for easier access across functions)
$global:g_progressForm = $null
$global:g_progressLabel = $null
$global:g_progressBar = $null

# endregion

# region --- UI Form Definition ---

Function Show-MigrationConfigUI {
    Param (
        # Default placeholder values for the UI fields
        [string]$DefaultTenantId = "YOUR_AZURE_AD_TENANT_ID_HERE", # 
        [string]$DefaultApplicationId = "YOUR_AZURE_AD_APP_APPLICATION_ID_HERE", 
        [string]$DefaultClientSecret = "YOUR_CLIENT_SECRET_VALUE_HERE", # Direct secret value
        [string]$DefaultSourceSiteSpecifier = "yourdomain.sharepoint.com:/sites/SourceSiteCollection", # Example
        [string]$DefaultDestSiteSpecifier = "yourdomain.sharepoint.com:/sites/DestinationSiteCollection", # Example
        [string]$DefaultSourceFolderPath = "Documents/MySourceFolder", # Example: Relative to the Documents library
        [string]$DefaultDestinationFolderPath = "Documents/MyDestinationFolder", # Example: Relative to the Documents library
        [bool]$DefaultResumeOperation = $false,
        [bool]$DefaultPreMigrationScan = $false,
        [bool]$DefaultCopyAllVersions = $false,
        [int]$DefaultMaxConcurrentCopies = 5,
        [int]$DefaultInitialRetryPauseSeconds = 5,
        [string]$DefaultExcludeFileExtensions = "tmp,bak,DS_Store,ini",
        [string]$DefaultExcludeFolderNames = "`$recycle" # Note: PowerShell needs backtick for $
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "SharePoint Migration Script Configuration"
    $form.Size = New-Object System.Drawing.Size(850, 650) # Increased size to accommodate labels
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle # Prevent resizing
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.AutoScroll = $true # Enable scrollbars if content exceeds form size

    # UI Element Y-position tracker to stack controls neatly
    $yPos = 20

    # Helper function to add a labeled textbox
    Function Add-LabeledTextBox {
        Param (
            [System.Windows.Forms.Form]$Form,
            [ref]$YPos,
            [string]$LabelText,
            [string]$InitialValue = "",
            [int]$LabelWidth = 220, # Increased label width to prevent cutoff
            [int]$TextBoxWidth = 400, # Adjusted textbox width
            [bool]$IsPassword = $false,
            [string]$Name = "" # Optional name for easy lookup if needed
        )
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(20, $YPos.Value)
        $label.Size = New-Object System.Drawing.Size($LabelWidth, 20)
        $label.Text = $LabelText
        $Form.Controls.Add($label)

        $textBox = New-Object System.Windows.Forms.TextBox
        # Explicitly cast to [int] to prevent 'op_Addition' error
        $textBox.Location = New-Object System.Drawing.Point(([int]20 + [int]$LabelWidth + [int]10), $YPos.Value)
        $textBox.Size = New-Object System.Drawing.Size($TextBoxWidth, 20)
        $textBox.Text = $InitialValue
        if ($IsPassword) { $textBox.UseSystemPasswordChar = $true }
        if ($Name) { $textBox.Name = $Name }
        $Form.Controls.Add($textBox)

        $YPos.Value += 30 # Increment Y position for the next control
        return $textBox # Return the textbox control for later retrieval of its value
    }

    # Helper function to add a labeled NumericUpDown control
    Function Add-LabeledNumericUpDown {
        Param (
            [System.Windows.Forms.Form]$Form,
            [ref]$YPos,
            [string]$LabelText,
            [int]$Minimum = 0,
            [int]$Maximum = 100,
            [int]$DefaultValue = 0,
            [int]$LabelWidth = 220, # Consistent label width
            [int]$NumericWidth = 80,
            [string]$Name = ""
        )
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(20, $YPos.Value)
        $label.Size = New-Object System.Drawing.Size($LabelWidth, 20)
        $label.Text = $LabelText
        $Form.Controls.Add($label)

        $numericUpDown = New-Object System.Windows.Forms.NumericUpDown
        # Explicitly cast to [int] to prevent 'op_Addition' error
        $numericUpDown.Location = New-Object System.Drawing.Point(([int]20 + [int]$LabelWidth + [int]10), $YPos.Value)
        $numericUpDown.Size = New-Object System.Drawing.Size($NumericWidth, 20)
        $numericUpDown.Minimum = $Minimum
        $numericUpDown.Maximum = $Maximum
        $numericUpDown.Value = $DefaultValue
        if ($Name) { $numericUpDown.Name = $Name }
        $Form.Controls.Add($numericUpDown)

        $YPos.Value += 30
        return $numericUpDown
    }

    # Helper function to add a checkbox
    Function Add-Checkbox {
        Param (
            [System.Windows.Forms.Form]$Form,
            [ref]$YPos,
            [string]$Text,
            [bool]$Checked = $false,
            [string]$Name = ""
        )
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Location = New-Object System.Drawing.Point(20, $YPos.Value)
        $checkbox.Size = New-Object System.Drawing.Size(500, 20) # Increased checkbox width
        $checkbox.Text = $Text
        $checkbox.Checked = $Checked
        if ($Name) { $checkbox.Name = $Name }
        $Form.Controls.Add($checkbox)

        $YPos.Value += 25
        return $checkbox
    }

    # --- Add UI Elements to the Form ---

    # Azure AD Credentials
    $textBoxTenantID = Add-LabeledTextBox -Form $form -YPos ([ref]$yPos) -LabelText "Tenant ID:" -InitialValue $DefaultTenantId -Name "TenantID"
    $textBoxApplicationID = Add-LabeledTextBox -Form $form -YPos ([ref]$yPos) -LabelText "Application ID:" -InitialValue $DefaultApplicationId -Name "ApplicationID" # Changed label/param
    $textBoxClientSecret = Add-LabeledTextBox -Form $form -YPos ([ref]$yPos) -LabelText "Client Secret Value:" -InitialValue $DefaultClientSecret -IsPassword $true -Name "ClientSecret" # Modified: direct value, hide with password chars

    $yPos += 10 # Spacer

    # SharePoint Paths
    $textBoxSourceSiteSpecifier = Add-LabeledTextBox -Form $form -YPos ([ref]$yPos) -LabelText "Source Site Specifier (e.g., domain.sharepoint.com:/sites/Site1):" -InitialValue $DefaultSourceSiteSpecifier -Name "SourceSiteSpecifier" -LabelWidth 350 # Wider label
    $textBoxDestSiteSpecifier = Add-LabeledTextBox -Form $form -YPos ([ref]$yPos) -LabelText "Destination Site Specifier (e.g., domain.sharepoint.com:/sites/Site2):" -InitialValue $DefaultDestSiteSpecifier -Name "DestSiteSpecifier" -LabelWidth 350 # Wider label
    $textBoxSourceFolderPath = Add-LabeledTextBox -Form $form -YPos ([ref]$yPos) -LabelText "Source Folder Path (relative to Documents, e.g., 'Source/Level1'):" -InitialValue $DefaultSourceFolderPath -Name "SourceFolderPath" -LabelWidth 350 # Wider label
    $textBoxDestinationFolderPath = Add-LabeledTextBox -Form $form -YPos ([ref]$yPos) -LabelText "Destination Folder Path (relative to Documents, e.g., 'Destination'):" -InitialValue $DefaultDestinationFolderPath -Name "DestinationFolderPath" -LabelWidth 350 # Wider label

    $yPos += 10 # Spacer

    # Operation Type (Radio Buttons in a GroupBox)
    $groupBoxOperation = New-Object System.Windows.Forms.GroupBox
    $groupBoxOperation.Location = New-Object System.Drawing.Point(20, $yPos)
    $groupBoxOperation.Size = New-Object System.Drawing.Size(650, 70)
    $groupBoxOperation.Text = "Operation Type"
    $form.Controls.Add($groupBoxOperation)

    $radioStartNew = New-Object System.Windows.Forms.RadioButton
    $radioStartNew.Location = New-Object System.Drawing.Point(15, 20)
    $radioStartNew.Size = New-Object System.Drawing.Size(200, 20)
    $radioStartNew.Text = "Start New Operation"
    $radioStartNew.Checked = -not $DefaultResumeOperation # Default selection based on parameter
    $groupBoxOperation.Controls.Add($radioStartNew)

    $radioResume = New-Object System.Windows.Forms.RadioButton
    $radioResume.Location = New-Object System.Drawing.Point(15, 45)
    $radioResume.Size = New-Object System.Drawing.Size(200, 20)
    $radioResume.Text = "Resume Previous Operation"
    $radioResume.Checked = $DefaultResumeOperation
    $groupBoxOperation.Controls.Add($radioResume)

    $yPos += 80 # Move yPos past the group box

    # Operational Settings (Checkboxes and NumericUpdowns)
    $checkboxPreMigrationScan = Add-Checkbox -Form $form -YPos ([ref]$yPos) -Text "Run in Pre-Migration Scan Mode (Dry Run)" -Checked $DefaultPreMigrationScan -Name "PreMigrationScan"
    $checkboxCopyAllVersions = Add-Checkbox -Form $form -YPos ([ref]$yPos) -Text "Attempt to Copy All File Versions (Limited Graph Support)" -Checked $DefaultCopyAllVersions -Name "CopyAllVersions"

    $numericUpDownMaxConcurrentCopies = Add-LabeledNumericUpDown -Form $form -YPos ([ref]$yPos) -LabelText "Max Concurrent File Copies:" -Minimum 1 -Maximum 20 -DefaultValue $DefaultMaxConcurrentCopies -Name "MaxConcurrentCopies"
    $numericUpDownInitialPauseSeconds = Add-LabeledNumericUpDown -Form $form -YPos ([ref]$yPos) -LabelText "Initial Retry Pause (seconds):" -Minimum 1 -Maximum 60 -DefaultValue $DefaultInitialRetryPauseSeconds -Name "InitialPauseSeconds"

    $yPos += 10 # Spacer

    # Exclusions
    $labelExclusions = New-Object System.Windows.Forms.Label
    $labelExclusions.Location = New-Object System.Drawing.Point(20, $yPos)
    $labelExclusions.Size = New-Object System.Drawing.Size(650, 20)
    $labelExclusions.Text = "Exclusions (comma-separated, e.g., 'tmp,bak' or '`$recycle,Forms'):"
    $form.Controls.Add($labelExclusions)
    $yPos += 25

    # Use default LabelWidth for the labels, but ensure TextBoxWidth is large enough for content
    $textBoxExcludeFileExtensions = Add-LabeledTextBox -Form $form -YPos ([ref]$yPos) -LabelText "Exclude File Extensions:" -InitialValue $DefaultExcludeFileExtensions -TextBoxWidth 500 -Name "ExcludeFileExtensions"
    $textBoxExcludeFolderNames = Add-LabeledTextBox -Form $form -YPos ([ref]$yPos) -LabelText "Exclude Folder Names:" -InitialValue $DefaultExcludeFolderNames -TextBoxWidth 500 -Name "ExcludeFolderNames"

    $yPos += 20 # Spacer

    # --- OK and Cancel Buttons ---
    $buttonOK = New-Object System.Windows.Forms.Button
    $buttonOK.Location = New-Object System.Drawing.Point(250, $yPos)
    $buttonOK.Size = New-Object System.Drawing.Size(75, 25)
    $buttonOK.Text = "OK"
    $buttonOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($buttonOK)

    $buttonCancel = New-Object System.Windows.Forms.Button
    $buttonCancel.Location = New-Object System.Drawing.Point(340, $yPos)
    $buttonCancel.Size = New-Object System.Drawing.Size(75, 25)
    $buttonCancel.Text = "Cancel"
    $buttonCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($buttonCancel)

    # --- Add event handlers for OK button ---
    $buttonOK.Add_Click({
        # Capture all user inputs into global variables
        $global:g_tenantId = $textBoxTenantID.Text
        $global:g_applicationId = $textBoxApplicationID.Text 
        $global:g_clientSecret = $textBoxClientSecret.Text 
        $global:g_sourceSiteSpecifier = $textBoxSourceSiteSpecifier.Text
        $global:g_destSiteSpecifier = $textBoxDestSiteSpecifier.Text
        $global:g_sourceFolderPath = $textBoxSourceFolderPath.Text
        $global:g_destinationFolderPath = $textBoxDestinationFolderPath.Text
        $global:g_resumeOperation = $radioResume.Checked
        $global:g_preMigrationScan = $checkboxPreMigrationScan.Checked
        $global:g_copyAllVersions = $checkboxCopyAllVersions.Checked
        $global:g_maxConcurrentCopies = [int]$numericUpDownMaxConcurrentCopies.Value
        $global:g_initialRetryPauseSeconds = [int]$numericUpDownInitialPauseSeconds.Value

        # Parse comma-separated exclusions into arrays
        $global:g_excludeFileExtensions = ($textBoxExcludeFileExtensions.Text -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $global:g_excludeFolderNames = ($textBoxExcludeFolderNames.Text -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

        # Basic input validation to ensure required fields are filled
        $missingFields = @()
        if ([string]::IsNullOrWhiteSpace($global:g_tenantId)) { $missingFields += "Tenant ID" }
        if ([string]::IsNullOrWhiteSpace($global:g_applicationId)) { $missingFields += "Application ID" } # Changed: Application ID
        if ([string]::IsNullOrWhiteSpace($global:g_clientSecret)) { $missingFields += "Client Secret Value" } # Changed: Check secret value directly
        if ([string]::IsNullOrWhiteSpace($global:g_sourceSiteSpecifier)) { $missingFields += "Source Site Specifier" }
        if ([string]::IsNullOrWhiteSpace($global:g_destSiteSpecifier)) { $missingFields += "Destination Site Specifier" }

        if ($missingFields.Count -gt 0) {
            [System.Windows.Forms.MessageBox]::Show(("Please fill in the following required fields:`n" + ($missingFields -join "`n")), "Missing Required Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            $form.DialogResult = [System.Windows.Forms.DialogResult]::None # Prevent form from closing if validation fails
        } else {
            $form.Close() # Close the form only if all validations pass
        }
    })

    $buttonCancel.Add_Click({
        $form.Close() # Close the form if Cancel is clicked
    })

    # Show the form modally and return the DialogResult (OK or Cancel)
    return $form.ShowDialog()
}

# endregion

# region --- Helper Functions ---

# Function for consistent logging to console and file
Function Write-Log {
    Param (
        [string]$Message,
        [string]$Level = "INFO", # Log level (CRITICAL, ERROR, WARNING, INFO, DEBUG, VERBOSE)
        [ValidateSet("Host", "LogFile", "Both")] # Where to output the log message
        [string]$OutputTo = "Both"
    )
    # Check if the log level is high enough to be displayed/recorded
    if ($global:LogLevels[$Level.ToUpper()] -ge $global:MinLogLevel) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] $Message"
        
        # Write to log file
        if ($OutputTo -eq "LogFile" -or $OutputTo -eq "Both") {
            # Ensure log file path is not empty before trying to use it
            if (-not [string]::IsNullOrWhiteSpace($global:g_logFilePath)) {
                # Ensure log file exists before appending
                if (-not (Test-Path $global:g_logFilePath)) {
                    # Create the directory if it doesn't exist
                    $logFileDir = Split-Path -Path $global:g_logFilePath -Parent
                    if (-not (Test-Path $logFileDir)) {
                        New-Item -Path $logFileDir -ItemType Directory -Force | Out-Null
                    }
                    New-Item -Path $global:g_logFilePath -ItemType File -Force | Out-Null
                }
                Add-Content -Path $global:g_logFilePath -Value $logEntry
            } else {
                # Fallback to console if log file path is not set (happens early in execution)
                Write-Host "[$timestamp] [WARN] Log file path not initialized. Outputting to console: $logEntry"
            }
        }
        # Write to console with color coding
        if ($OutputTo -eq "Host" -or $OutputTo -eq "Both") {
            switch ($Level.ToUpper()) {
                "CRITICAL" { Write-Host -ForegroundColor Red $logEntry }
                "ERROR"    { Write-Host -ForegroundColor Red $logEntry }
                "WARNING"  { Write-Host -ForegroundColor Yellow $logEntry }
                "INFO"     { Write-Host -ForegroundColor Green $logEntry }
                "DEBUG"    { Write-Host -ForegroundColor Cyan $logEntry }
                Default    { Write-Host $logEntry }
            }
        }
    }
}

# Function to write detailed copy records to a CSV file
Function Write-CopyRecord {
    Param (
        [string]$SourceSite,
        [string]$SourcePath,
        [string]$DestinationSite,
        [string]$DestinationPath,
        [string]$ItemType, # "File" or "Folder"
        [string]$Status, # e.g., "Completed", "Skipped", "Failed", "Scan Only"
        [string]$Notes,
        [string]$FileSize = "", # For files
        [string]$ItemModifiedDate = "", # For files/folders
        [string]$SourceHash = "", # For files (SHA1)
        [string]$DestHash = "", # For files (SHA1)
        [string]$HashMatch = "" # "True", "False", "N/A", "Partial (No Hash)"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    # Format as CSV record, ensuring proper quoting for fields that might contain commas
    $recordEntry = "`"$timestamp`",`"$SourceSite`",`"$SourcePath`",`"$DestinationSite`",`"$DestinationPath`",`"$ItemType`",`"$Status`",`"$Notes`",`"$FileSize`",`"$ItemModifiedDate`",`"$SourceHash`",`"$DestHash`",`"$HashMatch`""

    # Ensure record file path is not empty
    if (-not [string]::IsNullOrWhiteSpace($global:g_recordFilePath)) {
        # Add header row if the record file doesn't exist yet
        if (-not (Test-Path $global:g_recordFilePath)) {
            # Create the directory if it doesn't exist
            $recordFileDir = Split-Path -Path $global:g_recordFilePath -Parent
            if (-not (Test-Path $recordFileDir)) {
                New-Item -Path $recordFileDir -ItemType Directory -Force | Out-Null
            }
            Add-Content -Path $global:g_recordFilePath -Value "`"Timestamp`",`"Source Site`",`"Source Path`",`"Destination Site`",`"Destination Path`",`"Item Type`",`"Status`",`"Notes`",`"File Size (bytes)`",`"Item Last Modified Date`",`"Source SHA1 Hash`",`"Destination SHA1 Hash`",`"Hash Match`""
        }
        Add-Content -Path $global:g_recordFilePath -Value $recordEntry
    } else {
        Write-Log -Message "Record file path not initialized. Record not written for '$SourcePath'." -Level "WARNING" -OutputTo "Host"
    }
}

# Initialises log directories and loads processed paths if resuming
Function Initialize-LogAndResume {
    # Create base log directory if it doesn't exist
    if (-not (Test-Path $global:g_logBaseDirPath)) {
        New-Item -Path $global:g_logBaseDirPath -ItemType Directory -Force | Out-Null
    }

    # Set script start time for unique folder naming
    $global:g_scriptStartTime = Get-Date -Format 'yyyyMMdd_HHmmss'

    # Handle resume functionality: find the latest log folder
    if ($global:g_resumeOperation) {
        Write-Log -Message "Resume operation enabled. Searching for previous log files..." -Level "INFO"
        # Get all log folders and sort by last write time to find the newest one
        $previousLogFolders = Get-ChildItem -Path $global:g_logBaseDirPath -Directory -Filter "SharePointCopyLog-*" | Sort-Object LastWriteTime -Descending
        
        if ($previousLogFolders) {
            $latestLogFolder = $previousLogFolders | Select-Object -First 1
            $global:g_logFolderpath = $latestLogFolder.FullName
            # Find the latest log and record files within that folder
            $global:g_logFilePath = (Get-ChildItem -Path $global:g_logFolderpath -File -Filter "SharePointCopyLog-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
            $global:g_recordFilePath = (Get-ChildItem -Path $global:g_logFolderpath -File -Filter "SharePointCopyRecords-*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
            
            # Verify if necessary files exist for a proper resume
            if (-not (Test-Path $global:g_logFilePath) -or -not (Test-Path $global:g_recordFilePath)) {
                Write-Log -Message "Could not find complete log/record files for resume in '$($global:g_logFolderpath)'. Starting a fresh migration instead." -Level "WARNING"
                $global:g_resumeOperation = $false # Fallback to fresh start
                # Create new log folder for fresh start
                $newLogFolder = New-Item -Name "SharePointCopyLog-$global:g_scriptStartTime" -Path $global:g_logBaseDirPath -ItemType Directory -Force
                $global:g_logFolderpath = $newLogFolder.FullName # Correct assignment
                $global:g_logFilePath = Join-Path -Path $global:g_logFolderpath -ChildPath "SharePointCopyLog-$global:g_scriptStartTime.log" # Use Join-Path
                $global:g_recordFilePath = Join-Path -Path $global:g_logFolderpath -ChildPath "SharePointCopyRecords-$global:g_scriptStartTime.csv" # Use Join-Path
            } else {
                 Write-Log -Message "Resuming with log folder: '$global:g_logFolderpath'" -Level "INFO"
                 Write-Log -Message "Log file: '$global:g_logFilePath'" -Level "INFO"
                 Write-Log -Message "Record file: '$global:g_recordFilePath'" -Level "INFO"
                 Load-ProcessedPaths # Load paths that were already processed
            }
        } else {
            Write-Log -Message "No previous log folders found for resume. Starting a fresh migration." -Level "WARNING"
            $global:g_resumeOperation = $false
            # Create new log folder for fresh start
            $newLogFolder = New-Item -Name "SharePointCopyLog-$global:g_scriptStartTime" -Path $global:g_logBaseDirPath -ItemType Directory -Force
            $global:g_logFolderpath = $newLogFolder.FullName # Correct assignment
            $global:g_logFilePath = Join-Path -Path $global:g_logFolderpath -ChildPath "SharePointCopyLog-$global:g_scriptStartTime.log" # Use Join-Path
            $global:g_recordFilePath = Join-Path -Path $global:g_logFolderpath -ChildPath "SharePointCopyRecords-$global:g_scriptStartTime.csv" # Use Join-Path
        }
    } else {
        # Fresh start: always create a new log folder
        $newLogFolder = New-Item -Name "SharePointCopyLog-$global:g_scriptStartTime" -Path $global:g_logBaseDirPath -ItemType Directory -Force
        $global:g_logFolderpath = $newLogFolder.FullName # Correct assignment
        $global:g_logFilePath = Join-Path -Path $global:g_logFolderpath -ChildPath "SharePointCopyLog-$global:g_scriptStartTime.log" # Use Join-Path
        $global:g_recordFilePath = Join-Path -Path $global:g_logFolderpath -ChildPath "SharePointCopyRecords-$global:g_scriptStartTime.csv" # Use Join-Path
    }
    # For scan report path, always create a new one specific to the current run
    $global:g_scanReportPath = Join-Path -Path $global:g_logFolderpath -ChildPath "SharePointCopyScanReport-$global:g_scriptStartTime.csv"
}

# Loads paths from the record file into a hash table for quick lookup during resume
Function Load-ProcessedPaths {
    if (Test-Path $global:g_recordFilePath) {
        Write-Log -Message "Loading processed paths from '$global:g_recordFilePath' for resume..." -Level "INFO"
        # Read CSV and populate g_processedPaths with completed/skipped items
        Import-Csv -Path $global:g_recordFilePath | ForEach-Object {
            if ($_.Status -eq "Completed" -or $_.Status -eq "Skipped (Exists)" -or $_.Status -eq "Skipped (Newer/Same)") {
                $global:g_processedPaths[$_.SourcePath] = $true
            }
        }
        Write-Log -Message "Loaded $($global:g_processedPaths.Count) previously processed paths." -Level "INFO"
    }
}

# General function for making Graph API requests with retry logic
Function Invoke-GraphRequest {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [string]$Method = "GET",
        [object]$Body = $null,
        [string]$ContentType = "application/json",
        [int]$MaxRetries = 10,
        [int]$InitialDelaySeconds = $global:g_initialRetryPauseSeconds # Use UI provided initial delay
    )

    $attempt = 0
    $sleepDuration = $InitialDelaySeconds

    do {
        Try {
            Write-Log -Message "Making Graph API request: $Method $Uri (Attempt $($attempt + 1))" -Level "DEBUG"
            $response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method -Body $Body -ContentType $ContentType -ErrorAction Stop
            return $response # Success
        } Catch {
            $exception = $_.Exception
            $statusCode = $null
            $statusDescription = $null
            $errorMessage = $exception.Message
            $responseHeaders = $null

            # Try to extract details from WebException if available
            if ($exception.Response -is [System.Net.HttpWebResponse]) {
                $statusCode = $exception.Response.StatusCode.Value__
                $statusDescription = $exception.Response.StatusDescription
                $responseHeaders = $exception.Response.Headers
            }
            
            Write-Log -Message "API call failed (Attempt $($attempt + 1)): Status $statusCode ($statusDescription) for URI: $Uri. Message: $errorMessage" -Level "WARNING"
            if ($responseHeaders) {
                Write-Log -Message "Response Headers: $($responseHeaders | ConvertTo-Json -Compress)" -Level "DEBUG"
            }

            # Handle specific status codes for retries
            if ($statusCode -eq 429 -or $statusCode -eq 503) { # Too Many Requests / Service Unavailable
                $retryAfter = $null
                Try {
                    $retryAfterHeader = $responseHeaders["Retry-After"]
                    if ($retryAfterHeader) {
                        $retryAfter = [int]$retryAfterHeader # Use specified retry-after duration
                        Write-Log -Message "Received $statusCode. Retrying after $($retryAfter) seconds as per 'Retry-After' header." -Level "WARNING"
                        $sleepDuration = $retryAfter
                    } else {
                        Write-Log -Message "Received $statusCode, but no 'Retry-After' header. Using exponential backoff (current delay: $($sleepDuration)s)." -Level "WARNING"
                    }
                } Catch {
                    Write-Log -Message "Error parsing 'Retry-After' header: $($_.Exception.Message). Using exponential backoff." -Level "WARNING"
                }
            } elseif ($statusCode -eq 404) { # Not Found
                # Log 404s at DEBUG level unless it's a critical one that shouldn't be ignored
                Write-Log -Message "Resource not found (404) for URI: $Uri. This might be expected for path checks." -Level "DEBUG"
                Throw $_ # Re-throw 404 if it's unexpected for the caller to handle
            } elseif ($statusCode -ge 400 -and $statusCode -lt 500) { # Client errors (e.g., 401, 403, 400)
                Write-Log -Message "Client-side API error ($statusCode) for URI: $Uri. Message: $errorMessage. Not retrying." -Level "ERROR"
                Throw $_ # These usually indicate a configuration/permission issue, not transient.
            } else { # Other server errors or unexpected issues
                Write-Log -Message "API call failed (non-4xx error, status: $statusCode). Message: $errorMessage. Retrying in $($sleepDuration)s." -Level "WARNING"
            }

            $attempt++
            if ($attempt -ge $MaxRetries) {
                Write-Log -Message "Maximum retries ($MaxRetries) reached for URI: $Uri. Giving up on this request." -Level "ERROR"
                Throw $_ # Stop retrying after max attempts
            }

            Write-Log -Message "Waiting $sleepDuration seconds before next retry..." -Level "INFO"
            Start-Sleep -Seconds $sleepDuration

            # Double sleep duration for exponential backoff if no Retry-After header was present
            if ($statusCode -ne 429 -and $statusCode -ne 503 -or -not $retryAfter) {
                $sleepDuration = [int](($sleepDuration * 2) + (Get-Random -Minimum 1 -Maximum 3))
            }
        }
    } while ($true)
}

# Acquires an OAuth 2.0 client credentials access token for Microsoft Graph API
Function Get-GraphAccessToken {
    Param (
        [string]$TenantId,
        [string]$ApplicationId, # Changed parameter name
        [string]$ClientSecret
    )
    Try {
        $body = @{
            grant_type = "client_credentials"
            client_id = $ApplicationId # Still client_id for the API call
            client_secret = $ClientSecret
            scope = "https://graph.microsoft.com/.default" # Request all default permissions
        }
        Write-Log -Message "Attempting to acquire access token for Tenant ID: $TenantId, Application ID: $ApplicationId..." -Level "INFO" # Changed log message
        $tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        
        $global:g_accessToken = $tokenResponse.access_token
        $global:g_headers = @{ Authorization = "Bearer $($global:g_accessToken)" } # Set global headers for subsequent API calls
        Write-Log -Message "Access token acquired successfully. Expires in $($tokenResponse.expires_in) seconds." -Level "INFO"
        return $true
    } Catch {
        Write-Log -Message "Failed to acquire access token: $($_.Exception.Message). Check Tenant ID, Application ID, and Client Secret." -Level "CRITICAL" # Changed log message
        Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $global:g_sourceFolderPath `
            -DestinationSite $global:g_destSiteSpecifier -DestinationPath $global:g_destinationFolderPath `
            -ItemType "Authentication" -Status "Failed" -Notes "Authentication failed: $($_.Exception.Message)"
        return $false
    }
}

# Retrieves SharePoint Site ID and the default Documents drive ID
Function Get-SiteAndDriveIDs {
    Param (
        [string]$SiteSpecifier, # e.g., "yourdomain.sharepoint.com:/sites/SiteName"
        [string]$SiteType # "Source" or "Destination"
    )
    Try {
        Write-Log -Message "Getting $($SiteType) site ID for $($SiteSpecifier)..." -Level "INFO"
        # Use Graph API to get the site by its relative URL specifier
        $siteUrl = "https://graph.microsoft.com/v1.0/sites/$SiteSpecifier"
        $site = Invoke-GraphRequest -Uri $siteUrl -Headers $global:g_headers -Method Get
        $siteID = $site.id
        Write-Log -Message "$($SiteType) site ID: $($siteID)" -Level "INFO"

        Write-Log -Message "Getting $($SiteType) site 'Documents' drive ID..." -Level "INFO"
        # Get all drives for the site and filter for the "Documents" library
        $driveUrl = "https://graph.microsoft.com/v1.0/sites/$siteID/drives"
        $drives = Invoke-GraphRequest -Uri $driveUrl -Headers $global:g_headers -Method Get
        $driveId = ($drives.value | Where-Object { $_.name -eq "Documents" }).id
        if (-not $driveId) { Throw "$($SiteType) 'Documents' drive not found for site '$SiteSpecifier'. Ensure the default document library exists." }
        Write-Log -Message "$($SiteType) Documents drive ID: $($driveId)" -Level "INFO"

        # Store IDs in global variables based on SiteType
        if ($SiteType -eq "Source") {
            $global:g_sourceSiteID = $siteID
            $global:g_sourceSitedriveId = $driveId
        } elseif ($SiteType -eq "Destination") {
            $global:g_destSiteID = $siteID
            $global:g_destSitedriveId = $driveId
        }
        return $true
    }
    Catch {
        Write-Log -Message "Failed to get $($SiteType) site or drive IDs: $($_.Exception.Message). Check site specifier and permissions." -Level "CRITICAL"
        Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $global:g_sourceFolderPath `
            -DestinationSite $global:g_destSiteSpecifier -DestinationPath $global:g_destinationFolderPath `
            -ItemType "$($SiteType) Setup" -Status "Failed" -Notes "$($_.Exception.Message)"
        return $false
    }
}

# Converts a SharePoint path (like "Documents/MyFolder") to a Graph API relative path ("MyFolder" or just "")
# And ensures consistency (removes leading/trailing slashes and normalizes).
Function Convert-SharePointPathToRelative {
    Param (
        [string]$Path
    )
    $normalizedPath = $Path.Trim().TrimStart('/').Replace('\', '/') # Normalise slashes and trim leading/trailing
    # If the path starts with "documents/" (case-insensitive), remove it for Graph API's 'root:/' path
    if ($normalizedPath.StartsWith("documents/", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $normalizedPath.Substring("documents/".Length)
    }
    # If the path is just "documents" or "", return empty string as it refers to the drive root itself
    if ($normalizedPath -eq "documents" -or [string]::IsNullOrEmpty($normalizedPath)) {
        return ""
    }
    return $normalizedPath
}

# Checks if a given path exceeds SharePoint Online's length limits
Function Test-PathLength {
    Param (
        [string]$Path,
        [int]$MaxLength = 400 # SharePoint Online recommended path segment length
    )
    if ($Path.Length -gt $MaxLength) {
        Write-Log -Message "WARNING: Path exceeds SharePoint Online suggested limit ($MaxLength characters): '$Path' (Length: $($Path.Length))" -Level "WARNING"
        return $false
    }
    return $true
}

# Determines if an item should be excluded based on global exclusion lists
Function Should-ExcludeItem {
    Param (
        [string]$ItemName,
        [bool]$IsFolder
    )
    if ($IsFolder) {
        if ($global:g_excludeFolderNames -contains $ItemName) {
            Write-Log -Message "Excluding folder '$ItemName' as per exclusion list." -Level "INFO"
            return $true
        }
    } else {
        $extension = [System.IO.Path]::GetExtension($ItemName)
        if (-not [string]::IsNullOrEmpty($extension)) {
            $extension = $extension.TrimStart('.') # Remove leading dot
            if ($global:g_excludeFileExtensions -contains $extension) {
                Write-Log -Message "Excluding file '$ItemName' (extension .$extension) as per exclusion list." -Level "INFO"
                return $true
            }
        }
    }
    return $false
}

# Updates the progress bar and status label on the UI form
Function Update-ProgressBar {
    Param (
        [string]$CurrentItemPath = ""
    )
    # Use global variables directly
    $ProgressBar = $global:g_progressBar
    $StatusLabel = $global:g_progressLabel

    if (-not $ProgressBar -or -not $StatusLabel) {
        Write-Log -Message "WARNING: Global UI controls (ProgressBar or StatusLabel) are null. Cannot update progress." -Level "WARNING" -OutputTo "Host"
        return # Exit if controls are not valid
    }

    if ($ProgressBar.InvokeRequired) {
        $ProgressBar.Invoke([action]{
            # Check globals inside invoke as well for safety
            if (-not $global:g_progressBar -or -not $global:g_progressLabel) { return }

            $progressValue = 0
            if ($global:g_totalItemsToProcess -gt 0) {
                 $progressValue = [int](([double]$global:g_itemsProcessedCount / $global:g_totalItemsToProcess) * 100)
            }
            if ($progressValue -gt 100) { $progressValue = 100 } # Cap at 100%
            $global:g_progressBar.Value = $progressValue
            $global:g_progressLabel.Text = "Processing: $CurrentItemPath ($global:g_itemsProcessedCount / $global:g_totalItemsToProcess)"
            [System.Windows.Forms.Application]::DoEvents()
        })
    } else {
        $progressValue = 0
        if ($global:g_totalItemsToProcess -gt 0) {
             $progressValue = [int](([double]$global:g_itemsProcessedCount / $global:g_totalItemsToProcess) * 100)
        }
        if ($progressValue -gt 100) { $progressValue = 100 }
        $global:g_progressBar.Value = $progressValue
        $global:g_progressLabel.Text = "Processing: $CurrentItemPath ($global:g_itemsProcessedCount / $global:g_totalItemsToProcess)"
        [System.Windows.Forms.Application]::DoEvents()
    }
}

# endregion

# region --- Core Copy Function (Recursive) ---

# This function recursively copies/scans items (folders and files) from source to destination
Function Copy-SharePointItem {
    Param (
        [string]$SourceDriveId,
        [string]$SourceItemId, # ID of the current folder/file item
        [string]$CurrentSourceRelativePath, # Path relative to the source site's Documents root (for logging/records)
        [string]$DestinationDriveId,
        [string]$CurrentDestinationRelativePath, # Path relative to the dest site's Documents root (for Graph API paths)
        [hashtable]$Headers
    )

    Write-Log -Message "Processing Source Path: '$CurrentSourceRelativePath'" -Level "VERBOSE"
    # Update UI progress with the current item being processed (uses global UI controls)
    Update-ProgressBar -CurrentItemPath $CurrentSourceRelativePath

    $itemName = ""
    $isFolder = $false
    $itemModifiedDate = $null # Initialize as null
    $itemCreatedDate = $null  # Initialize as null
    $itemSize = ""
    $sourceSha1Hash = ""
    $destinationPathForCurrentItem = ""
    $graphDestPath = ""

    Try {
        # Get details of the current item from the source
        $itemUrl = "https://graph.microsoft.com/v1.0/drives/$SourceDriveId/items/$SourceItemId"
        $item = Invoke-GraphRequest -Uri $itemUrl -Headers $Headers -Method Get

        $itemName = $item.name
        $isFolder = ($item.folder -ne $null) # Check if 'folder' facet exists
        
        # Explicitly cast date/time strings from Graph API to [DateTime] objects
        $itemModifiedDate = [DateTime]$item.lastModifiedDateTime
        $itemCreatedDate = [DateTime]$item.createdDateTime
        
        $itemSize = $item.size # Null for folders
        $sourceSha1Hash = $null
        if ($item.file -and $item.file.hashes -and $item.file.hashes.sha1Hash) {
            $sourceSha1Hash = $item.file.hashes.sha1Hash # Get SHA1 hash for files
        }
        
        # Construct full destination path for the current item
        $destinationPathForCurrentItem = Join-Path -Path $CurrentDestinationRelativePath -ChildPath $itemName # Use Join-Path
        $graphDestPath = Convert-SharePointPathToRelative -Path $destinationPathForCurrentItem

        # Check for path length issues BEFORE other processing or exclusion checks
        if ($CurrentSourceRelativePath.Length -gt 0 -and -not (Test-PathLength -Path $graphDestPath)) {
            Write-Log -Message "Skipping '$CurrentSourceRelativePath' due to excessive path length ($($graphDestPath.Length) chars)." -Level "WARNING"
            Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $CurrentSourceRelativePath `
                -DestinationSite $global:g_destSiteSpecifier -DestinationPath $graphDestPath `
                -ItemType (if ($isFolder) { "Folder" } else { "File" }) -Status "Skipped (Path Too Long)" -Notes "Path exceeds SharePoint Online limit."
            $global:g_processedPaths[$CurrentSourceRelativePath] = $true # Mark as processed to prevent re-processing
            $global:g_itemsProcessedCount++
            return # Exit this recursive call
        }

        # Check if this item has been processed in a previous run (for resume)
        if ($global:g_resumeOperation -and $global:g_processedPaths.ContainsKey($CurrentSourceRelativePath)) {
            Write-Log -Message "Skipping '$CurrentSourceRelativePath' as it was previously processed." -Level "INFO"
            Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $CurrentSourceRelativePath `
                -DestinationSite $global:g_destSiteSpecifier -DestinationPath $graphDestPath `
                -ItemType (if ($isFolder) { "Folder" } else { "File" }) -Status "Skipped (Processed)" -Notes "Item previously marked as completed/skipped in resume file."
            $global:g_itemsProcessedCount++
            return # Exit this recursive call
        }

        # Check for exclusions (file extension or folder name)
        if (Should-ExcludeItem -ItemName $itemName -IsFolder $isFolder) {
            Write-Log -Message "Skipping '$CurrentSourceRelativePath' due to exclusion rules." -Level "INFO"
            Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $CurrentSourceRelativePath `
                -DestinationSite $global:g_destSiteSpecifier -DestinationPath $graphDestPath `
                -ItemType (if ($isFolder) { "Folder" } else { "File" }) -Status "Skipped (Excluded)" -Notes "Item name or extension in exclusion list."
            $global:g_processedPaths[$CurrentSourceRelativePath] = $true # Mark as processed to prevent re-processing
            $global:g_itemsProcessedCount++
            return # Exit this recursive call
        }

        # --- Handle Folders ---
        if ($isFolder) {
            Write-Log -Message "Handling folder: '$itemName' in '$CurrentSourceRelativePath'" -Level "INFO"
            
            if ($global:g_preMigrationScan) {
                # In scan mode, just log that it would be processed
                Write-Log -Message "[SCAN MODE] Would process folder: '$CurrentSourceRelativePath'." -Level "INFO"
                Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $CurrentSourceRelativePath `
                    -DestinationSite $global:g_destSiteSpecifier -DestinationPath $graphDestPath `
                    -ItemType "Folder" -Status "Scan Only" -Notes "Folder identified for potential copy."
                $global:g_processedPaths[$CurrentSourceRelativePath] = $true
            } else {
                # In copy mode, ensure destination folder exists
                $parentFolderGraphPathForCreation = Convert-SharePointPathToRelative -Path $CurrentDestinationRelativePath
                
                # Construct Graph API check URI for existing folder.
                # If $graphDestPath is empty (e.g., trying to create root folder, not typical), use root itself.
                $checkFolderUriSegment = if ([string]::IsNullOrEmpty($graphDestPath)) { "" } else { ":/$graphDestPath" }
                $checkFolderUri = "https://graph.microsoft.com/v1.0/drives/$DestinationDriveId/root$checkFolderUriSegment"

                $folderExists = $false
                Try {
                    # Attempt to get the folder; if successful, it exists
                    Invoke-GraphRequest -Uri $checkFolderUri -Headers $Headers -Method Get | Out-Null
                    $folderExists = $true
                    Write-Log -Message "Destination folder '$graphDestPath' already exists." -Level "INFO"
                } Catch {
                    # A 404 (Not Found) means the folder doesn't exist, which is expected before creation
                    if ($_.Exception.Response.StatusCode -eq 404) {
                        Write-Log -Message "Destination folder '$graphDestPath' does not exist. Will create." -Level "INFO"
                    } else {
                        Write-Log -Message "Error checking destination folder '$graphDestPath': $($_.Exception.Message)" -Level "WARNING"
                        Throw $_.Exception # Re-throw other unexpected errors
                    }
                }

                if (-not $folderExists) {
                    Write-Log -Message "Creating destination folder: '$graphDestPath'." -Level "INFO"
                    # Construct the Graph API URI to create a folder under its parent path
                    # FIX: Use curly braces to delimit the variable name before the colon
                    $createFolderUriSegment = if ([string]::IsNullOrEmpty($parentFolderGraphPathForCreation)) { "" } else { ":/$parentFolderGraphPathForCreation" }
                    $createFolderUri = "https://graph.microsoft.com/v1.0/drives/$DestinationDriveId/root${createFolderUriSegment}:/children" # FIXED LINE
                    
                    $newFolderBody = @{
                        name = $itemName
                        folder = @{} # Empty folder facet
                        fileSystemInfo = @{ # Preserve created/modified times
                            createdDateTime = $itemCreatedDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                            lastModifiedDateTime = $itemModifiedDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                        }
                    } | ConvertTo-Json

                    Invoke-GraphRequest -Uri $createFolderUri -Headers $Headers -Method Post -Body $newFolderBody -ContentType "application/json" | Out-Null
                    Write-Log -Message "Successfully created destination folder '$graphDestPath'." -Level "INFO"
                }
                
                # Record the folder operation status
                Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $CurrentSourceRelativePath `
                    -DestinationSite $global:g_destSiteSpecifier -DestinationPath $graphDestPath `
                    -ItemType "Folder" -Status "Completed" -Notes "Folder created/verified" `
                    -ItemModifiedDate $itemModifiedDate # This is now a DateTime object
                $global:g_processedPaths[$CurrentSourceRelativePath] = $true
            }

            $global:g_itemsProcessedCount++ # Increment count for the folder itself
            Update-ProgressBar -CurrentItemPath $CurrentSourceRelativePath # Uses global UI controls

            # Enumerate children of the current source folder and recurse
            $childrenUrl = "https://graph.microsoft.com/v1.0/drives/$SourceDriveId/items/$SourceItemId/children?`$top=999" # Use $top for pagination
            $childrenResponse = Invoke-GraphRequest -Uri $childrenUrl -Headers $Headers -Method Get
            
            # Handle pagination to get all children
            while ($true) {
                # Atomically add newly discovered items to total count to update progress bar more accurately
                $global:g_totalItemsToProcess += $childrenResponse.value.Count 
                
                foreach ($child in $childrenResponse.value) {
                    $childSourceRelativePath = Join-Path -Path $CurrentSourceRelativePath -ChildPath $child.name # Use Join-Path
                    # The destination relative path for children is the path of the *just processed* parent folder
                    $childDestinationRelativePath = $destinationPathForCurrentItem # This is the full path of the current folder
                    
                    # Recursive call for each child item
                    Copy-SharePointItem -SourceDriveId $SourceDriveId `
                        -SourceItemId $child.id `
                        -CurrentSourceRelativePath $childSourceRelativePath `
                        -DestinationDriveId $DestinationDriveId `
                        -CurrentDestinationRelativePath $childDestinationRelativePath `
                        -Headers $Headers
                }
                
                # Check for next page of results
                if ($childrenResponse.'@odata.nextLink') {
                    $childrenResponse = Invoke-GraphRequest -Uri $childrenResponse.'@odata.nextLink' -Headers $Headers -Method Get
                } else {
                    break # No more pages
                }
            }

        } else { # It's a file
            Write-Log -Message "Handling file: '$itemName' ($($item.size) bytes) in '$CurrentSourceRelativePath'" -Level "INFO"
            
            # These are already [DateTime] objects from the initial assignment above
            $sourceFileModified = $itemModifiedDate
            $sourceFileCreated = $itemCreatedDate
            $sourceFileSize = $item.size

            # Construct the full destination path for the file
            $destFileGraphPath = Convert-SharePointPathToRelative -Path $destinationPathForCurrentItem
            # If the destination file path is empty (e.g., root of the drive), Graph API root:/ is used
            $destFileUriSegment = if ([string]::IsNullOrEmpty($destFileGraphPath)) { "" } else { ":/$destFileGraphPath" }
            $destFileUrl = "https://graph.microsoft.com/v1.0/drives/$DestinationDriveId/root$destFileUriSegment"
            
            $destFileExists = $false
            $destFileModified = $null
            $destFileSize = $null
            $destSha1Hash = $null

            # Check if destination file exists
            Try {
                $existingDestItem = Invoke-GraphRequest -Uri $destFileUrl -Headers $Headers -Method Get
                $destFileExists = $true
                $destFileModified = [DateTime]$existingDestItem.lastModifiedDateTime # Cast here as well
                $destFileSize = $existingDestItem.size
                if ($existingDestItem.file -and $existingDestItem.file.hashes -and $existingDestItem.file.hashes.sha1Hash) {
                    $destSha1Hash = $existingDestItem.file.hashes.sha1Hash
                }
                Write-Log -Message "Destination file '$destFileGraphPath' exists. Size: $destFileSize, Modified: $destFileModified, Hash: $destSha1Hash." -Level "INFO"
            } Catch {
                # If 404, file doesn't exist, which is fine
                if ($_.Exception.Response.StatusCode -eq 404) {
                    Write-Log -Message "Destination file '$destFileGraphPath' does not exist. Will copy." -Level "INFO"
                } else {
                    Write-Log -Message "Error checking destination file '$destFileGraphPath': $($_.Exception.Message)" -Level "WARNING"
                }
            }

            $copyAction = "Copy" # Default action

            if ($destFileExists) {
                # Decide action based on file properties
                if ($sourceFileSize -eq $destFileSize -and $sourceFileModified -le $destFileModified) {
                    $copyAction = "Skip" # Destination is newer or identical in size/date
                    Write-Log -Message "File '$itemName': Destination is newer or identical. Skipping." -Level "INFO"
                    
                    # Determine hash match status for record
                    $hashMatchStatus = "N/A"
                    if ($sourceSha1Hash -and $destSha1Hash) {
                        if ($sourceSha1Hash -eq $destSha1Hash) {
                            $hashMatchStatus = "True"
                        } else {
                            $hashMatchStatus = "False"
                        }
                    } else {
                        $hashMatchStatus = "Partial (No Hash)"
                    }
                    Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $CurrentSourceRelativePath `
                        -DestinationSite $global:g_destSiteSpecifier -DestinationPath $destinationPathForCurrentItem `
                        -ItemType "File" -Status "Skipped (Newer/Same)" -Notes "File already exists and is newer or identical." `
                        -FileSize $sourceFileSize -ItemModifiedDate $sourceFileModified `
                        -SourceHash $sourceSha1Hash -DestHash $destSha1Hash -HashMatch $hashMatchStatus
                } elseif ($sourceFileSize -ne $destFileSize -or $sourceFileModified -gt $destFileModified) {
                    $copyAction = "Overwrite" # Source is newer or different
                    Write-Log -Message "File '$itemName': Source is newer or different. Overwriting." -Level "INFO"
                }
            }

            if ($global:g_preMigrationScan) {
                 # In scan mode, just log what would happen
                 Write-Log -Message "[SCAN MODE] Would $copyAction file: '$CurrentSourceRelativePath'." -Level "INFO"
                 Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $CurrentSourceRelativePath `
                    -DestinationSite $global:g_destSiteSpecifier -DestinationPath $destinationPathForCurrentItem `
                    -ItemType "File" -Status "Scan Only ($copyAction)" -Notes "File identified for potential $copyAction." `
                    -FileSize $sourceFileSize -ItemModifiedDate $sourceFileModified `
                    -SourceHash $sourceSha1Hash -DestHash $destSha1Hash -HashMatch "N/A (Scan)"
                 $global:g_processedPaths[$CurrentSourceRelativePath] = $true
            } elseif ($copyAction -ne "Skip") {
                # Actual file copy, using semaphore to limit concurrency
                $global:g_semaphore.Wait() # Acquire a slot in the semaphore
                Try {
                    Write-Log -Message "Initiating server-side copy for file '$itemName' to '$destinationPathForCurrentItem'." -Level "INFO"
                    
                    # Get the parent folder's relative path for the destination
                    $parentFolderFullPath = ($destinationPathForCurrentItem | Split-Path -Parent)
                    $parentFolderRelativePath = Convert-SharePointPathToRelative -Path $parentFolderFullPath
                    
                    $copyFileBody = @{
                        parentReference = @{
                            driveId = $DestinationDriveId
                            # FIX: Path should be relative to the drive root, starting with /
                            path = "/$parentFolderRelativePath" 
                        }
                        name = $itemName # New name of the file
                        fileSystemInfo = @{ # Preserve file system metadata
                            createdDateTime = $sourceFileCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                            lastModifiedDateTime = $sourceFileModified.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                        }
                    }

                    if ($global:g_copyAllVersions) {
                         $copyFileBody.Add("includeAllVersionHistory", $true) # Attempt to copy versions
                         Write-Log -Message "Attempting to copy all versions for '$itemName'." -Level "INFO"
                    }
                    $copyFileBodyJson = $copyFileBody | ConvertTo-Json -Depth 3

                    # Initiate the copy operation; @microsoft.graph.conflictBehavior=replace handles overwriting
                    $fileCopyUri = "$itemUrl/copy?@microsoft.graph.conflictBehavior=replace"
                    $fileCopyResponse = Invoke-GraphRequest -Uri $fileCopyUri -Method Post -Headers $Headers -Body $copyFileBodyJson -ContentType "application/json"

                    # Monitor the async copy operation using the Location header
                    $monitorFileUrl = $fileCopyResponse.Location
                    if ($monitorFileUrl) {
                        Write-Log -Message "File copy initiated for '$itemName'. Monitoring URL: $($monitorFileUrl)" -Level "INFO"
                        $fileStatus = ""
                        $fileAttempt = 0
                        $fileMaxAttempts = 60 # Max attempts for status check (e.g., 60 * 5s = 5 minutes timeout)

                        # Loop to poll the monitoring URL until completed or failed
                        While ($fileStatus -ne "completed" -and $fileStatus -ne "failed" -and $fileAttempt -lt $fileMaxAttempts) {
                            Start-Sleep -Seconds 5 # Wait before polling again
                            $monitorFileResponse = Invoke-GraphRequest -Uri $monitorFileUrl -Headers $Headers -Method Get -MaxRetries 5 -InitialDelaySeconds 1 -ErrorAction SilentlyContinue # Small retry for monitoring
                            if ($monitorFileResponse) {
                                $fileStatus = $monitorFileResponse.status
                                $fileStatusMessage = $monitorFileResponse.statusMessage
                                Write-Log -Message "File '$itemName' current status: $($fileStatus) - $($fileStatusMessage)" -Level "DEBUG"
                            } else {
                                Write-Log -Message "Could not retrieve status for file '$itemName' via monitoring URL (API call failed)." -Level "WARNING"
                                Break # Exit loop if monitoring URL itself fails
                            }
                            $fileAttempt++
                        }

                        If ($fileStatus -eq "completed") {
                            Write-Log -Message "File '$itemName' copied successfully. Validating hash..." -Level "INFO"
                            # ----- Hash Validation after successful copy -----
                            $hashMatchStatus = "N/A"
                            $finalDestSha1Hash = $null
                            Try {
                                # Get the newly copied item's details to retrieve its hash
                                $copiedDestItem = Invoke-GraphRequest -Uri $destFileUrl -Headers $Headers -Method Get
                                if ($copiedDestItem.file -and $copiedDestItem.file.hashes -and $copiedDestItem.file.hashes.sha1Hash) {
                                    $finalDestSha1Hash = $copiedDestItem.file.hashes.sha1Hash
                                }

                                if ($sourceSha1Hash -and $finalDestSha1Hash) {
                                    if ($sourceSha1Hash -eq $finalDestSha1Hash) { # Compare source and destination hashes
                                        $hashMatchStatus = "True"
                                        Write-Log -Message "SHA1 Hash match for '$itemName': Source ($sourceSha1Hash) == Destination ($finalDestSha1Hash)." -Level "INFO"
                                    } else {
                                        $hashMatchStatus = "False"
                                        Write-Log -Message "SHA1 Hash MISMATCH for '$itemName': Source ($sourceSha1Hash) != Destination ($finalDestSha1Hash)." -Level "ERROR"
                                    }
                                } else {
                                    Write-Log -Message "Could not retrieve SHA1 hash for source or destination file '$itemName' for validation." -Level "WARNING"
                                    $hashMatchStatus = "Partial (No Hash)"
                                }
                            } Catch {
                                Write-Log -Message "Error during hash validation for '$itemName': $($_.Exception.Message)" -Level "ERROR"
                                $hashMatchStatus = "Failed (Error)"
                            }
                            # --- End Hash Validation ---

                            Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $CurrentSourceRelativePath `
                                -DestinationSite $global:g_destSiteSpecifier -DestinationPath $destinationPathForCurrentItem `
                                -ItemType "File" -Status "Completed" -Notes "File copied." `
                                -FileSize $sourceFileSize -ItemModifiedDate $sourceFileModified `
                                -SourceHash $sourceSha1Hash -DestHash $finalDestSha1Hash -HashMatch $hashMatchStatus
                            $global:g_processedPaths[$CurrentSourceRelativePath] = $true
                        } ElseIf ($fileStatus -eq "failed") {
                            Write-Log -Message "File '$itemName' copy failed: $($fileStatusMessage)" -Level "ERROR"
                            Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $CurrentSourceRelativePath `
                                -DestinationSite $global:g_destSiteSpecifier -DestinationPath $destinationPathForCurrentItem `
                                -ItemType "File" -Status "Failed" -Notes "Copy failed: $($fileStatusMessage)" `
                                -FileSize $sourceFileSize -ItemModifiedDate $sourceFileModified `
                                -SourceHash $sourceSha1Hash -DestHash $destSha1Hash -HashMatch "N/A (Failed)"
                        } Else {
                            Write-Log -Message "File '$itemName' copy timed out or status unknown after monitoring." -Level "WARNING"
                             Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $CurrentSourceRelativePath `
                                -DestinationSite $global:g_destSiteSpecifier -DestinationPath $destinationPathForCurrentItem `
                                -ItemType "File" -Status "Timed Out (Unknown)" -Notes "Copy status unknown after monitoring timeout." `
                                -FileSize $sourceFileSize -ItemModifiedDate $sourceFileModified `
                                -SourceHash $sourceSha1Hash -DestHash $destSha1Hash -HashMatch "N/A (Timeout)"
                        }
                    } else {
                         Write-Log -Message "Copy initiated for '$itemName', but no monitoring URL was returned. Cannot track progress definitively." -Level "WARNING"
                         Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $CurrentSourceRelativePath `
                            -DestinationSite $global:g_destSiteSpecifier -DestinationPath $destinationPathForCurrentItem `
                            -ItemType "File" -Status "Initiated (No Monitor URL)" -Notes "File copy triggered, but no URL to track status." `
                            -FileSize $sourceFileSize -ItemModifiedDate $sourceFileModified `
                            -SourceHash $sourceSha1Hash -DestHash $destSha1Hash -HashMatch "N/A (No Monitor)"
                        $global:g_processedPaths[$CurrentSourceRelativePath] = $true
                    }
                } Catch {
                    Write-Log -Message "Error during concurrent file operation for '$CurrentSourceRelativePath': $($_.Exception.Message)" -Level "ERROR"
                    Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $CurrentSourceRelativePath `
                        -DestinationSite $global:g_destSiteSpecifier -DestinationPath $destinationPathForCurrentItem `
                        -ItemType "File" -Status "Failed - Concurrent Copy Error" -Notes "$($_.Exception.Message)" `
                        -FileSize $sourceFileSize -ItemModifiedDate $sourceFileModified `
                        -SourceHash $sourceSha1Hash -DestHash $destSha1Hash -HashMatch "N/A (Error)"
                } finally {
                    $global:g_semaphore.Release() # Release the semaphore slot
                }
            }
            $global:g_itemsProcessedCount++ # Increment count for the file itself
            Update-ProgressBar -CurrentItemPath $CurrentSourceRelativePath # Uses global UI controls
        }

    } Catch {
        # Catch any errors during the processing of a specific item
        Write-Log -Message "Error processing item '$CurrentSourceRelativePath': $($_.Exception.Message)" -Level "ERROR"
        # Determine ItemType for logging, falling back if $isFolder isn't set due to early error
        $logItemType = "Unknown"
        # Using a simple if statement for PowerShell 5.1 compatibility
        if ($isFolder -ne $null) {
            if ($isFolder) { $logItemType = "Folder" } else { $logItemType = "File" }
        }
        Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $CurrentSourceRelativePath `
            -DestinationSite $global:g_destSiteSpecifier -DestinationPath $destinationPathForCurrentItem `
            -ItemType $logItemType -Status "Failed - Processing Error" -Notes "$($_.Exception.Message)"
        $global:g_itemsProcessedCount++ # Increment even on error to ensure progress bar moves
        Update-ProgressBar -CurrentItemPath $CurrentSourceRelativePath # Uses global UI controls
    }
}

# endregion

# region --- Main Execution Flow ---

# --- Show UI and get configuration from the user ---
# Call Show-MigrationConfigUI without arguments to use its internal default placeholders
# The global variables ($global:g_tenantId etc.) will be updated by the UI when the user clicks OK.
$dialogResult = Show-MigrationConfigUI 

# If the user clicked OK on the configuration form, proceed with migration/scan
if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
    # $global:g_clientSecret is now directly populated by the UI.
    # $global:g_applicationId is now populated by the UI.

    # Initialize semaphore after maxConcurrentCopies is known from UI input
    $global:g_semaphore = [System.Threading.SemaphoreSlim]::new($global:g_maxConcurrentCopies)

    Write-Log -Message "Starting SharePoint content copy operation." -Level "CRITICAL"

    # Set up logging and check for resume state
    Initialize-LogAndResume

    # Create a new form for progress display
    $global:g_progressForm = New-Object System.Windows.Forms.Form
    $global:g_progressForm.Text = "Migration Progress"
    $global:g_progressForm.Size = New-Object System.Drawing.Size(500, 150)
    $global:g_progressForm.StartPosition = "CenterScreen"
    $global:g_progressForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
    $global:g_progressForm.MaximizeBox = $false
    $global:g_progressForm.MinimizeBox = $false

    $global:g_progressLabel = New-Object System.Windows.Forms.Label
    $global:g_progressLabel.Location = New-Object System.Drawing.Point(20, 20)
    $global:g_progressLabel.Size = New-Object System.Drawing.Size(450, 20)
    $global:g_progressLabel.Text = "Initializing..."
    $global:g_progressForm.Controls.Add($global:g_progressLabel)

    $global:g_progressBar = New-Object System.Windows.Forms.ProgressBar
    $global:g_progressBar.Location = New-Object System.Drawing.Point(20, 50)
    $global:g_progressBar.Size = New-Object System.Drawing.Size(450, 25)
    $global:g_progressBar.Minimum = 0
    $global:g_progressBar.Maximum = 100
    $global:g_progressBar.Value = 0
    $global:g_progressForm.Controls.Add($global:g_progressBar)

    # Show the progress form (non-modal, so script can continue execution)
    $global:g_progressForm.Show() | Out-Null
    [System.Windows.Forms.Application]::DoEvents() # Process UI events immediately to show the form

    # 1. Authentication: Acquire access token for Graph API
    if (-not (Get-GraphAccessToken -TenantId $global:g_tenantId -ApplicationId $global:g_applicationId -ClientSecret $global:g_clientSecret)) { # Changed parameter name
        Write-Log -Message "Script cannot proceed without a valid access token. Please check your Azure AD app registration and credentials. Exiting." -Level "CRITICAL"
        if ($global:g_progressForm) { $global:g_progressForm.Close(); $global:g_progressForm.Dispose() }
        Exit 1
    }

    # 2. Get Site and Drive IDs for both source and destination
    if (-not (Get-SiteAndDriveIDs -SiteSpecifier $global:g_sourceSiteSpecifier -SiteType "Source")) {
        Write-Log -Message "Script cannot proceed without valid source site/drive IDs. Exiting." -Level "CRITICAL"
        if ($global:g_progressForm) { $global:g_progressForm.Close(); $global:g_progressForm.Dispose() }
        Exit 1
    }
    if (-not (Get-SiteAndDriveIDs -SiteSpecifier $global:g_destSiteSpecifier -SiteType "Destination")) {
        Write-Log -Message "Script cannot proceed without valid destination site/drive IDs. Exiting." -Level "CRITICAL"
        if ($global:g_progressForm) { $global:g_progressForm.Close(); $global:g_progressForm.Dispose() }
        Exit 1
    }

    # 3. Handle Pre-Migration Scan Mode
    if ($global:g_preMigrationScan) {
        Write-Log -Message "--- RUNNING IN PRE-MIGRATION SCAN MODE ---" -Level "CRITICAL"
        Write-Log -Message "No files or folders will be copied. A detailed report will be generated at '$global:g_scanReportPath'." -Level "CRITICAL"
        
        # Ensure the scan report file is clean for this run
        if (Test-Path $global:g_scanReportPath) { Remove-Item $global:g_scanReportPath -Force }
        Add-Content -Path $global:g_scanReportPath -Value "`"Timestamp`",`"Source Site`",`"Source Path`",`"Destination Site`",`"Destination Path`",`"Item Type`",`"Status`",`"Notes`",`"File Size (bytes)`",`"Item Last Modified Date`",`"Source SHA1 Hash`",`"Destination SHA1 Hash`",`"Hash Match`""

        # Temporarily redirect Write-CopyRecord to the scan report file
        # This redefines the function in the current scope for the duration of the scan
        Remove-Item Function:\Write-CopyRecord -ErrorAction SilentlyContinue # Ensure no previous definition interferes
        Function Write-CopyRecord {
            Param (
                [string]$SourceSite, [string]$SourcePath, [string]$DestinationSite, [string]$DestinationPath,
                [string]$ItemType, [string]$Status, [string]$Notes, [string]$FileSize = "", [string]$ItemModifiedDate = "",
                [string]$SourceHash = "", [string]$DestHash = "", [string]$HashMatch = ""
            )
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $recordEntry = "`"$timestamp`",`"$SourceSite`",`"$SourcePath`",`"$DestinationSite`",`"$DestinationPath`",`"$ItemType`",`"$Status`",`"$Notes`",`"$FileSize`",`"$ItemModifiedDate`",`"$SourceHash`",`"$DestHash`",`"$HashMatch`""
            Add-Content -Path $global:g_scanReportPath -Value $recordEntry
        }
    }

    # 4. Start the Recursive Copy/Scan operation
    Try {
        $global:g_progressLabel.Text = "Getting initial source folder details..."
        [System.Windows.Forms.Application]::DoEvents()

        # Resolve the source root folder's Graph API path and ID
        # Example: if source is 'Documents/MySourceFolder', this gets the ID for 'MySourceFolder' within 'Documents'
        $sourceRootFolderGraphPath = Convert-SharePointPathToRelative -Path $global:g_sourceFolderPath
        $sourceRootFolderUrl = "https://graph.microsoft.com/v1.0/drives/$global:g_sourceSitedriveId/root:/$sourceRootFolderGraphPath"
        $sourceRootFolderItem = Invoke-GraphRequest -Uri $sourceRootFolderUrl -Headers $global:g_headers -Method Get
        $sourceRootFolderItemId = $sourceRootFolderItem.id
        Write-Log -Message "Resolved source folder ID for '$global:g_sourceFolderPath': $sourceRootFolderItemId" -Level "INFO"
        
        # Convert destination folder path for Graph API for the *parent* of the incoming items
        # Example: if dest is 'Documents/MyDestinationFolder', then files/folders from 'MySourceFolder'
        # should be copied into 'MyDestinationFolder'.
        # This is the path to the *target parent folder* where items will be copied *into*.
        $initialDestinationRelativePathGraph = Convert-SharePointPathToRelative -Path $global:g_destinationFolderPath
        
        Write-Log -Message "Starting recursive copy/scan from contents of '$global:g_sourceFolderPath' to '$global:g_destinationFolderPath'." -Level "INFO"

        # Initialize total items. The total count will be dynamically updated as folders are traversed.
        $global:g_totalItemsToProcess = 0 # Start at 0, will increment when children are discovered
        $global:g_itemsProcessedCount = 0

        # Now, enumerate the CHILDREN of the source root folder and call Copy-SharePointItem for each child.
        # This way, the children will be copied directly into the specified destination folder.
        $childrenUrl = "https://graph.microsoft.com/v1.0/drives/$global:g_sourceSitedriveId/items/$sourceRootFolderItemId/children?`$top=999"
        $childrenResponse = Invoke-GraphRequest -Uri $childrenUrl -Headers $global:g_headers -Method Get

        # Handle pagination for initial children
        while ($true) {
            $global:g_totalItemsToProcess += $childrenResponse.value.Count 

            foreach ($child in $childrenResponse.value) {
                # Calculate the full source path of the child (e.g., Documents/Source/Level1)
                $childSourceRelativePath = Join-Path -Path $global:g_sourceFolderPath -ChildPath $child.name
                
                # The destination path for these top-level children is directly under the user-specified destination folder.
                # So, CurrentDestinationRelativePath for these children is the *user-provided destination folder path*.
                # Copy-SharePointItem will then correctly create 'Documents/Destination/childName'
                Copy-SharePointItem -SourceDriveId $global:g_sourceSitedriveId `
                    -SourceItemId $child.id `
                    -CurrentSourceRelativePath $childSourceRelativePath `
                    -DestinationDriveId $global:g_destSitedriveId `
                    -CurrentDestinationRelativePath $global:g_destinationFolderPath `
                    -Headers $global:g_headers # Ensure no trailing space after backtick here
            }
            
            if ($childrenResponse.'@odata.nextLink') {
                $childrenResponse = Invoke-GraphRequest -Uri $childrenResponse.'@odata.nextLink' -Headers $global:g_headers -Method Get
            } else {
                break # No more pages
            }
        }
        
        # Final messages based on operation type
        if ($global:g_preMigrationScan) {
            Write-Log -Message "--- PRE-MIGRATION SCAN MODE COMPLETED. Report generated at '$global:g_scanReportPath' ---" -Level "CRITICAL"
            $global:g_progressLabel.Text = "Scan Completed! Report at $($global:g_scanReportPath)"
        } else {
            Write-Log -Message "SharePoint content copy operation completed." -Level "CRITICAL"
            $global:g_progressLabel.Text = "Migration Completed!"
        }
        $global:g_progressBar.Value = 100 # Ensure progress bar shows 100% at the end

    } Catch {
        # Catch any critical errors that occur during the main execution loop
        Write-Log -Message "An unhandled error occurred during the main copy execution: $($_.Exception.Message)" -Level "CRITICAL"
        Write-CopyRecord -SourceSite $global:g_sourceSiteSpecifier -SourcePath $global:g_sourceFolderPath `
            -DestinationSite $global:g_destSiteSpecifier -DestinationPath $global:g_destinationFolderPath `
            -ItemType "Overall" -Status "Failed - Overall Execution" -Notes "$($_.Exception.Message)"
        $global:g_progressLabel.Text = "Migration Failed: $($_.Exception.Message)"
        $global:g_progressBar.Value = 0 # Reset or show error state on failure
    } finally {
        # Ensure all semaphore slots are released, even if an error occurs, to prevent deadlocks
        while ($global:g_semaphore.CurrentCount -lt $global:g_maxConcurrentCopies) {
            $global:g_semaphore.Release()
        }
        # Give the user a moment to see the final message on the progress form
        Start-Sleep -Seconds 5
        # Close and dispose global progress form
        if ($global:g_progressForm) {
            $global:g_progressForm.Close()
            $global:g_progressForm.Dispose()
        }
    }

    Write-Log -Message "Script execution finished." -Level "CRITICAL"

} else {
    Write-Host "User cancelled the operation from the configuration window. Exiting script." -ForegroundColor Yellow
}

# Dispose of the main configuration form if it's still open (should be closed by now, but good practice)
if ($form) { $form.Dispose() }
