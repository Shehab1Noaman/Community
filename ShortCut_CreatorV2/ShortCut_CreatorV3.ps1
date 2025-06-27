# Intune Win32 Shortcut Packaging Script - Enhanced Single GUI Version (Boolean Fix)

#region Add Required Assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
#endregion

# Ensure the script is running in the correct directory
Set-Location -Path $PSScriptRoot

#region Logger Function
function Write-Log {
    param (
        [string]$Message,
        [string]$LogFile
    )
    $TimeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $LogMessage = "$TimeStamp - $Message"

    # Write log to file
    try {
        $LogMessage | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }
    catch {
        # Fallback if logging to file fails (e.g., permissions)
        Write-Host "WARNING: Could not write to log file $LogFile. Message: $($_.Exception.Message)"
    }
}
#endregion

#region GUI Helper Functions

# Function to display a GUI popup for file selection
function Get-FileBrowserInput {
    param (
        [string]$Title,
        [string]$Filter = "All Files (*.*)|*.*",
        [string]$InitialDirectory = (Get-Location).Path
    )
    Write-Log -Message "Get-FileBrowserInput called. Title: '$Title', Filter: '$Filter', InitialDirectory: '$InitialDirectory'" -LogFile $Script:LogFile

    try {
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.Title = $Title
        $OpenFileDialog.Filter = $Filter
        $OpenFileDialog.InitialDirectory = $InitialDirectory
        $OpenFileDialog.RestoreDirectory = $true
        $OpenFileDialog.CheckFileExists = $true
        $OpenFileDialog.CheckPathExists = $true

        $dialogResult = $OpenFileDialog.ShowDialog()
        Write-Log -Message "File dialog result: '$dialogResult'" -LogFile $Script:LogFile

        if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
            Write-Log -Message "Selected file: '$($OpenFileDialog.FileName)'" -LogFile $Script:LogFile
            return $OpenFileDialog.FileName
        } else {
            Write-Log -Message "File selection cancelled." -LogFile $Script:LogFile
            return $null # User cancelled
        }
    }
    catch {
        $errorMessage = "Error in Get-FileBrowserInput: $($_.Exception.Message)"
        Write-Log -Message $errorMessage -LogFile $Script:LogFile
        [System.Windows.Forms.MessageBox]::Show($errorMessage, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return $null
    }
}

# Function to display a GUI popup for folder selection
function Get-FolderBrowserInput {
    param (
        [string]$Title,
        [string]$InitialDirectory = (Get-Location).Path
    )
    Write-Log -Message "Get-FolderBrowserInput called. Title: '$Title', InitialDirectory: '$InitialDirectory'" -LogFile $Script:LogFile

    try {
        $FolderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowserDialog.Description = $Title
        $FolderBrowserDialog.SelectedPath = $InitialDirectory
        $FolderBrowserDialog.ShowNewFolderButton = $true

        $dialogResult = $FolderBrowserDialog.ShowDialog()
        Write-Log -Message "Folder dialog result: '$dialogResult'" -LogFile $Script:LogFile

        if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
            Write-Log -Message "Selected folder: '$($FolderBrowserDialog.SelectedPath)'" -LogFile $Script:LogFile
            return $FolderBrowserDialog.SelectedPath
        } else {
            Write-Log -Message "Folder selection cancelled." -LogFile $Script:LogFile
            return $null # User cancelled
        }
    }
    catch {
        $errorMessage = "Error in Get-FolderBrowserInput: $($_.Exception.Message)"
        Write-Log -Message $errorMessage -LogFile $Script:LogFile
        [System.Windows.Forms.MessageBox]::Show($errorMessage, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return $null
    }
}

# Define the function to display the error message with an exit button
function Show-ErrorAndExit {
    param (
        [string]$Message,
        [string]$LogMessage = "",
        [string]$LogFile = ""
    )

    # Display a GUI message box with an Exit button
    [System.Windows.Forms.MessageBox]::Show(
        $Message,
        "Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    if($LogFile -ne "" -and $LogMessage -ne ""){
        # Log the error message to the log file
        Write-Log -Message $LogMessage -LogFile $LogFile
    }
    exit 1
}

# Check existing IntuneWinAppUtil file and confirm deletion
function DeleteFileWithConfirmation {
    param (
        [string]$FilePath,
        [string]$LogFile,
        [string]$FileNameForPrompt
    )

    Write-Log -Message "DeleteFileWithConfirmation called for '$FilePath'." -LogFile $LogFile
    # Show a Yes/No message box asking if the user wants to delete the file
    $result = [System.Windows.Forms.MessageBox]::Show("The $FileNameForPrompt file already exists in the destination folder. Do you want to delete it: $FilePath?",
                                                       "Delete File Confirmation",
                                                       [System.Windows.Forms.MessageBoxButtons]::YesNo,
                                                       [System.Windows.Forms.MessageBoxIcon]::Question)

    Write-Log -Message "Deletion confirmation dialog result: '$result'." -LogFile $LogFile
    # Check the result of the message box (Yes or No)
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        # If Yes, delete the file
        try {
            Remove-Item $FilePath -Force -ErrorAction Stop
            Write-Log -Message "File '$FilePath' deleted successfully." -LogFile $LogFile
            return $true
        }
        catch {
            $errorMessage = "Failed to delete file '$FilePath'. Error: $($_.Exception.Message)"
            Show-ErrorAndExit -Message $errorMessage -LogMessage $errorMessage -LogFile $LogFile
            return $false
        }
    } else {
        # If No, exit the script
        Show-ErrorAndExit -Message 'The process has been canceled. Please rerun the script and choose another output path or allow deletion.'`
                          -LogMessage 'File deletion canceled by user. Exiting script.' -LogFile $LogFile
        return $false
    }
}

# Function to show an indeterminate progress window
function Show-ProgressWindow {
    param (
        [string]$Title = "Processing...",
        [string]$Message = "Please wait while the operation completes."
    )

    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = $Title
    $Form.Size = New-Object System.Drawing.Size(400, 150)
    $Form.StartPosition = 'CenterScreen'
    $Form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $Form.MinimizeBox = $false
    $Form.MaximizeBox = $false
    $Form.ControlBox = $false
    $Form.TopMost = $true

    $Label = New-Object System.Windows.Forms.Label
    $Label.Text = $Message
    $Label.Left = 20
    $Label.Top = 20
    $Label.Width = $Form.ClientSize.Width - 40
    $Label.AutoSize = $true
    $Label.Font = [System.Drawing.Font]::new("Microsoft Sans Serif", 10)
    $Form.Controls.Add($Label)

    $ProgressBar = New-Object System.Windows.Forms.ProgressBar
    $ProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
    $ProgressBar.Left = 20
    $ProgressBar.Top = $Label.Bottom + 20
    $ProgressBar.Width = $Form.ClientSize.Width - 40
    $ProgressBar.Height = 25
    $Form.Controls.Add($ProgressBar)

    $Script:ProgressForm = $Form
    $Script:ProgressForm.Show() | Out-Null
    # This is crucial: allow the form to render before blocking operations start
    [System.Windows.Forms.Application]::DoEvents()
}

# Function to close the progress window
function Close-ProgressWindow {
    if ($Script:ProgressForm -ne $null -and !$Script:ProgressForm.IsDisposed) {
        $Script:ProgressForm.Close()
        $Script:ProgressForm.Dispose()
        $Script:ProgressForm = $null
    }
}

# Main GUI for all inputs
function Show-MainConfigurationGUI {
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Shortcut Creator"
    $Form.Size = New-Object System.Drawing.Size(700, 600)
    $Form.MinimumSize = $Form.Size
    $Form.StartPosition = 'CenterScreen'
    $Form.MaximizeBox = $false
    $Form.MinimizeBox = $false
    $Form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle

    $FontHeader = [System.Drawing.Font]::new("Microsoft Sans Serif", 12, [System.Drawing.FontStyle]::Bold)
    $FontNormal = [System.Drawing.Font]::new("Microsoft Sans Serif", 10)

    $yPos = 20
    $labelHeight = 20
    $textBoxHeight = 25
    $controlSpacing = 10

    #region -- Global Inputs --
    $lblGlobal = New-Object System.Windows.Forms.Label
    $lblGlobal.Text = "Global Application Settings"
    $lblGlobal.Left = 20
    $lblGlobal.Top = $yPos
    $lblGlobal.AutoSize = $true
    $lblGlobal.Font = $FontHeader
    $Form.Controls.Add($lblGlobal)
    $yPos += $labelHeight + $controlSpacing

    $lblShortcutName = New-Object System.Windows.Forms.Label
    $lblShortcutName.Text = "App/Shortcut Name (e.g., 'MyCompanyApp'):"
    $lblShortcutName.Left = 20
    $lblShortcutName.Top = $yPos
    $lblShortcutName.AutoSize = $true
    $lblShortcutName.Font = $FontNormal
    $Form.Controls.Add($lblShortcutName)
    $yPos += $labelHeight

    $txtShortcutName = New-Object System.Windows.Forms.TextBox
    $txtShortcutName.Text = "MyApp"
    $txtShortcutName.Left = 20
    $txtShortcutName.Top = $yPos
    $txtShortcutName.Width = 300
    $txtShortcutName.Height = $textBoxHeight
    $txtShortcutName.Font = $FontNormal
    $Form.Controls.Add($txtShortcutName)
    $yPos += $textBoxHeight + $controlSpacing

    $lblShortcutVersion = New-Object System.Windows.Forms.Label
    $lblShortcutVersion.Text = "App/Shortcut Version (e.g., '1.0'):"
    $lblShortcutVersion.Left = 20
    $lblShortcutVersion.Top = $yPos
    $lblShortcutVersion.AutoSize = $true
    $lblShortcutVersion.Font = $FontNormal
    $Form.Controls.Add($lblShortcutVersion)
    $yPos += $labelHeight

    $txtShortcutVersion = New-Object System.Windows.Forms.TextBox
    $txtShortcutVersion.Text = "1.0"
    $txtShortcutVersion.Left = 20
    $txtShortcutVersion.Top = $yPos
    $txtShortcutVersion.Width = 100
    $txtShortcutVersion.Height = $textBoxHeight
    $txtShortcutVersion.Font = $FontNormal
    $Form.Controls.Add($txtShortcutVersion)
    $yPos += $textBoxHeight + $controlSpacing

    $lblOutputFolder = New-Object System.Windows.Forms.Label
    $lblOutputFolder.Text = "Output Folder for .intunewin file:"
    $lblOutputFolder.Left = 20
    $lblOutputFolder.Top = $yPos
    $lblOutputFolder.AutoSize = $true
    $lblOutputFolder.Font = $FontNormal
    $Form.Controls.Add($lblOutputFolder)
    $yPos += $labelHeight

    $txtOutputFolder = New-Object System.Windows.Forms.TextBox
    $txtOutputFolder.Text = "C:\Temp"
    $txtOutputFolder.Left = 20
    $txtOutputFolder.Top = $yPos
    $txtOutputFolder.Width = 400
    $txtOutputFolder.Height = $textBoxHeight
    $txtOutputFolder.ReadOnly = $true
    $txtOutputFolder.Font = $FontNormal
    $Form.Controls.Add($txtOutputFolder)

    $btnBrowseOutput = New-Object System.Windows.Forms.Button
    $btnBrowseOutput.Text = "Browse..."
    $btnBrowseOutput.Left = $txtOutputFolder.Right + 10
    $btnBrowseOutput.Top = $yPos
    $btnBrowseOutput.Width = 100
    $btnBrowseOutput.Height = $textBoxHeight
    $btnBrowseOutput.Add_Click({
        $selectedFolder = Get-FolderBrowserInput -Title "Select Output Folder" -InitialDirectory $txtOutputFolder.Text
        if ($selectedFolder) {
            $txtOutputFolder.Text = $selectedFolder
        }
    })
    $Form.Controls.Add($btnBrowseOutput)
    $yPos += $textBoxHeight + $controlSpacing * 2
    #endregion

    #region -- Main Action Type --
    $grpActionType = New-Object System.Windows.Forms.GroupBox
    $grpActionType.Text = "Choose Action Type"
    $grpActionType.Left = 20
    $grpActionType.Top = $yPos
    $grpActionType.Width = $Form.ClientSize.Width - 40
    $grpActionType.Height = 60
    $grpActionType.Font = $FontNormal
    $Form.Controls.Add($grpActionType)

    $rbCreateShortcut = New-Object System.Windows.Forms.RadioButton
    $rbCreateShortcut.Text = "Create Shortcut"
    $rbCreateShortcut.Left = 20
    $rbCreateShortcut.Top = 20
    $rbCreateShortcut.AutoSize = $true
    $rbCreateShortcut.Checked = $true
    $grpActionType.Controls.Add($rbCreateShortcut)

    $rbCopyFileFolder = New-Object System.Windows.Forms.RadioButton
    $rbCopyFileFolder.Text = "Copy File/Folder"
    $rbCopyFileFolder.Left = $rbCreateShortcut.Right + 50
    $rbCopyFileFolder.Top = 20
    $rbCopyFileFolder.AutoSize = $true
    $grpActionType.Controls.Add($rbCopyFileFolder)
    $yPos += $grpActionType.Height + $controlSpacing
    #endregion

    #region -- Shortcut Options (Conditional Visibility) --
    $grpShortcutOptions = New-Object System.Windows.Forms.GroupBox
    $grpShortcutOptions.Text = "Shortcut Configuration"
    $grpShortcutOptions.Left = 20
    $grpShortcutOptions.Top = $yPos
    $grpShortcutOptions.Width = $Form.ClientSize.Width - 40
    $grpShortcutOptions.Height = 200
    $grpShortcutOptions.Font = $FontNormal
    $Form.Controls.Add($grpShortcutOptions)

    $innerY = 20

    # Shortcut Target Type
    $lblTargetType = New-Object System.Windows.Forms.Label
    $lblTargetType.Text = "Shortcut Target Type:"
    $lblTargetType.Left = 20
    $lblTargetType.Top = $innerY
    $lblTargetType.AutoSize = $true # Corrected: used $true
    $lblTargetType.Font = $FontNormal
    $grpShortcutOptions.Controls.Add($lblTargetType)
    $innerY += $labelHeight

    $rbTargetURL = New-Object System.Windows.Forms.RadioButton
    $rbTargetURL.Text = "URL"
    $rbTargetURL.Left = 20
    $rbTargetURL.Top = $innerY
    $rbTargetURL.AutoSize = $true # Corrected: used $true
    $rbTargetURL.Checked = $true # Corrected: used $true
    $grpShortcutOptions.Controls.Add($rbTargetURL)

    $rbTargetFilePath = New-Object System.Windows.Forms.RadioButton
    $rbTargetFilePath.Text = ".exe File Path"
    $rbTargetFilePath.Left = $rbTargetURL.Right + 20
    $rbTargetFilePath.Top = $innerY
    $rbTargetFilePath.AutoSize = $true # Corrected: used $true
    $grpShortcutOptions.Controls.Add($rbTargetFilePath)

    $rbTargetMsApp = New-Object System.Windows.Forms.RadioButton
    $rbTargetMsApp.Text = "Microsoft Store App (AppUserModelID)"
    $rbTargetMsApp.Left = $rbTargetFilePath.Right + 20
    $rbTargetMsApp.Top = $innerY
    $rbTargetMsApp.AutoSize = $true # Corrected: used $true
    $grpShortcutOptions.Controls.Add($rbTargetMsApp)
    $innerY += $labelHeight + $controlSpacing

    $lblTargetValue = New-Object System.Windows.Forms.Label
    $lblTargetValue.Text = "Target Value (URL, File Path, or App ID):"
    $lblTargetValue.Left = 20
    $lblTargetValue.Top = $innerY
    $lblTargetValue.AutoSize = $true # Corrected: used $true
    $lblTargetValue.Font = $FontNormal
    $grpShortcutOptions.Controls.Add($lblTargetValue)
    $innerY += $labelHeight

    $txtTargetValue = New-Object System.Windows.Forms.TextBox
    $txtTargetValue.Text = "https://example.com"
    $txtTargetValue.Left = 20
    $txtTargetValue.Top = $innerY
    $txtTargetValue.Width = $grpShortcutOptions.ClientSize.Width - 150
    $txtTargetValue.Height = $textBoxHeight
    $txtTargetValue.Font = $FontNormal
    $grpShortcutOptions.Controls.Add($txtTargetValue)

    $btnBrowseTarget = New-Object System.Windows.Forms.Button
    $btnBrowseTarget.Text = "Browse..."
    $btnBrowseTarget.Left = $txtTargetValue.Right + 10
    $btnBrowseTarget.Top = $innerY
    $btnBrowseTarget.Width = 100
    $btnBrowseTarget.Height = $textBoxHeight
    $btnBrowseTarget.Add_Click({
        $selectedPath = Get-FileBrowserInput -Title "Select Target File" -Filter "Executable Files (*.exe)|*.exe|All Files (*.*)|*.*"
        if ($selectedPath) {
            $txtTargetValue.Text = $selectedPath
        }
    })
    $grpShortcutOptions.Controls.Add($btnBrowseTarget)
    $innerY += $textBoxHeight + $controlSpacing * 2

    # Shortcut Icon Path
    $lblIconPath = New-Object System.Windows.Forms.Label
    $lblIconPath.Text = "Shortcut Icon Path (.ico):"
    $lblIconPath.Left = 20
    $lblIconPath.Top = $innerY
    $lblIconPath.AutoSize = $true # Corrected: used $true
    $lblIconPath.Font = $FontNormal
    $grpShortcutOptions.Controls.Add($lblIconPath)
    $innerY += $labelHeight

    $txtIconPath = New-Object System.Windows.Forms.TextBox
    $txtIconPath.Text = "C:\Temp\example.ico"
    $txtIconPath.Left = 20
    $txtIconPath.Top = $innerY
    $txtIconPath.Width = $grpShortcutOptions.ClientSize.Width - 150
    $txtIconPath.Height = $textBoxHeight
    $txtIconPath.ReadOnly = $true # Corrected: used $true
    $txtIconPath.Font = $FontNormal
    $grpShortcutOptions.Controls.Add($txtIconPath)

    $btnBrowseIcon = New-Object System.Windows.Forms.Button
    $btnBrowseIcon.Text = "Browse..."
    $btnBrowseIcon.Left = $txtIconPath.Right + 10
    $btnBrowseIcon.Top = $innerY
    $btnBrowseIcon.Width = 100
    $btnBrowseIcon.Height = $textBoxHeight
    $btnBrowseIcon.Add_Click({
        $selectedIcon = Get-FileBrowserInput -Title "Select Shortcut Icon" -Filter "Icon Files (*.ico)|*.ico|All Files (*.*)|*.*"
        if ($selectedIcon) {
            $txtIconPath.Text = $selectedIcon
        }
    })
    $grpShortcutOptions.Controls.Add($btnBrowseIcon)

    # Set initial visibility
    $grpShortcutOptions.Visible = $rbCreateShortcut.Checked
    $btnBrowseTarget.Visible = $rbTargetFilePath.Checked

    # Handle radio button clicks to update visibility and default text
    $rbCreateShortcut.Add_CheckedChanged({
        $grpShortcutOptions.Visible = $rbCreateShortcut.Checked
        $grpCopyFileFolder.Visible = -not $rbCreateShortcut.Checked
    })

    # Event handlers for Target Type radio buttons
    $rbTargetURL.Add_CheckedChanged({
        if ($rbTargetURL.Checked) {
            $lblTargetValue.Text = "URL (e.g., https://example.com):"
            $txtTargetValue.Text = "https://example.com"
            $btnBrowseTarget.Visible = $false
        }
    })

    $rbTargetFilePath.Add_CheckedChanged({
        if ($rbTargetFilePath.Checked) {
            $lblTargetValue.Text = "File Path (e.g., C:\Program Files\App\App.exe):"
            $txtTargetValue.Text = "C:\Program Files\MyApplication\App.exe"
            $btnBrowseTarget.Visible = $true
        }
    })

    $rbTargetMsApp.Add_CheckedChanged({
        if ($rbTargetMsApp.Checked) {
            $lblTargetValue.Text = "AppUserModelID (e.g., Microsoft.CompanyPortal_8wekyb3d8bbwe!App):"
            $txtTargetValue.Text = "Microsoft.CompanyPortal_8wekyb3d8bbwe!App"
            $btnBrowseTarget.Visible = $false
        }
    })

    #endregion

    #region -- Copy File/Folder Options (Conditional Visibility) --
    $grpCopyFileFolder = New-Object System.Windows.Forms.GroupBox
    $grpCopyFileFolder.Text = "Copy File/Folder Configuration"
    $grpCopyFileFolder.Left = 20
    $grpCopyFileFolder.Top = $yPos
    $grpCopyFileFolder.Width = $Form.ClientSize.Width - 40
    $grpCopyFileFolder.Height = 100
    $grpCopyFileFolder.Font = $FontNormal
    $Form.Controls.Add($grpCopyFileFolder)

    $innerYCopy = 20

    $lblCopySourcePath = New-Object System.Windows.Forms.Label
    $lblCopySourcePath.Text = "Source File or Folder Path:"
    $lblCopySourcePath.Left = 20
    $lblCopySourcePath.Top = $innerYCopy
    $lblCopySourcePath.AutoSize = $true # Corrected: used $true
    $lblCopySourcePath.Font = $FontNormal
    $grpCopyFileFolder.Controls.Add($lblCopySourcePath)
    $innerYCopy += $labelHeight

    $txtCopySourcePath = New-Object System.Windows.Forms.TextBox
    $txtCopySourcePath.Text = "D:\MyDocument.pdf"
    $txtCopySourcePath.Left = 20
    $txtCopySourcePath.Top = $innerYCopy
    $txtCopySourcePath.Width = $grpCopyFileFolder.ClientSize.Width - 150
    $txtCopySourcePath.Height = $textBoxHeight
    $txtCopySourcePath.ReadOnly = $true # Corrected: used $true
    $txtCopySourcePath.Font = $FontNormal
    $grpCopyFileFolder.Controls.Add($txtCopySourcePath)

    $btnBrowseCopySource = New-Object System.Windows.Forms.Button
    $btnBrowseCopySource.Text = "Browse..."
    $btnBrowseCopySource.Left = $txtCopySourcePath.Right + 10
    $btnBrowseCopySource.Top = $innerYCopy
    $btnBrowseCopySource.Width = 100
    $btnBrowseCopySource.Height = $textBoxHeight
    $btnBrowseCopySource.Add_Click({
        $selectedItem = Get-FileBrowserInput -Title "Select File to Copy" -Filter "All Files (*.*)|*.*"
        if ($selectedItem) {
            $txtCopySourcePath.Text = $selectedItem
        }
    })
    $grpCopyFileFolder.Controls.Add($btnBrowseCopySource)

    # Set initial visibility (opposite of shortcut options)
    $grpCopyFileFolder.Visible = -not $rbCreateShortcut.Checked
    #endregion

    #region -- Action Buttons --
    $btnGenerate = New-Object System.Windows.Forms.Button
    $btnGenerate.Text = "Generate Package"
    $btnGenerate.Left = $Form.ClientSize.Width - 250
    $btnGenerate.Top = $Form.ClientSize.Height - 60
    $btnGenerate.Width = 120
    $btnGenerate.Height = 35
    $btnGenerate.Font = $FontNormal
    $Form.Controls.Add($btnGenerate)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Left = $btnGenerate.Right + 10
    $btnCancel.Top = $Form.ClientSize.Height - 60
    $btnCancel.Width = 100
    $btnCancel.Height = 35
    $btnCancel.Font = $FontNormal
    $Form.Controls.Add($btnCancel)

    $script:FormResult = $null

    $btnGenerate.Add_Click({
        # --- Validation Logic ---
        $errors = @()

        if ([string]::IsNullOrWhiteSpace($txtShortcutName.Text)) { $errors += "Application/Shortcut Name is required." }
        if ([string]::IsNullOrWhiteSpace($txtShortcutVersion.Text)) { $errors += "Version is required." }
        if ([string]::IsNullOrWhiteSpace($txtOutputFolder.Text)) { $errors += "Output Folder is required." }
        elseif (-not (Test-Path $txtOutputFolder.Text -PathType Container)) { $errors += "Output Folder does not exist." }

        if ($rbCreateShortcut.Checked) {
            if ([string]::IsNullOrWhiteSpace($txtTargetValue.Text)) { $errors += "Shortcut Target Value is required." }

            if ($rbTargetFilePath.Checked) {
                if (-not (Test-Path $txtTargetValue.Text)) { $errors += "Shortcut Target File Path does not exist." }
            } elseif ($rbTargetURL.Checked) {
                if (-not ($txtTargetValue.Text -match '^(https?|ftp|sftp|file)://')) {
                    $errors += "Invalid URL format for Shortcut Target. Must start with http(s)://, ftp://, sftp://, or file://."
                }
            }

            if ([string]::IsNullOrWhiteSpace($txtIconPath.Text)) { $errors += "Shortcut Icon Path is required." }
            elseif (-not (Test-Path $txtIconPath.Text -PathType Leaf)) { $errors += "Shortcut Icon file does not exist." }
            elseif ((Get-Item $txtIconPath.Text).Extension -ne ".ico") {
                if ($txtIconPath.Text -notmatch '\.(ico)$') {
                    $errors += "Shortcut Icon must be a .ico file (or specify icon index, e.g., 'C:\path\to\file.ico')."
                }
            }

        } elseif ($rbCopyFileFolder.Checked) {
            if ([string]::IsNullOrWhiteSpace($txtCopySourcePath.Text)) { $errors += "Source File or Folder Path is required for copying." }
            elseif (-not (Test-Path $txtCopySourcePath.Text)) { $errors += "Source File or Folder for copying does not exist." }
        }

        if ($errors.Count -gt 0) {
            [System.Windows.Forms.MessageBox]::Show(($errors | Out-String), "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        # Collect all inputs into a PSCustomObject
        $script:FormResult = [PSCustomObject]@{
            ShortcutName        = $txtShortcutName.Text.Trim()
            ShortcutVersion     = $txtShortcutVersion.Text.Trim()
            OutputFolder        = $txtOutputFolder.Text.Trim()
            ActionType          = if ($rbCreateShortcut.Checked) { "CreateShortCut" } else { "CopyFileFolder" }
            ShortcutTargetType = if ($rbCreateShortcut.Checked) {
                                     if ($rbTargetURL.Checked) { "URL" }
                                     elseif ($rbTargetFilePath.Checked) { "FilePath" }
                                     elseif ($rbTargetMsApp.Checked) { "MsApp" }
                                     else { $null }
                                   } else { $null }
            ShortcutTarget      = if ($rbCreateShortcut.Checked) { $txtTargetValue.Text.Trim() } else { $null }
            ShortcutIcon        = if ($rbCreateShortcut.Checked) { $txtIconPath.Text.Trim() } else { $null }
            CopySourcePath      = if ($rbCopyFileFolder.Checked) { $txtCopySourcePath.Text.Trim() } else { $null }
        }
        $Form.Close()
    })

    $btnCancel.Add_Click({
        $script:FormResult = $null
        $Form.Close()
    })
    #endregion

    $Form.ShowDialog() | Out-Null
    return $script:FormResult
}
#endregion

#region Main Script Logic Execution

# Define common paths (LogFile needs to be defined early for Write-Log to work)
$WorkingDir = Join-Path -Path $env:TEMP -ChildPath "IntuneWinPackage\TempApp"
$Script:LogFile = Join-Path -Path $WorkingDir -ChildPath "PackagingLog.txt"

# Create a temporary working directory for initial logging
try {
    New-Item -ItemType Directory -Path $WorkingDir -Force | Out-Null
} catch {
    Show-ErrorAndExit -Message "Failed to create initial working directory: $WorkingDir. Error: $($_.Exception.Message)" `
                      -LogMessage "Failed to create initial working directory: $WorkingDir. Error: $($_.Exception.Message)"
}

Write-Log -Message "Script started. Initial log file: $Script:LogFile" -LogFile $Script:LogFile

# Get all inputs from the single GUI window
$UserInput = Show-MainConfigurationGUI

if ($UserInput -eq $null) {
    Show-ErrorAndExit -Message 'Script terminated by user cancellation or no inputs provided.' -LogMessage 'User cancelled main GUI. Exiting script.' -LogFile $Script:LogFile
}

# Update WorkingDir and LogFile path based on UserInput.ShortcutName
$ShortcutName = $UserInput.ShortcutName
$ShortcutVersion =$UserInput.ShortcutVersion
$WorkingDir = Join-Path -Path $env:TEMP -ChildPath "IntuneWinPackage\$ShortcutName"
$OutputFolder = $UserInput.OutputFolder
$Script:LogFile = Join-Path -Path $WorkingDir -ChildPath "PackagingLog.txt"

# Recreate working directory (or ensure it exists) with the correct app name
try {
    New-Item -ItemType Directory -Path $WorkingDir -Force | Out-Null
} catch {
    Show-ErrorAndExit -Message "Failed to create final working directory: $WorkingDir. Error: $($_.Exception.Message)" `
                      -LogMessage "Failed to create final working directory: $WorkingDir. Error: $($_.Exception.Message)" -LogFile $Script:LogFile
}
# Start Writing the Log
Write-Log -Message "User provided Shortcut Name: $($UserInput.ShortcutName)" -LogFile $Script:LogFile
Write-Log -Message "User provided Version: $($UserInput.ShortcutVersion)" -LogFile $Script:LogFile
Write-Log -Message "User provided Output Folder: $($UserInput.OutputFolder)" -LogFile $Script:LogFile
Write-Log -Message "User chose Action Type: $($UserInput.ActionType)" -LogFile $Script:LogFile

# Check IntuneWinAppUtil for packaging
$IntuneWinAppUtilPath = ".\IntuneWinAppUtil.exe"
$IntuneWinFile = Join-Path -Path $UserInput.OutputFolder -ChildPath "Install_$ShortcutName.intunewin"

if (-not (Test-Path "$PSScriptRoot\$IntuneWinAppUtilPath")) {
    Show-ErrorAndExit -Message "IntuneWinAppUtil.exe not found at '$PSScriptRoot\$IntuneWinAppUtilPath'. Please place it in the script's directory."`
                      -LogMessage "IntuneWinAppUtil.exe not found. Exiting script." -LogFile $Script:LogFile
} elseif (Test-Path $IntuneWinFile) {
    if (-not (DeleteFileWithConfirmation -FilePath $IntuneWinFile -LogFile $Script:LogFile -FileNameForPrompt "$ShortcutName.intunewin")) {
        Show-ErrorAndExit -Message "Failed to delete existing .intunewin file. Exiting." `
                          -LogMessage "Failed to delete existing .intunewin file. Exiting." -LogFile $Script:LogFile
    }
}
##### Log the chooses
if ($UserInput.ActionType -eq "CreateShortCut") {
    Write-Log -Message "Shortcut Target Type: $($UserInput.ShortcutTargetType)" -LogFile $Script:LogFile
    Write-Log -Message "Shortcut Target: $($UserInput.ShortcutTarget)" -LogFile $Script:LogFile
    Write-Log -Message "Shortcut Icon Path: $($UserInput.ShortcutIcon)" -LogFile $Script:LogFile
} else { # CopyFileFolder
    Write-Log -Message "Copy Source Path: $($UserInput.CopySourcePath)" -LogFile $Script:LogFile
}


# Create Version, Install, Uninstall, Detection, Instructions files for Intune
$InstallScriptPath = Join-Path -Path $WorkingDir -ChildPath "Install_$ShortcutName.ps1"
$UninstallScriptPath = Join-Path -Path $WorkingDir -ChildPath "Uninstall_$ShortcutName.ps1"
$DetectionScriptPath = Join-Path -Path $WorkingDir -ChildPath "Detection_$ShortcutName.ps1"
$InstructionsFilePath = Join-Path -Path $UserInput.OutputFolder -ChildPath "IntuneInstructions_$ShortcutName.txt"
$ShortcutVersionInstallPath = Join-Path -Path $WorkingDir -ChildPath "$ShortcutVersion.ini"

# Generate common paths for installation scripts
$PublicDesktopFolder = "C:\Users\Public\Desktop"
$ShortcutIconPath = "C:\ProgramData\ShortcutsIcons"
$ShortcutVersionPath = "C:\ProgramData\ShortcutsVersion\$ShortcutName"
$CopyFile = $UserInput.CopySourcePath # Use value from GUI

# Create Version file for Intune
@"
# Version.ini
# Version control
$ShortcutVersion
"@ | Set-Content -Path $ShortcutVersionInstallPath -Encoding UTF8
Write-Log -Message "Created version file: $ShortcutVersionInstallPath" -LogFile $Script:LogFile

# Create instructions file for Intune
@"
Intune Packaging Instructions for $ShortcutName :

Install Command: powershell.exe -ExecutionPolicy Bypass -File ".\Install_$ShortcutName.ps1"
Uninstall Command: powershell.exe -ExecutionPolicy Bypass -File ".\Uninstall_$ShortcutName.ps1"
Detection Rules: Check Detection Script
"@ | Set-Content -Path $InstructionsFilePath
Write-Log -Message "Created Instructions file: $InstructionsFilePath" -LogFile $Script:LogFile

#++++++++++++++++++++++++++++++++++++++++++#

#Process the user's choice

if ($UserInput.ActionType -eq "CopyFileFolder") {

    # Copy the selected file/folder to the working directory
    try {
        Copy-Item -Path $CopyFile -Destination $WorkingDir -Recurse -Force -ErrorAction Stop
        $FileName = [System.IO.Path]::GetFileName($CopyFile)
        $FileExtension = [System.IO.Path]::GetExtension($CopyFile)
        $NewFileNameWithExtension = "$ShortcutName$FileExtension"
        Write-Log -Message "Copied file/folder '$FileName' to: $WorkingDir" -LogFile $Script:LogFile
        Rename-Item -Path (Join-Path -Path $WorkingDir -ChildPath $FileName) -NewName $NewFileNameWithExtension -ErrorAction Stop
        Write-Log -Message " Renamed '$FileName' to '$NewFileNameWithExtension'" -LogFile $Script:LogFile
    }
    catch {
        Show-ErrorAndExit -Message "Failed to copy file/folder '$CopyFile' to working directory. Error: $($_.Exception.Message)" `
                          -LogMessage "Failed to copy file/folder '$CopyFile'. Error: $($_.Exception.Message)" -LogFile $Script:LogFile
    }

    # Create Install file for Intune - File / Folder
    @"
    # Install_$ShortcutName.ps1
    # Copy the item to the Public Desktop folder
    Copy-Item -Path ".\$NewFileNameWithExtension" -Destination "$PublicDesktopFolder" -Recurse -Force -ErrorAction Stop
    if (-not (Test-Path "$ShortcutVersionPath")){New-Item -ItemType Directory -Path "$ShortcutVersionPath" -Force | Out-Null}
    Copy-Item -Path ".\$ShortcutVersion.ini" -Destination "$ShortcutVersionPath" -Recurse -Force -ErrorAction Stop
"@ | Set-Content -Path $InstallScriptPath

    # Log the creation of the install script
    Write-Log -Message "Created install script: $InstallScriptPath" -LogFile $Script:LogFile

    # Create Uninstall file for Intune
    @"
    # Uninstall_$ShortcutName.ps1
    # Remove the item from the Public Desktop folder

    Remove-Item -Path "$PublicDesktopFolder\$NewFileNameWithExtension" -Recurse -Force -ErrorAction Stop
    Remove-Item -Path "$ShortcutVersionPath\$ShortcutVersion.ini" -Recurse -Force -ErrorAction Stop
"@ | Set-Content -Path $UninstallScriptPath

    # Log the creation of the uninstall script
    Write-Log -Message "Created uninstall script: $UninstallScriptPath" -LogFile $Script:LogFile

    # Create Detection file for Intune
    @"
    # Detection_$ShortcutName.ps1
    # Detection Script for $ShortcutName (Copy File/Folder)

    # Check if the version file and item are present
    if ((Test-Path "$ShortcutVersionPath\$ShortcutVersion.ini") -and (Test-Path "$PublicDesktopFolder\$NewFileNameWithExtension")) {
        Write-Host "Version .ini file and item installation detected."
        exit 0
    } else {
        Write-Host "Version .ini file or item installation not detected."
        exit 1
    }
"@ | Set-Content -Path $DetectionScriptPath

    # Log the creation of the detection script
    Write-Log -Message "Created detection script: $DetectionScriptPath" -LogFile $Script:LogFile

}elseif ($UserInput.ActionType -eq "CreateShortCut") {
        $ShortcutTargetType = $UserInput.ShortcutTargetType
        $ShortcutTarget = $UserInput.ShortcutTarget
        $ShortcutIcon = $UserInput.ShortcutIcon

        # Generate shortcut (.lnk) file in working directory
        $ShortcutPath = Join-Path -Path $WorkingDir -ChildPath "$ShortcutName.lnk"
        try {
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
            if ($ShortcutTargetType.ToLower() -eq 'msapp') {
                $Shortcut.TargetPath = "%windir%\explorer.exe"
                $Shortcut.Arguments = "shell:AppsFolder\$ShortcutTarget"
            } else {
                $Shortcut.TargetPath = $ShortcutTarget
            }
            $Shortcut.IconLocation = "%ALLUSERSPROFILE%\ShortcutsIcons\$ShortcutName.ico"
            $Shortcut.Save()
            Write-Log -Message "Created shortcut: $ShortcutPath" -LogFile $Script:LogFile
        }
        catch {
            Show-ErrorAndExit -Message "Failed to create shortcut file. Error: $($_.Exception.Message)" `
                              -LogMessage "Failed to create shortcut file. Error: $($_.Exception.Message)" -LogFile $Script:LogFile
        }

        # Copy the shortcut icon to working directory
        try {
            Copy-Item -Path "$ShortcutIcon" -Destination "$WorkingDir\$ShortcutName.ico" -Force -ErrorAction Stop
            Write-Log -Message "Copied icon to: $WorkingDir\$ShortcutName.ico" -LogFile $Script:LogFile
        }
        catch {
            Show-ErrorAndExit -Message "Failed to copy shortcut icon. Error: $($_.Exception.Message)" `
                              -LogMessage "Failed to copy shortcut icon. Error: $($_.Exception.Message)" -LogFile $Script:LogFile
        }
        #===========
        # Build Install script content
        @"
        # Install_$ShortcutName.ps1
        # Create shortcut
        # Copy shortcut to Public Desktop folder
        Copy-Item -Path ".\$ShortcutName.lnk" -Destination "$PublicDesktopFolder" -Recurse -Force -ErrorAction Stop
        if (-not (Test-Path "$ShortcutIconPath")){New-Item -ItemType Directory -Path "$ShortcutIconPath" -Force | Out-Null}
        Copy-Item -Path ".\$ShortcutName.ico" -Destination "$ShortcutIconPath" -Recurse -Force -ErrorAction Stop
        if (-not (Test-Path "$ShortcutVersionPath")){New-Item -ItemType Directory -Path "$ShortcutVersionPath" -Force | Out-Null}
        Copy-Item -Path ".\$ShortcutVersion.ini" -Destination "$ShortcutVersionPath" -Recurse -Force | Out-Null
"@ | Set-Content -Path $InstallScriptPath
        Write-Log -Message "Created install script: $InstallScriptPath" -LogFile $Script:LogFile

        # Build Uninstall script content
        @"
        # Uninstall_$ShortcutName.ps1
        # Remove shortcut from Public Desktop folder
        Remove-Item -Path "$PublicDesktopFolder\$ShortcutName.lnk" -Force -ErrorAction SilentlyContinue

        # Remove icon from centralized icon path
        Remove-Item -Path "$ShortcutIconPath\$ShortcutName.ico" -Force -ErrorAction SilentlyContinue

        # Remove version file
        Remove-Item -Path "$ShortcutVersionPath\$ShortcutVersion.ini" -Force -ErrorAction SilentlyContinue
"@ | Set-Content -Path $UninstallScriptPath
        Write-Log -Message "Created uninstall script: $UninstallScriptPath" -LogFile $Script:LogFile

        # Create Detection file for Intune ###
        @"
        # Detection_$ShortcutName.ps1
        # Detection Script for $ShortcutName
        if ((Test-Path "$ShortcutVersionPath\$ShortcutVersion.ini") -and (Test-Path "$PublicDesktopFolder\$ShortcutName.lnk")) {
            Write-Host "Version .ini file and Shortcut installation detected."
            exit 0
        } else {
            Write-Host "Version .ini file and Shortcut installation not detected."
            exit 1
        }
"@ | Set-Content -Path $DetectionScriptPath
        Write-Log -Message "Created detection script: $DetectionScriptPath" -LogFile $Script:LogFile

}
# End if ($UserInput.ActionType -eq "CreateShortCut")

Close-ProgressWindow
Show-ProgressWindow -Title "Packaging Win32 App..." -Message "Creating .intunewin file, please wait. This may take a moment."
Write-Log -Message "Executing IntuneWinAppUtil.exe" -LogFile $Script:LogFile

$Arguments = "-c `"$WorkingDir`" -s `"$InstallScriptPath`" -o `"$OutputFolder`""
Write-Log -Message "Executing: $IntuneWinAppUtilPath $Arguments" -LogFile $Script:LogFile

$Process = Start-Process -FilePath $IntuneWinAppUtilPath -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
Write-Log -Message "Process exit code: $($Process.ExitCode)" -LogFile $Script:LogFile


# Handle process exit codes
if ($exitCode -eq 0) {
    Write-Log -Message "Packaging completed successfully! .intunewin file is located at $OutputFolder" -LogFile $LogFile
   
} else {
    # Corrected: Separate Write-Log and MessageBox::Show calls
    Write-Log -Message "Packaging failed with exit code $exitCode. Check the log file for details: $($Script:LogFile)" -LogFile $Script:LogFile
    }

# Copy Detection Script to Output Folder for easy access
Copy-Item -Path $DetectionScriptPath -Destination $OutputFolder -Recurse -Force -ErrorAction Stop
Write-Log -Message "Copied Detection script to output folder: $OutputFolder" -LogFile $Script:LogFile

# Clean up temporary working directory after packaging
Remove-Item -Path $WorkingDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Log -Message "Cleaned up working directory: $WorkingDir" -LogFile $LogFile

Close-ProgressWindow

#endregion