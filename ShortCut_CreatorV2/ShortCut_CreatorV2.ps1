# Intune Win32 Shortcut Packaging Script 

# Ensure the script is running in the correct directory 
Set-Location -Path $PSScriptRoot

# Add required assemblies for Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Logger Function
function Write-Log {
    param (
        [string]$Message,
        [string]$LogFile

    )
    $TimeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $LogMessage = "$TimeStamp - $Message"
    
    # Write log to file
    $LogMessage | Out-File -FilePath $LogFile -Append
    
}

# Function to display a GUI popup for user input
function Get-UserInput-GUI {
    param (
        [string]$Title,
        [string]$TextInput,
        [string]$Message,
        [string]$OptionA,
        [string]$OptionB,
        [string]$OptionC,
        [string]$OptionD
    )

    # Create the form
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = $Title
    $Form.Height = 200
    $Form.AutoSize = $True
    $Form.StartPosition = 'CenterScreen'


    # Define button properties
    $ButtonWidth = 150
    $ButtonHeight = 30
    $ButtonSpacing = 10
    $TotalButtonsWidth = ($ButtonWidth * 4) + ($ButtonSpacing * 3)
    $StartLeft = 10
    $TopPosition = 100


    # Add a label to display the message
    $Label = New-Object System.Windows.Forms.Label
    $Label.Text = $Message
    $Label.Left = 10
    $Label.Top = 20
    $Label.AutoSize = $True
    $Label.Font = [System.Drawing.Font]::new("Microsoft Sans Serif", 12)
    $Form.Controls.Add($Label)

    # Conditionally create and add a TextBox if $TextInput is provided
    
    if ($TextInput) {
        $TextBox = New-Object System.Windows.Forms.TextBox
        $TextBox.Text = $TextInput
        $TextBox.Left = 10
        $TextBox.Top = 50
        $TextBox.Width = 260
        $TextBox.Height = 20
        $TextBox.Font = [System.Drawing.Font]::new("Microsoft Sans Serif", 12, [System.Drawing.FontStyle]::Bold)
        $Form.Controls.Add($TextBox)

        }

    # Add Option A button
    $ButtonA = New-Object System.Windows.Forms.Button
    $ButtonA.Text = $OptionA
    $ButtonA.Left = $StartLeft
    $ButtonA.Top = $TopPosition
    $ButtonA.Width = $ButtonWidth
    $ButtonA.Height = $ButtonHeight
    $ButtonA.Add_Click({
        $Form.Tag = $OptionA
        $Form.Close() 
    })
    $Form.Controls.Add($ButtonA)

    # Add Option B button
    $ButtonB = New-Object System.Windows.Forms.Button
    $ButtonB.Text = $OptionB
    $ButtonB.Left = $StartLeft + $ButtonWidth + $ButtonSpacing
    $ButtonB.Top = $TopPosition
    $ButtonB.Width = $ButtonWidth
    $ButtonB.Height = $ButtonHeight
    $ButtonB.Add_Click({
        $Form.Tag = $OptionB
        $Form.Close()
    })
    $Form.Controls.Add($ButtonB)

     # Add Option C button
    if($OptionC){
        $ButtonC = New-Object System.Windows.Forms.Button
        $ButtonC.Text = $OptionC
        $ButtonC.Left = $StartLeft + ($ButtonWidth + $ButtonSpacing) * 2
        $ButtonC.Top = $TopPosition
        $ButtonC.Width = $ButtonWidth
        $ButtonC.Height = $ButtonHeight
        $ButtonC.Add_Click({
            $Form.Tag = $OptionC
            $Form.Close()
        })
        $Form.Controls.Add($ButtonC)
    }
    # Add Option D button
    if($OptionD){
        $ButtonD = New-Object System.Windows.Forms.Button
        $ButtonD.Text = $OptionD
        $ButtonD.Left = $StartLeft + ($ButtonWidth + $ButtonSpacing) * 3
        $ButtonD.Top = $TopPosition
        $ButtonD.Width = $ButtonWidth
        $ButtonD.Height = $ButtonHeight
        $ButtonD.Add_Click({
            $Form.Tag = $OptionD
            $Form.Close()
        })
        $Form.Controls.Add($ButtonD)
      }
    
    $Form.ShowDialog() | Out-Null

    
     # Conditionally create and add a TextBox if $TextInput is provided
    
        if ($Form.Tag -eq "Cancel"){
            exit
        }
        
        if ($TextInput) {

            return $TextBox.Text
        
        }else{
        
        return $Form.Tag
        }


}

# Define the function to display the error message with an exit button
function Show-ErrorAndExit {
    param (
        [string]$Message,
        [string]$LogMessage,
        [string]$LogFile
    )

    # Display a GUI message box with an Exit button
    [System.Windows.Forms.MessageBox]::Show(
        $Message,
        "Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    if($LogFile){
    # Log the error message to the log file
    Write-Log -Message $LogMessage -LogFile $LogFile
    }

    # Exit the script
   exit
}

# Check exsting IntuneWinAppUtil
function DeleteFileWithConfirmation {
    param (
        [string]$FilePath,
        [string]$LogFile
    )

    # Show a Yes/No message box asking if the user wants to delete the file
    $result = [System.Windows.Forms.MessageBox]::Show("The $ShortcutName.intunewin file already exists in the destination folder. Do you want to delete the file: $FilePath?", 
                                                      "Delete File Confirmation", 
                                                      [System.Windows.Forms.MessageBoxButtons]::YesNo, 
                                                      [System.Windows.Forms.MessageBoxIcon]::Question)

    # Check the result of the message box (Yes or No)
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        # If Yes, delete the file
        if (Test-Path $IntuneWinFile) {
            Remove-Item $IntuneWinFile -Force
            Write-Log -Message "File $IntuneWinFile deleted successfully." -LogFile $LogFile
        } else {
            Write-Log -Message "File $IntuneWinFile not found. Nothing to delete." -LogFile $LogFile
        }
    } else {
        # If No, exit the script
        Show-ErrorAndExit -Message 'The process has been canceled. Please rerun the script and choose another output path'`
                        -LogMessage 'File deletion canceled. Please re-run the script' -LogFile $LogFile
    }
}

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

#choose what you want the app to do 

$UserChoice = Get-UserInput-GUI -Title "Selection Required" -Message "Would you like to create a shortcut or copy a file/folder to your desktop?" -OptionA "Create ShortCut" -OptionB "Copy File/Folder"

if (-not ($UserChoice) -or ($UserChoice.Trim() -eq "")) {
    Show-ErrorAndExit -Message 'Script terminated due to no selection.'
         
}

# Prompt user for required inputs
$ShortcutName = Get-UserInput-GUI -Title 'File / Folder / Shorcut Name' -Message 'Please enter the name of the file, folder, or shortcut (e.g., "MyAppShortcut" or "MyFile"):' -OptionA "OK" -OptionB "Cancel" -TextInput "FirstFile"
 
if (-not ($ShortcutName) -or ($ShortcutName.Trim() -eq "")) {
    Show-ErrorAndExit -Message 'The Name is required. Please re-run the script and provide the name of the file, folder, or shortcut'
         
}else{
    #Creat workingDir
    $WorkingDir = Join-Path -Path $env:TEMP -ChildPath "IntuneWinPackage\$ShortcutName"
    New-Item -ItemType Directory -Path $WorkingDir -Force | Out-Null
    $LogFile = Join-Path -Path $WorkingDir -ChildPath "PackagingLog.txt"

    Write-Log -Message "Copied initial log data to final log file at $LogFile" -LogFile $LogFile
    Write-Log -Message "User provided Shortcut Name: $ShortcutName" -LogFile $LogFile
    }

$ShortcutVersion = Get-UserInput-GUI -Title 'Shortcut Version' -Message 'Enter the shortcut Version (e.g., 1.0):' -OptionA "OK" -OptionB "Cancel" -TextInput "1.0"
if (-not ($ShortcutVersion) -or ($ShortcutVersion.Trim() -eq "")) {
    Show-ErrorAndExit -Message 'Version is required. Please re-run the script and provide the Version.'`
                        -LogMessage 'Version is  required. Exiting script.' -LogFile $LogFile
}else{
    Write-Log -Message "User provided Version: $ShortcutVersion" -LogFile $LogFile
    }


   
#Choose the output folder
$OutputFolder = Get-UserInput-GUI -Title 'Output Folder' -Message 'Enter the output folder for the .intunewin file:' -OptionA "OK" -OptionB "Cancel" -TextInput "c:\temp"
if (-not ($OutputFolder) -or ($OutputFolder.Trim() -eq "")) {
    $OutputFolder = ".\"
}elseif (-not (Test-Path $OutputFolder)) {
    Show-ErrorAndExit -Message "$OutputFolder not found. Please re-run the script and provide valid input."`
                        -LogMessage "$OutputFolder not found. Exiting script." -LogFile $LogFile
}else{
    Write-Log -Message "User provided Output Folder: $OutputFolder" -LogFile $LogFile
    }

# Check IntuneWinAppUtil for packaging
$IntuneWinAppUtilPath = ".\IntuneWinAppUtil.exe"
$IntuneWinFile = Join-Path -Path $OutputFolder -ChildPath "Install_$ShortcutName.intunewin"

if (-not (Test-Path $IntuneWinAppUtilPath)) {
    Show-ErrorAndExit -Message "$IntuneWinAppUtilPath not found"`
                        -LogMessage "$IntuneWinAppUtilPath not found. Exiting script." -LogFile $LogFile
}elseif(Test-Path $IntuneWinFile){

DeleteFileWithConfirmation -FilePath $IntuneWinFile -LogFile $LogFile

}


# Create Version, Install, Uninstall, Detection, Instructions and Shortcut Version path  files for Intune
$InstallScriptPath = Join-Path -Path $WorkingDir -ChildPath "Install_$ShortcutName.ps1"
$UninstallScriptPath = Join-Path -Path $WorkingDir -ChildPath "Uninstall_$ShortcutName.ps1"
$DetectionScriptPath = Join-Path -Path $OutputFolder -ChildPath "Detection_$ShortcutName.ps1"
$InstructionsFilePath = Join-Path -Path $OutputFolder -ChildPath "IntuneInstructions_$ShortcutName.txt"
$ShortcutVersionInstallPath = Join-Path -Path $WorkingDir -ChildPath "$ShortcutVersion.ini"


# Create Version file for Intune
@"
# Version.ini
# Version control
$ShortcutVersion
"@ | Set-Content -Path $ShortcutVersionInstallPath
Write-Log -Message "Created version file: $ShortcutVersionInstallPath" -LogFile $LogFile

# Generate Files
$PublicDesktopFolder = "C:\Users\Public\Desktop"
$ShortcutIconPath = "C:\ProgramData\ShortcutsIcons"
$ShortcutVersionPath = "C:\ProgramData\ShortcutsVersion\$ShortcutName"

#++++++++++++++++++++++++++++++++++++++++++#

# Process the user's choice
if ($UserChoice -eq "Copy File/Folder") {
    
    $CopyFile = Get-UserInput-GUI -Title 'File / Folder Path' -Message 'Enter the full path to the file or Folder that you need to be downloaded on Users Desktop' -OptionA "OK" -OptionB "Cancel" -TextInput "D:\example"
    if (-not ($CopyFile) -or ($CopyFile.Trim() -eq "")) {
        Show-ErrorAndExit -Message 'Please re-run the script and Enter the File / Folder Path'`
                            -LogMessage 'No File / Folder Path added.' -LogFile $LogFile
    }elseif (-not (Test-Path $CopyFile)) {
        Show-ErrorAndExit -Message "$ShortcutIcon not found. Please re-run the script and provide valid input."`
                            -LogMessage "$ShortcutIcon not found. Exiting script." -LogFile $LogFile
    }else{
        Write-Log -Message "User provided File / Folder Path: $ShortcutIcon" -LogFile $LogFile
    }
    # Copy the shortcut icon to install folder
    Copy-Item -Path "$CopyFile" -Destination "$WorkingDir" -Recurse -Force
    $FileName = [System.IO.Path]::GetFileName($CopyFile)
    $NewFilePath = Join-Path -Path $WorkingDir -ChildPath $FileName

    #$CopiedItems = Join-Path -Path $WorkingDir -ChildPath "Install_$ShortcutName.ps1"
    Write-Log -Message "Copied file /folder to: $WorkingDir" -LogFile $LogFile


 # Create Install file for Intune
@"
# InstallShortcut.ps1
# Copy shortcut to Public Desktop folder

# Copy the shortcut to the Public Desktop folder
Copy-Item -Path ".\$FileName" -Destination "$PublicDesktopFolder" -Force

# Ensure the Shortcut Version Path exists and copy the version file
if (-not (Test-Path "$ShortcutVersionPath")) {
    New-Item -ItemType Directory -Path "$ShortcutVersionPath" -Force | Out-Null
}
Copy-Item -Path ".\$ShortcutVersion.ini" -Destination "$ShortcutVersionPath" -Force
"@ | Set-Content -Path $InstallScriptPath

# Log the creation of the install script
Write-Log -Message "Created install script: $InstallScriptPath" -LogFile $LogFile

# Create Uninstall file for Intune
@"
# UninstallShortcut.ps1
# Remove shortcut from Public Desktop folder

# Remove the shortcut from the Public Desktop folder
Remove-Item -Path "$PublicDesktopFolder\$FileName" -Force

# Remove the version file
Remove-Item -Path "$ShortcutVersionPath\$ShortcutVersion.ini" -Force
"@ | Set-Content -Path $UninstallScriptPath

# Log the creation of the uninstall script
Write-Log -Message "Created uninstall script: $UninstallScriptPath" -LogFile $LogFile

# Create Detection file for Intune
@"
# DetectionShortcut.ps1
# Detection Script for $ShortcutName

# Check if the version file and shortcut are present
if ((Test-Path "$ShortcutVersionPath\$ShortcutVersion.ini") -and (Test-Path "$PublicDesktopFolder\$FileName")) {
    Write-Host "Version .ini file and shortcut installation detected."
    exit 0
} else {
    Write-Host "Version .ini file and shortcut installation not detected."
    exit 1
}
"@ | Set-Content -Path $DetectionScriptPath

# Log the creation of the detection script
Write-Log -Message "Created detection script: $DetectionScriptPath" -LogFile $LogFile

        #++++++++++++++++++++++++++++++++++++++++++++++++++#
        #++++++++++++++++++++++++++++++++++++++++++++++++++#

}elseif ($UserChoice -eq "Create ShortCut") {

    $ShortcutTargetType = (Get-UserInput-GUI -Title 'Shortcut Target Type' -Message 'Enter the target type: URL, FilePath, or MsApp:' -OptionA "URL" -OptionB "FilePath" -OptionC "MsApp" -OptionD "Cancel").ToLower()
    if (-not ($ShortcutTargetType)) {
        Show-ErrorAndExit -Message 'Please re-run the script and Enter the target type: URL, FilePath, or MsApp'`
                            -LogMessage 'Shortcut Type is required. Exiting script.' -LogFile $LogFile
    }else{
        Write-Log -Message "User provided Shortcut Target Type: $ShortcutTargetType" -LogFile $LogFile
    }

    switch ($ShortcutTargetType) {
        'msapp' {
            $AppID = Get-UserInput-GUI 'MsApp AppUserModelID' 'Enter the AppUserModelID for the Microsoft Store app (e.g., Microsoft.CompanyPortal_8wekyb3d8bbwe!App):' -OptionA "OK" -OptionB "Cancel" -TextInput "Microsoft.CompanyPortal_8wekyb3d8bbwe!App"
            Write-Log -Message "User provided MsApp AppUserModelID: $AppID" -LogFile $LogFile

            if (-not ($AppID)) {
                Show-ErrorAndExit -Message 'Please re-run the script and Enter vaild  Application User Model ID (AppID)'`
                            -LogMessage 'Please re-run the script and Enter vaild  Application User Model ID (AppID).' -LogFile $LogFile
            }elseif (-not $AppID.Contains("!App")) {
                Write-Log -Message "The MSAPP does not contain '!App'. It will be appended automatically." -LogFile $LogFile
                $AppID += "!App"
            }
            $ShortcutTarget = "shell:AppsFolder\$AppID"
            Write-Log -Message "The MSAPP is set to: $AppID" -LogFile $LogFile
        }
        'filepath' {
            $ShortcutTarget = Get-UserInput-GUI 'File Path Target' 'Enter the path to the app or file (e.g., C:\Program Files\MyApp\app.exe):' -OptionA "OK" -OptionB "Cancel" -TextInput "C:\Program Files\MyApp\app.exe"
    
                if (-not ($ShortcutTarget)) {
                Show-ErrorAndExit -Message 'Please re-run the script and Enter vaild  File Path'`
                            -LogMessage 'File Path cant be Empty.' -LogFile $LogFile
            }elseif (-not (Test-Path $ShortcutTarget)) {
                Show-ErrorAndExit -Message "Target path does not exist: $ShortcutTarget" `
                                    -LogMessage "Target path does not exist: $ShortcutTarget" -LogFile $LogFile
            }else{
                Write-Log -Message "User provided File Path Target: $ShortcutTarget" -LogFile $LogFile
                }
        }
        'url' {
            $ShortcutTarget = Get-UserInput-GUI 'URL Target' 'Enter the URL (e.g., https://example.com):' -OptionA "OK" -OptionB "Cancel" -TextInput "https://example.com"
                if (-not ($ShortcutTarget) -or -not ($ShortcutTarget -match '^(https?|ftp|sftp|file)://')) {
                    Show-ErrorAndExit -Message 'Invalid URL. Please re-run the script and enter a valid URL (e.g., https://example.com, ftp://example.com, sftp://example.com, file://path).' `
                                        -LogMessage 'URL input was invalid or empty.' -LogFile $LogFile
                } else {
                    try {
                        # Parse the URL using [System.Uri] for advanced validation
                        $Uri = [System.Uri]::new($ShortcutTarget)
                        if (-not $Uri.IsAbsoluteUri) {
                            throw [System.Exception]::new("The URL must be an absolute URI.")
                        }
                        # Log the valid URL input
                        Write-Log -Message "User provided a valid URL Target: $ShortcutTarget" -LogFile $LogFile
                    } catch {
                            # Log and display an error if [System.Uri] validation fails
                            Show-ErrorAndExit -Message 'Invalid URL. Please ensure the URL is correctly formatted and absolute.' `
                                                -LogMessage "URL validation failed: $_" -LogFile $LogFile
                                }
                        }
        }
        default {
            Show-ErrorAndExit -Message "Invalid target type. Please choose either URL, FilePath, or MsApp."`
                                -LogMessage "Invalid target type entered: $ShortcutTargetType" -LogFile $LogFile
        }
    }

    $ShortcutIcon = Get-UserInput-GUI 'Shortcut Icon Path' 'Enter the full path to the icon file (.ico):' -OptionA "OK" -OptionB "Cancel" -TextInput "D:\Example.ico"
    if (-not ($ShortcutIcon)) {
        Show-ErrorAndExit -Message 'Please re-run the script and Enter the icon Path'`
                            -LogMessage 'No Icon path added.' -LogFile $LogFile
    }elseif (-not (Test-Path $ShortcutIcon)) {
        Show-ErrorAndExit -Message "$ShortcutIcon not found. Please re-run the script and provide valid input."`
                            -LogMessage "$ShortcutIcon not found. Exiting script." -LogFile $LogFile
    }else{
        Write-Log -Message "User provided Shortcut Icon Path: $ShortcutIcon" -LogFile $LogFile
        }


    # Generate shortcut (.lnk) file
    $ShortcutPath = Join-Path -Path $WorkingDir -ChildPath "$ShortcutName.lnk"
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
    if ($ShortcutTargetType -eq 'msapp') {
        $Shortcut.TargetPath = "%windir%\explorer.exe"
        $Shortcut.Arguments = $ShortcutTarget 
    } else {
        $Shortcut.TargetPath = $ShortcutTarget
    }
    $Shortcut.IconLocation = "%ALLUSERSPROFILE%\ShortcutsIcons\$ShortcutName.ico"
    $Shortcut.Save()
    Write-Log -Message "Created shortcut: $ShortcutPath" -LogFile $LogFile


 
    # Copy the shortcut icon to install folder
    Copy-Item -Path "$ShortcutIcon" -Destination "$WorkingDir\$ShortcutName.ico" -Force
    Write-Log -Message "Copied icon to: $WorkingDir\$ShortcutName.ico" -LogFile $LogFile

# Create Install file for Intune
@"
# InstallShortcut.ps1
# Copy shortcut to Public Desktop folder
Copy-Item -Path ".\$ShortcutName.lnk" -Destination "$PublicDesktopFolder" -Force

# Ensure the ShortcutIconPath directory exists, then copy the icon
if (-not (Test-Path "$ShortcutIconPath")) {
    New-Item -ItemType Directory -Path "$ShortcutIconPath" -Force | Out-Null
}
Copy-Item -Path ".\$ShortcutName.ico" -Destination "$ShortcutIconPath" -Force

# Ensure the ShortcutVersionPath directory exists, then copy the version info
if (-not (Test-Path "$ShortcutVersionPath")) {
    New-Item -ItemType Directory -Path "$ShortcutVersionPath" -Force | Out-Null
}
Copy-Item -Path ".\$ShortcutVersion.ini" -Destination "$ShortcutVersionPath" -Force
"@ | Set-Content -Path $InstallScriptPath

Write-Log -Message "Created install script: $InstallScriptPath" -LogFile $LogFile

# Create Uninstall file for Intune
@"
# UninstallShortcut.ps1
# Remove shortcut from Public Desktop folder
Remove-Item -Path "$PublicDesktopFolder\$ShortcutName.lnk" -Force

# Remove version file
Remove-Item -Path "$ShortcutVersionPath\$ShortcutVersion.ini" -Force
"@ | Set-Content -Path $UninstallScriptPath

Write-Log -Message "Created uninstall script: $UninstallScriptPath" -LogFile $LogFile

# Create Detection file for Intune
@"
# DetectionShortcut.ps1
# Detection Script for $ShortcutName

if ((Test-Path "$ShortcutVersionPath\$ShortcutVersion.ini") -and (Test-Path "$PublicDesktopFolder\$ShortcutName.lnk")) {
    Write-Host "Version .ini file and shortcut detected."
    exit 0
} else {
    Write-Host "Version .ini file and shortcut not detected."
    exit 1
}
"@ | Set-Content -Path $DetectionScriptPath

Write-Log -Message "Created detection script: $DetectionScriptPath" -LogFile $LogFile

}


# Create instructions file for Intune
@"
Intune Packaging Instructions for $ShortcutName :

Install Command: powershell.exe -ExecutionPolicy Bypass -File ".\Install_$ShortcutName.ps1"
Uninstall Command: powershell.exe -ExecutionPolicy Bypass -File ".\Uninstall_$ShortcutName.ps1"
Detection Rules: Check Detection Script
"@ | Set-Content -Path $InstructionsFilePath
Write-Log -Message "Created version file: $InstructionsFilePath" -LogFile $LogFile


$Arguments = "-c `"$WorkingDir`" -s `"$InstallScriptPath`" -o `"$OutputFolder`""
Write-Log -Message "Executing: $IntuneWinAppUtilPath $Arguments" -LogFile $LogFile

$Process = Start-Process -FilePath $IntuneWinAppUtilPath -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
Write-Log -Message "Process exit code: $($Process.ExitCode)" -LogFile $LogFile

# Handle process exit codes
if ($Process.ExitCode -eq 0) {

    Write-Log -Message "Packaging completed successfully! .intunewin file is located at $OutputFolder" -LogFile $LogFile
} else {
    Write-Log -Message "Packaging failed with exit code $($Process.ExitCode)" -LogFile $LogFile
}

# Clean up temporary working directory after packaging
#Remove-Item -Path $WorkingDir -Recurse -Force
#Write-Log -Message "Cleaned up working directory: $WorkingDir" -LogFile $LogFile

##Write-Log -Message "Packaging process completed successfully!" -LogFile $LogFile
