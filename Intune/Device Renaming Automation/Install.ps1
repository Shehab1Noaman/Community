[CmdletBinding()]
Param()

#schtasks /create /tn "Rename Device on Shutdown" /xml ".\Rename Device on Shutdown.xml" /f

# Ensure the script runs as a 64-bit process on x64 systems
# This helps avoid issues with file system redirection (SysWOW64)
if ($env:PROCESSOR_ARCHITEW6432 -ne $null -and $env:PROCESSOR_ARCHITEW6432 -ne "ARM64") {
    $powershell64bitPath = Join-Path $env:WINDIR "SysNative\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path $powershell64bitPath) {
        Write-Verbose "Relaunching as a 64-bit process..."
        & $powershell64bitPath -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        Exit $LASTEXITCODE
    } else {
        Write-Warning "Could not find 64-bit PowerShell executable at '$powershell64bitPath'."
        Write-Warning "Script will continue to run in 32-bit mode, which may lead to unexpected behavior."
    }
}

# ---

# Define base directory for application data and logging
$baseDir = Join-Path $env:ProgramData "Microsoft\Task"
$logFilePath = Join-Path $baseDir "Task.log"
$tagFilePath = Join-Path $baseDir "Task.tag"
$taskXmlPath = Join-Path $PSScriptRoot "Rename Device on Shutdown.xml" # Assuming XML is in the same directory as the script
$renameScriptFileName = "Rename-Device-on-Shutdown.ps1" # <--- IMPORTANT: Update this if your script name is different!
$sourceRenameScriptPath = Join-Path $PSScriptRoot $renameScriptFileName
$destinationRenameScriptPath = Join-Path $baseDir $renameScriptFileName

# ---

# Create base directory if it doesn't exist
try {
    if (-not (Test-Path $baseDir -PathType Container)) {
        Write-Verbose "Creating directory: $baseDir"
        New-Item -Path $baseDir -ItemType Directory -ErrorAction Stop | Out-Null
    }
} catch {
    Write-Error "Failed to create directory '$baseDir'. Error: $($_.Exception.Message)"
    Exit 1
}

# ---

# Start Transcript for logging script execution
try {
    Write-Verbose "Starting transcript to: $logFilePath"
    Start-Transcript -Path $logFilePath -Append -ErrorAction Stop
} catch {
    Write-Warning "Could not start transcript to '$logFilePath'. Error: $($_.Exception.Message)"
}
#---- 

# Create a tag file to indicate installation status (e.g., for Intune)
try {
    Write-Verbose "Creating tag file: $tagFilePath"
    Set-Content -Path $tagFilePath -Value "Installed" -Force -ErrorAction Stop
} catch {
    Write-Error "Failed to create tag file '$tagFilePath'. Error: $($_.Exception.Message)"
    # Decide if this should be a critical error or allow continuation
}


#---
#Copy Rename Script to $baseDir
try {
    Write-Verbose "Copying rename script from '$sourceRenameScriptPath' to '$destinationRenameScriptPath'..."
    if (Test-Path $sourceRenameScriptPath -PathType Leaf) {
        Copy-Item -Path $sourceRenameScriptPath -Destination $destinationRenameScriptPath -Force -ErrorAction Stop
        Write-Host "Successfully copied '$renameScriptFileName' to '$baseDir'."
    } else {
        Write-Error "Source rename script '$sourceRenameScriptPath' not found. Cannot proceed with installation."
        Exit 1 # Critical error, cannot create task without the script
    }
} catch {
    Write-Error "Could not copy the script to '$baseDir'. Error: $($_.Exception.Message)"
    Exit 1 # Critical error
}

# ---

# Schedule the task using the provided XML file
Write-Host "Attempting to create scheduled task 'Rename Device on Shutdown'..."
try {
    if (-not (Test-Path $taskXmlPath -PathType Leaf)) {
        Write-Error "Scheduled task XML file not found at '$taskXmlPath'. Cannot create task."
        Exit 1
    }

    # -f (Force) will overwrite an existing task with the same name
    $schtasksCommand = "schtasks"
    $schtasksArgs = @("/create", "/tn", "`"Rename Device on Shutdown`"", "/xml", "`"$taskXmlPath`"", "/f")

    # Using Start-Process for external commands provides more control over output and error streams
    $process = Start-Process -FilePath $schtasksCommand -ArgumentList $schtasksArgs -NoNewWindow -PassThru -Wait
    
    if ($process.ExitCode -eq 0) {
        Write-Host "Successfully created scheduled task 'Rename Device on Shutdown'."
    } else {
        Write-Error "Failed to create scheduled task. schtasks exited with code $($process.ExitCode)."
        # You might want to capture and display schtasks output for more details
    }
} catch {
    Write-Error "An error occurred while trying to create the scheduled task: $($_.Exception.Message)"
    Exit 1
}

# ---

# Stop Transcript
if ($Transcript) { # Check if transcript was successfully started
    try {
        Stop-Transcript
        Write-Verbose "Transcript stopped."
    } catch {
        Write-Warning "Could not stop transcript. Error: $($_.Exception.Message)"
    }
}
