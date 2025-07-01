[CmdletBinding()]
Param()

# Ensure the script runs as a 64-bit process on x64 systems
# This helps avoid issues with file system redirection (SysWOW64)
if ($env:PROCESSOR_ARCHITEW6432 -ne $null -and $env:PROCESSOR_ARCHITEW6432 -ne "ARM64") {
    $powershell64bitPath = Join-Path $env:WINDIR "SysNative\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path $powershell64bitPath) {
        Write-Verbose "Relaunching as a 64-bit process for uninstallation..."
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
$logFilePath = Join-Path $baseDir "Uninstall-Task.log" # Separate log for uninstallation
$tagFilePath = Join-Path $baseDir "Task.tag"
$taskName = "Rename Device on Shutdown"

# ---

# Start Transcript for logging script execution (if base directory exists or can be created)
try {
    # Ensure the base directory exists for the log file, or create it if missing
    if (-not (Test-Path $baseDir -PathType Container)) {
        Write-Verbose "Creating directory for uninstall log: $baseDir"
        New-Item -Path $baseDir -ItemType Directory -ErrorAction Stop | Out-Null
    }
    Write-Verbose "Starting uninstall transcript to: $logFilePath"
    Start-Transcript -Path $logFilePath -Append -ErrorAction Stop
} catch {
    Write-Warning "Could not start uninstall transcript to '$logFilePath'. Error: $($_.Exception.Message)"
}

# ---

# 1. Delete the Scheduled Task
Write-Host "Attempting to delete scheduled task '$taskName'..."
try {
    # Check if the task exists before trying to delete it
    $taskExists = (schtasks /query /tn "`"$taskName`"" /fo LIST 2>$null) -notmatch "ERROR:"
    
    if ($taskExists) {
        $schtasksCommand = "schtasks"
        $schtasksArgs = @("/delete", "/tn", "`"$taskName`"", "/f") # /f for force delete without prompt

        $process = Start-Process -FilePath $schtasksCommand -ArgumentList $schtasksArgs -NoNewWindow -PassThru -Wait
        
        if ($process.ExitCode -eq 0) {
            Write-Host "Successfully deleted scheduled task '$taskName'."
        } else {
            Write-Error "Failed to delete scheduled task '$taskName'. schtasks exited with code $($process.ExitCode)."
        }
    } else {
        Write-Host "Scheduled task '$taskName' not found. Nothing to delete."
    }
} catch {
    Write-Error "An error occurred while trying to delete the scheduled task: $($_.Exception.Message)"
    # Continue with other cleanup even if task deletion fails
}

# ---

# 2. Delete the Tag File
Write-Host "Attempting to delete tag file: $tagFilePath"
try {
    if (Test-Path $tagFilePath -PathType Leaf) {
        Remove-Item -Path $tagFilePath -Force -ErrorAction Stop
        Write-Host "Successfully deleted tag file: $tagFilePath"
    } else {
        Write-Host "Tag file '$tagFilePath' not found. Nothing to delete."
    }
} catch {
    Write-Error "Failed to delete tag file '$tagFilePath'. Error: $($_.Exception.Message)"
}

# ---

# 3. Delete the application directory (if empty or only contains log files)
# Be cautious with recursive deletion of ProgramData folders.
# Only delete if it's empty or contains only expected log files.
Write-Host "Attempting to remove directory: $baseDir"
try {
    if (Test-Path $baseDir -PathType Container) {
        # Get all items in the directory
        $itemsInDir = Get-ChildItem -Path $baseDir -Recurse -Force -ErrorAction SilentlyContinue
        
        # Define files that are safe to ignore (e.g., log files)
        $safeToIgnore = @(
            (Join-Path $baseDir "Task.log").ToLower()
            (Join-Path $baseDir "Uninstall-Task.log").ToLower()
        )

        # Check if there are any files other than the logs
        $otherFilesExist = $itemsInDir | Where-Object { 
            $_.PSIsContainer -eq $false -and 
            ($safeToIgnore -notcontains $_.FullName.ToLower()) 
        }

        if ($otherFilesExist.Count -eq 0) {
            # Only remove if it's empty or contains only the specified log files
            Remove-Item -Path $baseDir -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully removed directory: $baseDir"
        } else {
            Write-Warning "Directory '$baseDir' contains other files. Not removing to prevent data loss."
            $otherFilesExist | ForEach-Object { Write-Warning "  - Found: $($_.FullName)" }
        }
    } else {
        Write-Host "Directory '$baseDir' not found. Nothing to remove."
    }
} catch {
    Write-Error "Failed to remove directory '$baseDir'. Error: $($_.Exception.Message)"
}

# ---

# Stop Transcript
if ($Transcript) { # Check if transcript was successfully started
    try {
        Stop-Transcript
        Write-Verbose "Uninstall transcript stopped."
    } catch {
        Write-Warning "Could not stop uninstall transcript. Error: $($_.Exception.Message)"
    }
}

# Indicate successful uninstallation by exiting with 0
Exit 0
