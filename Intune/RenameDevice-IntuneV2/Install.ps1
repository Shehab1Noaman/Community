[CmdletBinding()]
Param()

# If running as a 32-bit process on an x64 system, re-launch as 64-bit
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64") {
    if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe") {
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$PSCommandPath"
        Exit $lastexitcode
    }
}

# --- Logging Setup ---
$baseDir  = Join-Path $env:ProgramData "Microsoft\RenameDevice"
$logFile  = Join-Path $baseDir "RenameDevice.log"
$tagFile  = Join-Path $baseDir "Rename.tag"

New-Item -Path $baseDir -ItemType Directory -Force | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ukTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date), "GMT Standard Time")
    $timestamp = $ukTime.ToString("yyyy-MM-dd HH:mm:ss")
    $entry = "[$timestamp GMT] [$Level] $Message"
    Add-Content -Path $logFile -Value $entry -Encoding UTF8
    Write-Output $entry
}

Write-Log "------- RenameDevice Install Started -------"
Write-Log "Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log "Script path: $PSCommandPath"
Write-Log "OS Architecture: $env:PROCESSOR_ARCHITECTURE | ARCHITEW6432: $env:PROCESSOR_ARCHITEW6432"

# --- Main Logic ---
try {

    Write-Log "Retrieving BIOS serial number..."
    $serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    Write-Log "Raw serial number: '$serial'"

    $serial = ($serial -replace '[^A-Za-z0-9-]', '').Trim().ToUpper()
    Write-Log "Cleaned serial number: '$serial'"

    if ([string]::IsNullOrWhiteSpace($serial)) {
        Write-Log "Serial number is empty after cleanup." "ERROR"
        exit 1
    }

    $newName = "Shtech$serial" # Change prefix to reflect your tenant
    Write-Log "Generated computer name: '$newName' (length: $($newName.Length))"

    if ($newName.Length -gt 15) {
        $newName = $newName.Substring(0, 15)
        Write-Log "Name truncated to 15 characters: '$newName'" "WARN"
    }

    $currentName = $env:COMPUTERNAME.ToUpper()
    Write-Log "Current computer name: '$currentName'"

    if ($currentName -ne $newName) {
        Write-Log "Renaming computer from '$currentName' to '$newName'..."
        Rename-Computer -NewName $newName -Force -ErrorAction Stop
        Write-Log "Rename-Computer completed successfully. Reboot required for change to take effect."
    } else {
        Write-Log "Computer name is already '$newName'. No rename needed."
    }

    Set-Content -Path $tagFile -Value $newName -Encoding ASCII -Force
    Write-Log "Tag file written to: '$tagFile'"

    Write-Log "------- RenameDevice Install Completed Successfully -------"
    exit 0

} catch {
    Write-Log "Unexpected error: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    Write-Log "------- RenameDevice Install Failed -------"
    exit 1
}
