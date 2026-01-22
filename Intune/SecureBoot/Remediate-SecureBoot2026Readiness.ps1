#requires -Version 5.1
<#
.SYNOPSIS
    Secure Boot 2026 Remediation - Enhanced version with improved error handling
    
.DESCRIPTION
    Remediates Secure Boot firmware updates (UEFI CA 2023) for Windows devices.
    Outputs comprehensive JSON with status, actions, and next steps.
    
.OUTPUTS
    Compressed JSON object with Status, Reason, NextSteps, PreState, Actions, PostState
    
.NOTES
    Exit 0 = Completed (Compliant)
    Exit 1 = NotCompleted (Requires action)
#>

[CmdletBinding()]
param()

# Constants
$SBRoot   = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$SBServ   = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
$Provider = "Microsoft-Windows-TPM-WMI"
$TaskPath = "\Microsoft\Windows\PI\"
$TaskName = "Secure-Boot-Update"

# Task completion check timeout (seconds)
$TaskWaitTimeout = 30  # Increased from 15 to allow more time for task completion
$TaskCheckInterval = 2 # Increased from 1 to reduce polling frequency
$RegistryWriteRetries = 3
$RegistryWriteRetryDelay = 2
$TaskStartRetries = 2
$TaskStartRetryDelay = 3

#region Helper Functions

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { 
        (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name 
    } catch { 
        $null 
    }
}

function Get-SafeTimestamp {
    try {
        return (Get-Date).ToString("o")
    } catch {
        # Fallback to basic string representation if DateTime formatting fails
        try {
            return (Get-Date).ToString()
        } catch {
            return "Unknown"
        }
    }
}

function First-Line {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    return (($Text -split "(\r?\n)")[0]).Trim()
}

function Get-TpmEvents {
    param([int[]]$Ids, [int]$Max = 200)
    try {
        Get-WinEvent -FilterHashtable @{
            LogName      = "System"
            ProviderName = $Provider
            Id           = $Ids
        } -MaxEvents $Max -ErrorAction SilentlyContinue
    } catch {
        @()
    }
}

function Get-FirmwareStateFromEvents {
    $events = Get-TpmEvents -Ids @(1795,1796,1797,1798,1799,1801,1808) -Max 300

    $latest1808 = $events | Where-Object { $_.Id -eq 1808 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
    $latest1801 = $events | Where-Object { $_.Id -eq 1801 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
    $latest1799 = $events | Where-Object { $_.Id -eq 1799 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
    $latestFwErr = $events | Where-Object { $_.Id -in 1795,1796,1797,1798 } | Sort-Object TimeCreated -Descending | Select-Object -First 1

    $state  = "Unknown"
    $reason = $null

    # Event 1808 = firmware applied successfully
    # Event 1801 = firmware updates staged/pending
    # Fixed: Use strict '>' comparison to avoid ambiguity when timestamps are equal
    if ($latest1808 -and (-not $latest1801 -or $latest1808.TimeCreated -gt $latest1801.TimeCreated)) {
        $state = "Applied"
    } elseif ($latest1801 -and (-not $latest1808 -or $latest1801.TimeCreated -gt $latest1808.TimeCreated)) {
        $state  = "Pending"
        $reason = First-Line -Text $latest1801.Message
    }

    [PSCustomObject]@{
        FirmwareState      = $state
        PendingReason      = $reason
        Latest1801Time     = $(if ($latest1801) { 
            try { $latest1801.TimeCreated.ToString("o") } catch { (Get-SafeTimestamp) }
        } else { $null })
        Latest1808Time     = $(if ($latest1808) { 
            try { $latest1808.TimeCreated.ToString("o") } catch { (Get-SafeTimestamp) }
        } else { $null })
        Latest1799Time     = $(if ($latest1799) { 
            try { $latest1799.TimeCreated.ToString("o") } catch { (Get-SafeTimestamp) }
        } else { $null })
        Latest1799Message  = $(if ($latest1799) { (First-Line -Text $latest1799.Message) } else { $null })
        LatestFwErrorId    = $(if ($latestFwErr) { $latestFwErr.Id } else { $null })
        LatestFwErrorTime  = $(if ($latestFwErr) { 
            try { $latestFwErr.TimeCreated.ToString("o") } catch { (Get-SafeTimestamp) }
        } else { $null })
        LatestFwErrorMsg   = $(if ($latestFwErr) { (First-Line -Text $latestFwErr.Message) } else { $null })
    }
}

function Get-BitLockerProtectionOn {
    param([string]$MountPoint = "C:")

    $result = [PSCustomObject]@{
        ProtectionOn = $null
        Method = $null
        Error = $null
        Confidence = "Unknown"  # Low, Medium, High
    }

    # Try PowerShell cmdlet first
    try {
        $blv = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
        if ($blv -and $null -ne $blv.ProtectionStatus) {
            $result.ProtectionOn = ($blv.ProtectionStatus -eq 'On')
            $result.Method = "Get-BitLockerVolume"
            $result.Confidence = "High"
            return $result
        }
    } catch {
        $result.Error = "Get-BitLockerVolume failed: $($_.Exception.Message)"
    }

    # Fallback to manage-bde (works across language versions)
    try {
        $out = & manage-bde -status $MountPoint 2>&1
        if ($LASTEXITCODE -eq 0 -and $out) {
            # Check for "Protection On" pattern (case-insensitive, flexible whitespace)
            if ($out -match "Protection\s+(On|Status:\s*On)") {
                $result.ProtectionOn = $true
                $result.Method = "manage-bde"
                $result.Confidence = "Medium"
                return $result
            }
            if ($out -match "Protection\s+(Off|Status:\s*Off)") {
                $result.ProtectionOn = $false
                $result.Method = "manage-bde"
                $result.Confidence = "Medium"
                return $result
            }
            # manage-bde ran but couldn't parse status
            $result.Method = "manage-bde"
            $result.Confidence = "Low"
            $result.Error = "manage-bde output could not be parsed"
        } else {
            $result.Error = "manage-bde failed with exit code $LASTEXITCODE"
        }
    } catch {
        $result.Error = "manage-bde exception: $($_.Exception.Message)"
    }

    return $result
}

function Suspend-BitLockerTwoReboots {
    param([string]$MountPoint = "C:")

    $result = [PSCustomObject]@{
        Attempted = $false
        Success   = $false
        Method    = $null
        Message   = $null
        Confidence = $null
    }

    $blStatus = Get-BitLockerProtectionOn -MountPoint $MountPoint
    
    # If confidence is too low, warn but don't block
    if ($blStatus.Confidence -eq "Unknown" -or $blStatus.Confidence -eq "Low") {
        $result.Attempted = $false
        $result.Success   = $false
        $result.Method    = "Detection"
        $result.Confidence = $blStatus.Confidence
        $result.Message   = "BitLocker status could not be reliably determined. Error: $($blStatus.Error). Proceeding without suspension (user may need recovery key)."
        return $result
    }

    if ($blStatus.ProtectionOn -ne $true) {
        $result.Attempted = $false
        $result.Success   = $true
        $result.Method    = "NotNeeded"
        $result.Confidence = $blStatus.Confidence
        $result.Message   = $(if ($blStatus.ProtectionOn -eq $false) { 
            "BitLocker protection is OFF (no suspend required)." 
        } else { 
            "BitLocker status unknown; not suspending." 
        })
        return $result
    }

    $result.Attempted = $true
    $result.Confidence = $blStatus.Confidence

    # Try PowerShell cmdlet first
    try {
        Suspend-BitLocker -MountPoint $MountPoint -RebootCount 2 -ErrorAction Stop | Out-Null
        $result.Success = $true
        $result.Method  = "Suspend-BitLocker"
        $result.Message = "BitLocker protection suspended for 2 reboots."
        return $result
    } catch {
        $result.Method  = "Suspend-BitLocker"
        $result.Message = "Suspend-BitLocker failed: $($_.Exception.Message)"
    }

    # Fallback to manage-bde
    try {
        $output = & manage-bde -protectors -disable $MountPoint -RebootCount 2 2>&1
        if ($LASTEXITCODE -eq 0) {
            $result.Success = $true
            $result.Method  = "manage-bde"
            $result.Message = "BitLocker protectors disabled for 2 reboots."
            return $result
        } else {
            $result.Method  = "manage-bde"
            $result.Message = "manage-bde failed with exit code $LASTEXITCODE"
        }
    } catch {
        $result.Method  = "manage-bde"
        $result.Message = "manage-bde disable failed: $($_.Exception.Message)"
    }
    
    return $result
}

function Get-HasUEFIServicingError {
    param([object]$errVal)
    if ($null -eq $errVal) { return $false }
    try { return ([int]$errVal -ne 0) } catch { return $false }
}

function Wait-ForTaskCompletion {
    param(
        [string]$TaskPath,
        [string]$TaskName,
        [int]$TimeoutSeconds = 30
    )
    
    $startTime = Get-Date
    $lastState = $null
    
    while (((Get-Date) - $startTime).TotalSeconds -lt $TimeoutSeconds) {
        Start-Sleep -Seconds $TaskCheckInterval
        
        try {
            $taskInfo = Get-ScheduledTaskInfo -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
            $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
            
            $currentState = $task.State
            
            # Task states: 0=Unknown, 1=Disabled, 2=Queued, 3=Ready, 4=Running
            # Ready (3) means task has completed and is ready to run again
            if ($currentState -eq 3) {
                # Verify the task actually ran recently (within our timeout window)
                if ($taskInfo.LastRunTime -and 
                    $taskInfo.LastRunTime -gt $startTime.AddSeconds(-5)) {
                    return [PSCustomObject]@{
                        Completed = $true
                        State = $currentState
                        LastTaskResult = $taskInfo.LastTaskResult
                        LastRunTime = $taskInfo.LastRunTime
                        TimedOut = $false
                    }
                }
            }
            
            $lastState = $currentState
            
        } catch {
            return [PSCustomObject]@{
                Completed = $false
                State = $null
                LastTaskResult = $null
                LastRunTime = $null
                TimedOut = $false
                Error = $_.Exception.Message
            }
        }
    }
    
    # Timeout reached - get final state
    try {
        $taskInfo = Get-ScheduledTaskInfo -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
        $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
        
        return [PSCustomObject]@{
            Completed = $false
            State = $task.State
            LastTaskResult = $taskInfo.LastTaskResult
            LastRunTime = $taskInfo.LastRunTime
            TimedOut = $true
        }
    } catch {
        return [PSCustomObject]@{
            Completed = $false
            State = $null
            LastTaskResult = $null
            LastRunTime = $null
            TimedOut = $true
            Error = $_.Exception.Message
        }
    }
}

function Set-AvailableUpdatesWithRetry {
    param(
        [string]$Path,
        [int]$Value,
        [int]$MaxRetries = 3,
        [int]$RetryDelay = 2
    )
    
    $result = [PSCustomObject]@{
        Success = $false
        Attempts = 0
        Verified = $false
        Error = $null
    }
    
    for ($i = 1; $i -le $MaxRetries; $i++) {
        $result.Attempts = $i
        
        try {
            # Ensure path exists
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            }
            
            # Write the value
            New-ItemProperty -Path $Path -Name "AvailableUpdates" -PropertyType DWord -Value $Value -Force -ErrorAction Stop | Out-Null
            
            # Verify the write
            Start-Sleep -Milliseconds 500  # Brief pause to ensure registry flush
            $readBack = Get-RegValue -Path $Path -Name "AvailableUpdates"
            
            if ($null -ne $readBack -and $readBack -eq $Value) {
                $result.Success = $true
                $result.Verified = $true
                return $result
            } else {
                $result.Error = "Verification failed: Read value '$readBack' does not match expected '$Value'"
            }
            
        } catch {
            $result.Error = $_.Exception.Message
        }
        
        # Retry if not successful and not last attempt
        if (-not $result.Success -and $i -lt $MaxRetries) {
            Start-Sleep -Seconds $RetryDelay
        }
    }
    
    return $result
}

function Start-ScheduledTaskWithRetry {
    param(
        [string]$TaskPath,
        [string]$TaskName,
        [int]$MaxRetries = 2,
        [int]$RetryDelay = 3
    )
    
    $result = [PSCustomObject]@{
        TaskFound = $false
        StartAttempts = 0
        StartSuccess = $false
        Error = $null
    }
    
    try {
        $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
        $result.TaskFound = $true
    } catch {
        $result.Error = "Task not found: $($_.Exception.Message)"
        return $result
    }
    
    for ($i = 1; $i -le $MaxRetries; $i++) {
        $result.StartAttempts = $i
        
        try {
            Start-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
            $result.StartSuccess = $true
            return $result
        } catch {
            $result.Error = $_.Exception.Message
            
            if ($i -lt $MaxRetries) {
                Start-Sleep -Seconds $RetryDelay
            }
        }
    }
    
    return $result
}

#endregion

#region Pre-State Assessment

$actions = New-Object System.Collections.Generic.List[object]

$secureBootOn = $null
try { 
    $secureBootOn = Confirm-SecureBootUEFI -ErrorAction Stop 
} catch { 
    $secureBootOn = $null 
}

$pre = [PSCustomObject]@{
    Timestamp                 = (Get-SafeTimestamp)
    Computer                  = $env:COMPUTERNAME
    SecureBootOn              = $secureBootOn
    UEFICA2023Status          = (Get-RegValue $SBServ "UEFICA2023Status")
    UEFICA2023Error           = (Get-RegValue $SBServ "UEFICA2023Error")
    WindowsUEFICA2023Capable  = (Get-RegValue $SBServ "WindowsUEFICA2023Capable")
    AvailableUpdates          = (Get-RegValue $SBRoot "AvailableUpdates")
    Firmware                  = (Get-FirmwareStateFromEvents)
}

$preHasError = Get-HasUEFIServicingError $pre.UEFICA2023Error

# Validate prerequisites: Secure Boot must be enabled
if ($secureBootOn -ne $true) {
    $out = [PSCustomObject]@{
        Status    = "NotCompleted"
        Reason    = "Secure Boot is not ON (or cannot be determined). Remediation requires Secure Boot to be enabled in UEFI/BIOS."
        NextSteps = @(
            "Enable Secure Boot in UEFI/BIOS firmware settings",
            "Verify device supports UEFI (not legacy BIOS)",
            "Re-run remediation after enabling Secure Boot"
        )
        PreState  = $pre
        Actions   = @()
        PostState = $pre
    }
    $out | ConvertTo-Json -Depth 12 -Compress
    exit 1
}

# Check if already compliant
if (($pre.Firmware.FirmwareState -eq "Applied") -and (-not $preHasError)) {
    $out = [PSCustomObject]@{
        Status    = "Completed"
        Reason    = "Device is already compliant. Firmware application confirmed (Event 1808) with no servicing errors."
        NextSteps = @()
        PreState  = $pre
        Actions   = @()
        PostState = $pre
    }
    $out | ConvertTo-Json -Depth 12 -Compress
    exit 0
}

#endregion

#region Remediation Actions

# Action 1: Set AvailableUpdates registry value with retry and verification
$setAU = Set-AvailableUpdatesWithRetry -Path $SBRoot -Value 0x5944 -MaxRetries $RegistryWriteRetries -RetryDelay $RegistryWriteRetryDelay
$actions.Add([PSCustomObject]@{
    Action   = "SetAvailableUpdates"
    Target   = "$SBRoot\AvailableUpdates"
    Value    = "0x5944"
    Success  = $setAU.Success
    Verified = $setAU.Verified
    Attempts = $setAU.Attempts
    Error    = $setAU.Error
})

# Action 2: Start Scheduled Task with retry
$taskStart = Start-ScheduledTaskWithRetry -TaskPath $TaskPath -TaskName $TaskName -MaxRetries $TaskStartRetries -RetryDelay $TaskStartRetryDelay

$startTask = [PSCustomObject]@{
    Action         = "StartScheduledTask"
    Task           = "$TaskPath$TaskName"
    TaskFound      = $taskStart.TaskFound
    StartAttempts  = $taskStart.StartAttempts
    StartSuccess   = $taskStart.StartSuccess
    TaskWaitTime   = 0
    TaskCompleted  = $false
    TaskState      = $null
    LastTaskResult = $null
    TimedOut       = $false
    Error          = $taskStart.Error
}

if ($taskStart.StartSuccess) {
    $startTime = Get-Date
    $waitResult = Wait-ForTaskCompletion -TaskPath $TaskPath -TaskName $TaskName -TimeoutSeconds $TaskWaitTimeout
    $startTask.TaskWaitTime = ((Get-Date) - $startTime).TotalSeconds
    $startTask.TaskCompleted = $waitResult.Completed
    $startTask.TaskState = $waitResult.State
    $startTask.TimedOut = $waitResult.TimedOut
    
    # Safe conversion of LastTaskResult to integer
    if ($null -ne $waitResult.LastTaskResult) {
        try {
            $startTask.LastTaskResult = [int]$waitResult.LastTaskResult
        } catch {
            $startTask.LastTaskResult = $waitResult.LastTaskResult  # Keep as-is if conversion fails
            if (-not $startTask.Error) {
                $startTask.Error = "Could not parse LastTaskResult as integer"
            }
        }
    }
    
    if ($waitResult.Error) {
        $startTask.Error = $waitResult.Error
    }
}

$actions.Add($startTask)

# Action 3: Suspend BitLocker to prevent recovery prompts during firmware update
$bl = Suspend-BitLockerTwoReboots -MountPoint "C:"
$actions.Add([PSCustomObject]@{
    Action     = "BitLockerSuspendForTwoReboots"
    Attempted  = $bl.Attempted
    Success    = $bl.Success
    Method     = $bl.Method
    Confidence = $bl.Confidence
    Message    = $bl.Message
})

#endregion

#region Post-State Assessment

# Wait a moment for events to be written after task execution
Start-Sleep -Seconds 2

$post = [PSCustomObject]@{
    Timestamp                 = (Get-SafeTimestamp)
    Computer                  = $env:COMPUTERNAME
    SecureBootOn              = $secureBootOn
    UEFICA2023Status          = (Get-RegValue $SBServ "UEFICA2023Status")
    UEFICA2023Error           = (Get-RegValue $SBServ "UEFICA2023Error")
    WindowsUEFICA2023Capable  = (Get-RegValue $SBServ "WindowsUEFICA2023Capable")
    AvailableUpdates          = (Get-RegValue $SBRoot "AvailableUpdates")
    Firmware                  = (Get-FirmwareStateFromEvents)
}

$postHasError = Get-HasUEFIServicingError $post.UEFICA2023Error
$compliantNow = ($post.Firmware.FirmwareState -eq "Applied") -and (-not $postHasError)

#endregion

#region Build Final Status

$status = "NotCompleted"
$reason = "Remediation actions completed, but device requires additional steps to reach compliance."
$nextSteps = @()

if ($compliantNow) {
    # Device is now compliant
    $status = "Completed"
    $reason = "Device is now compliant. Firmware application confirmed (Event 1808) with no servicing errors."
    $nextSteps = @()
} else {
    # Determine why not compliant and provide guidance
    
    if ($post.Firmware.FirmwareState -eq "Pending") {
        $reason = "Firmware updates are staged but not yet applied to device firmware (Event 1801 detected). Device requires reboot(s) to complete firmware application."
        if ($post.Firmware.PendingReason) { 
            $reason += " Details: $($post.Firmware.PendingReason)" 
        }
        $nextSteps += "Reboot the device (recommended: reboot twice if BitLocker was suspended)"
        $nextSteps += "Re-run detection after reboot to confirm Event 1808 appears"
        $nextSteps += "Ensure device remains powered during firmware update process"
        
    } elseif ($post.Firmware.FirmwareState -eq "Unknown") {
        $reason = "Cannot confirm firmware application from event logs (1801/1808 events not found or inconclusive). Device may need reboot and re-check."
        $nextSteps += "Reboot the device to allow firmware updates to process"
        $nextSteps += "Re-run detection after reboot"
        $nextSteps += "Check System event log for TPM-WMI provider events (1795-1808)"
    }

    # Check for critical action failures
    $auAction = $actions | Where-Object { $_.Action -eq "SetAvailableUpdates" } | Select-Object -First 1
    if ($auAction -and -not $auAction.Success) {
        $reason += " CRITICAL: Failed to set AvailableUpdates registry value after $($auAction.Attempts) attempts."
        $nextSteps += "Verify administrative privileges and registry access"
        $nextSteps += "Manually verify HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates = 0x5944"
        $nextSteps += "Error details: $($auAction.Error)"
    } elseif ($auAction -and -not $auAction.Verified) {
        $nextSteps += "Warning: Registry write succeeded but verification failed"
        $nextSteps += "Manually check registry value: $($auAction.Target)"
    }

    # Check for servicing errors
    if ($postHasError) {
        $reason += " Servicing error detected (UEFICA2023Error is non-zero: $($post.UEFICA2023Error))."
        $nextSteps += "Investigate Secure Boot servicing error in registry: $SBServ\UEFICA2023Error"
        $nextSteps += "Check TPM-WMI events 1795-1798 for firmware error details"
        $nextSteps += "Ensure device firmware is up to date from OEM"
    }

    # Check for firmware errors
    if ($post.Firmware.LatestFwErrorId) {
        $errMsg = if ($post.Firmware.LatestFwErrorMsg) { 
            ": $($post.Firmware.LatestFwErrorMsg)" 
        } else { 
            "" 
        }
        $nextSteps += "Firmware error detected (Event $($post.Firmware.LatestFwErrorId)$errMsg)"
        $nextSteps += "Check for BIOS/UEFI firmware updates from device manufacturer"
        $nextSteps += "Verify device supports UEFI CA 2023 updates"
    }

    # Check task execution status
    $taskAction = $actions | Where-Object { $_.Action -eq "StartScheduledTask" } | Select-Object -First 1
    if ($taskAction) {
        if (-not $taskAction.TaskFound) {
            $nextSteps += "Scheduled task '$TaskName' not found - device may be missing Windows components"
            $nextSteps += "Verify Windows Update KB containing Secure Boot update is installed"
            $nextSteps += "Check Task Scheduler for task existence at $TaskPath$TaskName"
            
        } elseif (-not $taskAction.StartSuccess) {
            $nextSteps += "Failed to start scheduled task after $($taskAction.StartAttempts) attempts: $($taskAction.Error)"
            $nextSteps += "Manually run task '$TaskName' from Task Scheduler"
            
        } elseif ($taskAction.TimedOut) {
            $nextSteps += "Task '$TaskName' did not complete within $TaskWaitTimeout seconds (may still be running)"
            $nextSteps += "Wait 2-5 minutes and check Task Scheduler for task status"
            $nextSteps += "Check System event log for TPM-WMI events after task completes"
            
        } elseif (-not $taskAction.TaskCompleted) {
            $nextSteps += "Task '$TaskName' execution status unclear (State: $($taskAction.TaskState))"
            $nextSteps += "Check Task Scheduler for detailed task status"
            
        } elseif ($null -ne $taskAction.LastTaskResult -and $taskAction.LastTaskResult -ne 0) {
            # Safe hex conversion
            try {
                $hexCode = "0x$([Convert]::ToString([int]$taskAction.LastTaskResult, 16))"
            } catch {
                $hexCode = $taskAction.LastTaskResult
            }
            $nextSteps += "Task '$TaskName' completed with error code: $hexCode"
            $nextSteps += "Check Task Scheduler Operational log for detailed task execution errors"
        }
    }

    # Check BitLocker suspension
    $blAction = $actions | Where-Object { $_.Action -eq "BitLockerSuspendForTwoReboots" } | Select-Object -First 1
    if ($blAction) {
        if ($blAction.Attempted -and -not $blAction.Success) {
            $nextSteps += "WARNING: BitLocker suspension failed - device may prompt for recovery key after firmware update"
            $nextSteps += "Ensure BitLocker recovery key is available before rebooting"
            $nextSteps += "Error: $($blAction.Message)"
        } elseif (-not $blAction.Attempted -and $blAction.Confidence -in @("Unknown", "Low")) {
            $nextSteps += "WARNING: BitLocker status could not be determined reliably"
            $nextSteps += "Have BitLocker recovery key available as a precaution"
            $nextSteps += "Details: $($blAction.Message)"
        }
    }
}

#endregion

#region Output Results

$out = [PSCustomObject]@{
    Status    = $status
    Reason    = $reason
    NextSteps = $nextSteps
    PreState  = $pre
    Actions   = $actions
    PostState = $post
}

$out | ConvertTo-Json -Depth 12 -Compress

if ($compliantNow) {
    exit 0
} else {
    exit 1
}

#endregion
