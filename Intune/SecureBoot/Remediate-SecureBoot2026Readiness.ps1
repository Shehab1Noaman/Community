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
$TaskWaitTimeout = 15
$TaskCheckInterval = 1

#region Helper Functions

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { 
        (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name 
    } catch { 
        $null 
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
    if ($latest1808 -and (-not $latest1801 -or $latest1808.TimeCreated -ge $latest1801.TimeCreated)) {
        $state = "Applied"
    } elseif ($latest1801 -and (-not $latest1808 -or $latest1801.TimeCreated -gt $latest1808.TimeCreated)) {
        $state  = "Pending"
        $reason = First-Line -Text $latest1801.Message
    }

    [PSCustomObject]@{
        FirmwareState      = $state
        PendingReason      = $reason
        Latest1801Time     = $(if ($latest1801) { $latest1801.TimeCreated.ToString("o") } else { $null })
        Latest1808Time     = $(if ($latest1808) { $latest1808.TimeCreated.ToString("o") } else { $null })
        Latest1799Time     = $(if ($latest1799) { $latest1799.TimeCreated.ToString("o") } else { $null })
        Latest1799Message  = $(if ($latest1799) { (First-Line -Text $latest1799.Message) } else { $null })
        LatestFwErrorId    = $(if ($latestFwErr) { $latestFwErr.Id } else { $null })
        LatestFwErrorTime  = $(if ($latestFwErr) { $latestFwErr.TimeCreated.ToString("o") } else { $null })
        LatestFwErrorMsg   = $(if ($latestFwErr) { (First-Line -Text $latestFwErr.Message) } else { $null })
    }
}

function Get-BitLockerProtectionOn {
    param([string]$MountPoint = "C:")

    # Try PowerShell cmdlet first
    try {
        $blv = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
        if ($blv -and $blv.ProtectionStatus) { 
            return ($blv.ProtectionStatus -eq 'On') 
        }
    } catch { }

    # Fallback to manage-bde (works across language versions)
    try {
        $out = & manage-bde -status $MountPoint 2>$null
        if ($out) {
            # Check for "Protection On" pattern (case-insensitive, flexible whitespace)
            if ($out -match "Protection\s+(On|Status:\s*On)") { return $true }
            if ($out -match "Protection\s+(Off|Status:\s*Off)") { return $false }
        }
    } catch { }

    return $null
}

function Suspend-BitLockerTwoReboots {
    param([string]$MountPoint = "C:")

    $result = [PSCustomObject]@{
        Attempted = $false
        Success   = $false
        Method    = $null
        Message   = $null
    }

    $protOn = Get-BitLockerProtectionOn -MountPoint $MountPoint
    if ($protOn -ne $true) {
        $result.Attempted = $false
        $result.Success   = $true
        $result.Method    = "NotNeeded"
        $result.Message   = $(if ($protOn -eq $false) { 
            "BitLocker protection is OFF (no suspend required)." 
        } else { 
            "BitLocker status unknown; not suspending." 
        })
        return $result
    }

    $result.Attempted = $true

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
        [int]$TimeoutSeconds = 15
    )
    
    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        Start-Sleep -Seconds $TaskCheckInterval
        $elapsed += $TaskCheckInterval
        
        try {
            $taskInfo = Get-ScheduledTaskInfo -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
            # State 3 = Ready (completed), State 4 = Disabled
            if ($taskInfo.LastTaskResult -ne $null -and 
                $taskInfo.LastRunTime -gt (Get-Date).AddSeconds(-$TimeoutSeconds)) {
                return $taskInfo
            }
        } catch {
            return $null
        }
    }
    
    # Timeout reached
    return $null
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
    Timestamp                 = (Get-Date).ToString("o")
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

# Action 1: Set AvailableUpdates registry value (0x5944 = UEFI CA 2023)
$setAU = [PSCustomObject]@{
    Action  = "SetAvailableUpdates"
    Target  = "$SBRoot\AvailableUpdates"
    Value   = "0x5944"
    Success = $false
    Error   = $null
}
try {
    if (-not (Test-Path $SBRoot)) {
        New-Item -Path $SBRoot -Force -ErrorAction Stop | Out-Null
    }
    New-ItemProperty -Path $SBRoot -Name "AvailableUpdates" -PropertyType DWord -Value 0x5944 -Force -ErrorAction Stop | Out-Null
    $setAU.Success = $true
} catch {
    $setAU.Error = $_.Exception.Message
}
$actions.Add($setAU)

# Action 2: Start Scheduled Task to apply firmware update
$startTask = [PSCustomObject]@{
    Action         = "StartScheduledTask"
    Task           = "$TaskPath$TaskName"
    TaskFound      = $false
    StartAttempt   = $false
    StartSuccess   = $false
    LastTaskResult = $null
    TaskWaitTime   = 0
    Error          = $null
}
try {
    $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        $startTask.TaskFound = $true
        $startTask.StartAttempt = $true
        
        # Record time before starting
        $startTime = Get-Date
        Start-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
        $startTask.StartSuccess = $true

        # Wait for task to complete or timeout
        $taskInfo = Wait-ForTaskCompletion -TaskPath $TaskPath -TaskName $TaskName -TimeoutSeconds $TaskWaitTimeout
        $startTask.TaskWaitTime = ((Get-Date) - $startTime).TotalSeconds
        
        if ($taskInfo) {
            $startTask.LastTaskResult = $taskInfo.LastTaskResult
        } else {
            $startTask.Error = "Task did not complete within $TaskWaitTimeout seconds"
        }
    } else {
        $startTask.Error = "Scheduled task not found"
    }
} catch {
    $startTask.Error = $_.Exception.Message
}
$actions.Add($startTask)

# Action 3: Suspend BitLocker to prevent recovery prompts during firmware update
$bl = Suspend-BitLockerTwoReboots -MountPoint "C:"
$actions.Add([PSCustomObject]@{
    Action    = "BitLockerSuspendForTwoReboots"
    Attempted = $bl.Attempted
    Success   = $bl.Success
    Method    = $bl.Method
    Message   = $bl.Message
})

#endregion

#region Post-State Assessment

$post = [PSCustomObject]@{
    Timestamp                 = (Get-Date).ToString("o")
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
    if (-not $setAU.Success) {
        $reason += " CRITICAL: Failed to set AvailableUpdates registry value."
        $nextSteps += "Verify administrative privileges and registry access"
        $nextSteps += "Manually verify HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates = 0x5944"
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
            $nextSteps += "Failed to start scheduled task: $($taskAction.Error)"
            $nextSteps += "Manually run task '$TaskName' from Task Scheduler"
            
        } elseif ($taskAction.LastTaskResult -ne $null -and [int]$taskAction.LastTaskResult -ne 0) {
            $nextSteps += "Task '$TaskName' completed with error code: 0x$([Convert]::ToString($taskAction.LastTaskResult, 16))"
            $nextSteps += "Check Task Scheduler Operational log for detailed task execution errors"
        }
    }

    # Check BitLocker suspension
    $blAction = $actions | Where-Object { $_.Action -eq "BitLockerSuspendForTwoReboots" } | Select-Object -First 1
    if ($blAction -and $blAction.Attempted -and -not $blAction.Success) {
        $nextSteps += "Warning: BitLocker suspension failed - device may prompt for recovery key after firmware update"
        $nextSteps += "Ensure BitLocker recovery key is available before rebooting"
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
