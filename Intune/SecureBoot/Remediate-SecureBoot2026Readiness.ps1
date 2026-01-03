#requires -Version 5.1
<#
Remediation (Microsoft-aligned):
  - If not updated, set AvailableUpdates=0x5944 (enterprise trigger) and start Secure-Boot-Update task.
  - Does NOT change HighConfidenceOptOut/MicrosoftUpdateManagedOptIn (you manage those by policy).
  - Records key status + relevant events.

Exit 0 = now compliant
Exit 1 = still not compliant / needs reboot / firmware issue
#>

[CmdletBinding()]
param()

$BaseDir = "C:\ProgramData\SecureBoot2026"
$LogPath = Join-Path $BaseDir "readiness.log"
$RegOut  = "HKLM:\SOFTWARE\Company\SecureBoot2026"

New-Item -Path $BaseDir -ItemType Directory -Force | Out-Null
New-Item -Path $RegOut -Force | Out-Null

function Write-Log($msg) {
  Add-Content -Path $LogPath -Encoding UTF8 -Value ("{0} [{1}] {2}" -f (Get-Date -Format s), $env:COMPUTERNAME, $msg)
}
function Set-RegString($name, $value) {
  New-ItemProperty -Path $RegOut -Name $name -Value ([string]$value) -PropertyType String -Force | Out-Null
}
function Get-RegValue($path, $name) {
  try { (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { $null }
}

$SBRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$SBServ = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
$provider = "TPM-WMI"

# Must have Secure Boot ON; otherwise these updates are not applicable (Microsoft guidance focuses on SB-enabled devices)
$secureBootOn = $null
try { $secureBootOn = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $secureBootOn = $null }

if ($secureBootOn -ne $true) {
  Write-Log "Remediation v2: Secure Boot is not ON (or cannot be determined). Skipping AvailableUpdates trigger."
  Set-RegString "RemediationResult" "Skipped: Secure Boot not ON / unknown"
  exit 1
}

$UEFICA2023Status = Get-RegValue $SBServ "UEFICA2023Status"
$UEFICA2023Error  = Get-RegValue $SBServ "UEFICA2023Error"
$statusUpdated = ($UEFICA2023Status -and $UEFICA2023Status.Trim().ToLower() -eq "updated")

# Check firmware error event 1795 (OEM firmware returned error applying SB variables) :contentReference[oaicite:15]{index=15}
$fw1795 = $null
try { $fw1795 = Get-WinEvent -FilterHashtable @{LogName="System"; ProviderName=$provider; Id=1795} -MaxEvents 1 -ErrorAction Stop } catch {}

if ($fw1795) {
  Write-Log "Remediation v2: Found Event 1795 (firmware error applying Secure Boot variables). Likely needs OEM firmware update."
  Set-RegString "FirmwareIssueDetected" "True"
  Set-RegString "FirmwareIssueLast1795" $fw1795.TimeCreated
  # Still proceed to trigger if not updated (sometimes firmware update is required, but trigger may still be useful for logging progress)
}

if (-not $statusUpdated) {
  # Enterprise trigger: AvailableUpdates=0x5944 :contentReference[oaicite:16]{index=16}
  try {
    New-Item -Path $SBRoot -Force | Out-Null
    New-ItemProperty -Path $SBRoot -Name "AvailableUpdates" -PropertyType DWord -Value 0x5944 -Force | Out-Null
    Write-Log "Remediation v2: Set AvailableUpdates=0x5944"
  } catch {
    Write-Log "Remediation v2: Failed to set AvailableUpdates: $($_.Exception.Message)"
    Set-RegString "RemediationResult" "Failed to set AvailableUpdates"
    exit 1
  }

  # Kick the scheduled task now (instead of waiting up to 12 hours) :contentReference[oaicite:17]{index=17}
  $taskName = "\Microsoft\Windows\PI\Secure-Boot-Update"
  try {
    if (Get-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update" -ErrorAction SilentlyContinue) {
      Start-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update"
      Write-Log "Remediation v2: Started scheduled task $taskName"
    } else {
      Write-Log "Remediation v2: Scheduled task not found: $taskName"
    }
  } catch {
    Write-Log "Remediation v2: Failed to start scheduled task: $($_.Exception.Message)"
  }

  Set-RegString "RebootRecommended" "True"
  Write-Log "Remediation v2: Reboot recommended (boot manager step may require restart)."
} else {
  Write-Log "Remediation v2: Already Updated per UEFICA2023Status."
}

# Re-evaluate success: Status Updated OR Event 1808 exists :contentReference[oaicite:18]{index=18}
$UEFICA2023Status2 = Get-RegValue $SBServ "UEFICA2023Status"
$UEFICA2023Error2  = Get-RegValue $SBServ "UEFICA2023Error"
$statusUpdated2 = ($UEFICA2023Status2 -and $UEFICA2023Status2.Trim().ToLower() -eq "updated")
$hasError2 = ($UEFICA2023Error2 -ne $null -and [int]$UEFICA2023Error2 -ne 0)

$event1808 = $null
try { $event1808 = Get-WinEvent -FilterHashtable @{LogName="System"; ProviderName=$provider; Id=1808} -MaxEvents 1 -ErrorAction Stop } catch {}

$nowSafe = $statusUpdated2 -or ($event1808 -ne $null)
if ($hasError2) { $nowSafe = $false }

Set-RegString "PostRemediationStatus" $UEFICA2023Status2
Set-RegString "PostRemediationError"  $UEFICA2023Error2
Set-RegString "PostRemediationLast1808" ($(if ($event1808) { $event1808.TimeCreated } else { "" }))
Set-RegString "RemediationResult" ($(if ($nowSafe) { "Compliant" } else { "NotYetCompliant/NeedsRebootOrInvestigation" }))

Write-Log "Remediation v2: PostStatus=$UEFICA2023Status2; PostError=$UEFICA2023Error2; Last1808=$($event1808.TimeCreated); CompliantNow=$nowSafe"

if ($nowSafe) { exit 0 } else { exit 1 }
