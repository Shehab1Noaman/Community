#requires -Version 5.1
<#
Detection criteria (Microsoft-aligned):
  1) Secure Boot is ON (Confirm-SecureBootUEFI)
  2) UEFICA2023Status = "Updated"  OR System Event 1808 exists
  3) UEFICA2023Error is missing or 0
  4) No newer failure events after latest success (1801/1795/1796)

Exit 0 = Compliant (SafeForJune2026 = True)
Exit 1 = Not compliant
#>

[CmdletBinding()]
param(
  [int]$MaxEventsToScan = 200
)


function Set-RegString($name, $value) {
  New-ItemProperty -Path $RegOut -Name $name -Value ([string]$value) -PropertyType String -Force | Out-Null
}

# --- Official registry paths (per Microsoft guidance) ---
$SBRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$SBServ = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"

# Helper: safe reg read
function Get-RegValue($path, $name) {
  try { (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { $null }
}

# 1) Secure Boot enabled
$secureBootOn = $null
try { $secureBootOn = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $secureBootOn = $null }

# 2) Status keys
$UEFICA2023Status = Get-RegValue $SBServ "UEFICA2023Status"   # NotStarted / InProgress / Updated :contentReference[oaicite:7]{index=7}
$UEFICA2023Error  = Get-RegValue $SBServ "UEFICA2023Error"    # 0 or non-zero error :contentReference[oaicite:8]{index=8}

# Optional visibility (assists + trigger)
$AvailableUpdates          = Get-RegValue $SBRoot "AvailableUpdates"          # 0x5944 triggers deployment :contentReference[oaicite:9]{index=9}
$HighConfidenceOptOut      = Get-RegValue $SBRoot "HighConfidenceOptOut"      # assist toggle :contentReference[oaicite:10]{index=10}
$MicrosoftUpdateManagedOptIn = Get-RegValue $SBRoot "MicrosoftUpdateManagedOptIn" # assist toggle :contentReference[oaicite:11]{index=11}
$WindowsUEFICA2023Capable  = Get-RegValue $SBServ "WindowsUEFICA2023Capable"  # optional (0/1/2) :contentReference[oaicite:12]{index=12}

# 3) Event checks (System log, provider TPM-WMI; success=1808, failure=1801, firmware error=1795)
$provider = "TPM-WMI"
$success1808 = $null
$fail1801    = $null
$fw1795      = $null
$err1796     = $null

try {
  $success1808 = Get-WinEvent -FilterHashtable @{LogName="System"; ProviderName=$provider; Id=1808} -MaxEvents 1 -ErrorAction Stop
} catch {}
try {
  $fail1801 = Get-WinEvent -FilterHashtable @{LogName="System"; ProviderName=$provider; Id=1801} -MaxEvents 1 -ErrorAction Stop
} catch {}
try {
  $fw1795 = Get-WinEvent -FilterHashtable @{LogName="System"; ProviderName=$provider; Id=1795} -MaxEvents 1 -ErrorAction Stop
} catch {}
try {
  $err1796 = Get-WinEvent -FilterHashtable @{LogName="System"; ProviderName=$provider; Id=1796} -MaxEvents 1 -ErrorAction Stop
} catch {}

$latestSuccessTime = if ($success1808) { $success1808.TimeCreated } else { $null }
$latestFailureTimes = @(
  $(if ($fail1801) { $fail1801.TimeCreated } else { $null }),
  $(if ($fw1795) { $fw1795.TimeCreated } else { $null }),
  $(if ($err1796) { $err1796.TimeCreated } else { $null })
) | Where-Object { $_ -ne $null }

$latestFailureTime = if ($latestFailureTimes) { ($latestFailureTimes | Sort-Object -Descending | Select-Object -First 1) } else { $null }

# Official “updated” signal
$statusSaysUpdated = ($UEFICA2023Status -and $UEFICA2023Status.Trim().ToLower() -eq "updated")
$eventSaysUpdated  = ($success1808 -ne $null)

# Error signal
$hasUEFIError = ($UEFICA2023Error -ne $null -and [int]$UEFICA2023Error -ne 0)

# “No errors after success” rule
$errorsAfterSuccess = $false
if ($latestSuccessTime -and $latestFailureTime) {
  $errorsAfterSuccess = ($latestFailureTime -gt $latestSuccessTime)
}

# FINAL verdict (aligned to playbook “Updated” + 1808 + no error)
$safe =
  ($secureBootOn -eq $true) -and
  ($statusSaysUpdated -or $eventSaysUpdated) -and
  (-not $hasUEFIError) -and
  (-not $errorsAfterSuccess)

$summary = [PSCustomObject]@{
  Timestamp = (Get-Date -Format s)
  Computer  = $env:COMPUTERNAME
  SecureBootOn = $secureBootOn
  UEFICA2023Status = $UEFICA2023Status
  UEFICA2023Error  = $UEFICA2023Error
  WindowsUEFICA2023Capable = $WindowsUEFICA2023Capable
  AvailableUpdates = $AvailableUpdates
  HighConfidenceOptOut = $HighConfidenceOptOut
  MicrosoftUpdateManagedOptIn = $MicrosoftUpdateManagedOptIn
  LatestEvent1808 = $latestSuccessTime
  LatestFailureTime = $latestFailureTime
  ErrorsAfterSuccess = $errorsAfterSuccess
  SafeForJune2026 = $safe
}

$json = $summary | ConvertTo-Json -Depth 4

Write-Output $json

if ($safe) { exit 0 } else { exit 1 }
