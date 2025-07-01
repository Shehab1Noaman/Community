# Get the computer's serial number
$serial = Get-WmiObject -Class Win32_BIOS | Select-Object SerialNumber
$serial = $serial.SerialNumber

# Set your desired new computer name here (e.g., "Shtech" + SerialNumber)
$newName = "Shtech" + $serial

# Get the current computer name
$currentName = $env:COMPUTERNAME

# Check if a rename is needed
if ($currentName -ne $newName) {
    Write-Host "Renaming computer from '$currentName' to '$newName'..."
    # Rename the computer without forcing a restart
    Rename-Computer -NewName $newName -Force -ErrorAction Stop
    exit 0
}
