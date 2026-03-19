[CmdletBinding()]
Param()

# If running as a 32-bit process on an x64 system, re-launch as 64-bit
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64") {
    if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe") {
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$PSCommandPath"
        Exit $lastexitcode
    }
}

# --- Main Logic ---

$baseDir = Join-Path $env:ProgramData "Microsoft\RenameDevice"
$tagFile = Join-Path $baseDir "Rename.tag"

New-Item -Path $baseDir -ItemType Directory -Force | Out-Null

$serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
$serial = ($serial -replace '[^A-Za-z0-9-]', '').Trim().ToUpper()

if ([string]::IsNullOrWhiteSpace($serial)) {
    throw "Serial number is empty."
}

$newName = "Shtech$serial" #change Shetech to reflect your tenant
if ($newName.Length -gt 15) { $newName = $newName.Substring(0, 15) }

$currentName = $env:COMPUTERNAME.ToUpper()

if ($currentName -ne $newName) {
    Rename-Computer -NewName $newName -Force -ErrorAction Stop
}

Set-Content -Path $tagFile -Value $newName -Encoding ASCII -Force

Write-Output "Rename staged or already compliant"
exit 0
