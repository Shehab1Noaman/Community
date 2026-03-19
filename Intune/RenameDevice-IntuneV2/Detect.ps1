$baseDir = Join-Path $env:ProgramData "Microsoft\RenameDevice"
$tagFile = Join-Path $baseDir "Rename.tag"

$serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
$serial = ($serial -replace '[^A-Za-z0-9-]', '').Trim().ToUpper()

if ([string]::IsNullOrWhiteSpace($serial)) { exit 1 }

$desiredName = "Shetech$serial" #Change Shtech to reflect your tenant
if ($desiredName.Length -gt 15) { $desiredName = $desiredName.Substring(0, 15) }

$currentName = $env:COMPUTERNAME.ToUpper()

if ($currentName -eq $desiredName) {
    Write-Output "Detected: name already correct"
    exit 0
}

if (Test-Path $tagFile) {
    $tagValue = (Get-Content $tagFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim().ToUpper()
    if ($tagValue -eq $desiredName) {
        Write-Output "Detected: rename pending reboot"
        exit 0
    }
}

exit 1
