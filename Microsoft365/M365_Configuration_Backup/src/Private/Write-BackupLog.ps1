function Write-BackupLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Verbose', 'Information', 'Warning', 'Error')]
        [string]$Level,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [string]$LogPath
    )

    $entry = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString('o')
        Level     = $Level
        Message   = $Message
    }

    switch ($Level) {
        'Verbose' { Write-Verbose -Message $Message }
        'Information' { Write-Host "[INFO] $Message" }
        'Warning' { Write-Warning -Message $Message }
        'Error' { Write-Error -Message $Message }
    }

    if ($LogPath) {
        $entry | ConvertTo-Json -Compress | Add-Content -Path $LogPath -Encoding UTF8
    }
}
