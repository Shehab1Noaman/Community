function Invoke-WithThrottleRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OperationName = 'Operation',

        [Parameter()]
        [ValidateRange(0, 20)]
        [int]$MaxRetries = 6,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$BaseDelaySeconds = 2,

        [Parameter()]
        [ValidateRange(1, 600)]
        [int]$MaxDelaySeconds = 120,

        [Parameter()]
        [ValidateRange(0.0, 1.0)]
        [double]$JitterRatio = 0.2,

        [Parameter()]
        [int[]]$RetryStatusCodes = @(429, 500, 502, 503, 504),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$TransientErrorPattern = '\b(throttl|too many requests|temporar|timed out|timeout|connection (closed|reset|failed)|name resolution|network error|service unavailable|gateway timeout)\b',

        [Parameter()]
        [string]$LogPath
    )

    $runtimeSettings = Get-BackupThrottleSettings
    if (-not $PSBoundParameters.ContainsKey('MaxRetries')) {
        $MaxRetries = $runtimeSettings.MaxRetries
    }
    if (-not $PSBoundParameters.ContainsKey('BaseDelaySeconds')) {
        $BaseDelaySeconds = $runtimeSettings.BaseDelaySeconds
    }
    if (-not $PSBoundParameters.ContainsKey('MaxDelaySeconds')) {
        $MaxDelaySeconds = $runtimeSettings.MaxDelaySeconds
    }
    if (-not $PSBoundParameters.ContainsKey('JitterRatio')) {
        $JitterRatio = $runtimeSettings.JitterRatio
    }

    Add-BackupRetryMetric -MetricName 'TotalOperations' -Value 1
    $failureCount = 0

    while ($true) {
        try {
            return & $ScriptBlock
        }
        catch {
            $statusCode = $null
            try {
                if ($_.Exception -and ($_.Exception.PSObject.Properties.Match('Response').Count -gt 0) -and $_.Exception.Response -and $_.Exception.Response.StatusCode) {
                    $statusCode = $_.Exception.Response.StatusCode.value__
                }
            } catch { $statusCode = $null }

            $message = $_.Exception.Message
            $isTransientWithoutStatus = ($null -eq $statusCode) -and ($message -match $TransientErrorPattern)
            $shouldRetry = ($statusCode -in $RetryStatusCodes) -or $isTransientWithoutStatus

            if ((-not $shouldRetry) -or ($failureCount -ge $MaxRetries)) {
                throw
            }

            $failureCount++
            Add-BackupRetryMetric -MetricName 'RetryAttempts' -Value 1

            if ($statusCode -eq 429 -or $message -match '(?i)throttl|too many requests') {
                Add-BackupRetryMetric -MetricName 'ThrottledResponses' -Value 1
            }

            $retryAfterSeconds = Get-RetryAfterSecondsFromException -Exception $_.Exception

            if ($null -ne $retryAfterSeconds) {
                $delaySeconds = [Math]::Min([int][Math]::Ceiling($retryAfterSeconds), $MaxDelaySeconds)
            }
            else {
                $exponentialDelay = [Math]::Min($BaseDelaySeconds * [Math]::Pow(2, $failureCount - 1), $MaxDelaySeconds)
                $jitterWindow = [Math]::Max(1.0, $exponentialDelay * $JitterRatio)
                $jitter = Get-Random -Minimum 0.0 -Maximum $jitterWindow
                $delaySeconds = [int][Math]::Min([Math]::Ceiling($exponentialDelay + $jitter), $MaxDelaySeconds)
            }

            Add-BackupRetryMetric -MetricName 'TotalBackoffSeconds' -Value $delaySeconds

            $statusText = if ($null -ne $statusCode) { "HTTP $statusCode" } else { 'TransientError' }
            $retryMessage = "Retrying [$OperationName] after $delaySeconds second(s). Attempt $failureCount/$MaxRetries. Reason: $statusText"
            Write-BackupLog -Level Warning -Message $retryMessage -LogPath $LogPath

            Start-Sleep -Seconds $delaySeconds
        }
    }
}

function Get-DefaultBackupThrottleSettings {
    [CmdletBinding()]
    param()

    return [ordered]@{
        MaxRetries       = 6
        BaseDelaySeconds = 2
        MaxDelaySeconds  = 120
        JitterRatio      = 0.2
    }
}

function Set-BackupThrottleSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Settings
    )

    $defaults = Get-DefaultBackupThrottleSettings
    $merged = [ordered]@{}
    foreach ($key in $defaults.Keys) {
        if ($Settings.ContainsKey($key) -and $null -ne $Settings[$key]) {
            $merged[$key] = $Settings[$key]
        }
        else {
            $merged[$key] = $defaults[$key]
        }
    }

    $script:BackupThrottleSettings = $merged
}

function Get-BackupThrottleSettings {
    [CmdletBinding()]
    param()

    if (-not $script:BackupThrottleSettings) {
        $script:BackupThrottleSettings = Get-DefaultBackupThrottleSettings
    }

    return $script:BackupThrottleSettings
}

function Initialize-BackupRetryMetrics {
    [CmdletBinding()]
    param()

    $script:BackupRetryMetrics = [ordered]@{
        TotalOperations    = 0
        RetryAttempts      = 0
        ThrottledResponses = 0
        TotalBackoffSeconds = 0
    }
}

function Add-BackupRetryMetric {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('TotalOperations', 'RetryAttempts', 'ThrottledResponses', 'TotalBackoffSeconds')]
        [string]$MetricName,

        [Parameter(Mandatory)]
        [int]$Value
    )

    if (-not $script:BackupRetryMetrics) {
        Initialize-BackupRetryMetrics
    }

    $script:BackupRetryMetrics[$MetricName] += $Value
}

function Get-BackupRetryMetrics {
    [CmdletBinding()]
    param()

    if (-not $script:BackupRetryMetrics) {
        Initialize-BackupRetryMetrics
    }

    return [PSCustomObject]@{
        TotalOperations     = $script:BackupRetryMetrics.TotalOperations
        RetryAttempts       = $script:BackupRetryMetrics.RetryAttempts
        ThrottledResponses  = $script:BackupRetryMetrics.ThrottledResponses
        TotalBackoffSeconds = $script:BackupRetryMetrics.TotalBackoffSeconds
    }
}

function Get-RetryAfterSecondsFromException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Exception]$Exception
    )

    $retryAfterValue = $null
    $retryAfterMsValue = $null

    $response = $null
    try {
        if ($Exception -and ($Exception.PSObject.Properties.Match('Response').Count -gt 0)) {
            $response = $Exception.Response
        }
    } catch { $response = $null }

    if ($response -and $response.Headers) {
        $headers = $response.Headers

        if ($headers.PSObject.Properties.Name -contains 'Retry-After') {
            $retryAfterValue = $headers.'Retry-After'
        }
        elseif ($headers.PSObject.Properties.Name -contains 'retry-after') {
            $retryAfterValue = $headers.'retry-after'
        }

        if ($headers.PSObject.Properties.Name -contains 'x-ms-retry-after-ms') {
            $retryAfterMsValue = $headers.'x-ms-retry-after-ms'
        }
    }

    if ($retryAfterValue) {
        [int]$seconds = 0
        if ([int]::TryParse([string]$retryAfterValue, [ref]$seconds)) {
            return [Math]::Max(1, $seconds)
        }

        [datetimeoffset]$dateValue = [datetimeoffset]::MinValue
        if ([datetimeoffset]::TryParse([string]$retryAfterValue, [ref]$dateValue)) {
            $delta = $dateValue - [datetimeoffset]::UtcNow
            if ($delta.TotalSeconds -gt 0) {
                return [Math]::Max(1, [int][Math]::Ceiling($delta.TotalSeconds))
            }
        }
    }

    if ($retryAfterMsValue) {
        [int]$milliseconds = 0
        if ([int]::TryParse([string]$retryAfterMsValue, [ref]$milliseconds)) {
            return [Math]::Max(1, [int][Math]::Ceiling($milliseconds / 1000.0))
        }
    }

    $errorDetailsMessage = $null
    try {
        if ($Exception.PSObject.Properties['ErrorDetails'] -and $Exception.ErrorDetails) {
            $errorDetailsMessage = $Exception.ErrorDetails.Message
        }
    } catch { $errorDetailsMessage = $null }

    $errorText = @(
        $Exception.Message,
        $errorDetailsMessage
    ) -join ' '

    $retryAfterMatches = [regex]::Matches($errorText, '(?i)retry-?after\D+(\d+)')
    if ($retryAfterMatches.Count -gt 0) {
        return [Math]::Max(1, [int]$retryAfterMatches[0].Groups[1].Value)
    }

    $retryAfterMsMatches = [regex]::Matches($errorText, '(?i)x-ms-retry-after-ms\D+(\d+)')
    if ($retryAfterMsMatches.Count -gt 0) {
        return [Math]::Max(1, [int][Math]::Ceiling(([int]$retryAfterMsMatches[0].Groups[1].Value) / 1000.0))
    }

    return $null
}