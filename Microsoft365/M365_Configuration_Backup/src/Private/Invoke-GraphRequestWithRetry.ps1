function Invoke-GraphRequestWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')]
        [string]$Method = 'GET',

        [Parameter()]
        [hashtable]$Body,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaxRetries = 5,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$BaseDelaySeconds = 2,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$TransientErrorPattern = '\b(timed out|timeout|temporary|connection (closed|reset|failed)|name resolution|network error)\b',

        [Parameter()]
        [string]$LogPath
    )

    $params = @{
        Uri    = $Uri
        Method = $Method
    }

    if ($Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 50)
        $params.ContentType = 'application/json'
    }

    return Invoke-WithThrottleRetry -OperationName "Graph $Method $Uri" -MaxRetries $MaxRetries -BaseDelaySeconds $BaseDelaySeconds -TransientErrorPattern $TransientErrorPattern -LogPath $LogPath -ScriptBlock {
        Invoke-MgGraphRequest @params
    }
}
