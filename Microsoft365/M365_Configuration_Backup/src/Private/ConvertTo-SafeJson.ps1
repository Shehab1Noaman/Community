function ConvertTo-SafeJson {
    <#
    .SYNOPSIS
        Wrapper around ConvertTo-Json with cycle detection, bounded depth, and
        suppression of the noisy depth-exceeded warning that fires on rich
        Graph / Exchange objects.

    .DESCRIPTION
        Default depth is 20 (enough for any real Graph/EXO payload — the
        builtin default of 100 forces ConvertTo-Json to walk every property
        graph that deeply, which on large collections of PSObjects with
        self-referencing properties can hang for minutes).

        Falls back to a sanitizing pass that:
          - rebuilds IDictionary instances with stringified keys (works around
            PowerShell 7 cmdlets like Get-DataClassification that emit
            hashtables keyed by enums)
          - breaks cycles by replacing already-visited reference-type nodes
            with the literal string '<cycle>'
          - hard-stops recursion at $Depth even in the sanitizer
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject,

        [Parameter()]
        [int]$Depth = 20
    )

    try {
        return (ConvertTo-Json -InputObject $InputObject -Depth $Depth -WarningAction SilentlyContinue -ErrorAction Stop)
    }
    catch {
        if ($_.Exception.Message -notmatch 'not supported for serialization' -and `
            $_.Exception.Message -notmatch 'Keys must be strings' -and `
            $_.Exception.Message -notmatch 'circular' -and `
            $_.Exception.Message -notmatch 'self-referencing') {
            throw
        }
    }

    $visited = [System.Collections.Generic.HashSet[object]]::new(
        [System.Collections.Generic.EqualityComparer[object]]::Default
    )

    function Convert-Node {
        param($Node, [int]$Level)

        if ($null -eq $Node) { return $null }
        if ($Level -ge $Depth) { return [string]$Node }

        $t = $Node.GetType()
        if ($Node -is [string] -or $t.IsPrimitive -or $Node -is [datetime] -or
            $Node -is [datetimeoffset] -or $Node -is [timespan] -or
            $Node -is [guid] -or $Node -is [decimal] -or $t.IsEnum) {
            return $Node
        }

        if (-not $t.IsValueType) {
            if ($visited.Contains($Node)) { return '<cycle>' }
            [void]$visited.Add($Node)
        }

        if ($Node -is [System.Collections.IDictionary]) {
            $newDict = [ordered]@{}
            foreach ($k in @($Node.Keys)) {
                $newDict["$k"] = Convert-Node $Node[$k] ($Level + 1)
            }
            return $newDict
        }
        if ($Node -is [System.Collections.IEnumerable]) {
            $list = @()
            foreach ($item in $Node) { $list += ,(Convert-Node $item ($Level + 1)) }
            return $list
        }
        if ($Node.PSObject -and $Node.PSObject.Properties) {
            $obj = [ordered]@{}
            foreach ($p in $Node.PSObject.Properties) {
                try { $obj[$p.Name] = Convert-Node $p.Value ($Level + 1) }
                catch { $obj[$p.Name] = [string]$p.Value }
            }
            return [pscustomobject]$obj
        }
        return [string]$Node
    }

    $sanitized = Convert-Node $InputObject 0
    return (ConvertTo-Json -InputObject $sanitized -Depth $Depth -WarningAction SilentlyContinue)
}
