function ConvertTo-CanonicalJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject,

        [Parameter()]
        [string[]]$IgnoreFields = @(),

        [Parameter()]
        [string[]]$IgnoreFieldSuffixes = @(),

        [Parameter()]
        [switch]$SortArrays
    )

    $ignoreSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($f in $IgnoreFields) {
        if (-not [string]::IsNullOrWhiteSpace($f)) { [void]$ignoreSet.Add($f) }
    }

    $suffixList = @()
    foreach ($s in $IgnoreFieldSuffixes) {
        if (-not [string]::IsNullOrWhiteSpace($s)) { $suffixList += $s }
    }

    $script:__cj_ignoreSet = $ignoreSet
    $script:__cj_suffixList = $suffixList
    $script:__cj_sortArrays = [bool]$SortArrays.IsPresent

    function _ShouldIgnoreKey {
        param([string]$Name)

        if ($script:__cj_ignoreSet.Contains($Name)) { return $true }
        foreach ($suffix in $script:__cj_suffixList) {
            if ($Name.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        return $false
    }

    function _Normalize {
        param($Value)

        if ($null -eq $Value) { return $null }

        if ($Value -is [System.Collections.IDictionary]) {
            $sorted = [ordered]@{}
            $keys = @($Value.Keys) | Sort-Object { [string]$_ }
            foreach ($k in $keys) {
                $name = [string]$k
                if (_ShouldIgnoreKey -Name $name) { continue }
                $sorted[$name] = _Normalize -Value $Value[$k]
            }
            return $sorted
        }

        if ($Value -is [System.Management.Automation.PSCustomObject]) {
            $sorted = [ordered]@{}
            $names = @($Value.PSObject.Properties.Name) | Sort-Object
            foreach ($p in $names) {
                if (_ShouldIgnoreKey -Name $p) { continue }
                $sorted[$p] = _Normalize -Value $Value.$p
            }
            return $sorted
        }

        if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($item in $Value) {
                [void]$list.Add((_Normalize -Value $item))
            }

            if ($script:__cj_sortArrays) {
                $sortedList = $list | Sort-Object -Property @{ Expression = { ($_ | ConvertTo-Json -Depth 100 -Compress) } }
                $list = New-Object System.Collections.Generic.List[object]
                foreach ($item in @($sortedList)) { [void]$list.Add($item) }
            }

            return ,@($list.ToArray())
        }

        return $Value
    }

    $normalized = _Normalize -Value $InputObject
    return ($normalized | ConvertTo-Json -Depth 100 -Compress)
}
