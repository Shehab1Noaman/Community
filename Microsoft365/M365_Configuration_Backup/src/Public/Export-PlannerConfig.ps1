function Export-PlannerConfig {
    <#
    .SYNOPSIS
        Exports Microsoft Planner plans, buckets and tasks for every M365 group.
    .DESCRIPTION
        Iterates Microsoft 365 groups via Graph, then dumps planner plans, buckets and tasks
        for each. Requires Group.Read.All and Tasks.Read.All app permissions on Graph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [string]$LogPath,

        [Parameter()]
        [int]$PerObjectMaxItems = 0
    )

    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

    function Get-PlannerCollection {
        param([Parameter(Mandatory)][string]$Uri)
        $all  = New-Object System.Collections.Generic.List[object]
        $next = $Uri
        while (-not [string]::IsNullOrWhiteSpace($next)) {
            $resp = Invoke-GraphRequestWithRetry -Uri $next -MaxRetries 2 -LogPath $LogPath
            if ($null -eq $resp) { break }
            $batch = @(); $nextLink = $null
            if ($resp -is [System.Collections.IDictionary]) {
                if ($resp.Contains('value')) { $batch = @($resp['value']) } else { $batch = @($resp) }
                if ($resp.Contains('@odata.nextLink')) { $nextLink = [string]$resp['@odata.nextLink'] }
            } elseif ($resp.PSObject.Properties.Name -contains 'value') {
                $batch = @($resp.value)
                if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $nextLink = [string]$resp.'@odata.nextLink' }
            } else { $batch = @($resp) }
            foreach ($i in $batch) {
                if ($i -is [System.Collections.IDictionary]) { $all.Add([pscustomobject]$i) | Out-Null }
                else { $all.Add($i) | Out-Null }
            }
            $next = $nextLink
        }
        return ,$all.ToArray()
    }

    try {
        $groups = Get-PlannerCollection -Uri "/v1.0/groups?`$filter=groupTypes/any(c:c+eq+'Unified')&`$select=id,displayName&`$top=999"
        $groups = @($groups)
        if ($PerObjectMaxItems -gt 0 -and $groups.Count -gt $PerObjectMaxItems) {
            Write-BackupLog -Level Information -Message "Planner export capped at $PerObjectMaxItems of $($groups.Count) groups" -LogPath $LogPath
            $groups = $groups | Select-Object -First $PerObjectMaxItems
        }
        Write-BackupLog -Level Information -Message "Planner export starting for $($groups.Count) M365 group(s)" -LogPath $LogPath

        $allPlans   = @()
        $allBuckets = @()
        $allTasks   = @()
        $i = 0
        foreach ($g in $groups) {
            $i++
            if (($i % 25) -eq 0) {
                Write-BackupLog -Level Information -Message "Planner progress: $i / $($groups.Count) groups" -LogPath $LogPath
            }
            try {
                $plans = Get-PlannerCollection -Uri "/v1.0/groups/$($g.id)/planner/plans"
                foreach ($p in @($plans)) {
                    $p | Add-Member -NotePropertyName '_groupId' -NotePropertyValue $g.id -Force
                    $p | Add-Member -NotePropertyName '_groupName' -NotePropertyValue $g.displayName -Force
                    $allPlans += $p

                    try {
                        $buckets = Get-PlannerCollection -Uri "/v1.0/planner/plans/$($p.id)/buckets"
                        foreach ($b in @($buckets)) {
                            $b | Add-Member -NotePropertyName '_planId' -NotePropertyValue $p.id -Force
                            $b | Add-Member -NotePropertyName '_groupId' -NotePropertyValue $g.id -Force
                            $allBuckets += $b
                        }
                    } catch {
                        Write-BackupLog -Level Warning -Message "Planner buckets failed [plan=$($p.id)]: $($_.Exception.Message)" -LogPath $LogPath
                    }

                    try {
                        $tasks = Get-PlannerCollection -Uri "/v1.0/planner/plans/$($p.id)/tasks"
                        foreach ($t in @($tasks)) {
                            $t | Add-Member -NotePropertyName '_planId' -NotePropertyValue $p.id -Force
                            $t | Add-Member -NotePropertyName '_groupId' -NotePropertyValue $g.id -Force
                            $allTasks += $t
                        }
                    } catch {
                        Write-BackupLog -Level Warning -Message "Planner tasks failed [plan=$($p.id)]: $($_.Exception.Message)" -LogPath $LogPath
                    }
                }
            } catch {
                # 403/404 expected for non-Teams groups
            }
        }

        ConvertTo-SafeJson -InputObject @($allPlans)   -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'PlannerPlans.json')   -Encoding UTF8
        ConvertTo-SafeJson -InputObject @($allBuckets) -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'PlannerBuckets.json') -Encoding UTF8
        ConvertTo-SafeJson -InputObject @($allTasks)   -Depth 20 | Set-Content -Path (Join-Path $OutputPath 'PlannerTasks.json')   -Encoding UTF8

        Write-BackupLog -Level Information -Message "Planner export complete: $($allPlans.Count) plans, $($allBuckets.Count) buckets, $($allTasks.Count) tasks" -LogPath $LogPath
    }
    catch {
        Write-BackupLog -Level Warning -Message "Planner export failed: $($_.Exception.Message)" -LogPath $LogPath
    }
}
