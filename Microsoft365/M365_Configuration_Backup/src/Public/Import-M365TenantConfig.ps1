function Import-M365TenantConfig {
    <#
    .SYNOPSIS
        Applies (imports) backed-up M365 configuration objects back to the tenant.

    .DESCRIPTION
        Reads configuration JSON files from a backup snapshot and pushes the settings
        back to the tenant via the appropriate service cmdlets. Supports selective
        restore by -Workloads, -ObjectNames, and -WorkloadObjectTypes filters.

        Use -WhatIf to preview changes without applying them. A -RemapConfig hashtable
        can translate identifiers (e.g. group IDs) from the source tenant to the
        target tenant for cross-tenant migrations.

    .PARAMETER BackupPath
        Path to the backup snapshot folder to restore from.

    .PARAMETER Workloads
        Workloads to restore. Defaults to EntraID, ExchangeOnline, Teams, SharePoint,
        and Intune when not specified.

    .PARAMETER ObjectNames
        Optional list of specific object names to restore (e.g. policy display names).

    .PARAMETER WorkloadObjectTypes
        Hashtable mapping workload name to an array of object type names to restore.
        Null or missing key means all object types for that workload.

    .PARAMETER RemapConfig
        Hashtable for identifier remapping (source ID -> target ID). Useful for
        cross-tenant migrations.

    .PARAMETER OperationLogPath
        Optional. Path to write a per-operation restore log.

    .EXAMPLE
        Import-M365TenantConfig -BackupPath C:\backup\tenant\20260101-120000

    .EXAMPLE
        Import-M365TenantConfig -BackupPath C:\backup\tenant\20260101-120000 `
                                -Workloads Intune -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BackupPath,

        [Parameter()]
        [ValidateSet('EntraID', 'ExchangeOnline', 'Teams', 'SharePoint', 'Intune', 'Compliance', 'Defender', 'PowerPlatform', 'Planner', 'Users')]
        [string[]]$Workloads = @('EntraID', 'ExchangeOnline', 'Teams', 'SharePoint', 'Intune'),

        [Parameter()]
        [string[]]$ObjectNames,

        # Key = workload name, Value = string[] of enabled object-type names.
        # Null value or missing key = all object types for that workload.
        [Parameter()]
        [hashtable]$WorkloadObjectTypes,

        [Parameter()]
        [hashtable]$RemapConfig,

        [Parameter()]
        [string]$OperationLogPath
    )

    if (-not (Test-Path -Path $BackupPath)) {
        throw "BackupPath not found: $BackupPath"
    }

    $applyFailures = [System.Collections.Generic.List[string]]::new()

    # ── helpers ──────────────────────────────────────────────────────────────

    function Add-ApplyFailure {
        param([Parameter(Mandatory)][string]$Message)

        if (-not [string]::IsNullOrWhiteSpace($Message)) {
            [void]$applyFailures.Add($Message)
        }
    }

    function Test-ObjectTypeEnabled {
        param(
            [Parameter(Mandatory)] [hashtable]$WOT,
            [Parameter(Mandatory)] [string]$Workload,
            [Parameter(Mandatory)] [string]$ObjectType
        )

        if ($null -eq $WOT -or -not $WOT.ContainsKey($Workload)) {
            return $true  # no filter = all enabled
        }

        $allowed = @($WOT[$Workload])
        if ($allowed.Count -eq 0) {
            return $false  # explicit workload filter with no types = none enabled
        }

        return ($ObjectType -in $allowed)
    }

    function Remove-ReadOnlyIntuneFields {
        param(
            [Parameter(Mandatory)] $Item,
            [string[]]$ExtraExclude = @()
        )

        $readOnly = @(
            'id', 'createdDateTime', 'lastModifiedDateTime', 'version',
            'assignments', '@odata.context', '@odata.nextLink',
            'managedDevices', 'settingCount', 'payloadTypes'
        )

        $exclude = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($f in ($readOnly + $ExtraExclude)) { $null = $exclude.Add($f) }

        function Copy-FilteredIntuneValue {
            param(
                $Value,
                [bool]$IsNested = $false
            )

            if ($null -eq $Value) { return $null }

            if ($Value -is [System.Collections.IDictionary]) {
                $result = [ordered]@{}
                foreach ($key in @($Value.Keys)) {
                    $name = [string]$key
                    if ($exclude.Contains($name)) { continue }
                    if ($name -like '*@odata.context' -or $name -like '*@odata.nextLink') { continue }
                    if ($IsNested -and $name -eq '@odata.type') { continue }
                    $result[$name] = Copy-FilteredIntuneValue -Value $Value[$key] -IsNested $true
                }
                return $result
            }

            if ($Value -is [PSCustomObject]) {
                $result = [ordered]@{}
                foreach ($prop in $Value.PSObject.Properties) {
                    if ($exclude.Contains($prop.Name)) { continue }
                    if ($prop.Name -like '*@odata.context' -or $prop.Name -like '*@odata.nextLink') { continue }
                    if ($IsNested -and $prop.Name -eq '@odata.type') { continue }
                    $result[$prop.Name] = Copy-FilteredIntuneValue -Value $prop.Value -IsNested $true
                }
                return $result
            }

            if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
                return @($Value | ForEach-Object { Copy-FilteredIntuneValue -Value $_ -IsNested $true })
            }

            return $Value
        }

        return (Copy-FilteredIntuneValue -Value $Item)
    }

    function Get-ObjectFieldCount {
        param([Parameter()] $InputObject)

        if ($null -eq $InputObject) { return 0 }
        if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject.Count }
        if ($InputObject -is [PSCustomObject]) {
            return @($InputObject.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' }).Count
        }

        return @($InputObject).Count
    }

    function Find-MatchByDisplayName {
        param(
            [Parameter(Mandatory)] $BackupItem,
            [Parameter(Mandatory)] $CurrentItems
        )

        $name = [string]$BackupItem.displayName
        return ($CurrentItems | Where-Object { [string]$_.displayName -eq $name } | Select-Object -First 1)
    }

    function Read-BackupJson {
        param([Parameter(Mandatory)] [string]$Path)

        if (-not (Test-Path -Path $Path)) { return @() }

        $raw = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }

        try {
            $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
            # Handle Graph envelope { value: [...] }
            # Use Where-Object instead of .Name member-enumeration to avoid StrictMode crash on array types
            if ($null -ne ($parsed.PSObject.Properties | Where-Object Name -eq 'value')) {
                return @($parsed.value)
            }
            return @($parsed)
        }
        catch {
            Write-Warning "Failed to parse backup JSON [$Path]: $($_.Exception.Message)"
            return @()
        }
    }

    function Write-RestoreOperationLog {
        param(
            [Parameter(Mandatory)] [string]$Workload,
            [Parameter(Mandatory)] [string]$ObjectType,
            [Parameter(Mandatory)] [string]$Name,
            [Parameter(Mandatory)] [string]$Action,
            [Parameter(Mandatory)] [string]$Status,
            [string]$TargetId,
            $PreviousState,
            $RequestedBody,
            [string]$ErrorMessage
        )

        if ([string]::IsNullOrWhiteSpace($OperationLogPath)) { return }

        [pscustomobject]@{
            Timestamp     = (Get-Date).ToString('o')
            Workload      = $Workload
            ObjectType    = $ObjectType
            Name          = $Name
            Action        = $Action
            Status        = $Status
            TargetId      = $TargetId
            PreviousState = $PreviousState
            RequestedBody = $RequestedBody
            ErrorMessage  = $ErrorMessage
        } | ConvertTo-Json -Depth 30 -Compress | Add-Content -Path $OperationLogPath -Encoding UTF8
    }

    function Invoke-IntuneRestore {
        param(
            [Parameter(Mandatory)] [string]$ObjectType,
            [Parameter(Mandatory)] [string]$WorkloadPath,
            [Parameter(Mandatory)] [string]$GetUri,
            [Parameter(Mandatory)] [string]$PatchUriTemplate,  # use {id} placeholder
            [string]$CreateUri,
            [string]$AssignUriTemplate,  # use {id} placeholder; e.g. '/beta/deviceManagement/deviceConfigurations/{id}/assign'
            [string[]]$ExtraReadOnlyFields = @(),
            [string]$ActionLabel,
            [System.Management.Automation.PSCmdlet]$CallerCmdlet,
            [string[]]$NameFilter  # $ObjectNames passed through
        )
        $backupItems = Read-BackupJson -Path (Join-Path $WorkloadPath "$ObjectType.json")
        if (@($backupItems).Count -eq 0) {
            Write-Verbose "[$ObjectType] No backup items found, skipping."
            return
        }

        try {
            $currentResponse = Invoke-MgGraphRequest -Uri $GetUri -Method GET -ErrorAction Stop
            $currentItems = if ($currentResponse.value) { @($currentResponse.value) } else { @($currentResponse) }
        }
        catch {
            Add-ApplyFailure -Message "[$ObjectType] Failed to retrieve current tenant items: $($_.Exception.Message)"
            Write-Warning "[$ObjectType] Failed to retrieve current tenant items: $($_.Exception.Message)"
            return
        }

        foreach ($item in $backupItems) {
            $name = [string]$item.displayName
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            if ($NameFilter -and $name -notin $NameFilter) { continue }

            $itemOdataTypeProp = $item.PSObject.Properties['@odata.type']
            $itemOdataType = if ($null -ne $itemOdataTypeProp) { [string]$itemOdataTypeProp.Value } else { '' }
            if ($ObjectType -eq 'ConfigurationProfiles' -and $itemOdataType -eq '#microsoft.graph.windowsUpdateForBusinessConfiguration') {
                Write-Verbose "[$ObjectType] Skipping '$name' in generic deviceConfigurations restore; handled by UpdateRings."
                continue
            }

            # Capture assignments from backup before stripping (they are removed by Remove-ReadOnlyIntuneFields)
            $backupAssignments = @()
            if (-not [string]::IsNullOrWhiteSpace($AssignUriTemplate)) {
                $assignmentsProp = $item.PSObject.Properties['assignments']
                $rawAssignments = if ($null -ne $assignmentsProp) { $assignmentsProp.Value } else { $null }
                if ($null -ne $rawAssignments) {
                    # Keep only the target sub-object from each assignment (strip read-only 'id')
                    $backupAssignments = @($rawAssignments | ForEach-Object {
                        $targetProp = $_.PSObject.Properties['target']
                        if ($null -ne $targetProp -and $null -ne $targetProp.Value) { @{ target = $targetProp.Value } }
                    } | Where-Object { $null -ne $_ })
                }
            }

            $body = Remove-ReadOnlyIntuneFields -Item $item -ExtraExclude $ExtraReadOnlyFields
            if ($RemapConfig) {
                $body = Invoke-BackupRemap -InputObject $body -RemapConfig $RemapConfig
            }

            if ((Get-ObjectFieldCount -InputObject $body) -eq 0) {
                Write-Warning "[$ObjectType] Skipping '$name': no restorable fields in backup."
                Write-RestoreOperationLog -Workload 'Intune' -ObjectType $ObjectType -Name $name -Action 'Review' -Status 'Skipped' -RequestedBody $body -ErrorMessage 'No restorable fields in backup.'
                continue
            }

            $match = Find-MatchByDisplayName -BackupItem $item -CurrentItems $currentItems
            $label = if ($ActionLabel) { $ActionLabel } else { $ObjectType }
            $shouldProcessTarget = "${label}:$name"

            if (-not $match) {
                if ([string]::IsNullOrWhiteSpace($CreateUri)) {
                    Write-Warning "[$ObjectType] No match found for '$name' in current tenant, skipping."
                    continue
                }

                if ($CallerCmdlet.ShouldProcess($shouldProcessTarget, 'Create')) {
                    try {
                        $bodyJson = $body | ConvertTo-Json -Depth 30
                        # Debug: log request body for failures on specific object names
                        if ($name -like '*update ring*' -or $name -like '*Autopilot*' -or $name -like '*HealthScript*') {
                            $bodyLogPath = Join-Path (Split-Path $OperationLogPath) "debug-body-$([guid]::NewGuid().ToString().Substring(0,8)).json"
                            @{ ObjectType = $ObjectType; Name = $name; Uri = $CreateUri; Body = $bodyJson } | ConvertTo-Json -Depth 10 | Set-Content -Path $bodyLogPath
                        }
                        $newObj = Invoke-MgGraphRequest -Uri $CreateUri -Method POST -Body $bodyJson -ContentType 'application/json' -ErrorAction Stop
                        Write-RestoreOperationLog -Workload 'Intune' -ObjectType $ObjectType -Name $name -Action 'Create' -Status 'Success' -RequestedBody $body
                        Write-Verbose "[$ObjectType] Created '$name'."

                        # Restore assignments for newly created object
                        if (-not [string]::IsNullOrWhiteSpace($AssignUriTemplate) -and $backupAssignments.Count -gt 0 -and $newObj.id) {
                            $assignUri = $AssignUriTemplate -replace '\{id\}', [string]$newObj.id
                            $assignBody = @{ assignments = $backupAssignments } | ConvertTo-Json -Depth 10
                            try {
                                Invoke-MgGraphRequest -Uri $assignUri -Method POST -Body $assignBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
                                Write-Verbose "[$ObjectType] Restored $($backupAssignments.Count) assignment(s) for '$name'."
                            }
                            catch {
                                Add-ApplyFailure -Message "[$ObjectType] Created '$name' but failed to restore assignments: $($_.Exception.Message)"
                                Write-Warning "[$ObjectType] Created '$name' but failed to restore assignments: $($_.Exception.Message)"
                            }
                        }
                    }
                    catch {
                        Write-RestoreOperationLog -Workload 'Intune' -ObjectType $ObjectType -Name $name -Action 'Create' -Status 'Failed' -RequestedBody $body -ErrorMessage $_.Exception.Message
                        Add-ApplyFailure -Message "[$ObjectType] Failed to create '$name': $($_.Exception.Message)"
                        Write-Warning "[$ObjectType] Failed to create '$name': $($_.Exception.Message)"
                    }
                }
                continue
            }

            if ($CallerCmdlet.ShouldProcess($shouldProcessTarget, 'Restore')) {
                $uri = $PatchUriTemplate -replace '\{id\}', [string]$match.id
                $currentBody = Remove-ReadOnlyIntuneFields -Item $match -ExtraExclude $ExtraReadOnlyFields
                $desiredCanonical = ConvertTo-CanonicalJson -InputObject $body -SortArrays
                $currentCanonical = ConvertTo-CanonicalJson -InputObject $currentBody -SortArrays

                if ($desiredCanonical -ne $currentCanonical) {
                    try {
                        $currentDetail = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
                        $currentDetailBody = Remove-ReadOnlyIntuneFields -Item $currentDetail -ExtraExclude $ExtraReadOnlyFields
                        $currentCanonical = ConvertTo-CanonicalJson -InputObject $currentDetailBody -SortArrays
                    }
                    catch {
                        Write-Verbose "[$ObjectType] Failed to retrieve detailed current object for '$name'; continuing with update attempt."
                    }
                }

                if ($desiredCanonical -eq $currentCanonical) {
                    Write-Verbose "[$ObjectType] Skipping '$name': current tenant object already matches restorable state."
                    Write-RestoreOperationLog -Workload 'Intune' -ObjectType $ObjectType -Name $name -Action 'Update' -Status 'Skipped' -TargetId ([string]$match.id) -PreviousState $match -RequestedBody $body -ErrorMessage 'Current tenant object already matches restorable state.'
                    continue
                }

                try {
                    $bodyJson = $body | ConvertTo-Json -Depth 30
                    # Debug: log request body for failures on specific object names
                    if ($name -like '*update ring*' -or $name -like '*Autopilot*' -or $name -like '*HealthScript*') {
                        $bodyLogPath = Join-Path (Split-Path $OperationLogPath) "debug-body-$([guid]::NewGuid().ToString().Substring(0,8)).json"
                        @{ ObjectType = $ObjectType; Name = $name; Uri = $uri; Body = $bodyJson } | ConvertTo-Json -Depth 10 | Set-Content -Path $bodyLogPath
                    }
                    Invoke-MgGraphRequest -Uri $uri -Method PATCH -Body $bodyJson -ContentType 'application/json' -ErrorAction Stop | Out-Null
                    Write-RestoreOperationLog -Workload 'Intune' -ObjectType $ObjectType -Name $name -Action 'Update' -Status 'Success' -TargetId ([string]$match.id) -PreviousState $match -RequestedBody $body
                    Write-Verbose "[$ObjectType] Restored '$name'."

                    # Restore assignments for updated object
                    if (-not [string]::IsNullOrWhiteSpace($AssignUriTemplate) -and $backupAssignments.Count -gt 0) {
                        $assignUri = $AssignUriTemplate -replace '\{id\}', [string]$match.id
                        $assignBody = @{ assignments = $backupAssignments } | ConvertTo-Json -Depth 10
                        try {
                            Invoke-MgGraphRequest -Uri $assignUri -Method POST -Body $assignBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
                            Write-Verbose "[$ObjectType] Restored $($backupAssignments.Count) assignment(s) for '$name'."
                        }
                        catch {
                            Add-ApplyFailure -Message "[$ObjectType] Restored '$name' but failed to restore assignments: $($_.Exception.Message)"
                            Write-Warning "[$ObjectType] Restored '$name' but failed to restore assignments: $($_.Exception.Message)"
                        }
                    }
                }
                catch {
                    Write-RestoreOperationLog -Workload 'Intune' -ObjectType $ObjectType -Name $name -Action 'Update' -Status 'Failed' -TargetId ([string]$match.id) -PreviousState $match -RequestedBody $body -ErrorMessage $_.Exception.Message
                    Add-ApplyFailure -Message "[$ObjectType] Failed to restore '$name': $($_.Exception.Message)"
                    Write-Warning "[$ObjectType] Failed to restore '$name': $($_.Exception.Message)"
                }
            }
        }
    }

    function Invoke-IntuneScriptRestore {
        <#
            Restores Intune script-style objects (deviceManagementScripts, deviceHealthScripts,
            deviceShellScripts, deviceComplianceScripts).

            - Reads the consolidated $BackupFile (which contains the full base64 script content).
            - For each backup entry: matches existing tenant script by displayName.
              - Match found  -> PATCH /{collection}/{id} with $BodyFields.
              - No match     -> POST /{collection} to create a new one.
            - Microsoft built-in proactive remediations (publisher == 'Microsoft') are read-only;
              pass -SkipMicrosoftPublisher for DeviceHealthScripts to skip them gracefully.
        #>
        param(
            [Parameter(Mandatory)] [string]$ObjectType,
            [Parameter(Mandatory)] [string]$WorkloadPath,
            [Parameter(Mandatory)] [string]$BackupFile,
            [Parameter(Mandatory)] [string]$CollectionUri,
            [string[]]$ContentFields = @(),
            [Parameter(Mandatory)] [string[]]$BodyFields,
            [switch]$SkipMicrosoftPublisher,
            [string]$ActionLabel,
            [System.Management.Automation.PSCmdlet]$CallerCmdlet,
            [string[]]$NameFilter
        )

        $backupItems = Read-BackupJson -Path (Join-Path $WorkloadPath $BackupFile)
        if (@($backupItems).Count -eq 0) {
            Write-Verbose "[$ObjectType] No backup items found, skipping."
            return
        }

        try {
            $currentResponse = Invoke-MgGraphRequest -Uri $CollectionUri -Method GET -ErrorAction Stop
            $currentItems = if ($currentResponse.value) { @($currentResponse.value) } else { @($currentResponse) }
        }
        catch {
            Write-Warning "[$ObjectType] Failed to retrieve current tenant items: $($_.Exception.Message)"
            return
        }

        $label = if ($ActionLabel) { $ActionLabel } else { $ObjectType }

        foreach ($item in $backupItems) {
            $name = [string]$item.displayName
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            if ($NameFilter -and $name -notin $NameFilter) { continue }

            if ($SkipMicrosoftPublisher -and ([string]$item.publisher -eq 'Microsoft')) {
                Write-Verbose "[$ObjectType] Skipping Microsoft built-in script '$name' (read-only)."
                continue
            }

            # Build body from explicit BodyFields list. Skip null/empty content fields so we don't
            # blank out a script body if the backup happens to lack base64 content.
            $body = [ordered]@{}
            foreach ($field in $BodyFields) {
                if ($item.PSObject.Properties.Name -notcontains $field) { continue }
                $val = $item.$field
                if (($field -in $ContentFields) -and [string]::IsNullOrWhiteSpace([string]$val)) { continue }
                $body[$field] = $val
            }

            if ($RemapConfig) {
                $body = Invoke-BackupRemap -InputObject $body -RemapConfig $RemapConfig
            }

            if ((Get-ObjectFieldCount -InputObject $body) -eq 0) {
                Write-Warning "[$ObjectType] Skipping '$name': no restorable fields in backup."
                Write-RestoreOperationLog -Workload 'Intune' -ObjectType $ObjectType -Name $name -Action 'Review' -Status 'Skipped' -RequestedBody $body -ErrorMessage 'No restorable fields in backup.'
                continue
            }

            $match = Find-MatchByDisplayName -BackupItem $item -CurrentItems $currentItems
            $shouldProcessTarget = "${label}:$name"

            if (-not $match) {
                if ($CallerCmdlet.ShouldProcess($shouldProcessTarget, 'Create')) {
                    try {
                        Invoke-MgGraphRequest -Uri $CollectionUri -Method POST `
                            -Body ($body | ConvertTo-Json -Depth 30) -ContentType 'application/json' -ErrorAction Stop | Out-Null
                        Write-RestoreOperationLog -Workload 'Intune' -ObjectType $ObjectType -Name $name -Action 'Create' -Status 'Success' -RequestedBody $body
                        Write-Verbose "[$ObjectType] Created '$name'."
                    }
                    catch {
                        Write-RestoreOperationLog -Workload 'Intune' -ObjectType $ObjectType -Name $name -Action 'Create' -Status 'Failed' -RequestedBody $body -ErrorMessage $_.Exception.Message
                        Add-ApplyFailure -Message "[$ObjectType] Failed to create '$name': $($_.Exception.Message)"
                        Write-Warning "[$ObjectType] Failed to create '$name': $($_.Exception.Message)"
                    }
                }
                continue
            }

            if ($CallerCmdlet.ShouldProcess($shouldProcessTarget, 'Restore')) {
                $uri = "$CollectionUri/$([string]$match.id)"
                try {
                    Invoke-MgGraphRequest -Uri $uri -Method PATCH `
                        -Body ($body | ConvertTo-Json -Depth 30) -ContentType 'application/json' -ErrorAction Stop | Out-Null
                    Write-RestoreOperationLog -Workload 'Intune' -ObjectType $ObjectType -Name $name -Action 'Update' -Status 'Success' -TargetId ([string]$match.id) -PreviousState $match -RequestedBody $body
                    Write-Verbose "[$ObjectType] Restored '$name'."
                }
                catch {
                    Write-RestoreOperationLog -Workload 'Intune' -ObjectType $ObjectType -Name $name -Action 'Update' -Status 'Failed' -TargetId ([string]$match.id) -PreviousState $match -RequestedBody $body -ErrorMessage $_.Exception.Message
                    Add-ApplyFailure -Message "[$ObjectType] Failed to restore '$name': $($_.Exception.Message)"
                    Write-Warning "[$ObjectType] Failed to restore '$name': $($_.Exception.Message)"
                }
            }
        }
    }

    # ── main loop ─────────────────────────────────────────────────────────────

    foreach ($workload in $Workloads) {
        $workloadPath = Join-Path -Path $BackupPath -ChildPath $workload
        if (-not (Test-Path -Path $workloadPath)) {
            Write-Warning "Workload path not found, skipping: $workloadPath"
            continue
        }

        switch ($workload) {
            'ExchangeOnline' {
                $acceptedDomainFile = Join-Path -Path $workloadPath -ChildPath 'AcceptedDomains.json'
                if (Test-Path -Path $acceptedDomainFile) {
                    $acceptedDomains = Get-Content -Path $acceptedDomainFile -Raw | ConvertFrom-Json
                    foreach ($domain in $acceptedDomains) {
                        if ($ObjectNames -and $domain.Name -notin $ObjectNames) { continue }

                        if ($PSCmdlet.ShouldProcess("AcceptedDomain:$($domain.Name)", 'Restore accepted domain')) {
                            try {
                                $domainName = if ($RemapConfig) { Invoke-BackupStringRemap -Value ([string]$domain.DomainName) -RemapConfig $RemapConfig } else { [string]$domain.DomainName }
                                if (-not (Get-AcceptedDomain -Identity $domain.Name -ErrorAction SilentlyContinue)) {
                                    New-AcceptedDomain -Name $domain.Name -DomainName $domainName -DomainType $domain.DomainType | Out-Null
                                    Write-RestoreOperationLog -Workload 'ExchangeOnline' -ObjectType 'AcceptedDomains' -Name ([string]$domain.Name) -Action 'Create' -Status 'Success' -RequestedBody @{ Name = $domain.Name; DomainName = $domainName; DomainType = $domain.DomainType }
                                }
                            }
                            catch {
                                Write-RestoreOperationLog -Workload 'ExchangeOnline' -ObjectType 'AcceptedDomains' -Name ([string]$domain.Name) -Action 'Create' -Status 'Failed' -RequestedBody @{ Name = $domain.Name; DomainName = $domain.DomainName; DomainType = $domain.DomainType } -ErrorMessage $_.Exception.Message
                                Add-ApplyFailure -Message "Failed restoring accepted domain [$($domain.Name)]: $($_.Exception.Message)"
                                Write-Warning "Failed restoring accepted domain [$($domain.Name)]: $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }

            'Teams' {
                Write-Warning 'Teams restore currently applies a minimal safe subset of policy settings and should be expanded per tenant standards.'
                $meetingFile = Join-Path -Path $workloadPath -ChildPath 'MeetingPolicies.json'
                if (Test-Path -Path $meetingFile) {
                    $meetingPolicies = Get-Content -Path $meetingFile -Raw | ConvertFrom-Json
                    foreach ($policy in $meetingPolicies) {
                        if ($ObjectNames -and $policy.Identity -notin $ObjectNames) { continue }

                        if ($PSCmdlet.ShouldProcess("TeamsMeetingPolicy:$($policy.Identity)", 'Restore Teams meeting policy')) {
                            try {
                                Set-CsTeamsMeetingPolicy -Identity $policy.Identity -AllowCloudRecording $policy.AllowCloudRecording -ErrorAction Stop
                                Write-RestoreOperationLog -Workload 'Teams' -ObjectType 'MeetingPolicies' -Name ([string]$policy.Identity) -Action 'Update' -Status 'Success' -RequestedBody @{ Identity = $policy.Identity; AllowCloudRecording = $policy.AllowCloudRecording }
                            }
                            catch {
                                Write-RestoreOperationLog -Workload 'Teams' -ObjectType 'MeetingPolicies' -Name ([string]$policy.Identity) -Action 'Update' -Status 'Failed' -RequestedBody @{ Identity = $policy.Identity; AllowCloudRecording = $policy.AllowCloudRecording } -ErrorMessage $_.Exception.Message
                                Add-ApplyFailure -Message "Failed restoring Teams meeting policy [$($policy.Identity)]: $($_.Exception.Message)"
                                Write-Warning "Failed restoring Teams meeting policy [$($policy.Identity)]: $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }

            'Intune' {
                $anyTypeEnabled = $false

                # CompliancePolicies
                if (Test-ObjectTypeEnabled -WOT $WorkloadObjectTypes -Workload 'Intune' -ObjectType 'CompliancePolicies') {
                    $anyTypeEnabled = $true
                    Invoke-IntuneRestore -ObjectType 'CompliancePolicies' -WorkloadPath $workloadPath `
                        -GetUri '/beta/deviceManagement/deviceCompliancePolicies' `
                        -PatchUriTemplate '/beta/deviceManagement/deviceCompliancePolicies/{id}' `
                        -ExtraReadOnlyFields @('scheduledActionsForRule', 'deviceStatuses', 'userStatuses') `
                        -ActionLabel 'Intune/CompliancePolicy' -CallerCmdlet $PSCmdlet -NameFilter $ObjectNames
                }

                # ConfigurationProfiles
                if (Test-ObjectTypeEnabled -WOT $WorkloadObjectTypes -Workload 'Intune' -ObjectType 'ConfigurationProfiles') {
                    $anyTypeEnabled = $true
                    Invoke-IntuneRestore -ObjectType 'ConfigurationProfiles' -WorkloadPath $workloadPath `
                        -GetUri '/beta/deviceManagement/deviceConfigurations' `
                        -PatchUriTemplate '/beta/deviceManagement/deviceConfigurations/{id}' `
                        -CreateUri '/beta/deviceManagement/deviceConfigurations' `
                        -AssignUriTemplate '/beta/deviceManagement/deviceConfigurations/{id}/assign' `
                        -ExtraReadOnlyFields @('deviceStatuses', 'userStatuses', 'deviceStatusOverview', 'userStatusOverview', 'supportsScopeTags', 'deviceManagementApplicabilityRuleOsVersion', 'deviceManagementApplicabilityRuleDeviceMode', 'deviceManagementApplicabilityRuleOsEdition', 'assignments@odata.context', 'featureUpdatesRollbackStartDateTime', 'qualityUpdatesRollbackStartDateTime', 'featureUpdatesPauseExpiryDateTime', 'qualityUpdatesPauseExpiryDateTime', 'featureUpdatesPauseStartDate', 'qualityUpdatesPauseStartDate') `
                        -ActionLabel 'Intune/ConfigurationProfile' -CallerCmdlet $PSCmdlet -NameFilter $ObjectNames
                }

                # SettingsCatalogPolicies
                if (Test-ObjectTypeEnabled -WOT $WorkloadObjectTypes -Workload 'Intune' -ObjectType 'SettingsCatalogPolicies') {
                    $anyTypeEnabled = $true
                    # Settings catalog PATCH supports name/description/roleScopeTagIds; settings are a separate sub-resource.
                    $backupPolicies = Read-BackupJson -Path (Join-Path $workloadPath 'SettingsCatalogPolicies.json')
                    if (@($backupPolicies).Count -gt 0) {
                        try {
                            $currentResp = Invoke-MgGraphRequest -Uri '/beta/deviceManagement/configurationPolicies' -Method GET -ErrorAction Stop
                            $currentPolicies = if ($currentResp.value) { @($currentResp.value) } else { @() }
                        }
                        catch {
                            Add-ApplyFailure -Message "[SettingsCatalogPolicies] Failed to retrieve current policies: $($_.Exception.Message)"
                            Write-Warning "[SettingsCatalogPolicies] Failed to retrieve current policies: $($_.Exception.Message)"
                            $currentPolicies = @()
                        }

                        foreach ($policy in $backupPolicies) {
                            $name = [string]$policy.name
                            if ([string]::IsNullOrWhiteSpace($name)) { continue }
                            if ($ObjectNames -and $name -notin $ObjectNames) { continue }

                            $match = $currentPolicies | Where-Object { [string]$_.name -eq $name } | Select-Object -First 1
                            if (-not $match) {
                                Write-Warning "[SettingsCatalogPolicies] No match for '$name', skipping."
                                continue
                            }

                            if ($PSCmdlet.ShouldProcess("Intune/SettingsCatalogPolicy:$name", 'Restore')) {
                                # PATCH metadata (name, description, roleScopeTagIds)
                                $metaBody = @{
                                    name             = $policy.name
                                    description      = $policy.description
                                    roleScopeTagIds  = $policy.roleScopeTagIds
                                }
                                try {
                                    Invoke-MgGraphRequest -Uri "/beta/deviceManagement/configurationPolicies/$([string]$match.id)" `
                                        -Method PATCH -Body ($metaBody | ConvertTo-Json -Depth 10) -ContentType 'application/json' -ErrorAction Stop | Out-Null
                                    Write-Verbose "[SettingsCatalogPolicies] Restored metadata for '$name'."
                                }
                                catch {
                                    Add-ApplyFailure -Message "[SettingsCatalogPolicies] Failed to restore metadata for '$name': $($_.Exception.Message)"
                                    Write-Warning "[SettingsCatalogPolicies] Failed to restore metadata for '$name': $($_.Exception.Message)"
                                }

                                # PATCH settings sub-resource if backup has them
                                if ($policy.PSObject.Properties.Name -contains 'settings' -and $policy.settings) {
                                    $settingsBody = @{ settings = $policy.settings }
                                    try {
                                        Invoke-MgGraphRequest -Uri "/beta/deviceManagement/configurationPolicies/$([string]$match.id)/settings" `
                                            -Method PATCH -Body ($settingsBody | ConvertTo-Json -Depth 50) -ContentType 'application/json' -ErrorAction Stop | Out-Null
                                        Write-Verbose "[SettingsCatalogPolicies] Restored settings for '$name'."
                                    }
                                    catch {
                                        Add-ApplyFailure -Message "[SettingsCatalogPolicies] Failed to restore settings for '$name': $($_.Exception.Message)"
                                        Write-Warning "[SettingsCatalogPolicies] Failed to restore settings for '$name': $($_.Exception.Message)"
                                    }
                                }
                            }
                        }
                    }
                }

                # UpdateRings
                if (Test-ObjectTypeEnabled -WOT $WorkloadObjectTypes -Workload 'Intune' -ObjectType 'UpdateRings') {
                    $anyTypeEnabled = $true
                    Invoke-IntuneRestore -ObjectType 'UpdateRings' -WorkloadPath $workloadPath `
                        -GetUri '/beta/deviceManagement/deviceConfigurations?$filter=isof(''microsoft.graph.windowsUpdateForBusinessConfiguration'')' `
                        -PatchUriTemplate '/beta/deviceManagement/deviceConfigurations/{id}' `
                        -AssignUriTemplate '/beta/deviceManagement/deviceConfigurations/{id}/assign' `
                        -ExtraReadOnlyFields @('deviceStatuses', 'userStatuses', 'deviceStatusOverview', 'userStatusOverview', 'supportsScopeTags', 'deviceManagementApplicabilityRuleOsVersion', 'deviceManagementApplicabilityRuleDeviceMode', 'deviceManagementApplicabilityRuleOsEdition', 'assignments@odata.context', 'featureUpdatesRollbackStartDateTime', 'qualityUpdatesRollbackStartDateTime', 'featureUpdatesPauseExpiryDateTime', 'qualityUpdatesPauseExpiryDateTime', 'featureUpdatesPauseStartDate', 'qualityUpdatesPauseStartDate') `
                        -ActionLabel 'Intune/UpdateRing' -CallerCmdlet $PSCmdlet -NameFilter $ObjectNames
                }

                # AutopilotProfiles
                if (Test-ObjectTypeEnabled -WOT $WorkloadObjectTypes -Workload 'Intune' -ObjectType 'AutopilotProfiles') {
                    $anyTypeEnabled = $true
                    Invoke-IntuneRestore -ObjectType 'AutopilotProfiles' -WorkloadPath $workloadPath `
                        -GetUri '/beta/deviceManagement/windowsAutopilotDeploymentProfiles' `
                        -PatchUriTemplate '/beta/deviceManagement/windowsAutopilotDeploymentProfiles/{id}' `
                        -ExtraReadOnlyFields @('managedDevices', 'assignedDevices') `
                        -ActionLabel 'Intune/AutopilotProfile' -CallerCmdlet $PSCmdlet -NameFilter $ObjectNames
                }

                # AssignmentFilters
                if (Test-ObjectTypeEnabled -WOT $WorkloadObjectTypes -Workload 'Intune' -ObjectType 'AssignmentFilters') {
                    $anyTypeEnabled = $true
                    Invoke-IntuneRestore -ObjectType 'AssignmentFilters' -WorkloadPath $workloadPath `
                        -GetUri '/beta/deviceManagement/assignmentFilters' `
                        -PatchUriTemplate '/beta/deviceManagement/assignmentFilters/{id}' `
                        -ExtraReadOnlyFields @('payloadTypes', 'contextDeviceTypes') `
                        -ActionLabel 'Intune/AssignmentFilter' -CallerCmdlet $PSCmdlet -NameFilter $ObjectNames
                }

                # DeviceManagementComplianceSettings (single global settings object)
                if (Test-ObjectTypeEnabled -WOT $WorkloadObjectTypes -Workload 'Intune' -ObjectType 'DeviceManagementComplianceSettings') {
                    $anyTypeEnabled = $true
                    $settingsFile = Join-Path $workloadPath 'DeviceManagementComplianceSettings.json'
                    $backupSettings = Read-BackupJson -Path $settingsFile
                    if (@($backupSettings).Count -gt 0) {
                        $settingsObj = $backupSettings[0]
                        if ($PSCmdlet.ShouldProcess('Intune/DeviceManagementComplianceSettings', 'Restore')) {
                            $body = Remove-ReadOnlyIntuneFields -Item $settingsObj
                            if ($RemapConfig) {
                                $body = Invoke-BackupRemap -InputObject $body -RemapConfig $RemapConfig
                            }
                            try {
                                Invoke-MgGraphRequest -Uri '/beta/deviceManagement/settings' -Method PATCH `
                                    -Body ($body | ConvertTo-Json -Depth 10) -ContentType 'application/json' -ErrorAction Stop | Out-Null
                                Write-RestoreOperationLog -Workload 'Intune' -ObjectType 'DeviceManagementComplianceSettings' -Name 'DeviceManagementComplianceSettings' -Action 'Update' -Status 'Success' -RequestedBody $body
                                Write-Verbose '[DeviceManagementComplianceSettings] Restored.'
                            }
                            catch {
                                Write-RestoreOperationLog -Workload 'Intune' -ObjectType 'DeviceManagementComplianceSettings' -Name 'DeviceManagementComplianceSettings' -Action 'Update' -Status 'Failed' -RequestedBody $body -ErrorMessage $_.Exception.Message
                                Add-ApplyFailure -Message "[DeviceManagementComplianceSettings] Failed to restore: $($_.Exception.Message)"
                                Write-Warning "[DeviceManagementComplianceSettings] Failed to restore: $($_.Exception.Message)"
                            }
                        }
                    }
                }

                if (Test-ObjectTypeEnabled -WOT $WorkloadObjectTypes -Workload 'Intune' -ObjectType 'Scripts') {
                    $anyTypeEnabled = $true
                    Invoke-IntuneScriptRestore -ObjectType 'Scripts' -WorkloadPath $workloadPath `
                        -BackupFile 'DeviceManagementScripts.json' `
                        -CollectionUri '/beta/deviceManagement/deviceManagementScripts' `
                        -ContentFields @('scriptContent') `
                        -BodyFields @('displayName','description','runAsAccount','fileName','scriptContent','enforceSignatureCheck','runAs32Bit','roleScopeTagIds') `
                        -ActionLabel 'Intune/Script' -CallerCmdlet $PSCmdlet -NameFilter $ObjectNames
                }

                if (Test-ObjectTypeEnabled -WOT $WorkloadObjectTypes -Workload 'Intune' -ObjectType 'DeviceHealthScripts') {
                    $anyTypeEnabled = $true
                    Invoke-IntuneScriptRestore -ObjectType 'DeviceHealthScripts' -WorkloadPath $workloadPath `
                        -BackupFile 'DeviceHealthScripts.json' `
                        -CollectionUri '/beta/deviceManagement/deviceHealthScripts' `
                        -ContentFields @('detectionScriptContent','remediationScriptContent') `
                        -BodyFields @('displayName','description','publisher','runAsAccount','enforceSignatureCheck','runAs32Bit','detectionScriptContent','remediationScriptContent','roleScopeTagIds','deviceHealthScriptType') `
                        -SkipMicrosoftPublisher `
                        -ActionLabel 'Intune/DeviceHealthScript' -CallerCmdlet $PSCmdlet -NameFilter $ObjectNames
                }

                if (Test-ObjectTypeEnabled -WOT $WorkloadObjectTypes -Workload 'Intune' -ObjectType 'ShellScripts') {
                    $anyTypeEnabled = $true
                    Invoke-IntuneScriptRestore -ObjectType 'ShellScripts' -WorkloadPath $workloadPath `
                        -BackupFile 'ShellScripts.json' `
                        -CollectionUri '/beta/deviceManagement/deviceShellScripts' `
                        -ContentFields @('scriptContent') `
                        -BodyFields @('displayName','description','fileName','scriptContent','runAsAccount','blockExecutionNotifications','executionFrequency','retryCount','roleScopeTagIds') `
                        -ActionLabel 'Intune/ShellScript' -CallerCmdlet $PSCmdlet -NameFilter $ObjectNames
                }

                if (Test-ObjectTypeEnabled -WOT $WorkloadObjectTypes -Workload 'Intune' -ObjectType 'DeviceComplianceScripts') {
                    $anyTypeEnabled = $true
                    Invoke-IntuneScriptRestore -ObjectType 'DeviceComplianceScripts' -WorkloadPath $workloadPath `
                        -BackupFile 'DeviceComplianceScripts.json' `
                        -CollectionUri '/beta/deviceManagement/deviceComplianceScripts' `
                        -ContentFields @('detectionScriptContent') `
                        -BodyFields @('displayName','description','publisher','detectionScriptContent','runAsAccount','enforceSignatureCheck','runAs32Bit','roleScopeTagIds') `
                        -ActionLabel 'Intune/DeviceComplianceScript' -CallerCmdlet $PSCmdlet -NameFilter $ObjectNames
                }

                if (-not $anyTypeEnabled) {
                    Write-Warning "Restore for [Intune] is export-first and requires custom mapping/approval before apply."
                }
            }

            default {
                Write-Warning "Restore for [$workload] is export-first and requires custom mapping/approval before apply."
            }
        }
    }

    if ($applyFailures.Count -gt 0) {
        $summary = ($applyFailures | Select-Object -First 10) -join '; '
        throw "Restore apply completed with $($applyFailures.Count) failure(s). $summary"
    }
}
