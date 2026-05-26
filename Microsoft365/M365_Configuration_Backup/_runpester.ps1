Import-Module Pester -MinimumVersion 5.0
$cfg = New-PesterConfiguration
$cfg.Run.Path = '.\tests'
$cfg.Output.Verbosity = 'Detailed'
$cfg.TestResult.Enabled = $false
$cfg.Run.PassThru = $true
$r = Invoke-Pester -Configuration $cfg
"PASS=$($r.PassedCount) FAIL=$($r.FailedCount) SKIP=$($r.SkippedCount) TOTAL=$($r.TotalCount) DURATION=$($r.Duration)"
if ($r.Failed) { $r.Failed | ForEach-Object { "FAIL: $($_.ExpandedPath) :: $($_.ErrorRecord.Exception.Message)" } }
