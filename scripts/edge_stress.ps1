param(
    [Parameter(Mandatory = $true)][string]$BaseUrl,
    [Parameter(Mandatory = $true)][string]$Token,
    [int]$TotalJobs = 200,
    [int]$Parallel = 20,
    [string]$WasmUrl = "",
    [string]$WasmPath = "",
    [string]$AppId = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($WasmUrl) -and [string]::IsNullOrWhiteSpace($WasmPath) -and [string]::IsNullOrWhiteSpace($AppId)) {
    throw "Provide one of -WasmUrl / -WasmPath / -AppId"
}

$headers = @{
    "Authorization" = "Bearer $Token"
    "Content-Type"  = "application/json"
}

function Submit-EdgeJob {
    param(
        [int]$Index,
        [string]$Base,
        [hashtable]$Headers,
        [string]$Url,
        [string]$Path,
        [string]$App
    )

    $body = @{
        function = "_start"
        args = @("stress", "$Index")
        env = @{ EDGE_STRESS = "1"; EDGE_JOB_INDEX = "$Index" }
        priority = 0
        timeout_ms = 30000
        max_retries = 1
    }

    if (-not [string]::IsNullOrWhiteSpace($Url)) { $body.wasm_url = $Url }
    if (-not [string]::IsNullOrWhiteSpace($Path)) { $body.wasm_path = $Path }
    if (-not [string]::IsNullOrWhiteSpace($App)) { $body.app_id = $App }

    $resp = Invoke-RestMethod -Method Post -Uri "$Base/api/v1/edge/jobs/submit" -Headers $Headers -Body ($body | ConvertTo-Json -Depth 10)
    return $resp.job_id
}

Write-Host "[1/4] Warmup health check..."
$health = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/v1/edge/health"
Write-Host ("Edge health: " + ($health.status))

Write-Host "[2/4] Submitting $TotalJobs jobs with parallelism $Parallel ..."
$submitted = [System.Collections.Concurrent.ConcurrentBag[string]]::new()

$pool = [RunspaceFactory]::CreateRunspacePool(1, $Parallel)
$pool.Open()
$jobs = @()

for ($i = 1; $i -le $TotalJobs; $i++) {
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool

    [void]$ps.AddScript(${function:Submit-EdgeJob}.ToString())
    [void]$ps.AddStatement()
    [void]$ps.AddCommand("Submit-EdgeJob")
    [void]$ps.AddParameter("Index", $i)
    [void]$ps.AddParameter("Base", $BaseUrl)
    [void]$ps.AddParameter("Headers", $headers)
    [void]$ps.AddParameter("Url", $WasmUrl)
    [void]$ps.AddParameter("Path", $WasmPath)
    [void]$ps.AddParameter("App", $AppId)

    $handle = $ps.BeginInvoke()
    $jobs += [PSCustomObject]@{ PS = $ps; Handle = $handle }
}

foreach ($j in $jobs) {
    try {
        $result = $j.PS.EndInvoke($j.Handle)
        if ($result) {
            [void]$submitted.Add($result[0].ToString())
        }
    } catch {
        Write-Warning "Submit failed: $($_.Exception.Message)"
    } finally {
        $j.PS.Dispose()
    }
}
$pool.Close()
$pool.Dispose()

Write-Host ("Submitted jobs: " + $submitted.Count)

Write-Host "[3/4] Polling completion..."
$timeoutAt = (Get-Date).AddMinutes(20)
$lastPrint = Get-Date

while ((Get-Date) -lt $timeoutAt) {
    $stats = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/v1/edge/stats" -Headers $headers

    if (((Get-Date) - $lastPrint).TotalSeconds -ge 2) {
        Write-Host ("pending=" + $stats.jobs_pending + " running=" + $stats.jobs_running + " completed=" + $stats.jobs_completed + " failed=" + $stats.jobs_failed + " cancelled=" + $stats.jobs_cancelled)
        $lastPrint = Get-Date
    }

    if (($stats.jobs_pending -eq 0) -and ($stats.jobs_running -eq 0)) {
        break
    }
    Start-Sleep -Milliseconds 800
}

Write-Host "[4/4] Final verification and summary..."
$all = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/v1/edge/jobs?limit=1000" -Headers $headers

$completed = 0
$failed = 0
$cancelled = 0
foreach ($it in $all.items) {
    switch ($it.status) {
        "completed" { $completed++ }
        "failed" { $failed++ }
        "cancelled" { $cancelled++ }
    }
}

Write-Host "========== EDGE STRESS SUMMARY =========="
Write-Host ("Total jobs queried: " + $all.total)
Write-Host ("Completed: " + $completed)
Write-Host ("Failed: " + $failed)
Write-Host ("Cancelled: " + $cancelled)
Write-Host "========================================="

if ($failed -gt 0) {
    throw "Stress test finished with failures"
}
