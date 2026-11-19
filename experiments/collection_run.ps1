param(
    [Parameter(Mandatory=$true)][ValidateSet('COLLECTION','FUNCTIONAL_TEST')][string]$Purpose,
    [Parameter(Mandatory=$true)][string]$Plan,
    [Parameter(Mandatory=$true)][string]$RunId,
    [Parameter(Mandatory=$true)][string]$BaselinePolicySha256,
    [string]$Manifest,
    [switch]$RecordCommit,
    [string]$CommitTrailer = ''
)
# Gate 5C one-run orchestrator (serial; one invocation = one run; never starts a substitute itself).
# Order: runtime/Git preflight -> read-only pre-audit -> detached publisher-only workload (waits for
# observer coverage) -> observer (COLLECTION through observation_collect.ps1) -> read-only post-audit
# -> offline reconciliation -> COLLECTION: append RUN_COLLECTED/RUN_VOIDED -> -RecordCommit: commit +
# push the manifest path only and verify HEAD == origin/master on a clean tree (controller decision C5).
# Exit: 0 ACCEPT/complete, 4 VOID recorded, 3 STOP (nothing more may run until reviewed), 2 refused.
# It never builds, pulls, restarts the broker, mutates policy, prunes or deletes evidence.
$ErrorActionPreference = 'Stop'
$root = 'C:/Projects/AZTA'
$compose = @('compose', '-p', 'azta-journal', '-f', 'compose.yaml', '-f', 'compose.observation.yaml')
function Stop-Run([string]$message) { Write-Output "CAMPAIGN_STOP $RunId $message"; exit 3 }
if ($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') { Write-Output 'REFUSED invalid run id'; exit 2 }
if ($BaselinePolicySha256 -notmatch '^[0-9a-f]{64}$') { Write-Output 'REFUSED baseline policy digest'; exit 2 }
if (($Purpose -eq 'COLLECTION') -ne [bool]$Manifest) { Write-Output 'REFUSED COLLECTION requires -Manifest; FUNCTIONAL_TEST forbids it'; exit 2 }
if ($RecordCommit -and $Purpose -ne 'COLLECTION') { Write-Output 'REFUSED -RecordCommit is for COLLECTION only'; exit 2 }
$planRel = $Plan -replace '\\','/'
if ($planRel -notmatch '^configs/collection_plans/[A-Za-z0-9_-]+\.json$') { Write-Output 'REFUSED plan path'; exit 2 }
Set-Location -LiteralPath $root
if ((git rev-parse --show-toplevel) -replace '\\','/' -ne $root) { Write-Output 'REFUSED workspace'; exit 2 }
$planJson = Get-Content -LiteralPath $planRel -Raw | ConvertFrom-Json
$runConfig = $planJson.runs.$RunId
if (-not $runConfig) { Write-Output 'REFUSED run is not in the plan'; exit 2 }
$windowMs = [int]$runConfig.window_duration_ms
$windowCount = [int]$runConfig.planned_window_count
# One new directory per attempt, so an early STOP never blocks or overwrites a later attempt's log.
$logDir = "results/raw/collection-orchestrator/$RunId-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))"
New-Item -ItemType Directory -Path $logDir -ErrorAction Stop | Out-Null  # fails if it already exists

# ---- Git preflight (COLLECTION) --------------------------------------------------------
if ($Purpose -eq 'COLLECTION') {
    git fetch origin
    if ($LASTEXITCODE -ne 0) { Stop-Run 'git fetch failed' }
    if ((git rev-parse HEAD) -ne (git rev-parse origin/master)) { Stop-Run 'HEAD differs from origin/master' }
    if (git status --porcelain) { Stop-Run 'working tree not clean' }
    $dry = & "$PSScriptRoot/observation_collect.ps1" -Manifest $Manifest -RunId $RunId -WindowDurationMs $windowMs `
        -WindowCount $windowCount -BindingAuditRef "$RunId-audit-pre" -DryRun | ConvertFrom-Json
    if ($dry.result -ne 'DRYRUN_ACCEPTED') { Stop-Run 'wrapper dry run refused' }
    $gitCommit = $dry.git_commit
    $manifestSha = $dry.manifest_sha256
}

# ---- runtime preflight -----------------------------------------------------------------
$image = docker image inspect --format '{{.Id}}' azta-journal-runtime:gate3
if ($LASTEXITCODE -ne 0) { Stop-Run 'accepted runtime image missing (no build performed)' }
# Names only: Windows PowerShell 5.1 strips embedded double quotes from native arguments.
$running = @(docker ps --filter 'label=com.docker.compose.project=azta-journal' --format '{{.Names}}')
if ($LASTEXITCODE -ne 0) { Stop-Run 'docker ps failed' }
if ($running.Count -ne 1 -or $running[0] -ne 'azta-journal-broker-1') { Stop-Run "unexpected project containers: $($running -join ',')" }
$others = @(docker ps --format '{{.Names}}' | Where-Object { $_ -match 'azta' -and $_ -notmatch 'broker' })
if ($others.Count -gt 0) { Stop-Run "unexpected AZTA containers: $($others -join ',')" }
"pre: image=$image running=$($running -join ',') utc=$((Get-Date).ToUniversalTime().ToString('o'))" | Out-File "$logDir/orchestrator.log" -Encoding utf8

function Invoke-Audit([string]$stage) {
    $ref = "$RunId-audit-$stage"
    $out = & docker @($compose + @('--profile', 'operator', 'run', '--rm', '--no-deps', '-T', 'binding-audit', '--run-id', $ref))
    $code = $LASTEXITCODE
    "audit-$stage exit=$code $out" | Out-File "$logDir/orchestrator.log" -Append -Encoding utf8
    $path = "results/raw/$ref/binding_audit.json"
    if ($code -ne 0 -or -not (Test-Path -LiteralPath $path)) { return $null }
    return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
}

$pre = Invoke-Audit 'pre'
if (-not $pre -or $pre.verdict -ne 'PASS' -or $pre.policy_sha256 -ne $BaselinePolicySha256) {
    Stop-Run 'pre-run binding audit failed or policy digest differs from the campaign baseline; no workload started'
}

# ---- workload (detached; it waits for the observer's COVERAGE_START before connecting) ------
$workloadName = "azta-g5c-wl-$RunId"
$envArgs = @('-e', "AZTA_RUNTIME_IMAGE=$image")
$workloadArgs = @('--purpose', $Purpose, '--plan', "/app/$planRel", '--run-id', $RunId)
if ($Purpose -eq 'COLLECTION') {
    $envArgs += @('-e', "AZTA_GIT_COMMIT=$gitCommit", '-e', 'AZTA_GIT_STATE=clean', '-e', "AZTA_MANIFEST_SHA256=$manifestSha")
    $workloadArgs += @('--manifest', "/app/$Manifest")
}
$null = & docker @($compose + @('--profile', 'collection', 'run', '-d', '--no-deps', '-T', '--name', $workloadName) + $envArgs + @('collection-workload') + $workloadArgs)
if ($LASTEXITCODE -ne 0) { Stop-Run 'workload container did not start' }

# ---- observer --------------------------------------------------------------------------
$observerFailed = $false
try {
    if ($Purpose -eq 'COLLECTION') {
        & "$PSScriptRoot/observation_collect.ps1" -Manifest $Manifest -RunId $RunId -WindowDurationMs $windowMs `
            -WindowCount $windowCount -BindingAuditRef "$RunId-audit-pre" | Out-File "$logDir/observer.log" -Encoding utf8
    } else {
        & docker @($compose + @('--profile', 'observation', 'run', '--rm', '--no-deps', '-T', '-e', "AZTA_RUNTIME_IMAGE=$image",
            'observation', '--purpose', 'FUNCTIONAL_TEST', '--collection-run-id', $RunId, '--window-duration-ms', "$windowMs",
            '--window-count', "$windowCount", '--binding-audit-ref', "$RunId-audit-pre")) | Out-File "$logDir/observer.log" -Encoding utf8
        if ($LASTEXITCODE -ne 0) { $observerFailed = $true }
    }
} catch {
    $observerFailed = $true
    "observer error: $($_.Exception.Message)" | Out-File "$logDir/orchestrator.log" -Append -Encoding utf8
}
$workloadExit = docker wait $workloadName
docker logs $workloadName | Out-File "$logDir/workload.log" -Encoding utf8
$null = docker rm $workloadName
"observer_failed=$observerFailed workload_exit=$workloadExit" | Out-File "$logDir/orchestrator.log" -Append -Encoding utf8

$post = Invoke-Audit 'post'
$auditDrift = (-not $post) -or $post.verdict -ne 'PASS' -or $post.policy_sha256 -ne $BaselinePolicySha256

# ---- reconciliation / finalize (offline, no network, no secrets) -------------------------
$tools = $compose + @('--profile', 'collection', 'run', '--rm', '--no-deps', '-T', 'collection-tools')
$reconcile = @('experiments.collection_reconcile', '--run-id', $RunId, '--plan', "/app/$planRel", '--purpose', $Purpose,
    '--baseline-policy-sha256', $BaselinePolicySha256)
if ($Purpose -eq 'COLLECTION') { $reconcile += @('--manifest', "/app/$Manifest") }
$reconcileOut = & docker @($tools + $reconcile)
$reconcileCode = $LASTEXITCODE
"reconcile exit=$reconcileCode $reconcileOut" | Out-File "$logDir/orchestrator.log" -Append -Encoding utf8
Write-Output $reconcileOut
if ($reconcileCode -eq 2) { Stop-Run 'reconciliation could not run' }
$report = Get-Content -LiteralPath "results/raw/collection/$RunId/reconciliation.json" -Raw | ConvertFrom-Json
if ($report.verdict -eq 'NOT_STARTED') { Stop-Run 'run did not start; nothing recorded; the run stays planned' }

$verdict = $report.verdict
if ($Purpose -eq 'COLLECTION') {
    $finalOut = & docker @($tools + @('experiments.collection_finalize', 'record', '--run-id', $RunId,
        '--manifest', "/app/$Manifest", '--plan', "/app/$planRel"))
    $finalCode = $LASTEXITCODE
    "finalize exit=$finalCode $finalOut" | Out-File "$logDir/orchestrator.log" -Append -Encoding utf8
    Write-Output $finalOut
    if ($finalCode -ne 0 -and $finalCode -ne 4) { Stop-Run 'finalize failed; inspect the manifest before anything else' }
    if ($RecordCommit) {
        $message = "Record Gate 5C run $RunId $verdict"
        & "$PSScriptRoot/collection_record_commit.ps1" -RepoRoot $root -Manifest $Manifest -Message $message -Trailer $CommitTrailer
        if ($LASTEXITCODE -ne 0) { Stop-Run 'manifest commit/push/verify failed; do not start another run' }
    }
}
Write-Output "RUN_RESULT $RunId purpose=$Purpose verdict=$verdict campaign_stop=$($report.campaign_stop) review_flags=$(@($report.review_flags).Count)"
if ($report.campaign_stop -or $auditDrift) { Stop-Run 'campaign STOP condition (see reconciliation report)' }
if ($verdict -eq 'ACCEPT') { exit 0 }
exit 4
