param(
    [Parameter(Mandatory=$true)][ValidateSet('COLLECTION','FUNCTIONAL_TEST')][string]$Purpose,
    [Parameter(Mandatory=$true)][string]$Plan,
    [Parameter(Mandatory=$true)][string]$RunId,
    [Parameter(Mandatory=$true)][string]$BaselinePolicySha256,
    # Explicit, no defaults: the identity-audit cadence and the margin before the end of coverage are controller decisions.
    [Parameter(Mandatory=$true)][ValidateRange(0,3600)][int]$AuditIntervalSeconds,
    [Parameter(Mandatory=$true)][ValidateRange(1,3600)][int]$AuditEdgeMarginSeconds,
    [string]$ExpectedPartition = '',
    [string]$Manifest = '',
    [string]$ExpectedGitHead = '',
    [switch]$RecordCommit,
    [string]$CommitTrailer = '',
    [string]$RepoRoot = 'C:/Projects/AZTA',
    [switch]$DryRun
)
# Gate 5F.3 workload-v2 one-run orchestrator (PREPARED, NEVER RUN; an unapproved engineering candidate; serial; one invocation = one
# run; it never starts a substitute itself). Order: preflight -> read-only audit `pre` -> detached publisher-only workload (it waits for
# observer coverage) -> detached observer -> read-only audits `p01`, `p02`, ... at the declared cadence, anchored at the observer's own
# COVERAGE_START -> read-only audit `post` -> offline reconciliation (verifies the cadence from the pinned capture instants) ->
# COLLECTION: append RUN_COLLECTED/RUN_VOIDED -> -RecordCommit: LOCAL commit of the manifest path only.
# Differences from the frozen v1 orchestrator, all deliberate:
#   * no `git fetch` and no `git push`: COLLECTION requires -ExpectedGitHead; FUNCTIONAL_TEST can pin a reviewed rehearsal commit
#     with the same option. When pinned, HEAD must equal it and the working tree must be clean. Pushing is a separate decision.
#   * -ExpectedPartition is mandatory for COLLECTION and must equal the plan's intended partition of the run, so a CAL_V2, D_shadow or
#     D_test run can never be started under the wrong label. It is checked before any Docker call and never printed into evidence.
#   * the plan must be a v2 plan that is APPROVED (a controller approval reference) for COLLECTION.
#   * -AuditIntervalSeconds (0 = pre/post only) and -AuditEdgeMarginSeconds have NO defaults; with a cadence the margin may not exceed it.
#   * extra shared-Docker safeguards: only the broker may be running in the project, no other AZTA container, no leftover container of
#     this tooling, and every container this script starts is removed by name (never by prune, filter or volume operation).
# -DryRun performs every refusal check that needs no Docker or network, prints the exact ordered command plan as JSON, and stops: it
# contacts neither Docker nor Git remotes and writes nothing.
# Exit: 0 ACCEPT/complete, 4 VOID recorded, 3 STOP (nothing more may run until reviewed), 2 refused.
# It never builds, pulls, restarts the broker, mutates policy, prunes or deletes evidence.
$ErrorActionPreference = 'Stop'
$root = $RepoRoot -replace '\\','/'
function Stop-Run([string]$message) { Write-Output "CAMPAIGN_STOP $RunId $message"; exit 3 }
function Refuse([string]$message) { Write-Output "REFUSED $message"; exit 2 }
if ($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') { Refuse 'invalid run id' }
if ($BaselinePolicySha256 -notmatch '^[0-9a-f]{64}$') { Refuse 'baseline policy digest' }
if (($Purpose -eq 'COLLECTION') -ne [bool]$Manifest) { Refuse 'COLLECTION requires -Manifest; FUNCTIONAL_TEST forbids it' }
if ($Purpose -eq 'COLLECTION') {
    if ($ExpectedGitHead -notmatch '^[0-9a-f]{40}$') { Refuse 'COLLECTION requires -ExpectedGitHead (the 40-hex controller-named freeze commit)' }
    if ($ExpectedPartition -notin @('CAL_V2', 'D_shadow', 'D_test')) { Refuse 'COLLECTION requires -ExpectedPartition CAL_V2, D_shadow or D_test' }
} elseif ($ExpectedPartition) { Refuse 'FUNCTIONAL_TEST forbids -ExpectedPartition' }
if ($ExpectedGitHead -and $ExpectedGitHead -notmatch '^[0-9a-f]{40}$') { Refuse 'ExpectedGitHead must be a full 40-hex commit' }
if ($RecordCommit -and $Purpose -ne 'COLLECTION') { Refuse '-RecordCommit is for COLLECTION only' }
if ($AuditIntervalSeconds -gt 0 -and $AuditEdgeMarginSeconds -gt $AuditIntervalSeconds) { Refuse 'the audit edge margin may not exceed the audit interval' }
$planRel = $Plan -replace '\\','/'
if ($planRel -notmatch '^configs/collection_plans/[A-Za-z0-9_-]+\.json$') { Refuse 'plan path' }
if (-not $DryRun -and $root -ne 'C:/Projects/AZTA') { Refuse 'a live run requires the AZTA workspace' }
Set-Location -LiteralPath $root
if ((git rev-parse --show-toplevel) -replace '\\','/' -ne $root) { Refuse 'workspace' }
$planJson = Get-Content -LiteralPath $planRel -Raw | ConvertFrom-Json
if ($planJson.schema -ne 'azta.collection.plan_candidate') { Refuse 'not a workload-v2 plan (the v1 orchestrator handles v1 plans)' }
$runConfig = $planJson.runs.$RunId
if (-not $runConfig) { Refuse 'run is not in the plan' }
if ($Purpose -eq 'COLLECTION') {
    if ($planJson.approval_status -ne 'APPROVED') { Refuse 'the plan is an UNAPPROVED_CANDIDATE; COLLECTION needs a controller approval reference' }
    $cell = @($planJson.cells | Where-Object { $_.run_id -eq $RunId })
    if ($cell.Count -ne 1) { Refuse 'run has no unique cell in the plan' }
    if ($cell[0].intended_partition -ne $ExpectedPartition) { Refuse 'expected partition differs from the plan; nothing started' }
} elseif ($planJson.kind -ne 'FUNCTIONAL_TEST') { Refuse 'FUNCTIONAL_TEST uses only a FUNCTIONAL_TEST plan' }
if ($Purpose -eq 'COLLECTION' -and ($Manifest -replace '\\', '/') -match '^configs/collection_manifests/[A-Za-z0-9_-]+\.jsonl$') {
    # A run id that already has a terminal manifest record is NEVER repeated (the container-side check repeats this, but only after containers
    # and audits have started): refuse before anything runs. A path outside the manifests directory is refused later by the observer wrapper.
    try {
        $terminal = @(Get-Content -LiteralPath $Manifest | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } |
            Where-Object { $_.collection_run_id -eq $RunId -and $_.entry_type -in @('RUN_COLLECTED', 'RUN_VOIDED', 'RUN_INVALIDATED') })
    } catch { Refuse 'the manifest is not readable as JSON lines' }
    if ($terminal.Count -gt 0) { Refuse "run already has a terminal manifest record ($($terminal[0].entry_type)); a collected, voided or invalidated run id is never repeated" }
}
$windowMs = [int]$runConfig.window_duration_ms
$windowCount = [int]$runConfig.planned_window_count
if ($windowMs -le 0 -or $windowCount -le 0) { Refuse 'plan window geometry' }
$coverageSeconds = $windowMs * $windowCount / 1000.0
if ($AuditIntervalSeconds -gt 0 -and [math]::Floor($coverageSeconds / $AuditIntervalSeconds) -gt 99) { Refuse 'cadence would exceed 99 periodic audits (stage names p01..p99)' }

# ---- Git preflight (COLLECTION): offline; HEAD must be the named freeze commit; clean tree ----------------------------
$gitCommit = ''
$manifestSha = ''
if ($Purpose -eq 'FUNCTIONAL_TEST') {
    $gitCommit = git rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { Refuse 'cannot establish Git HEAD' }
    if ($ExpectedGitHead -and $gitCommit -ne $ExpectedGitHead) { Refuse 'HEAD is not the controller-named rehearsal commit' }
    if ($ExpectedGitHead -and (git status --porcelain)) { Refuse 'working tree not clean' }
}
if ($Purpose -eq 'COLLECTION') {
    if ((git rev-parse HEAD) -ne $ExpectedGitHead) { Refuse 'HEAD is not the controller-named freeze commit' }
    if (git status --porcelain) { Refuse 'working tree not clean' }
    try {
        $dry = & "$PSScriptRoot/observation_collect_v2.ps1" -Manifest $Manifest -RunId $RunId -WindowDurationMs $windowMs `
            -WindowCount $windowCount -BindingAuditRef "$RunId-audit-pre" -ExpectedGitHead $ExpectedGitHead -RepoRoot $root -DryRun | ConvertFrom-Json
    } catch { Refuse "observer wrapper dry run refused: $($_.Exception.Message)" }
    if ($dry.result -ne 'DRYRUN_ACCEPTED') { Refuse 'observer wrapper dry run refused' }
    $gitCommit = $dry.git_commit
    $manifestSha = $dry.manifest_sha256
}

$compose = @('compose', '-p', 'azta-journal', '-f', 'compose.yaml', '-f', 'compose.observation.yaml',
    '-f', 'configs/gate5f3/compose.collection_v2.yaml')
# FUNCTIONAL_TEST evidence is isolated from every scientific observer session, including metadata discovery.
$evidenceRoot = 'results/raw'
$volumeArgs = @()
if ($Purpose -eq 'FUNCTIONAL_TEST') {
    $evidenceRoot = "results/raw/functional/$RunId"
    $volumeArgs = @('--volume', ($root + '/' + $evidenceRoot + ':/results'))
}
# Name-only listing of the observer sessions that exist NOW (nothing is opened) and its canonical digest. The orchestrator takes this boundary
# before it starts either container and hands it to the workload; the workload never takes its own (its start-up work is slower than the observer).
function Get-SessionSnapshot {
    $names = @()
    if (Test-Path -LiteralPath "$evidenceRoot/observation") { $names = @(Get-ChildItem -LiteralPath "$evidenceRoot/observation" -Directory -Name) }
    $sorted = [string[]]$names
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $text = (@($sorted | ForEach-Object { "$_`n" })) -join ''
    $sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($text))).Replace('-', '').ToLowerInvariant()
    return [pscustomobject]@{ names = $sorted; value = ('v1:' + ($sorted -join ',')); sha256 = $sha }
}
$workloadName = "azta-g5f3-wl-$RunId"
$observerName = "azta-g5f3-ob-$RunId"
$workloadArgs = @('--purpose', $Purpose, '--plan', "/app/$planRel", '--run-id', $RunId)
if ($Purpose -eq 'COLLECTION') { $workloadArgs += @('--manifest', "/app/$Manifest") }
$functionalObserverArgs = @('v2-observer', '--purpose', 'FUNCTIONAL_TEST', '--collection-run-id', $RunId,
    '--window-duration-ms', "$windowMs", '--window-count', "$windowCount", '--binding-audit-ref', "$RunId-audit-pre")
$tools = $compose + @('--profile', 'collection-v2', 'run', '--rm', '--no-deps', '-T') + $volumeArgs + @('v2-tools')
$reconcile = @('experiments.collection_reconcile_v2', '--run-id', $RunId, '--plan', "/app/$planRel", '--purpose', $Purpose,
    '--baseline-policy-sha256', $BaselinePolicySha256, '--audit-interval-s', "$AuditIntervalSeconds")
if ($Purpose -eq 'COLLECTION') { $reconcile += @('--manifest', "/app/$Manifest") }
$observerSessionPlaceholder = '<id of the NEW observer session of this run>'
$script:observerSession = $null
$finalize = @('experiments.collection_finalize_v2', 'record', '--run-id', $RunId, '--manifest', "/app/$Manifest", '--plan', "/app/$planRel")
function Audit-Command([string]$stage) {
    return $compose + @('--profile', 'operator', 'run', '--rm', '--no-deps', '-T') + $volumeArgs + @('binding-audit', '--run-id', "$RunId-audit-$stage")
}

if ($DryRun) {
    [pscustomobject]@{
        result = 'DRYRUN_ACCEPTED'; purpose = $Purpose; run_id = $RunId; partition_checked = ($Purpose -eq 'COLLECTION')
        git_commit = $gitCommit; manifest_sha256 = $manifestSha; window_duration_ms = $windowMs; planned_window_count = $windowCount
        evidence_root = $evidenceRoot; expected_git_head = $ExpectedGitHead
        audit_interval_seconds = $AuditIntervalSeconds; audit_edge_margin_seconds = $AuditEdgeMarginSeconds
        periodic_audit_anchor = 'observer COVERAGE_START'; git_fetch_or_push = $false
        containers_started_by_dry_run = 0
        audits = @('pre', 'periodic (p01..)', 'post')
        docker_audit_pre = (Audit-Command 'pre')
        docker_workload = ($compose + @('--profile', 'collection-v2', 'run', '-d', '--no-deps', '-T', '--name', $workloadName,
            '-e', 'AZTA_RUNTIME_IMAGE=<image id>') + $volumeArgs + @('v2-workload') + $workloadArgs)
        docker_observer = $(if ($Purpose -eq 'FUNCTIONAL_TEST') {
            $compose + @('--profile', 'collection-v2', 'run', '-d', '--no-deps', '-T', '--name', $observerName,
                '-e', 'AZTA_RUNTIME_IMAGE=<image id>') + $volumeArgs + $functionalObserverArgs
        } else { $null })
        docker_reconcile = ($tools + $reconcile + @('--observer-session-id', $observerSessionPlaceholder))
        session_discovery = 'names of existing session directories are listed before the run; only NEW directories are ever opened'
        preexisting_sessions = $(& { $snap = Get-SessionSnapshot; [pscustomobject]@{ session_names = @($snap.names).Count; sha256 = $snap.sha256 } })
        workload_environment = @('AZTA_PREEXISTING_SESSIONS', 'AZTA_PREEXISTING_SESSIONS_SHA256')
        docker_finalize = $(if ($Purpose -eq 'COLLECTION') { $tools + $finalize } else { $null })
    } | ConvertTo-Json -Compress -Depth 6
    exit 0
}
if ($Purpose -eq 'FUNCTIONAL_TEST') {
    if (Test-Path -LiteralPath $evidenceRoot) { Refuse 'functional evidence directory already exists; use a new authorized run id' }
    New-Item -ItemType Directory -Path $evidenceRoot -ErrorAction Stop | Out-Null
}

# ---- one new directory per attempt, so an early STOP never blocks or overwrites a later attempt's log -------------------
$logDir = "results/raw/collection-orchestrator/$RunId-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))"
New-Item -ItemType Directory -Path $logDir -ErrorAction Stop | Out-Null  # fails if it already exists
function Log([string]$line) { $line | Out-File "$logDir/orchestrator.log" -Append -Encoding utf8 }

# ---- runtime preflight (shared-Docker safeguards) ---------------------------------------------------------------------------
$image = docker image inspect --format '{{.Id}}' azta-journal-runtime:gate3
if ($LASTEXITCODE -ne 0) { Stop-Run 'accepted runtime image missing (no build performed)' }
# Names only: Windows PowerShell 5.1 strips embedded double quotes from native arguments.
$running = @(docker ps --filter 'label=com.docker.compose.project=azta-journal' --format '{{.Names}}')
if ($LASTEXITCODE -ne 0) { Stop-Run 'docker ps failed' }
if ($running.Count -ne 1 -or $running[0] -ne 'azta-journal-broker-1') { Stop-Run "unexpected project containers: $($running -join ',')" }
$others = @(docker ps --format '{{.Names}}' | Where-Object { $_ -match 'azta' -and $_ -notmatch 'broker' })
if ($others.Count -gt 0) { Stop-Run "unexpected AZTA containers: $($others -join ',')" }
$leftovers = @(docker ps -a --format '{{.Names}}' | Where-Object { $_ -in @($workloadName, $observerName) })
if ($leftovers.Count -gt 0) { Stop-Run "leftover container of an earlier attempt of this run: $($leftovers -join ',')" }
Log "pre: image=$image running=$($running -join ',') utc=$((Get-Date).ToUniversalTime().ToString('o')) purpose=$Purpose cadence=$AuditIntervalSeconds margin=$AuditEdgeMarginSeconds"

function Invoke-Audit([string]$stage) {
    $ref = "$RunId-audit-$stage"
    $out = & docker @(Audit-Command $stage)
    $code = $LASTEXITCODE
    Log "audit-$stage exit=$code $out"
    $path = "$evidenceRoot/$ref/binding_audit.json"
    if ($code -ne 0 -or -not (Test-Path -LiteralPath $path)) { return $null }
    return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
}
function Audit-Drift($audit) { return (-not $audit) -or $audit.verdict -ne 'PASS' -or $audit.policy_sha256 -ne $BaselinePolicySha256 }

$pre = Invoke-Audit 'pre'
if (Audit-Drift $pre) { Stop-Run 'pre-run binding audit failed or policy digest differs from the campaign baseline; no workload started' }

# ---- name-only snapshot of the existing session directories: nothing that predates this run may be opened by any discovery --------
$snapshot = Get-SessionSnapshot
$preSessions = @($snapshot.names)
Log "pre-existing observer sessions (names only, not opened): $($preSessions.Count) sha256=$($snapshot.sha256)"
@($snapshot.names) | Out-File "$logDir/preexisting_sessions.txt" -Encoding ascii

# ---- workload (detached; it waits for the observer's COVERAGE_START before connecting) -------------------------------------
$envArgs = @('-e', "AZTA_RUNTIME_IMAGE=$image")
if ($Purpose -eq 'COLLECTION') { $envArgs += @('-e', "AZTA_GIT_COMMIT=$gitCommit", '-e', 'AZTA_GIT_STATE=clean', '-e', "AZTA_MANIFEST_SHA256=$manifestSha") }
elseif ($ExpectedGitHead) { $envArgs += @('-e', "AZTA_GIT_COMMIT=$gitCommit", '-e', 'AZTA_GIT_STATE=clean') }
$workloadEnv = $envArgs + @('-e', "AZTA_PREEXISTING_SESSIONS=$($snapshot.value)", '-e', "AZTA_PREEXISTING_SESSIONS_SHA256=$($snapshot.sha256)")
$null = & docker @($compose + @('--profile', 'collection-v2', 'run', '-d', '--no-deps', '-T', '--name', $workloadName) + $workloadEnv + $volumeArgs + @('v2-workload') + $workloadArgs)
if ($LASTEXITCODE -ne 0) { Stop-Run 'workload container did not start' }

# ---- observer (detached, so that periodic audits can be taken while it covers) ---------------------------------------------
$observerFailed = $false
try {
    if ($Purpose -eq 'COLLECTION') {
        & "$PSScriptRoot/observation_collect_v2.ps1" -Manifest $Manifest -RunId $RunId -WindowDurationMs $windowMs -WindowCount $windowCount `
            -BindingAuditRef "$RunId-audit-pre" -ExpectedGitHead $ExpectedGitHead -ContainerName $observerName | Out-File "$logDir/observer-start.log" -Encoding utf8
    } else {
        $null = & docker @($compose + @('--profile', 'collection-v2', 'run', '-d', '--no-deps', '-T', '--name', $observerName) + $envArgs + $volumeArgs + $functionalObserverArgs)
        if ($LASTEXITCODE -ne 0) { $observerFailed = $true }
    }
} catch {
    $observerFailed = $true
    Log "observer start error: $($_.Exception.Message)"
}

function Observer-Running { return ((docker inspect -f '{{.State.Running}}' $observerName) -eq 'true') }
function Find-NewSession {
    # Only directories that did not exist before this run are opened; the sealed historical sessions are never searched.
    if (-not (Test-Path -LiteralPath "$evidenceRoot/observation")) { return $null }
    $found = $null
    foreach ($name in @(Get-ChildItem -LiteralPath "$evidenceRoot/observation" -Directory -Name | Where-Object { $_ -notin $preSessions })) {
        $metaPath = "$evidenceRoot/observation/$name/session_metadata.json"
        if (-not (Test-Path -LiteralPath $metaPath)) { continue }
        $data = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
        if ($data.collection_run_id -ne $RunId) { continue }
        if ($found) { Stop-Run 'more than one NEW observer session names this run' }
        $found = $name
    }
    return $found
}
function Coverage-Start {
    $name = Find-NewSession
    if (-not $name) { return $null }
    $script:observerSession = $name
    $health = "$evidenceRoot/observation/$name/health.jsonl"
    if (-not (Test-Path -LiteralPath $health)) { return $null }
    foreach ($line in Get-Content -LiteralPath $health) {
        try { $record = $line | ConvertFrom-Json } catch { continue }
        if ($record.kind -eq 'COVERAGE_START') {
            return [DateTimeOffset]::Parse($record.utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
        }
    }
    return $null
}

# ---- periodic read-only audits, anchored at the observer's own coverage start; never outside planned coverage ---------------
if (-not $observerFailed -and $AuditIntervalSeconds -gt 0) {
    $start = $null
    while (-not $start -and (Observer-Running)) { $start = Coverage-Start; if (-not $start) { Start-Sleep -Milliseconds 500 } }
    if ($start) {
        $plannedEnd = $start.AddSeconds($coverageSeconds)
        for ($k = 1; $k -le 99; $k++) {
            $due = $start.AddSeconds($k * $AuditIntervalSeconds)
            if ($due.AddSeconds($AuditEdgeMarginSeconds) -gt $plannedEnd) { break }
            $wait = ($due - [DateTimeOffset]::UtcNow).TotalSeconds
            if ($wait -gt 0) { Start-Sleep -Milliseconds ([int][math]::Ceiling($wait * 1000)) }
            if (-not (Observer-Running)) { Log "observer stopped before periodic audit $k"; break }
            $periodic = Invoke-Audit ('p{0:d2}' -f $k)
            if (Audit-Drift $periodic) { Log "periodic audit $k failed or drifted"; $observerFailed = $true; break }
        }
    } else { Log 'observer coverage start was never observed; no periodic audit taken' }
}

$observerExit = docker wait $observerName
docker logs $observerName | Out-File "$logDir/observer.log" -Encoding utf8
$null = docker rm $observerName
if ($observerExit -ne '0') { $observerFailed = $true }
$workloadExit = docker wait $workloadName
docker logs $workloadName | Out-File "$logDir/workload.log" -Encoding utf8
$null = docker rm $workloadName
Log "observer_failed=$observerFailed observer_exit=$observerExit workload_exit=$workloadExit"

$post = Invoke-Audit 'post'
$auditDrift = Audit-Drift $post

# ---- reconciliation / finalize (offline, no network, no secrets) ---------------------------------------------------------------
if (-not $script:observerSession) { $null = Coverage-Start }
if (-not $script:observerSession) { Stop-Run 'no NEW observer session was created for this run; nothing is reconciled by scanning' }
$reconcile += @('--observer-session-id', $script:observerSession)
$reconcileOut = & docker @($tools + $reconcile)
$reconcileCode = $LASTEXITCODE
Log "reconcile exit=$reconcileCode $reconcileOut"
Write-Output $reconcileOut
if ($reconcileCode -eq 2) { Stop-Run 'reconciliation could not run' }
$report = Get-Content -LiteralPath "$evidenceRoot/collection/$RunId/reconciliation.json" -Raw | ConvertFrom-Json
if ($report.verdict -eq 'NOT_STARTED') { Stop-Run 'run did not start; nothing recorded; the run stays planned' }

$verdict = $report.verdict
if ($Purpose -eq 'COLLECTION') {
    $finalOut = & docker @($tools + $finalize)
    $finalCode = $LASTEXITCODE
    Log "finalize exit=$finalCode $finalOut"
    Write-Output $finalOut
    if ($finalCode -ne 0 -and $finalCode -ne 4) { Stop-Run 'finalize failed; inspect the manifest before anything else' }
    if ($RecordCommit) {
        $message = "Record workload-v2 run $RunId $verdict"
        & "$PSScriptRoot/collection_record_commit_v2.ps1" -RepoRoot $root -Manifest $Manifest -Message $message -Trailer $CommitTrailer
        if ($LASTEXITCODE -ne 0) { Stop-Run 'local manifest commit failed; do not start another run' }
    }
}
Write-Output "RUN_RESULT $RunId purpose=$Purpose verdict=$verdict campaign_stop=$($report.campaign_stop) review_flags=$(@($report.review_flags).Count)"
if ($report.campaign_stop -or $auditDrift) { Stop-Run 'campaign STOP condition (see reconciliation report)' }
if ($verdict -eq 'ACCEPT') { exit 0 }
exit 4
