param(
    [Parameter(Mandatory=$true)][string]$Manifest,
    [Parameter(Mandatory=$true)][string]$RunId,
    [Parameter(Mandatory=$true)][int]$WindowDurationMs,
    [Parameter(Mandatory=$true)][int]$WindowCount,
    [Parameter(Mandatory=$true)][string]$BindingAuditRef,
    [Parameter(Mandatory=$true)][string]$ExpectedGitHead,
    [string]$ContainerName = '',
    [string]$RepoRoot = 'C:/Projects/AZTA',
    [switch]$DryRun
)
# Gate 5F.3 workload-v2 observer wrapper (PREPARED, NEVER RUN). Refuses unless the schema-2 manifest planning state is committed in a clean
# checkpoint whose HEAD is exactly the controller-named freeze commit (-ExpectedGitHead); it never fetches or pushes, so the pin is an
# explicit commit, not a remote. The container repeats the manifest check against the manifest digest.
# -DryRun performs every refusal check, prints the exact observation command and the digest that would be passed to the container, and
# stops before any Docker call. -ContainerName runs the observer detached under that name (the orchestrator then polls it while it takes
# its periodic read-only audits); without it the observer runs in the foreground. -RepoRoot exists only so the refusal matrix can run
# against a throwaway clone; a live (non-DryRun) run requires the AZTA workspace.
$ErrorActionPreference = 'Stop'
$root = $RepoRoot -replace '\\','/'
if ($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') { throw 'Invalid run ID' }
if ($ExpectedGitHead -notmatch '^[0-9a-f]{40}$') { throw 'COLLECTION_REFUSED expected git head must be a full 40-hex commit' }
if ($ContainerName -and $ContainerName -notmatch '^azta-g5f3-[A-Za-z0-9_.-]{1,80}$') { throw 'Invalid container name' }
if (-not $DryRun -and $root -ne 'C:/Projects/AZTA') { throw 'Run from the AZTA workspace' }
Push-Location -LiteralPath $root
try {
    if ((git rev-parse --show-toplevel) -replace '\\','/' -ne $root) { throw 'Run from the AZTA workspace' }
    $relative = $Manifest -replace '\\','/'
    if ($relative -notmatch '^configs/collection_manifests/[A-Za-z0-9_-]+\.jsonl$') {
        throw 'COLLECTION_REFUSED manifest must be a tracked file under configs/collection_manifests/'
    }
    $dirty = git status --porcelain
    if ($LASTEXITCODE -ne 0 -or $dirty) { throw 'COLLECTION_REFUSED working tree is not clean' }
    # No stderr redirection: in Windows PowerShell 5.1 a redirected native stderr becomes a terminating error under 'Stop'.
    $tracked = git ls-files -- $relative
    if ($LASTEXITCODE -ne 0 -or -not $tracked) { throw 'COLLECTION_REFUSED manifest is not committed' }
    git diff --quiet HEAD -- $relative
    if ($LASTEXITCODE -ne 0) { throw 'COLLECTION_REFUSED manifest differs from the committed planning state' }
    $head = git rev-parse HEAD
    if ($head -ne $ExpectedGitHead) { throw 'COLLECTION_REFUSED HEAD is not the controller-named freeze commit' }
    $digest = (Get-FileHash -LiteralPath $relative -Algorithm SHA256).Hash.ToLowerInvariant()
    $runArgs = @('run', '--rm', '--no-deps', '-T')
    if ($ContainerName) { $runArgs = @('run', '-d', '--no-deps', '-T', '--name', $ContainerName) }
    $arguments = @('compose', '-p', 'azta-journal', '-f', 'compose.yaml', '-f', 'compose.observation.yaml',
        '-f', 'configs/gate5f3/compose.collection_v2.yaml', '--profile', 'collection-v2') + $runArgs + @(
        '-e', "AZTA_GIT_COMMIT=$head", '-e', 'AZTA_GIT_STATE=clean', '-e', "AZTA_MANIFEST_SHA256=$digest")
    $observer = @('v2-observer', '--purpose', 'COLLECTION', '--collection-run-id', $RunId,
        '--window-duration-ms', "$WindowDurationMs", '--window-count', "$WindowCount",
        '--binding-audit-ref', $BindingAuditRef, '--manifest', "/app/$relative")
    if ($DryRun) {
        [pscustomobject]@{ result = 'DRYRUN_ACCEPTED'; git_commit = $head; manifest_sha256 = $digest
            docker = ($arguments + @('-e', 'AZTA_RUNTIME_IMAGE=<image id>') + $observer) } | ConvertTo-Json -Compress
        return
    }
    $image = docker image inspect --format '{{.Id}}' azta-journal-runtime:gate3
    if ($LASTEXITCODE -ne 0) { throw 'Existing runtime image missing; no build performed' }
    & docker @($arguments + @('-e', "AZTA_RUNTIME_IMAGE=$image") + $observer)
    if ($LASTEXITCODE -ne 0) { throw "Collection session did not start or complete (exit $LASTEXITCODE); inspect preserved evidence" }
} finally {
    Pop-Location
}
