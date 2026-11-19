param(
    [Parameter(Mandatory=$true)][string]$Manifest,
    [Parameter(Mandatory=$true)][string]$RunId,
    [Parameter(Mandatory=$true)][int]$WindowDurationMs,
    [Parameter(Mandatory=$true)][int]$WindowCount,
    [Parameter(Mandatory=$true)][string]$BindingAuditRef,
    [string]$RepoRoot = 'C:/Projects/AZTA',
    [switch]$DryRun
)
# Gate 5C real-collection wrapper. Refuses unless the manifest planning state is committed in a
# clean checkpoint; the container repeats the check against the manifest digest.
# -DryRun performs every refusal check, prints the exact observation command and the digest that
# would be passed to the container, and stops before any Docker call. -RepoRoot exists only so the
# refusal matrix can run against a throwaway clone; a live (non-DryRun) run requires the AZTA workspace.
$ErrorActionPreference = 'Stop'
$root = $RepoRoot -replace '\\','/'
if ($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') { throw 'Invalid run ID' }
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
    # No stderr redirection: in Windows PowerShell 5.1 a redirected native stderr becomes a terminating
    # error under 'Stop', which replaced this refusal message with raw git text (found in Gate 5C Phase A).
    $tracked = git ls-files -- $relative
    if ($LASTEXITCODE -ne 0 -or -not $tracked) { throw 'COLLECTION_REFUSED manifest is not committed' }
    git diff --quiet HEAD -- $relative
    if ($LASTEXITCODE -ne 0) { throw 'COLLECTION_REFUSED manifest differs from the committed planning state' }
    $head = git rev-parse HEAD
    $digest = (Get-FileHash -LiteralPath $relative -Algorithm SHA256).Hash.ToLowerInvariant()
    $arguments = @('compose', '-p', 'azta-journal', '-f', 'compose.yaml', '-f', 'compose.observation.yaml',
        'run', '--rm', '--no-deps', '-T',
        '-e', "AZTA_GIT_COMMIT=$head", '-e', 'AZTA_GIT_STATE=clean', '-e', "AZTA_MANIFEST_SHA256=$digest")
    $observer = @('observation', '--purpose', 'COLLECTION', '--collection-run-id', $RunId,
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
    if ($LASTEXITCODE -ne 0) { throw "Collection session did not complete (exit $LASTEXITCODE); inspect preserved evidence" }
} finally {
    Pop-Location
}
