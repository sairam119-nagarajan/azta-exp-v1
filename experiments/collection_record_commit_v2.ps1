param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [Parameter(Mandatory=$true)][string]$Manifest,
    [Parameter(Mandatory=$true)][string]$Message,
    [string]$Trailer = ''
)
# Gate 5F.3 LOCAL record commit (PREPARED, NEVER RUN). After a finalized workload-v2 run it commits ONLY the manifest path to the local
# repository and requires a clean tree afterwards. It never pushes, fetches, force-pushes, amends or stages broadly: whether and when
# the result is pushed is a separate decision of the operator and the Main Controller, not part of the run (the frozen v1 helper, which
# pushes and verifies origin/master, is left untouched).
$ErrorActionPreference = 'Stop'
$relative = $Manifest -replace '\\','/'
if ($relative -notmatch '^configs/collection_manifests/[A-Za-z0-9_-]+\.jsonl$') { Write-Output 'RECORD_REFUSED manifest path'; exit 2 }
$git = @('-C', $RepoRoot)
$status = @(git @git status --porcelain)
if ($LASTEXITCODE -ne 0) { Write-Output 'RECORD_REFUSED git status failed'; exit 2 }
if ($status.Count -ne 1 -or $status[0] -ne " M $relative") {
    Write-Output "RECORD_REFUSED expected only the manifest to be modified; found: $($status -join ' | ')"; exit 2
}
git @git add -- $relative
if ($LASTEXITCODE -ne 0) { Write-Output 'RECORD_FAILED add'; exit 1 }
$staged = @(git @git diff --cached --name-only)
if ($staged.Count -ne 1 -or $staged[0] -ne $relative) { Write-Output 'RECORD_FAILED unexpected staged scope'; exit 1 }
$full = $Message
if ($Trailer) { $full = "$Message`n`n$Trailer" }
git @git commit -q -m $full
if ($LASTEXITCODE -ne 0) { Write-Output 'RECORD_FAILED commit'; exit 1 }
if (git @git status --porcelain) { Write-Output 'RECORD_FAILED tree not clean after commit'; exit 1 }
$head = git @git rev-parse HEAD
Write-Output "RECORD_COMMITTED_LOCAL $head"
exit 0
