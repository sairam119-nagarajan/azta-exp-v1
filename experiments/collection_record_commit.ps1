param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [Parameter(Mandatory=$true)][string]$Manifest,
    [Parameter(Mandatory=$true)][string]$Message,
    [string]$Trailer = ''
)
# Controller decision C5: after every finalized run, commit ONLY the manifest path, push, fetch and
# require a clean tree with HEAD == origin/master before anything else may run. Refuses if any other
# path changed. Never force-pushes, never amends, never stages broadly.
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
git @git push -q origin HEAD:master
if ($LASTEXITCODE -ne 0) { Write-Output 'RECORD_FAILED push'; exit 1 }
git @git fetch -q origin
if ($LASTEXITCODE -ne 0) { Write-Output 'RECORD_FAILED fetch'; exit 1 }
$head = git @git rev-parse HEAD
$remote = git @git rev-parse origin/master
if ($head -ne $remote) { Write-Output "RECORD_FAILED HEAD $head != origin/master $remote"; exit 1 }
if (git @git status --porcelain) { Write-Output 'RECORD_FAILED tree not clean after commit'; exit 1 }
Write-Output "RECORD_COMMITTED $head"
exit 0
