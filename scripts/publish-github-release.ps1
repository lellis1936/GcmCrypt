param(
    [string]$Version = "1.4.0",
    [string]$Remote = "origin",
    [string]$Repo = "lellis1936/GcmCrypt",
    [string]$TargetBranch = "master"
)

$ErrorActionPreference = "Stop"

function Invoke-Native {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

function Test-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

if (!(Test-Command "gh")) {
    throw "GitHub CLI (gh) is required. Install it and run 'gh auth login' before using this script."
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$tag = "v$Version"
$releaseTitle = "Version $Version"
$releaseDir = Join-Path $repoRoot "release-assets"
$net48Asset = Join-Path $releaseDir "GcmCrypt-net48.exe"
$net8Asset = Join-Path $releaseDir "GcmCrypt-net8-win-x64-self-contained.exe"
$notesFile = Join-Path $releaseDir "release-notes-$tag.md"

Push-Location $repoRoot
try {
    Invoke-Native "gh" @("auth", "status")

    $workingTreeChanges = git status --porcelain
    if ($workingTreeChanges) {
        throw "The working tree has uncommitted or untracked changes. Commit, stash, or remove them before creating a release."
    }

    Invoke-Native "git" @("fetch", $Remote)

    $localTagExists = $true
    git rev-parse --verify --quiet $tag | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $localTagExists = $false
    }

    if ($localTagExists) {
        throw "Local tag '$tag' already exists. Refusing to overwrite an existing release tag."
    }

    $remoteTagExists = $true
    git ls-remote --exit-code --tags $Remote $tag | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $remoteTagExists = $false
    }

    if ($remoteTagExists) {
        throw "Remote tag '$tag' already exists. Refusing to overwrite an existing release tag."
    }

    $targetCommit = (git rev-parse "$Remote/$TargetBranch").Trim()
    if ($LASTEXITCODE -ne 0 -or !$targetCommit) {
        throw "Could not resolve release target '$Remote/$TargetBranch'."
    }

    Invoke-Native "powershell" @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ".\scripts\package-release.ps1")

    if (!(Test-Path -LiteralPath $net48Asset) -or !(Test-Path -LiteralPath $net8Asset)) {
        throw "Expected release assets were not created in $releaseDir"
    }

$notes = @"
v$Version

Changes:
- Add authenticated original plaintext length to file format 1.3.
- Detect removal of complete trailing encrypted chunks.
- Preserve compatibility with file formats 1.1 and 1.2.

Assets:
- GcmCrypt-net48.exe: .NET Framework 4.8 build.
- GcmCrypt-net8-win-x64-self-contained.exe: trimmed, compressed, self-contained .NET 8 win-x64 build.
"@

    Set-Content -LiteralPath $notesFile -Value $notes -Encoding UTF8

    Invoke-Native "git" @("tag", "-a", $tag, $targetCommit, "-m", "GcmCrypt $tag")
    Invoke-Native "git" @("push", $Remote, $tag)

    Invoke-Native "gh" @(
        "release", "create", $tag,
        $net48Asset,
        $net8Asset,
        "--repo", $Repo,
        "--title", $releaseTitle,
        "--notes-file", $notesFile,
        "--verify-tag"
    )

    Write-Host "Created GitHub release $tag for $Repo"
}
finally {
    Pop-Location
}
