param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$project = Join-Path $repoRoot "GcmCrypt\GcmCrypt.csproj"
$solution = Join-Path $repoRoot "GcmCrypt.sln"
$releaseDir = Join-Path $repoRoot "release-assets"
$net8PublishProfile = "net8-win-x64-single-trimmed-compressed"
$net8PublishDir = Join-Path $repoRoot "publish\$net8PublishProfile"

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

if (Test-Path -LiteralPath $releaseDir) {
    Remove-Item -LiteralPath $releaseDir -Recurse -Force
}

New-Item -ItemType Directory -Path $releaseDir | Out-Null

Invoke-Native "dotnet" @("build", $solution, "-c", $Configuration)
Invoke-Native "dotnet" @("publish", $project, "-f", "net8.0", "/p:PublishProfile=$net8PublishProfile")

$net48Output = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\net48"
$net48Dest = Join-Path $releaseDir "GcmCrypt-net48.exe"
Copy-Item -LiteralPath (Join-Path $net48Output "GcmCrypt.exe") -Destination $net48Dest -Force

$net8Source = Join-Path $net8PublishDir "GcmCrypt.exe"
$net8Dest = Join-Path $releaseDir "GcmCrypt-net8-win-x64-self-contained.exe"
Copy-Item -LiteralPath $net8Source -Destination $net8Dest -Force

Get-ChildItem -LiteralPath $releaseDir | Select-Object Name,Length
