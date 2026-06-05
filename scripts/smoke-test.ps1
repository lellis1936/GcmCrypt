param(
    [string]$Configuration = "Debug",
    [string[]]$TargetFrameworks = @("net48", "net8.0")
)

$ErrorActionPreference = "Stop"

function Assert-SameFile {
    param(
        [string]$Expected,
        [string]$Actual
    )

    $expectedBytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Expected))
    $actualBytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Actual))

    if ($expectedBytes.Length -ne $actualBytes.Length) {
        throw "Length mismatch between $Expected and $Actual"
    }

    for ($i = 0; $i -lt $expectedBytes.Length; $i++) {
        if ($expectedBytes[$i] -ne $actualBytes[$i]) {
            throw "Byte mismatch at offset $i between $Expected and $Actual"
        }
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$project = Join-Path $repoRoot "GcmCrypt\GcmCrypt.csproj"
$testDir = Join-Path $repoRoot "smoke-test-output"

if (Test-Path -LiteralPath $testDir) {
    Remove-Item -LiteralPath $testDir -Recurse -Force
}

New-Item -ItemType Directory -Path $testDir | Out-Null

$inputFile = Join-Path $testDir "input.txt"
$password = "testpass"
[System.IO.File]::WriteAllText($inputFile, "GcmCrypt smoke test`r`nTargets: $($TargetFrameworks -join ', ')`r`n", [System.Text.Encoding]::UTF8)

foreach ($targetFramework in $TargetFrameworks) {
    dotnet build $project --configuration $Configuration --framework $targetFramework
}

foreach ($encryptTarget in $TargetFrameworks) {
    $encryptExe = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\$encryptTarget\GcmCrypt.exe"
    $encryptedFile = Join-Path $testDir "encrypted-$encryptTarget.gcm"

    & $encryptExe -e -f $password $inputFile $encryptedFile

    foreach ($decryptTarget in $TargetFrameworks) {
        $decryptExe = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\$decryptTarget\GcmCrypt.exe"
        $outputFile = Join-Path $testDir "decrypted-$encryptTarget-to-$decryptTarget.txt"

        & $decryptExe -d -f $password $encryptedFile $outputFile
        Assert-SameFile $inputFile $outputFile
    }
}

Write-Host "Smoke test passed for: $($TargetFrameworks -join ', ')"
