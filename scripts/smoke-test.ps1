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

function Invoke-Native {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    $output = & $FilePath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE`n$($output -join "`n")"
    }

    return ($output -join "`n")
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
$passwords = @("testpass", "passwörd-漢字")
[System.IO.File]::WriteAllText($inputFile, "GcmCrypt smoke test`r`nTargets: $($TargetFrameworks -join ', ')`r`n", [System.Text.Encoding]::UTF8)

foreach ($targetFramework in $TargetFrameworks) {
    Invoke-Native "dotnet" @("build", $project, "--configuration", $Configuration, "--framework", $targetFramework)
}

for ($passwordIndex = 0; $passwordIndex -lt $passwords.Count; $passwordIndex++) {
    $password = $passwords[$passwordIndex]

    foreach ($encryptTarget in $TargetFrameworks) {
        $encryptExe = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\$encryptTarget\GcmCrypt.exe"
        $encryptedFile = Join-Path $testDir "encrypted-$passwordIndex-$encryptTarget.gcm"

        & $encryptExe -e -f $password $inputFile $encryptedFile

        foreach ($decryptTarget in $TargetFrameworks) {
            $decryptExe = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\$decryptTarget\GcmCrypt.exe"
            $outputFile = Join-Path $testDir "decrypted-$passwordIndex-$encryptTarget-to-$decryptTarget.txt"

            [System.IO.File]::WriteAllText($outputFile, "existing output")
            [System.IO.File]::WriteAllText("$outputFile.PARTIAL", "stale partial output")
            & $decryptExe -d -f $password $encryptedFile $outputFile
            Assert-SameFile $inputFile $outputFile
            if (Test-Path -LiteralPath "$outputFile.PARTIAL") {
                throw "Successful decryption left a partial file for $encryptTarget to $decryptTarget"
            }
        }
    }
}

$password = $passwords[0]
$truncationInput = Join-Path $testDir "truncation-input.bin"
$truncationBytes = New-Object byte[] (3 * 64 * 1024)
for ($i = 0; $i -lt $truncationBytes.Length; $i++) {
    $truncationBytes[$i] = [byte]($i % 251)
}
[System.IO.File]::WriteAllBytes($truncationInput, $truncationBytes)

foreach ($encryptTarget in $TargetFrameworks) {
    $encryptExe = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\$encryptTarget\GcmCrypt.exe"
    $encryptedFile = Join-Path $testDir "truncation-$encryptTarget.gcm"
    & $encryptExe -e -f $password $truncationInput $encryptedFile | Out-Null

    $truncatedFile = Join-Path $testDir "truncation-$encryptTarget-short.gcm"
    Copy-Item -LiteralPath $encryptedFile -Destination $truncatedFile
    $truncatedStream = [System.IO.File]::Open(
        $truncatedFile,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    try {
        $truncatedStream.SetLength($truncatedStream.Length - (64 * 1024 + 16))
    }
    finally {
        $truncatedStream.Dispose()
    }

    foreach ($decryptTarget in $TargetFrameworks) {
        $decryptExe = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\$decryptTarget\GcmCrypt.exe"
        $outputFile = Join-Path $testDir "truncated-$encryptTarget-to-$decryptTarget.out"
        $output = & $decryptExe -d -f $password $truncatedFile $outputFile 2>&1
        if (($output -join "`n") -notmatch "Decrypted file length mismatch") {
            throw "Trailing chunk truncation was not detected for $encryptTarget to $decryptTarget"
        }
        if (Test-Path -LiteralPath $outputFile) {
            throw "Failed decryption created the requested final output for $encryptTarget to $decryptTarget"
        }
        if (!(Test-Path -LiteralPath "$outputFile.PARTIAL")) {
            throw "Failed decryption did not retain a .PARTIAL output for $encryptTarget to $decryptTarget"
        }
    }
}

Write-Host "Smoke test passed for: $($TargetFrameworks -join ', ')"
