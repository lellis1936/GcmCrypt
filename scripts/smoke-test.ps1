param(
    [string]$Configuration = "Debug",
    [string[]]$TargetFrameworks = @("net48", "net8.0"),
    [string]$LegacyExecutable
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

function Read-BigEndianInt32 {
    param(
        [byte[]]$Bytes,
        [int]$Offset
    )

    $valueBytes = New-Object byte[] 4
    [Array]::Copy($Bytes, $Offset, $valueBytes, 0, 4)
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($valueBytes)
    }
    return [BitConverter]::ToInt32($valueBytes, 0)
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$project = Join-Path $repoRoot "GcmCrypt\GcmCrypt.csproj"
$testDir = Join-Path $repoRoot "smoke-test-output"

if (Test-Path -LiteralPath $testDir) {
    $resolvedRepoRoot = [System.IO.Path]::GetFullPath($repoRoot)
    $resolvedTestDir = [System.IO.Path]::GetFullPath($testDir)
    if (!$resolvedTestDir.StartsWith($resolvedRepoRoot + [System.IO.Path]::DirectorySeparatorChar)) {
        throw "Refusing to remove smoke-test output outside the repository"
    }
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

        $encryptedBytes = [System.IO.File]::ReadAllBytes($encryptedFile)
        if ($encryptedBytes.Length -lt 102) {
            throw "Encrypted file is too short to contain a v1.5 header"
        }
        if ($encryptedBytes[0] -ne [byte][char]'G' -or
            $encryptedBytes[1] -ne [byte][char]'C' -or
            $encryptedBytes[2] -ne [byte][char]'M' -or
            $encryptedBytes[3] -ne 1 -or
            $encryptedBytes[4] -ne 5) {
            throw "Encryption did not write file format 1.5"
        }
        if ((Read-BigEndianInt32 $encryptedBytes 82) -ne 600000) {
            throw "File format 1.5 contains an unexpected default PBKDF2 iteration count"
        }

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

$customIterations = 750000
foreach ($encryptTarget in $TargetFrameworks) {
    $encryptExe = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\$encryptTarget\GcmCrypt.exe"
    $encryptedFile = Join-Path $testDir "custom-iterations-$encryptTarget.gcm"
    & $encryptExe -e -f -iter $customIterations $passwords[0] $inputFile $encryptedFile

    $encryptedBytes = [System.IO.File]::ReadAllBytes($encryptedFile)
    if ((Read-BigEndianInt32 $encryptedBytes 82) -ne $customIterations) {
        throw "Custom PBKDF2 iteration count was not stored for $encryptTarget"
    }

    foreach ($decryptTarget in $TargetFrameworks) {
        $decryptExe = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\$decryptTarget\GcmCrypt.exe"
        $outputFile = Join-Path $testDir "custom-iterations-$encryptTarget-to-$decryptTarget.txt"
        & $decryptExe -d -f $passwords[0] $encryptedFile $outputFile
        Assert-SameFile $inputFile $outputFile
    }
}

$cliTestExe = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\$($TargetFrameworks[0])\GcmCrypt.exe"
$cliOutput = & $cliTestExe -d -f -iter 600000 $passwords[0] `
    (Join-Path $testDir "encrypted-0-$($TargetFrameworks[0]).gcm") `
    (Join-Path $testDir "invalid-cli.out") 2>&1
if (($cliOutput -join "`n") -notmatch "-iter is only valid for encryption") {
    throw "-iter was not rejected during decryption"
}

$invalidSignatureFile = Join-Path $testDir "invalid-signature.gcm"
[System.IO.File]::WriteAllBytes(
    $invalidSignatureFile,
    [byte[]]([byte][char]'N', [byte][char]'O', [byte][char]'T', 0xFF, 0xFF))

$unsupportedVersionFile = Join-Path $testDir "unsupported-version.gcm"
[System.IO.File]::WriteAllBytes(
    $unsupportedVersionFile,
    [byte[]]([byte][char]'G', [byte][char]'C', [byte][char]'M', 0xFF, 0xFF))

foreach ($targetFramework in $TargetFrameworks) {
    $decryptExe = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\$targetFramework\GcmCrypt.exe"

    $invalidSignatureOutput = & $decryptExe -d -f $passwords[0] `
        $invalidSignatureFile (Join-Path $testDir "invalid-signature-$targetFramework.out") 2>&1
    $invalidSignatureMessage = $invalidSignatureOutput -join "`n"
    $hasSignatureError = $invalidSignatureMessage -match "Input file is not a GcmCrypt file"
    $hasVersionError = $invalidSignatureMessage -match "Unsupported input file version"
    if (!$hasSignatureError -or $hasVersionError) {
        throw "Invalid signature was not reported correctly for $targetFramework"
    }

    $unsupportedVersionOutput = & $decryptExe -d -f $passwords[0] `
        $unsupportedVersionFile (Join-Path $testDir "unsupported-version-$targetFramework.out") 2>&1
    if (($unsupportedVersionOutput -join "`n") -notmatch "Unsupported input file version") {
        throw "Unsupported version was not reported correctly for $targetFramework"
    }
}

if ($LegacyExecutable) {
    if (!(Test-Path -LiteralPath $LegacyExecutable)) {
        throw "Legacy executable not found: $LegacyExecutable"
    }

    $legacyEncryptedFile = Join-Path $testDir "legacy-v1.3.gcm"
    & $LegacyExecutable -e -f $passwords[0] $inputFile $legacyEncryptedFile

    $legacyBytes = [System.IO.File]::ReadAllBytes($legacyEncryptedFile)
    if ($legacyBytes[3] -ne 1 -or $legacyBytes[4] -ne 3) {
        throw "Legacy executable did not produce file format 1.3"
    }

    foreach ($decryptTarget in $TargetFrameworks) {
        $decryptExe = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\$decryptTarget\GcmCrypt.exe"
        $outputFile = Join-Path $testDir "legacy-v1.3-to-$decryptTarget.txt"
        & $decryptExe -d -f $passwords[0] $legacyEncryptedFile $outputFile
        Assert-SameFile $inputFile $outputFile
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

$parameterSource = Join-Path $testDir "encrypted-0-$($TargetFrameworks[0]).gcm"
$invalidParametersFile = Join-Path $testDir "invalid-pbkdf2-iterations.gcm"
$invalidParametersBytes = [System.IO.File]::ReadAllBytes($parameterSource)
$invalidParametersBytes[82] = 0x00
$invalidParametersBytes[83] = 0x01
$invalidParametersBytes[84] = 0x86
$invalidParametersBytes[85] = 0x9F
[System.IO.File]::WriteAllBytes($invalidParametersFile, $invalidParametersBytes)

foreach ($decryptTarget in $TargetFrameworks) {
    $decryptExe = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\$decryptTarget\GcmCrypt.exe"
    $outputFile = Join-Path $testDir "invalid-pbkdf2-iterations-$decryptTarget.out"
    $output = & $decryptExe -d -f $passwords[0] $invalidParametersFile $outputFile 2>&1
    if (($output -join "`n") -notmatch "invalid PBKDF2 iteration count") {
        throw "Invalid PBKDF2 iteration count was not rejected for $decryptTarget"
    }
    if (Test-Path -LiteralPath $outputFile) {
        throw "Invalid PBKDF2 parameters created an output file for $decryptTarget"
    }
}

Write-Host "Smoke test passed for: $($TargetFrameworks -join ', ')"
