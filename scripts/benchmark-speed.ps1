param(
    [int]$SizeMB = 512,
    [int]$Iterations = 5,
    [string]$Configuration = "Release",
    [string[]]$TargetFrameworks = @("net48", "net8.0")
)

$ErrorActionPreference = "Stop"

function New-RandomFile {
    param(
        [string]$Path,
        [long]$SizeBytes
    )

    $bufferSize = 1024 * 1024
    $buffer = New-Object byte[] $bufferSize

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $remaining = $SizeBytes
            while ($remaining -gt 0) {
                $count = [int][Math]::Min($buffer.Length, $remaining)
                $rng.GetBytes($buffer, 0, $count)
                $stream.Write($buffer, 0, $count)
                $remaining -= $count
            }
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $rng.Dispose()
    }
}

function Invoke-GcmCrypt {
    param(
        [string]$Exe,
        [string[]]$Arguments
    )

    $output = & $Exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$Exe failed with exit code $LASTEXITCODE`n$output"
    }

    return ($output -join "`n")
}

function Get-ReportedMilliseconds {
    param(
        [string]$Output,
        [string]$Operation
    )

    $pattern = "AES GCM $Operation took (?<ms>\d+) ms"
    $match = [regex]::Match($Output, $pattern)
    if (!$match.Success) {
        throw "Could not parse $Operation timing from output:`n$Output"
    }

    return [int]$match.Groups["ms"].Value
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$benchDir = Join-Path $repoRoot "benchmark-output"
$inputFile = Join-Path $benchDir "input.bin"
$sizeBytes = [long]$SizeMB * 1024 * 1024
$password = "benchmark-password"

if (!(Test-Path -LiteralPath $benchDir)) {
    New-Item -ItemType Directory -Path $benchDir | Out-Null
}

if (!(Test-Path -LiteralPath $inputFile) -or ((Get-Item -LiteralPath $inputFile).Length -ne $sizeBytes)) {
    Write-Host "Creating $SizeMB MB random input file..."
    New-RandomFile -Path $inputFile -SizeBytes $sizeBytes
}

$results = New-Object System.Collections.Generic.List[object]

for ($i = 1; $i -le $Iterations; $i++) {
    $iterationTargets = $TargetFrameworks
    if (($i % 2) -eq 0) {
        $iterationTargets = @($TargetFrameworks[($TargetFrameworks.Length - 1)..0])
    }

    foreach ($target in $iterationTargets) {
        $exe = Join-Path $repoRoot "GcmCrypt\bin\$Configuration\$target\GcmCrypt.exe"
        if (!(Test-Path -LiteralPath $exe)) {
            throw "Missing executable: $exe"
        }

        $encryptedFile = Join-Path $benchDir "$target-$i.gcm"
        $decryptedFile = Join-Path $benchDir "$target-$i.out"

        $encryptOutput = Invoke-GcmCrypt $exe @("-e", "-f", $password, $inputFile, $encryptedFile)
        $encryptMs = Get-ReportedMilliseconds $encryptOutput "encryption"

        $decryptOutput = Invoke-GcmCrypt $exe @("-d", "-f", $password, $encryptedFile, $decryptedFile)
        $decryptMs = Get-ReportedMilliseconds $decryptOutput "decryption"

        Remove-Item -LiteralPath $encryptedFile, $decryptedFile -Force

        $results.Add([pscustomobject]@{
            Target = $target
            Iteration = $i
            EncryptMs = $encryptMs
            EncryptMBps = [Math]::Round($SizeMB / ($encryptMs / 1000.0), 2)
            DecryptMs = $decryptMs
            DecryptMBps = [Math]::Round($SizeMB / ($decryptMs / 1000.0), 2)
        })
    }
}

$results | Format-Table -AutoSize

Write-Host ""
Write-Host "Averages:"
$results |
    Group-Object Target |
    ForEach-Object {
        $group = $_.Group
        [pscustomobject]@{
            Target = $_.Name
            EncryptMs = [Math]::Round(($group | Measure-Object EncryptMs -Average).Average, 2)
            EncryptMBps = [Math]::Round(($group | Measure-Object EncryptMBps -Average).Average, 2)
            DecryptMs = [Math]::Round(($group | Measure-Object DecryptMs -Average).Average, 2)
            DecryptMBps = [Math]::Round(($group | Measure-Object DecryptMBps -Average).Average, 2)
        }
    } |
    Format-Table -AutoSize
