# SecretHarbor Canonical Installer for Windows (PowerShell)
# Repository: https://github.com/logn10/SecretHarbor
# Releases: https://github.com/logn10/SecretHarbor/releases
#
# Usage:
#   irm https://github.com/logn10/SecretHarbor/releases/latest/download/install.ps1 | iex
#   or:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1

[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$InstallDir = "",
    [switch]$DryRun,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) {
    Write-Host "==> " -ForegroundColor Cyan -NoNewline
    Write-Host $msg
}

function Write-Success($msg) {
    Write-Host "✓ " -ForegroundColor Green -NoNewline
    Write-Host $msg
}

function Write-WarningMsg($msg) {
    Write-Host "⚠️  " -ForegroundColor Yellow -NoNewline
    Write-Host $msg
}

function Write-ErrorMsg($msg) {
    Write-Host "Error: " -ForegroundColor Red -NoNewline
    Write-Host $msg
    exit 1
}

# 1. Detect Architecture
$arch = $env:PROCESSOR_ARCHITECTURE
switch -Regex ($arch) {
    "AMD64|x86_64" { $platformArch = "amd64" }
    "ARM64"        { $platformArch = "arm64" }
    default {
        Write-ErrorMsg "Unsupported processor architecture: $arch. Please visit https://github.com/logn10/SecretHarbor/releases for manual builds."
    }
}

$platform = "windows-$platformArch"
Write-Info "Detected platform: $platform"

# 2. Determine Installation Directory
if (-not $InstallDir) {
    $InstallDir = Join-Path $env:LOCALAPPDATA "Programs\SecretHarbor"
}

if ($DryRun) {
    Write-Info "Dry run requested. Checking installation path: $InstallDir"
    Write-Success "Pre-flight checks passed for $platform"
    exit 0
}

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 3. Base URLs and Version Discovery
$ghRepo = if ($env:SECRETHARBOR_GITHUB_REPO) { $env:SECRETHARBOR_GITHUB_REPO } else { "logn10/SecretHarbor" }
$ghReleases = "https://github.com/$ghRepo/releases"
$customBase = if ($env:SECRETHARBOR_UPDATE_URL) { $env:SECRETHARBOR_UPDATE_URL.TrimEnd("/") } else { "" }
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("shb-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    # Resolve target version cleanly without bash syntax
    $targetVer = if ($Version) { $Version.TrimStart("v") } else { "" }
    if (-not $targetVer) {
        $manifestUrl = if ($customBase) { "$customBase/manifest.json" } else { "$ghReleases/latest/download/manifest.json" }
        try {
            $manifestJson = Invoke-RestMethod -Uri $manifestUrl -UseBasicParsing -TimeoutSec 15 -ErrorAction SilentlyContinue
            if ($manifestJson -and $manifestJson.version) {
                $targetVer = $manifestJson.version.TrimStart("v")
            }
        } catch {
            # Version stays empty; handled below.
        }
    }

    if (-not $targetVer) {
        Write-ErrorMsg "Could not determine the latest release version. Pass -Version <version> explicitly (see $ghReleases)."
    }

    $releaseBase = if ($customBase) { "$customBase/v$targetVer" } else { "$ghReleases/download/v$targetVer" }
    $artifactName = "secretharbor_${targetVer}_windows_${platformArch}.zip"
    $artifactUrl = "$releaseBase/$artifactName"
    $downloadFile = Join-Path $tempDir $artifactName

    Write-Info "Downloading SecretHarbor release for $platform (v$targetVer)..."
    Invoke-WebRequest -Uri $artifactUrl -OutFile $downloadFile -UseBasicParsing

    # 4. Download and Compare Checksum against checksums.txt
    $checksumsUrl = "$releaseBase/checksums.txt"
    $checksumsFile = Join-Path $tempDir "checksums.txt"

    Invoke-WebRequest -Uri $checksumsUrl -OutFile $checksumsFile -UseBasicParsing -ErrorAction SilentlyContinue

    $computedHash = (Get-FileHash -Path $downloadFile -Algorithm SHA256).Hash.ToLower()

    if (Test-Path $checksumsFile) {
        $checksumContent = Get-Content $checksumsFile
        $expectedHash = ""
        foreach ($line in $checksumContent) {
            if ($line -like "*$artifactName*") {
                $parts = -split $line
                if ($parts.Length -ge 1) {
                    $expectedHash = $parts[0].ToLower().Trim()
                    break
                }
            }
        }

        if ($expectedHash) {
            Write-Info "Verifying artifact integrity against checksums.txt..."
            if ($computedHash -ne $expectedHash) {
                Write-ErrorMsg "Checksum mismatch! Expected: $expectedHash, Computed: $computedHash"
            }
            Write-Success "Cryptographic checksum verified (SHA256: $computedHash)"
        } else {
            Write-ErrorMsg "Checksum for $artifactName not found in checksums.txt. Aborting installation."
        }
    } else {
        Write-ErrorMsg "Failed to obtain checksums.txt. Installation of unverified binary aborted."
    }

    # 5. Extract Archive and Install Binaries
    Expand-Archive -Path $downloadFile -DestinationPath $tempDir -Force
    $extractedShb = Join-Path $tempDir "shb.exe"
    $extractedSecretharbor = Join-Path $tempDir "secretharbor.exe"

    if (Test-Path $extractedShb) {
        Move-Item -Path $extractedShb -Destination (Join-Path $InstallDir "shb.exe") -Force
        if (Test-Path $extractedSecretharbor) {
            Move-Item -Path $extractedSecretharbor -Destination (Join-Path $InstallDir "secretharbor.exe") -Force
        } else {
            Copy-Item -Path (Join-Path $InstallDir "shb.exe") -Destination (Join-Path $InstallDir "secretharbor.exe") -Force
        }
    } else {
        Write-ErrorMsg "Extracted archive did not contain shb.exe"
    }

    # 6. PATH Environment Management
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$InstallDir*") {
        Write-Info "Adding $InstallDir to user PATH..."
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
        $env:Path += ";$InstallDir"
    }

    Write-Success "SecretHarbor installed successfully!"
    Write-Success "shb command installed to $InstallDir"

    Write-Host ""
    Write-Host "Run:" -ForegroundColor Cyan
    Write-Host "  shb init"
    Write-Host "  shb run claude"
}
finally {
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
