<#
.SYNOPSIS
  Build the easySSH Windows installers (.exe and .msi).

.DESCRIPTION
  Run this on Windows. It installs the Tauri CLI on first use, then produces an
  NSIS setup .exe and a WiX .msi under src-tauri\target\release\bundle.

  macOS .dmg files cannot be produced here — Apple's tooling only runs on macOS.
  Use scripts/build.sh on a Mac, or push a tag and let the GitHub Actions
  workflow build both platforms from one release.

.EXAMPLE
  .\scripts\build.ps1
  .\scripts\build.ps1 -Bundles nsis
#>

[CmdletBinding()]
param(
  # Which installers to produce. "nsis" is the .exe, "msi" the Windows Installer package.
  [ValidateSet('nsis', 'msi', 'nsis,msi')]
  [string]$Bundles = 'nsis,msi'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "warn $msg" -ForegroundColor Yellow }

try {
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "Rust is not installed. Install it from https://rustup.rs and reopen this terminal."
  }

  # The MSVC linker is required; the GNU toolchain will not produce a usable bundle.
  $target = (rustc -vV | Select-String '^host:').ToString().Split(' ')[1]
  if ($target -notlike '*msvc*') {
    Write-Warn "Rust host toolchain is '$target'. easySSH expects the MSVC toolchain."
    Write-Warn "If the build fails, run: rustup default stable-x86_64-pc-windows-msvc"
  }

  cargo tauri --version *> $null
  if ($LASTEXITCODE -ne 0) {
    Write-Step 'Installing the Tauri CLI (one time)'
    cargo install tauri-cli --version "^2" --locked
    if ($LASTEXITCODE -ne 0) { throw 'Could not install the Tauri CLI.' }
  }

  Write-Step "Bundling $Bundles"
  cargo tauri build --bundles $Bundles
  if ($LASTEXITCODE -ne 0) { throw 'The Tauri build failed. See the output above.' }

  Write-Step 'Artifacts'
  $bundleDir = Join-Path $root 'src-tauri\target\release\bundle'
  $artifacts = Get-ChildItem -Path $bundleDir -Recurse -ErrorAction SilentlyContinue |
               Where-Object { $_.Extension -in '.exe', '.msi' }

  if (-not $artifacts) {
    throw "No installers found under $bundleDir"
  }

  foreach ($a in $artifacts) {
    $mb = [math]::Round($a.Length / 1MB, 1)
    Write-Host ("   {0}  ({1} MB)" -f $a.FullName, $mb) -ForegroundColor Green
  }

  Write-Host "`nDone." -ForegroundColor Green
}
finally {
  Pop-Location
}
