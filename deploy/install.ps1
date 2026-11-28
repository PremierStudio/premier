#Requires -Version 5.1
<#
.SYNOPSIS
  Install Premier for Windows x64 from PremierStudio/premier GitHub releases.

.DESCRIPTION
  Downloads premier-<tag>-x86_64-pc-windows-msvc.zip and its .sha256 file,
  checks SHA-256, and copies premier.exe plus ui\ under
  %LOCALAPPDATA%\Premier. Prints a PATH note and does not change PATH.

.PARAMETER Tag
  GitHub release tag, for example v1.2.3. Defaults to the latest release.

.PARAMETER Prefix
  Install root. Defaults to %LOCALAPPDATA%\Premier.
#>
[CmdletBinding()]
param(
    [string]$Tag,
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'Premier')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = if ($env:PREMIER_REPO) { $env:PREMIER_REPO } else { 'PremierStudio/premier' }
if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    throw "Premier publishes a Windows build for x86_64 only (this machine is $($env:PROCESSOR_ARCHITECTURE))."
}

if (-not $Tag) {
    $headers = @{
        'User-Agent' = 'premier-install'
        Accept       = 'application/vnd.github+json'
    }
    $release = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$Repo/releases/latest"
    if (-not $release.tag_name) {
        throw 'GitHub did not return a latest release tag.'
    }
    $Tag = [string]$release.tag_name
}

if ($Tag -notmatch '^[A-Za-z0-9._-]+$') {
    throw "Refusing tag '$Tag'."
}

$Name = "premier-$Tag-x86_64-pc-windows-msvc"
$ZipName = "$Name.zip"
$Base = "https://github.com/$Repo/releases/download/$Tag"
$Work = Join-Path ([System.IO.Path]::GetTempPath()) ("premier-install-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $Work | Out-Null

try {
    $zipPath = Join-Path $Work $ZipName
    $sumPath = Join-Path $Work "$ZipName.sha256"
    Write-Host "downloading $ZipName"
    Invoke-WebRequest -Uri "$Base/$ZipName" -OutFile $zipPath
    Invoke-WebRequest -Uri "$Base/$ZipName.sha256" -OutFile $sumPath

    $expected = ((Get-Content -Raw $sumPath).Trim() -split '\s+')[0].ToLowerInvariant()
    if ($expected -notmatch '^[0-9a-f]{64}$') {
        throw "Checksum file for $ZipName is not a SHA-256 digest."
    }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "SHA-256 mismatch for $ZipName."
    }

    Expand-Archive -Path $zipPath -DestinationPath $Work -Force
    $extracted = Join-Path $Work $Name
    $exe = Join-Path $extracted 'premier.exe'
    $ui = Join-Path $extracted 'ui'
    if (-not (Test-Path -LiteralPath $exe) -or -not (Test-Path -LiteralPath $ui)) {
        throw 'Archive does not contain premier.exe and ui/.'
    }

    $bin = Join-Path $Prefix 'bin'
    $uiDest = Join-Path $Prefix 'ui'
    New-Item -ItemType Directory -Force -Path $bin | Out-Null
    if (Test-Path -LiteralPath $uiDest) {
        Remove-Item -LiteralPath $uiDest -Recurse -Force
    }
    Copy-Item -LiteralPath $exe -Destination (Join-Path $bin 'premier.exe') -Force
    Copy-Item -LiteralPath $ui -Destination $uiDest -Recurse -Force

    Write-Host "installed $(Join-Path $bin 'premier.exe')"
    Write-Host "studio UI $uiDest"
    Write-Host "Set PREMIER_STATIC_UI_DIR to $uiDest before 'premier serve' when the UI is not on the default path."

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $needle = $bin.TrimEnd('\')
    $present = $false
    if ($userPath) {
        $present = @($userPath -split ';' | ForEach-Object { $_.Trim().TrimEnd('\') }) -contains $needle
    }
    if (-not $present) {
        Write-Host ""
        Write-Host "PATH note: $bin is not on your user PATH."
        Write-Host "Add it, then open a new terminal:"
        Write-Host "  `$bin = '$bin'"
        Write-Host '  $path = [Environment]::GetEnvironmentVariable(''Path'', ''User'')'
        Write-Host '  [Environment]::SetEnvironmentVariable(''Path'', (($path, $bin) -join '';'').Trim('';''), ''User'')'
    }
}
finally {
    if (Test-Path -LiteralPath $Work) {
        Remove-Item -LiteralPath $Work -Recurse -Force
    }
}
