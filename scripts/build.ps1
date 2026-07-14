[CmdletBinding()]
param(
    [ValidateSet('Release')]
    [string] $Configuration = 'Release',

    [ValidateSet('x86', 'x64')]
    [string] $Platform = 'x64',

    [switch] $NoClean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')

$repositoryRoot = Get-RepositoryRoot
$solution = Join-Path $repositoryRoot 'SbieHide.sln'
$msbuild = Get-MSBuildPath
$logDirectory = Join-Path $repositoryRoot 'artifacts\logs'
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
if (-not $NoClean -and $Platform -eq 'x86') {
    $artifactDirectory = Get-ArtifactDirectory -Configuration $Configuration -Platform $Platform
    foreach ($unsupportedArtifact in @('SbieHideEx.dll', 'SbieHideExLoader.exe')) {
        Remove-Item -LiteralPath (Join-Path $artifactDirectory $unsupportedArtifact) `
            -Force -ErrorAction SilentlyContinue
    }
}
$binaryLog = Join-Path $logDirectory "SbieHide-$Configuration-$Platform.binlog"

$targets = if ($NoClean) { 'Build' } else { 'Clean;Build' }
$arguments = @(
    $solution,
    '/nologo',
    '/m',
    '/nr:false',
    '/verbosity:minimal',
    "/t:$targets",
    "/p:Configuration=$Configuration",
    "/p:Platform=$Platform",
    "/bl:$binaryLog"
)

Write-Host "MSBuild: $msbuild"
Write-Host "Building $Configuration|$Platform (targets: $targets)"
& $msbuild @arguments
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) {
    Write-Error "MSBuild failed with exit code $exitCode. Binary log: $binaryLog" -ErrorAction Continue
}
exit $exitCode
