[CmdletBinding()]
param(
    [ValidateSet('Release')]
    [string] $Configuration = 'Release',

    [ValidateSet('x86', 'x64')]
    [string] $Platform = 'x64',

    [switch] $SkipBuild,
    [switch] $SkipSandbox,
    [string] $SandboxieHome
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')

$powerShell = (Get-Process -Id $PID).Path
if (-not $SkipBuild) {
    & $powerShell -NoProfile -File (Join-Path $PSScriptRoot 'build.ps1') `
        -Configuration $Configuration -Platform $Platform
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

$artifactDirectory = Get-ArtifactDirectory -Configuration $Configuration -Platform $Platform
$expectedFiles = @('SbieHide.dll', 'SbieTestConsole.exe')
if ($Configuration -eq 'Release' -and $Platform -eq 'x64') {
    $expectedFiles += @('SbieHideEx.dll', 'SbieHideExLoader.exe')
}
if ($Platform -eq 'x86') {
    foreach ($unsupportedArtifact in @('SbieHideEx.dll', 'SbieHideExLoader.exe')) {
        $unsupportedPath = Join-Path $artifactDirectory $unsupportedArtifact
        if (Test-Path -LiteralPath $unsupportedPath -PathType Leaf) {
            throw "Unsupported stale x86 artifact must be removed: $unsupportedPath"
        }
    }
}

$paths = @{}
foreach ($fileName in $expectedFiles) {
    $path = Join-Path $artifactDirectory $fileName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Expected build output is missing: $path"
    }
    $actualArchitecture = Get-PortableExecutableArchitecture -Path $path
    if ($actualArchitecture -ne $Platform) {
        throw "$fileName is $actualArchitecture; expected $Platform."
    }
    $paths[$fileName] = $path
    Write-Host "Verified $fileName ($actualArchitecture)."
}

$dumpbin = Get-DumpBinPath
function Assert-Exports {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string[]] $Names,
        [switch] $AllowX86CDecoration
    )

    $output = (& $dumpbin /nologo /exports $Path 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "dumpbin failed while reading exports from '$Path'."
    }

    foreach ($name in $Names) {
        $prefix = if ($AllowX86CDecoration) { '_?' } else { '' }
        $pattern = "(?m)^\s*\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+$prefix$([regex]::Escape($name))(?:\s|$)"
        if (-not [regex]::IsMatch($output, $pattern)) {
            throw "Required export '$name' is missing from '$Path'."
        }
    }
}

function Assert-ExportOrdinals {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][hashtable] $ExpectedOrdinals
    )
    $output = (& $dumpbin /nologo /exports $Path 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "dumpbin failed while reading export ordinals from '$Path'."
    }
    foreach ($entry in $ExpectedOrdinals.GetEnumerator()) {
        $pattern = "(?m)^\s*$($entry.Value)\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+$([regex]::Escape($entry.Key))(?:\s|$)"
        if (-not [regex]::IsMatch($output, $pattern)) {
            throw "Export '$($entry.Key)' did not preserve ordinal $($entry.Value) in '$Path'."
        }
    }
}

function Assert-NoDynamicDependencies {
    param([Parameter(Mandatory)][string] $Path)
    $output = (& $dumpbin /nologo /dependents $Path 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "dumpbin failed while reading dependencies from '$Path'."
    }
    if ([regex]::IsMatch($output, '(?im)^\s*[^\s]+\.dll\s*$')) {
        throw "No-CRT payload '$Path' unexpectedly imports a DLL.`n$output"
    }
}

Assert-Exports -Path $paths['SbieHide.dll'] -Names @('GetHookAPIs', 'NotifyShims') `
    -AllowX86CDecoration:($Platform -eq 'x86')

if ($paths.ContainsKey('SbieHideEx.dll')) {
    $exExports = @(
        'NTDLL_BASE_ADDRESS',
        'NTDLL_SIZE',
        'SBIEHIDE_BASE_ADDRESS',
        'SBIEHIDE_SIZE',
        'ENTRY_DATA',
        'ENTRY_DATA_SIZE',
        'MODULE_INITIALIZATION_STATE',
        'MODULE_INITIALIZATION_FAILURE_STAGE',
        'ModulePreProcessInitRoutine',
        'MODULE_INITIALIZATION_SIGNAL',
        'LDR_LOAD_DLL_BOOTSTRAP_TARGET',
        'LDR_LOAD_DLL_BOOTSTRAP_ORIGINAL',
        'LdrLoadDllBootstrapDetours',
        'LDR_GET_DLL_HANDLE_HIT_COUNT',
        'LDR_GET_DLL_HANDLE_HIDE_COUNT',
        'NtFreeVirtualMemorySystemCallIndex',
        'NtQueryVirtualMemorySystemCallIndex',
        'NtQuerySystemInformationSystemCallIndex',
        'NtAllocateVirtualMemorySystemCallIndex',
        'NtDelayExecutionSystemCallIndex',
        'NtProtectVirtualMemorySystemCallIndex',
        'NtQueryInformationProcessSystemCallIndex',
        'NtQuerySectionSystemCallIndex',
        'NtQueryInformationFileSystemCallIndex',
        'NtQueryObjectSystemCallIndex',
        'NtQueryVirtualMemoryDetours',
        'NtQueryObjectDetours',
        'NtQueryInformationFileDetours',
        'NtQuerySectionDetours',
        'NtQuerySystemInformationDetours',
        'NtQueryInformationProcessDetours'
    )
    Assert-Exports -Path $paths['SbieHideEx.dll'] -Names $exExports
    Assert-ExportOrdinals -Path $paths['SbieHideEx.dll'] -ExpectedOrdinals @{
        ENTRY_DATA = 1
        ENTRY_DATA_SIZE = 2
        NTDLL_BASE_ADDRESS = 3
        NTDLL_SIZE = 4
        NtAllocateVirtualMemorySystemCallIndex = 5
        NtDelayExecutionSystemCallIndex = 6
        NtFreeVirtualMemorySystemCallIndex = 7
        NtProtectVirtualMemorySystemCallIndex = 8
        NtQueryInformationFileSystemCallIndex = 9
        NtQueryInformationProcessSystemCallIndex = 10
        NtQueryObjectSystemCallIndex = 11
        NtQuerySectionSystemCallIndex = 12
        NtQuerySystemInformationSystemCallIndex = 13
        NtQueryVirtualMemorySystemCallIndex = 14
        SBIEHIDE_BASE_ADDRESS = 15
        SBIEHIDE_SIZE = 16
        NtQueryInformationFileDetours = 17
        NtQueryInformationProcessDetours = 18
        NtQueryObjectDetours = 19
        NtQuerySectionDetours = 20
        NtQuerySystemInformationDetours = 21
        NtQueryVirtualMemoryDetours = 22
    }
    Assert-NoDynamicDependencies -Path $paths['SbieHideEx.dll']
}

if (-not $SkipSandbox) {
    $sandboxArguments = @(
        '-NoProfile',
        '-File', (Join-Path $PSScriptRoot 'sandbox-smoke.ps1'),
        '-Configuration', $Configuration,
        '-Platform', $Platform
    )
    if ($SandboxieHome) {
        $sandboxArguments += @('-SandboxieHome', $SandboxieHome)
    }
    & $powerShell @sandboxArguments
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    if ($Platform -eq 'x64') {
        $extendedArguments = @(
            '-NoProfile',
            '-File', (Join-Path $PSScriptRoot 'ex-loader-smoke.ps1'),
            '-Configuration', $Configuration
        )
        if ($SandboxieHome) {
            $extendedArguments += @('-SandboxieHome', $SandboxieHome)
        }
        & $powerShell @extendedArguments
        exit $LASTEXITCODE
    }
    exit 0
}

Write-Host 'Artifact verification completed; Sandboxie smoke test was skipped.'
