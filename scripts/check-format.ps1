[CmdletBinding()]
param([switch] $Fix)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Common.ps1')

$clangFormat = Get-ClangFormatPath
$repositoryRoot = Get-RepositoryRoot
$firstPartyFiles = @(
    'SbieHide/APIHook.cpp',
    'SbieHide/APIHook.h',
    'SbieHide/HiddenNameMatcher.cpp',
    'SbieHide/HiddenNameMatcher.h',
    'SbieHide/HookRegistry.cpp',
    'SbieHide/HookRegistry.h',
    'SbieHide/QueryProxy.cpp',
    'SbieHide/QueryProxy.h',
    'SbieHide/HideFromPEB.cpp',
    'SbieHide/HideFromPEB.h',
    'SbieHide/LibEntry.cpp',
    'SbieHide/MemoryImageHideInformation.cpp',
    'SbieHide/MemoryImageHideInformation.h',
    'SbieHideEx/address_finder.cpp',
    'SbieHideEx/address_finder.h',
    'SbieHideEx/detours.h',
    'SbieHideEx/entry.cpp',
    'SbieHideEx/hidden_name.h',
    'SbieHideEx/loader_detours.cpp',
    'SbieHideEx/query_detours.cpp',
    'SbieHideEx/rt.cpp',
    'SbieHideEx/simple_runtime_library.h',
    'SbieHideExLoader/entry.cpp',
    'SbieHideExLoader/CommandLine.cpp',
    'SbieHideExLoader/CommandLine.h',
    'SbieHideExLoader/PeImageView.cpp',
    'SbieHideExLoader/PeImageView.h',
    'SbieHideExLoader/ProcessLauncher.cpp',
    'SbieHideExLoader/ProcessLauncher.h',
    'SbieHideExLoader/NtdllRemapper.cpp',
    'SbieHideExLoader/NtdllRemapper.h',
    'SbieHideExLoader/SbieHideLoader.cpp',
    'SbieHideExLoader/SbieHideLoader.h',
    'SbieTestConsole/ConsoleEntry.cpp',
    'SbieTestConsole/DetectionChecks.cpp',
    'SbieTestConsole/DetectionChecks.h'
) | ForEach-Object { Join-Path $repositoryRoot $_ }

$missing = $firstPartyFiles | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) }
if ($missing) {
    throw "First-party format whitelist contains missing files: $($missing -join ', ')"
}

if ($Fix) {
    & $clangFormat -i @firstPartyFiles
} else {
    & $clangFormat --dry-run --Werror @firstPartyFiles
}
exit $LASTEXITCODE
