[CmdletBinding()]
param(
    [ValidateSet('Release')]
    [string] $Configuration = 'Release',

    [string] $SandboxieHome
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')

$sandboxieRoot = Get-SandboxieInstallationPath -PreferredPath $SandboxieHome
$startExe = Join-Path $sandboxieRoot 'Start.exe'
$sbieIniExe = Join-Path $sandboxieRoot 'SbieIni.exe'
$artifactDirectory = Get-ArtifactDirectory -Configuration $Configuration -Platform 'x64'
$loader = Join-Path $artifactDirectory 'SbieHideExLoader.exe'
$core = Join-Path $artifactDirectory 'SbieHideEx.dll'
$standardPlugin = Join-Path $artifactDirectory 'SbieHide.dll'
$testConsole = Join-Path $artifactDirectory 'SbieTestConsole.exe'

foreach ($path in @($loader, $core, $standardPlugin, $testConsole)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required extended smoke-test artifact is missing: $path"
    }
}

$boxName = "SbieHideExSmoke_$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$markerDirectory = Join-Path (Get-RepositoryRoot) 'artifacts\logs'
New-Item -ItemType Directory -Path $markerDirectory -Force | Out-Null
$markerPath = Join-Path $markerDirectory "$boxName.marker"
$coreBasePath = Join-Path $markerDirectory "$boxName.core-base"
$evidenceBaseName = "SbieHideVmpTls_$([guid]::NewGuid().ToString('N'))"
$evidenceEventName = $evidenceBaseName
$sessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
$evidenceIpcPath = "\Sessions\$sessionId\BaseNamedObjects\$evidenceBaseName"
$evidenceCreated = $false
$evidenceEvent = [System.Threading.EventWaitHandle]::new(
    $false,
    [System.Threading.EventResetMode]::ManualReset,
    $evidenceEventName,
    [ref] $evidenceCreated)
if (-not $evidenceCreated) {
    $evidenceEvent.Dispose()
    throw "Synthetic VMP evidence event already existed: $evidenceEventName"
}
Remove-Item -LiteralPath $markerPath, $coreBasePath -Force -ErrorAction SilentlyContinue

function Invoke-SbieIni {
    param([Parameter(ValueFromRemainingArguments)][string[]] $Arguments)
    $code = Invoke-NativeProcess -FilePath $sbieIniExe -Arguments $Arguments -TimeoutSeconds 20
    if ($code -ne 0) {
        throw "SbieIni.exe failed with exit code ${code}: $($Arguments -join ' ')"
    }
}

function Assert-SbieIniValue {
    param(
        [Parameter(Mandatory)][string] $Section,
        [Parameter(Mandatory)][string] $Setting,
        [Parameter(Mandatory)][string] $ExpectedValue
    )
    $result = Invoke-NativeProcessOutput -FilePath $sbieIniExe -Arguments @(
        'query', $Section, $Setting
    ) -TimeoutSeconds 20
    $actual = $result.StandardOutput.Trim()
    if ($result.ExitCode -ne 0 -or $actual -ine $ExpectedValue) {
        throw "Sandboxie setting verification failed for [$Section] ${Setting}: expected '$ExpectedValue', got '$actual' (exit $($result.ExitCode))."
    }
}

$boxCreated = $false
$exitCode = 1
try {
    $boxCreated = $true
    Invoke-SbieIni set $boxName Enabled y
    Invoke-SbieIni set $boxName ConfigLevel 10
    Invoke-SbieIni set $boxName AutoDelete n
    Invoke-SbieIni set $boxName OpenFilePath $markerDirectory
    Invoke-SbieIni set $boxName OpenIpcPath '*'
    Assert-SbieIniValue -Section $boxName -Setting Enabled -ExpectedValue 'y'
    Assert-SbieIniValue -Section $boxName -Setting ConfigLevel -ExpectedValue '10'
    Assert-SbieIniValue -Section $boxName -Setting AutoDelete -ExpectedValue 'n'
    Assert-SbieIniValue -Section $boxName -Setting OpenFilePath -ExpectedValue $markerDirectory
    Assert-SbieIniValue -Section $boxName -Setting OpenIpcPath -ExpectedValue '*'
    $reloadCode = Invoke-NativeProcess -FilePath $startExe -Arguments @('/reload') -TimeoutSeconds 20
    if ($reloadCode -ne 0) {
        throw "Sandboxie configuration reload failed with exit code $reloadCode."
    }


    Write-Host "Running SbieHideExLoader.exe in disposable Sandboxie box '$boxName'."
    $loaderExitCode = Invoke-NativeProcess -FilePath $startExe -Arguments @(
        "/box:$boxName", '/wait', '/silent', $loader, '--write-core-base', $coreBasePath,
        '--verify-initialization',
        '--module', $core, $testConsole, '--write-marker-after-parent-exit', $markerPath,
        '--core-base-file', $coreBasePath
    ) -TimeoutSeconds 60
    if ($loaderExitCode -ne 0) {
        throw "SbieHideExLoader failed with exit code $loaderExitCode."
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (-not (Test-Path -LiteralPath $markerPath -PathType Leaf) -and
           [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        throw 'The resumed child did not reach its entry point; the PR #8 lifecycle regression may have returned.'
    }

    $marker = Get-Content -LiteralPath $markerPath -Raw
    if ($marker -notmatch 'SbieHideEx child reached its entry point') {
        throw "The extended-loader child reported: $($marker.Trim())"
    }

    Invoke-SbieIni set $boxName InjectDll64 $standardPlugin
    Assert-SbieIniValue -Section $boxName -Setting InjectDll64 -ExpectedValue $standardPlugin
    $baselineReloadCode = Invoke-NativeProcess -FilePath $startExe -Arguments @('/reload') -TimeoutSeconds 20
    if ($baselineReloadCode -ne 0) {
        throw "Sandboxie negative-control reload failed with exit code $baselineReloadCode."
    }
    Write-Host 'Confirming the standard SbieHide path cannot satisfy the synthetic TLS integrity probe.'
    [void] $evidenceEvent.Reset()
    $baselineExitCode = Invoke-NativeProcess -FilePath $startExe -Arguments @(
        "/box:$boxName", '/wait', '/silent', $testConsole,
        '--vmp-integrity-probe', $evidenceIpcPath
    ) -TimeoutSeconds 60
    Write-Host "Synthetic VMP baseline exit code: $baselineExitCode"
    if (-not $evidenceEvent.WaitOne(0)) {
        throw 'Synthetic VMP negative control exited without signaling after detecting TLS entry-point tamper.'
    }
    if ($baselineExitCode -ne 0x1796 -and $baselineExitCode -ne 0x40010004) {
        throw "Synthetic VMP negative control returned unexpected exit code $baselineExitCode."
    }
    Write-Host "Synthetic VMP negative control rejected the patched entry point (exit code $baselineExitCode)."

    Write-Host 'Synthetic VMP TLS entry-point integrity was preserved by SbieHideEx.'
    Write-Host 'SbieHideEx child reached its entry point after the loader exited.'
    $exitCode = 0
} finally {
    if ($boxCreated) {
        $cleanupFailed = $false
        try {
            $code = Invoke-NativeProcess -FilePath $startExe -Arguments @(
                "/box:$boxName", '/terminate', '/silent'
            ) -TimeoutSeconds 20
            if ($code -ne 0) { throw "exit code $code" }
        } catch {
            Write-Warning "Sandboxie process termination failed: $_"
            $cleanupFailed = $true
        }
        try {
            $code = Invoke-NativeProcess -FilePath $startExe -Arguments @(
                "/box:$boxName", 'delete_sandbox_silent', '/silent'
            ) -TimeoutSeconds 20
            if ($code -ne 0) { throw "exit code $code" }
        } catch {
            Write-Warning "Sandboxie content deletion failed: $_"
            $cleanupFailed = $true
        }
        try {
            Invoke-SbieIni set $boxName '*'
        } catch {
            Write-Warning "Sandboxie configuration deletion failed: $_"
            $cleanupFailed = $true
        }
        try {
            $code = Invoke-NativeProcess -FilePath $startExe -Arguments @('/reload') -TimeoutSeconds 20
            if ($code -ne 0) { throw "exit code $code" }
            $remainingConfiguration = @(& $sbieIniExe query $boxName 2>$null)
            if ($LASTEXITCODE -ne 0 -or $remainingConfiguration.Count -ne 0) {
                throw "temporary section '$boxName' still exists"
            }
        } catch {
            Write-Warning "Sandboxie cleanup reload failed: $_"
            $cleanupFailed = $true
        }
        if ($cleanupFailed) {
            $exitCode = 1
        } else {
            Write-Host 'Cleanup: completed.'
        }
    }
    foreach ($temporaryPath in @($markerPath, $coreBasePath)) {
        try {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction Stop
        } catch [System.Management.Automation.ItemNotFoundException] {
        } catch {
            Write-Warning "Temporary-file cleanup failed for '$temporaryPath': $_"
            $exitCode = 1
        }
    }
    $evidenceEvent.Dispose()
}

exit $exitCode
