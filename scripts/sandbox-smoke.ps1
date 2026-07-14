[CmdletBinding()]
param(
    [ValidateSet('Release')]
    [string] $Configuration = 'Release',

    [ValidateSet('x86', 'x64')]
    [string] $Platform = 'x64',

    [string] $SandboxieHome
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')


$sandboxieRoot = Get-SandboxieInstallationPath -PreferredPath $SandboxieHome
$startExe = Join-Path $sandboxieRoot 'Start.exe'
$sbieIniExe = Join-Path $sandboxieRoot 'SbieIni.exe'
$artifactDirectory = Get-ArtifactDirectory -Configuration $Configuration -Platform $Platform
$testConsole = Join-Path $artifactDirectory 'SbieTestConsole.exe'
$plugin = Join-Path $artifactDirectory 'SbieHide.dll'

foreach ($path in @($testConsole, $plugin)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required smoke-test artifact is missing: $path"
    }
}

$boxName = "SbieHideSmoke_$([guid]::NewGuid().ToString('N').Substring(0, 8))"

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
    Invoke-SbieIni set $boxName AutoDelete y
    if ($Platform -eq 'x64') {
        Invoke-SbieIni set $boxName InjectDll64 $plugin
    } else {
        Invoke-SbieIni set $boxName InjectDll $plugin
    }
    Assert-SbieIniValue -Section $boxName -Setting Enabled -ExpectedValue 'y'
    Assert-SbieIniValue -Section $boxName -Setting ConfigLevel -ExpectedValue '10'
    if ($Platform -eq 'x64') {
        Assert-SbieIniValue -Section $boxName -Setting InjectDll64 -ExpectedValue $plugin
    } else {
        Assert-SbieIniValue -Section $boxName -Setting InjectDll -ExpectedValue $plugin
    }
    $reloadCode = Invoke-NativeProcess -FilePath $startExe -Arguments @('/reload') -TimeoutSeconds 20
    if ($reloadCode -ne 0) {
        throw "Sandboxie configuration reload failed with exit code $reloadCode."
    }

    Write-Host "Running SbieTestConsole.exe in disposable Sandboxie box '$boxName'."
    $exitCode = Invoke-NativeProcess -FilePath $startExe -Arguments @(
        "/box:$boxName", '/wait', $testConsole, '--self-test'
    ) -TimeoutSeconds 60
    Write-Host "Sandboxie smoke-test exit code: $exitCode"
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
}

exit $exitCode
