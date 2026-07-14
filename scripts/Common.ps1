Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-VsWherePath {
    $command = Get-Command vswhere.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $candidate = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        return $candidate
    }

    throw 'vswhere.exe was not found. Install Visual Studio 18 using the repository .vsconfig file.'
}

function Get-VisualStudioInstallationPath {
    $vswhere = Get-VsWherePath
    $installationPath = & $vswhere -latest -version '[18.0,19.0)' -products '*' `
        -requires Microsoft.Component.MSBuild Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath

    if ($LASTEXITCODE -ne 0 -or -not $installationPath) {
        throw 'Visual Studio 18 with MSBuild and the C++ x86/x64 tools was not found.'
    }

    return ($installationPath | Select-Object -First 1).Trim()
}

function Get-MSBuildPath {
    $path = Join-Path (Get-VisualStudioInstallationPath) 'MSBuild\Current\Bin\MSBuild.exe'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "MSBuild.exe was not found at '$path'."
    }
    return $path
}

function Get-DumpBinPath {
    $installationPath = Get-VisualStudioInstallationPath
    $candidates = Get-ChildItem -Path (Join-Path $installationPath 'VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe') -File |
        Sort-Object FullName -Descending
    if (-not $candidates) {
        throw 'dumpbin.exe was not found in the selected Visual Studio installation.'
    }
    return $candidates[0].FullName
}

function Get-ClangFormatPath {
    $command = Get-Command clang-format.exe -ErrorAction SilentlyContinue
    if (-not $command) {
        $command = Get-Command clang-format -ErrorAction SilentlyContinue
    }
    if ($command) {
        return $command.Source
    }

    $installationPath = Get-VisualStudioInstallationPath
    $candidates = @(
        (Join-Path $installationPath 'VC\Tools\Llvm\x64\bin\clang-format.exe'),
        (Join-Path $installationPath 'VC\Tools\Llvm\bin\clang-format.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    throw 'clang-format was not found on PATH or in the selected Visual Studio installation.'
}

function Get-RepositoryRoot {
    return (Split-Path -Parent $PSScriptRoot)
}

function Get-ArtifactDirectory {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Release')]
        [string] $Configuration,

        [Parameter(Mandatory)]
        [ValidateSet('x86', 'x64')]
        [string] $Platform
    )

    return Join-Path (Get-RepositoryRoot) "artifacts\bin\$Platform\$Configuration"
}

function Get-SandboxieInstallationPath {
    param([string] $PreferredPath)

    $candidates = @(
        $PreferredPath,
        $env:SANDBOXIE_HOME,
        (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Sandboxie-Plus'),
        (Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Sandboxie-Plus')
    ) | Where-Object { $_ }

    foreach ($candidate in $candidates) {
        if ((Test-Path -LiteralPath (Join-Path $candidate 'Start.exe') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $candidate 'SbieIni.exe') -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw 'Sandboxie-Plus Start.exe and SbieIni.exe were not found. Pass -SandboxieHome or set SANDBOXIE_HOME.'
}

function Get-PortableExecutableArchitecture {
    param([Parameter(Mandatory)][string] $Path)

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            throw "'$Path' is not a PE file (missing MZ signature)."
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "'$Path' is not a PE file (missing PE signature)."
        }
        $machine = $reader.ReadUInt16()
    } finally {
        $stream.Dispose()
    }

    switch ($machine) {
        0x014C { return 'x86' }
        0x8664 { return 'x64' }
        default { throw ("Unsupported PE machine 0x{0:X4} in '{1}'." -f $machine, $Path) }
    }
}

function ConvertTo-NativeCommandLineArgument {
    param([AllowEmptyString()][string] $Argument)

    if ($Argument.Length -ne 0 -and $Argument -notmatch '[\s"]') {
        return $Argument
    }

    $builder = [System.Text.StringBuilder]::new()
    [void] $builder.Append('"')
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq '\') {
            ++$backslashes
            continue
        }
        if ($character -eq '"') {
            [void] $builder.Append('\', 2 * $backslashes + 1)
            [void] $builder.Append('"')
        } else {
            [void] $builder.Append('\', $backslashes)
            [void] $builder.Append($character)
        }
        $backslashes = 0
    }
    [void] $builder.Append('\', 2 * $backslashes)
    [void] $builder.Append('"')
    return $builder.ToString()
}

function Invoke-NativeProcess {
    param(
        [Parameter(Mandatory)][string] $FilePath,
        [string[]] $Arguments = @(),
        [ValidateRange(1, 3600)][int] $TimeoutSeconds = 60
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    if ($null -ne $startInfo.PSObject.Properties['ArgumentList']) {
        foreach ($argument in $Arguments) {
            $startInfo.ArgumentList.Add($argument)
        }
    } else {
        $startInfo.Arguments = (($Arguments | ForEach-Object {
            ConvertTo-NativeCommandLineArgument $_
        }) -join ' ')
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Unable to start native process '$FilePath'."
        }
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $killError = $null
            try {
                $process.Kill()
            } catch {
                $killError = $_
            }
            if (-not $process.WaitForExit(5000)) {
                $detail = if ($null -ne $killError) { ": $killError" } else { '' }
                throw "Native process timed out and could not be terminated: $FilePath$detail"
            }
            throw "Native process timed out after $TimeoutSeconds seconds: $FilePath"
        }
        return $process.ExitCode
    } finally {
        $process.Dispose()
    }
}

function Invoke-NativeProcessOutput {
    param(
        [Parameter(Mandatory)][string] $FilePath,
        [string[]] $Arguments = @(),
        [ValidateRange(1, 3600)][int] $TimeoutSeconds = 60
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    if ($null -ne $startInfo.PSObject.Properties['ArgumentList']) {
        foreach ($argument in $Arguments) {
            $startInfo.ArgumentList.Add($argument)
        }
    } else {
        $startInfo.Arguments = (($Arguments | ForEach-Object {
            ConvertTo-NativeCommandLineArgument $_
        }) -join ' ')
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Unable to start native process '$FilePath'."
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try {
                if ($null -ne $process.PSObject.Methods['Kill'] -and
                    $process.PSObject.Methods['Kill'].OverloadDefinitions -match 'Boolean') {
                    $process.Kill($true)
                } else {
                    $process.Kill()
                }
            } catch {
                Write-Verbose "Unable to terminate timed-out process: $_"
            }
            [void] $process.WaitForExit(5000)
            throw "Native process timed out after $TimeoutSeconds seconds: $FilePath"
        }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            StandardOutput = $stdoutTask.GetAwaiter().GetResult()
            StandardError = $stderrTask.GetAwaiter().GetResult()
        }
    } finally {
        $process.Dispose()
    }
}
