# SbieHide

SbieHide is a plugin for [Sandboxie-Plus](https://github.com/sandboxie-plus/Sandboxie) that hides common user-mode evidence of `SbieDll.dll`. The standard plugin supports x86 and x64 processes; the TLS-oriented SbieHideEx path is x64-only.

## Build prerequisites

- Windows 10 or Windows 11
- Visual Studio 18 Enterprise (or another Visual Studio edition with `v145`) installed from the repository `.vsconfig`
- MSVC `v145`, C++ desktop tools, MASM, and Windows SDK `10.0.26100.0`
- PowerShell 7 or Windows PowerShell 5.1

In Visual Studio Installer, choose **Import configuration** and select `.vsconfig`, or open the repository in Visual Studio and accept the missing-component prompt.

The standard plugin builds the vendored MinHook v1.3.3 sources directly, so it does not depend on compiler-version-specific prebuilt `.lib` files.

The solution intentionally exposes only the following effective matrix:

| Solution configuration | Built projects | Output directory and PE files |
| --- | --- | --- |
| `Release|x86` | `SbieHide`, `SbieTestConsole` | `artifacts/bin/x86/Release/`: `SbieHide.dll`, `SbieTestConsole.exe` |
| `Release|x64` | all four projects | `artifacts/bin/x64/Release/`: `SbieHide.dll`, `SbieTestConsole.exe`, `SbieHideEx.dll`, `SbieHideExLoader.exe` |

`SbieHideEx` and `SbieHideExLoader` are not mapped into the x86 solution build. Both are rejected outside `Release|x64`; the payload additionally uses no CRT with `/NOENTRY`, `/NODEFAULTLIB`, and the Native subsystem. Debug solution configurations were removed so Visual Studio cannot silently select stale extended binaries.

## Build and verify

The build script finds `vswhere.exe` and the matching Visual Studio `MSBuild.exe`, cleans by default, builds the selected matrix entry, and writes a binary log under `artifacts/logs/`.

```powershell
pwsh -File .\scripts\build.ps1 -Configuration Release -Platform x64
pwsh -File .\scripts\test.ps1 -Configuration Release -Platform x64 -SkipBuild -SkipSandbox
```

`test.ps1` verifies every expected PE file, its x86/x64 machine type, the standard plugin exports (`GetHookAPIs`, `NotifyShims`), the complete SbieHideEx loader/payload export contract, the historical SbieHideEx ordinals `1..22`, and the payload's no-dynamic-dependency/no-CRT contract. Use `-SkipBuild` only when the selected output already exists. Use `-SkipSandbox` on machines without Sandboxie-Plus, including hosted CI.

Generated files are kept out of project directories:

```text
artifacts/
  bin/<x86|x64>/Release/   DLL and EXE files
  obj/<project>/...        compiler intermediates
  logs/                    MSBuild .binlog files
```

The Windows GitHub Actions workflow builds both effective matrix entries on hosted runners, checks an explicit first-party clang-format whitelist, verifies artifacts, and uploads short-lived workflow artifacts. Trusted `master` pushes and a weekly schedule run x86 and x64 runtime gates on a self-hosted Windows runner labeled `sandboxie`; maintainers can run the same matrix manually with `workflow_dispatch` and `run_sandboxie=true`. Pull requests never execute untrusted code on that self-hosted runner. The workflow has read-only repository permissions and does not publish releases or push changes.

## Usage

### Standard SbieHide plugin

Configure the DLL matching the sandboxed process architecture. Self-image tracking is address-based, so renaming the built DLL does not change the hiding behavior.

```ini
InjectDll64=C:\path\to\x64\SbieHide.dll
InjectDll=C:\path\to\x86\SbieHide.dll
```

Restart the affected sandbox after changing its configuration.

### SbieHideEx for TLS-time detection

`SbieHideExLoader.exe` and the default `SbieHideEx.dll` must be from `Release|x64`. Keep them in the same directory, or select the payload explicitly with `--module`. The loader and target must both be x64.

This path targets TLS-time entry-point integrity checks such as the behavior reported in [Sandboxie #1796](https://github.com/sandboxie-plus/Sandboxie/issues/1796). It bootstraps before Sandboxie loads `SbieDll.dll`, temporarily restores the target's original entry-point bytes while TLS callbacks run, and restores Sandboxie's entry hook afterward.

```powershell
$start = "C:\Program Files\Sandboxie-Plus\Start.exe"
& $start /box:YourBox /wait .\SbieHideExLoader.exe "C:\Path With Spaces\target.exe" --target-option value
& $start /box:YourBox /wait .\SbieHideExLoader.exe --module "D:\Tools\SbieHideEx.dll" "C:\Path\target.exe" arg1 arg2
```

```text
Usage: SbieHideExLoader.exe [--module <SbieHideEx.dll>] <target.exe> [arguments...]
```

Run the loader itself inside the intended Sandboxie box (as above), unless a Sandboxie Forced Program rule already guarantees that placement. Exit code `0` means the suspended child was mapped, patched, and resumed. Failures return the corresponding Win32 error code. The loader does not wait for the successfully resumed target to exit. Do not combine SbieHideEx with the standard `InjectDll`/`InjectDll64` plugin in the same launch path.

## Local Sandboxie smoke test

Install Sandboxie-Plus, then run:

```powershell
pwsh -File .\scripts\test.ps1 -Configuration Release -Platform x64 `
  -SandboxieHome "C:\Program Files\Sandboxie-Plus"
```

`-SandboxieHome` is optional when Sandboxie-Plus is installed in its default directory or `SANDBOXIE_HOME` is set. The x64 test first creates a disposable box, injects `SbieHide.dll`, and runs the automated detection checks. It then creates a second box without the standard plugin and runs a synthetic VMProtect-style TLS integrity gate: the negative control must reject Sandboxie's patched executable entry point, while the `SbieHideExLoader.exe` path must preserve the original entry bytes during TLS and still reach the target entry point after the loader exits. This covers Sandboxie #1796 as well as the lifecycle regression in PR #8 and issues #6/#7. The x86 test runs the standard-plugin stage only. Both stages reload Sandboxie configuration explicitly, propagate failures, and explicitly remove their disposable box contents and configuration.

These are repeatable launch, injection, API-filter, synthetic TLS-integrity, TLS-visibility, and child-lifecycle smoke tests; they are not proof that every protection implementation or detection technique is hidden on every Windows or Sandboxie version.

To run individual Sandboxie stages against an existing build:

```powershell
pwsh -File .\scripts\sandbox-smoke.ps1 -Configuration Release -Platform x64
pwsh -File .\scripts\ex-loader-smoke.ps1 -Configuration Release
```

## Detection coverage

- PEB loader-list and hash-link visibility
- `NtQueryVirtualMemory` memory and mapped-filename information
- `NtQueryObject` object-name information
- `NtQueryInformationFile` file-name information
- `NtQuerySection` original-base information
- Selected `NtQuerySystemInformation` and `NtQueryInformationProcess` results
- TLS-time detection path through SbieHideEx

## Loader lifetime fixes

[PR #8](https://github.com/VeroFess/SbieHide/pull/8) fixes the successful-launch lifetime bug reported in [issue #6](https://github.com/VeroFess/SbieHide/issues/6) and [issue #7](https://github.com/VeroFess/SbieHide/issues/7). The loader now owns and terminates the suspended child only while startup is incomplete. After `NtResumeProcess` succeeds it commits the child handle state, releases only loader-local mapping memory, and leaves the target running. Startup failures still clean up the suspended child and return a nonzero Win32 error.

## Limitations and troubleshooting

- SbieHide is user-mode only and cannot hide kernel-visible Sandboxie state.
- SbieHideEx is supported only for x64 targets and Windows versions compatible with its syscall and NTDLL patching assumptions.
- `SbieHideEx.dll` is an internal payload for `SbieHideExLoader.exe`; do not inject or initialize it in an already-running multithreaded process. Its internal NTDLL hooks are installed during the loader-controlled, suspended-process bootstrap.
- Use exactly one method: standard injection or SbieHideEx.
- Confirm that DLL and target architectures match and that the plugin path is readable inside the sandbox.
- If `test.ps1` reports missing exports or a wrong machine type, delete `artifacts/` and rebuild rather than copying an older binary.
- If a target still detects Sandboxie, include the Windows version, Sandboxie-Plus version, architecture, selected method, and a minimal sample when opening an issue.

## License

SbieHide is licensed under the MIT License. Dependencies remain under their respective licenses.
