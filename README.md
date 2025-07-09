# SbieHide

A plugin written for [sandboxie-plus](https://github.com/sandboxie-plus/Sandboxie) to combat the detection of sbiedll.dll.

## Features

- Bypasses common sandbox detection methods
- Supports both 32-bit and 64-bit applications
- Includes advanced TLS-based detection countermeasures
- Easy integration with Sandboxie-Plus

## Usage

### Method 1: Standard SbieHide Plugin

Compile this plugin or download pre-compiled files from [Release](https://github.com/VeroFess/SbieHide/releases).

**Important: Ensure the plugin filename contains the string 'sbiehide', otherwise it will not hide itself.**

Open the Sandboxie-Plus configuration file and add the following configuration to the sandbox that needs to hide from inner programs:

```ini
InjectDll64=Path\to\64\SbieHide.dll
InjectDll=Path\to\32\SbieHide.dll
```

### Method 2: SbieHideEx for TLS Detection

For applications that use TLS (Thread Local Storage) for detection, we have added **SbieHideEx** and **SbieHideExLoader**.

**Usage:**
```bash
Usage: SbieHideExLoader.exe <target_executable> [arguments...]
```

**Note: If you use SbieHideEx, you should NOT use the standard SbieHide plugin. Choose one method only.**

## Detection Methods Bypassed

The following detection techniques have been successfully bypassed:

- **PEB (Process Environment Block) manipulation:**
  - Peb->InLoadOrderModuleList
  - Peb->InMemoryOrderModuleList
  - Peb->InInitializationOrderModuleList
  - Peb->HashLinks

- **Windows API hooking:**
  - NtQueryVirtualMemory [MemoryBasicInformation|MemoryMappedFilenameInformation|MemoryRegionInformation|MemoryImageInformation|MemoryRegionInformationEx|MemoryEnclaveImageInformation|MemoryBasicInformationCapped]
  - NtQueryObject [ObjectNameInformation]
  - NtQueryInformationFile [FileNameInformation|FileAllInformation]
  - NtQuerySection [SectionOriginalBaseInformation]

- **TLS-based detection** (SbieHideEx only)

## Important Disclaimers

⚠️ **Anti-Cheat Warning**: Do not use this plugin to bypass anti-cheat systems. This plugin's behavior is similar to some cheats and may result in account bans.

⚠️ **Kernel Detection**: This module cannot counter kernel-level detection methods. Such countermeasures would require a driver implementation, which could trigger Microsoft PatchGuard.

## Troubleshooting

If some applications still detect sbiedll.dll, please:

1. Verify you're using the correct method (SbieHide vs SbieHideEx)
2. Ensure the plugin filename contains 'sbiehide'
3. Check that the configuration is properly applied
4. Create an issue with a sample application for further investigation

## License

SbieHide is licensed under the MIT License. Dependencies are under their respective licenses.

