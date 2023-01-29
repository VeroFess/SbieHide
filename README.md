# SbieHide

A plugin written for [sandboxie-plus](https://github.com/sandboxie-plus/Sandboxie), which is used to fight the detection of sbiedll.dll

## How to use?

Compile this plug-in or download pre-compiled files from [Release](https://github.com/VeroFess/SbieHide/releases)


**You should ensure file name of this plug-in contains the string 'sbiehide', otherwise it will not hide itself.**


Open the configuration file of sandboxie-plus and add the following configuration to the sandbox which need to hide from inner program:

```
InjectDll64=Path\to\64\SbieHide.dll
InjectDll=Path\to\32\SbieHide.dll
```

-----

## About some applications are still detected sbiedll.dll

First of all, you should not use this plug-in for bypass anti-cheating, 

The behavior of this plug-in is very similar to some cheat, which may cause your account banned!

Secondly, this module cannot fight the detection of the kernel layer. Related confrontation needs to write in a driver, and doing so in the kernel will make Microsoft Patchguard unhappy.

Finally, please bring a sample in issue, and I will try to correct this problem.

-----

## The detection that has been passed

* Peb->InLoadOrderModuleList
* Peb->InMemoryOrderModuleList
* Peb->InInitializationOrderModuleList
* Peb->HashLinks
* NtQueryVirtualMemory [MemoryBasicInformation|MemoryMappedFilenameInformation|MemoryRegionInformation|MemoryImageInformation|MemoryRegionInformationEx|MemoryEnclaveImageInformation|MemoryBasicInformationCapped]
* NtQueryObject [ObjectNameInformation]
* NtQueryInformationFile [FileNameInformation|FileAllInformation]
* NtQuerySection [SectionOriginalBaseInformation]

-----

## LICENSE
SbieHide is licensed under the MIT License. Dependencies are under their respective licenses.

