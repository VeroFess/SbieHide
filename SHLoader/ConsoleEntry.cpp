#include "MINT.h"
#include <stdio.h>
#include <Psapi.h>
#include <map>

PCCH ProcessPath    = "pafish.vmp.exe";

#ifdef _WIN64
    #define POINTER_HEX_FORMART "0x%016llX"
#else
    #define POINTER_HEX_FORMART "0x%08X"
#endif

#ifdef _WIN64
constexpr const char *LibraryName = "ScyllaHideGenericPluginx64.dll";
#else
constexpr const char *LibraryName   = "ScyllaHideGenericPluginx86.dll";
#endif

#ifdef _WIN64
constexpr const char *NtLibraryName = "C:\\Windows\\System32\\ntdll.dll";
#else
constexpr const char *NtLibraryName = "C:\\Windows\\SysWow64\\ntdll.dll";
#endif

typedef void(__cdecl *LOGWRAPPER)(const wchar_t *msg);
typedef void (*ScyllaHideInitType)(const WCHAR *Directory, LOGWRAPPER Logger, LOGWRAPPER ErrorLogger);
typedef void (*ScyllaHideResetType)();
typedef void (*ScyllaHideDebugLoopType)(const DEBUG_EVENT *DebugEvent);

void ScyllaHideLogger(const wchar_t *msg) {
    printf("[*] [ScyllaHide] %ls\n", msg);
}

void ScyllaHideErrorLogger(const wchar_t *msg) {
    printf("[!] [ScyllaHide] %ls\n", msg);
}

char      LoadedModuleNameBuffer[0x1000]                = {};
char      EntryPointBytecode[0x40]                      = {};
char      NtQueryInforationProcessBytecode[0x100]       = {};
char      EntryPointBytecodeHooked[0x40]                = {};
char      NtQueryInforationProcessBytecodeHooked[0x100] = {};
UINT      NtQueryInforationProcessBytecodeSize          = 0;
ULONG_PTR RvaOfNtQueryInformationProcess                = 0;

ULONG_PTR RvaToFoa(PIMAGE_SECTION_HEADER SectionHeaders, ULONG_PTR Address) {
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        if (SectionHeaders[i].VirtualAddress <= Address && SectionHeaders[i].VirtualAddress + SectionHeaders[i].SizeOfRawData >= Address) {
            UINT Offset = Address - SectionHeaders[i].VirtualAddress;
            return static_cast<ULONG_PTR>(SectionHeaders[i].PointerToRawData + Offset);
        }
    }

    return static_cast<ULONG_PTR>(-1);
}

UINT GetCopySize(PUCHAR Address) {
    UINT Count = 0;

    while (!(Address[Count] == 0xC3 || (Address[Count] == 0xC2 && Address[Count + 1] == 0x1c))) {
        Count++;
    }

    return Count;
}

BOOL GetNtQueryInforationProcessBytecode() {
    HANDLE                  FileHandle                       = INVALID_HANDLE_VALUE;
    LARGE_INTEGER           FileSize                         = {};
    PCHAR                   FileBuffer                       = nullptr;
    DWORD                   ReadedSize                       = 0;
    PIMAGE_DOS_HEADER       DosHeader                        = nullptr;
    PIMAGE_NT_HEADERS       NtHeaders                        = nullptr;
    PIMAGE_SECTION_HEADER   SectionHeaders                   = nullptr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory                  = nullptr;
    PDWORD                  AddressOfFunctions               = NULL;
    PDWORD                  AddressOfNames                   = NULL;
    PWORD                   AddressOfNameOrdinals            = NULL;
    PUCHAR                  NtQueryInformationProcessAddress = 0;

    if ((FileHandle = CreateFileA(NtLibraryName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!GetFileSizeEx(FileHandle, &FileSize)) {
        return FALSE;
    }

    if (FileSize.QuadPart == 0) {
        return FALSE;
    }

    if ((FileBuffer = reinterpret_cast<PCHAR>(malloc(FileSize.QuadPart))) == nullptr) {
        return FALSE;
    }

    if (!ReadFile(FileHandle, FileBuffer, FileSize.QuadPart, &ReadedSize, NULL)) {
        return FALSE;
    }

    CloseHandle(FileHandle);

    DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(FileBuffer);
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(FileBuffer + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return ERROR_INVALID_DATA;
    }

    SectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(FileBuffer + DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    ExportDirectory       = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(FileBuffer + RvaToFoa(SectionHeaders, NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    AddressOfFunctions    = reinterpret_cast<PDWORD>(FileBuffer + RvaToFoa(SectionHeaders, ExportDirectory->AddressOfFunctions));
    AddressOfNames        = reinterpret_cast<PDWORD>(FileBuffer + RvaToFoa(SectionHeaders, ExportDirectory->AddressOfNames));
    AddressOfNameOrdinals = reinterpret_cast<PWORD>(FileBuffer + RvaToFoa(SectionHeaders, ExportDirectory->AddressOfNameOrdinals));

    for (int i = 0; i < ExportDirectory->NumberOfNames; i++) {
        PCCH FunctionName = reinterpret_cast<PCCH>(FileBuffer + RvaToFoa(SectionHeaders, AddressOfNames[i]));

        if (_stricmp(FunctionName, "NtQueryInformationProcess") == 0) {
            RvaOfNtQueryInformationProcess       = AddressOfFunctions[AddressOfNameOrdinals[i]];
            NtQueryInformationProcessAddress     = reinterpret_cast<PUCHAR>(FileBuffer + RvaToFoa(SectionHeaders, RvaOfNtQueryInformationProcess));
            NtQueryInforationProcessBytecodeSize = GetCopySize(NtQueryInformationProcessAddress);

            if (NtQueryInforationProcessBytecodeSize > 0) {
                memcpy_s(NtQueryInforationProcessBytecode, 0x100, NtQueryInformationProcessAddress, NtQueryInforationProcessBytecodeSize);
                free(FileBuffer);
                return TRUE;
            }
        }
    }

    free(FileBuffer);
    return FALSE;
}

int main(int argc, char *argv[]) {
    STARTUPINFOA                   StartupInfo             = {};
    PROCESS_INFORMATION            ProcessInfo             = {};
    DEBUG_EVENT                    DebugEvent              = {};
    HMODULE                        ScyllaHideHandle        = {};
    ScyllaHideInitType             ScyllaHideInit          = {};
    ScyllaHideResetType            ScyllaHideReset         = {};
    ScyllaHideDebugLoopType        ScyllaHideDebugLoop     = {};
    CONTEXT                        DebuggeeContext         = {};
    HANDLE                         ModuleFileMap           = INVALID_HANDLE_VALUE;
    LPVOID                         ModuleFileMapedMemory   = NULL;
    UNICODE_STRING                 LoadedModuleName        = {};
    UNICODE_STRING                 LoadedModuleNameLowCase = {};
    POBJECT_NAME_INFORMATION       LoadedModuleNameInfo    = reinterpret_cast<POBJECT_NAME_INFORMATION>(LoadedModuleNameBuffer);
    UNICODE_STRING                 LoadedModuleNameTmp     = {};
    SIZE_T                         ReadedLength            = 0;
    NTSTATUS                       Status                  = STATUS_SUCCESS;
    ULONG_PTR                      EntryPoint              = 0;
    ULONG_PTR                      ImageBase               = 0;
    ULONG_PTR                      NtdllImageBase          = 0;
    IMAGE_DOS_HEADER               DosHeader               = {};
    IMAGE_NT_HEADERS               NtHeaders               = {};
    IMAGE_OPTIONAL_HEADER          OptionalHeader          = {};
    IMAGE_TLS_DIRECTORY            TlsDirectory            = {};
    ULONG_PTR                      BytecodeOfTls           = 0;
    ULONG_PTR                      TlsCallbackIndex        = 0;
    ULONG_PTR                      TlsCallbackOffset       = 0;
    DWORD                          OldProtect              = 0;
    std::map<ULONG_PTR, ULONG_PTR> TlsCallbackModifyMap;

    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
    RtlZeroMemory(&ProcessInfo, sizeof(ProcessInfo));
    RtlZeroMemory(&DebugEvent, sizeof(DebugEvent));

    StartupInfo.cb = sizeof(STARTUPINFOA);

    GetNtQueryInforationProcessBytecode();

    if ((ScyllaHideHandle = LoadLibraryA(LibraryName)) == NULL) {
        return STATUS_APP_INIT_FAILURE;
    }

    if ((ScyllaHideInit = reinterpret_cast<ScyllaHideInitType>(GetProcAddress(ScyllaHideHandle, "ScyllaHideInit"))) == NULL) {
        return STATUS_APP_INIT_FAILURE;
    }

    if ((ScyllaHideReset = reinterpret_cast<ScyllaHideResetType>(GetProcAddress(ScyllaHideHandle, "ScyllaHideReset"))) == NULL) {
        return STATUS_APP_INIT_FAILURE;
    }

    if ((ScyllaHideDebugLoop = reinterpret_cast<ScyllaHideDebugLoopType>(GetProcAddress(ScyllaHideHandle, "ScyllaHideDebugLoop"))) == NULL) {
        return STATUS_APP_INIT_FAILURE;
    }

    ScyllaHideInit(NULL, ScyllaHideLogger, ScyllaHideErrorLogger);

    if (!CreateProcessA(ProcessPath, NULL, NULL, NULL, TRUE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &StartupInfo, &ProcessInfo)) {
        CloseHandle(ProcessInfo.hProcess);
        CloseHandle(ProcessInfo.hThread);
        return STATUS_APP_INIT_FAILURE;
    }

    while (WaitForDebugEvent(&DebugEvent, INFINITE)) {
        ScyllaHideDebugLoop(&DebugEvent);

        switch (DebugEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
            printf("[*] New exception [0x%08X] at " POINTER_HEX_FORMART " [%s]\n", DebugEvent.u.Exception.ExceptionRecord.ExceptionCode, reinterpret_cast<ULONG_PTR>(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress), DebugEvent.u.Exception.dwFirstChance ? "First Chance" : "Second Chance");

            if (reinterpret_cast<ULONG_PTR>(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress) == EntryPoint) {
                if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_EXCEPTION_HANDLED)) {
                    return STATUS_UNSUCCESSFUL;
                }

                // TODO: Call to sbiedll.dll
                break;
            }

            if (TlsCallbackModifyMap.find(reinterpret_cast<ULONG_PTR>(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress)) != TlsCallbackModifyMap.end()) {
                for (auto saved : TlsCallbackModifyMap) {
                    if (!WriteProcessMemory(ProcessInfo.hProcess, reinterpret_cast<PVOID>(saved.first), &saved.second, sizeof(ULONG_PTR), &ReadedLength)) {
                        printf("[!] Can not restore hook of tls callback!\n");
                        return STATUS_UNSUCCESSFUL;
                    }
                }

                VirtualProtectEx(ProcessInfo.hProcess, reinterpret_cast<PVOID>(EntryPoint), 0x40, PAGE_EXECUTE_READWRITE, &OldProtect);

                if (!WriteProcessMemory(ProcessInfo.hProcess, reinterpret_cast<PVOID>(EntryPoint), EntryPointBytecode, 0x40, &ReadedLength)) {
                    printf("[!] Can not restore hook of tls entrypoint!, error = 0x%08X\n", GetLastError());
                    return STATUS_UNSUCCESSFUL;
                }

                if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_EXCEPTION_HANDLED)) {
                    return STATUS_UNSUCCESSFUL;
                }

                break;
            }

            if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED)) {
                return STATUS_UNSUCCESSFUL;
            }

            break;

        case CREATE_PROCESS_DEBUG_EVENT:
            printf("[*] Process created! Image base = " POINTER_HEX_FORMART "; Entry point = " POINTER_HEX_FORMART " ...\n", reinterpret_cast<ULONG_PTR>(DebugEvent.u.CreateProcessInfo.lpBaseOfImage), reinterpret_cast<ULONG_PTR>(DebugEvent.u.CreateProcessInfo.lpStartAddress));
            EntryPoint = reinterpret_cast<ULONG_PTR>(DebugEvent.u.CreateProcessInfo.lpStartAddress);
            ImageBase  = reinterpret_cast<ULONG_PTR>(DebugEvent.u.CreateProcessInfo.lpBaseOfImage);

            if (!ReadProcessMemory(DebugEvent.u.CreateProcessInfo.hProcess, reinterpret_cast<PVOID>(EntryPoint), EntryPointBytecode, 0x40, &ReadedLength)) {
                printf("[!] Can not read process memory!\n");
                return STATUS_UNSUCCESSFUL;
            }

            if (!ReadProcessMemory(DebugEvent.u.CreateProcessInfo.hProcess, reinterpret_cast<PVOID>(ImageBase), &DosHeader, sizeof(IMAGE_DOS_HEADER), &ReadedLength)) {
                printf("[!] Can not read process memory!\n");
                return STATUS_UNSUCCESSFUL;
            }

            if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                printf("[!] Can not read process memory!\n");
                return ERROR_INVALID_DATA;
            }

            if (!ReadProcessMemory(DebugEvent.u.CreateProcessInfo.hProcess, reinterpret_cast<PVOID>(ImageBase + DosHeader.e_lfanew), &NtHeaders, sizeof(IMAGE_NT_HEADERS), &ReadedLength)) {
                printf("[!] Can not read process memory!\n");
                return STATUS_UNSUCCESSFUL;
            }

            if (NtHeaders.Signature != IMAGE_NT_SIGNATURE) {
                printf("[!] Can not read process memory!\n");
                return ERROR_INVALID_DATA;
            }

            if (NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size == 0) {
                printf("[*] This program not include tls callback!\n");
                goto CDECleanAndContinue;
            }

            if (!ReadProcessMemory(DebugEvent.u.CreateProcessInfo.hProcess, reinterpret_cast<PVOID>(ImageBase + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress), &TlsDirectory, sizeof(IMAGE_TLS_DIRECTORY), &ReadedLength)) {
                printf("[!] Can not read process memory!\n");
                return STATUS_UNSUCCESSFUL;
            }

            if (TlsDirectory.AddressOfCallBacks == NULL) {
                printf("[*] This program not include tls callback!\n");
                goto CDECleanAndContinue;
            }

            do {
                if (!ReadProcessMemory(DebugEvent.u.CreateProcessInfo.hProcess, reinterpret_cast<PVOID>((TlsDirectory.AddressOfCallBacks - NtHeaders.OptionalHeader.ImageBase + ImageBase) + TlsCallbackIndex * sizeof(ULONG_PTR)), &TlsCallbackOffset, sizeof(ULONG_PTR), &ReadedLength)) {
                    printf("[!] Can not read process memory!\n");
                    return STATUS_UNSUCCESSFUL;
                }

                if (TlsCallbackOffset == 0) {
                    break;
                }

                if (!ReadProcessMemory(DebugEvent.u.CreateProcessInfo.hProcess, reinterpret_cast<PVOID>(TlsCallbackOffset), &BytecodeOfTls, sizeof(ULONG_PTR), &ReadedLength)) {
                    printf("[!] Can not read process memory!\n");
                    return STATUS_UNSUCCESSFUL;
                }

                TlsCallbackModifyMap.insert({ TlsCallbackOffset, BytecodeOfTls });

                BytecodeOfTls = 0xCCCCCCCC;

                if (!WriteProcessMemory(DebugEvent.u.CreateProcessInfo.hProcess, reinterpret_cast<PVOID>(TlsCallbackOffset), &BytecodeOfTls, sizeof(ULONG_PTR), &ReadedLength)) {
                    printf("[!] Can not read process memory!\n");
                    return STATUS_UNSUCCESSFUL;
                }

                TlsCallbackIndex++;
            } while (true);

            if (TlsCallbackModifyMap.empty() == true) {
                printf("[*] This program not include tls callback!\n");
                goto CDECleanAndContinue;
            } else {
                printf("[*] Found tls callback!\n");
            }

        CDECleanAndContinue:

            if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE)) {
                return STATUS_UNSUCCESSFUL;
            }

            break;

        case CREATE_THREAD_DEBUG_EVENT:
            printf("[*] New thread created at " POINTER_HEX_FORMART " ...\n", reinterpret_cast<ULONG_PTR>(DebugEvent.u.CreateThread.lpStartAddress));

            RtlZeroMemory(&DebuggeeContext, sizeof(CONTEXT));
            DebuggeeContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            NtGetContextThread(DebugEvent.u.CreateProcessInfo.hThread, &DebuggeeContext);

            DebuggeeContext.Dr0 = EntryPoint;
            DebuggeeContext.Dr7 = 0x101;

            NtSetContextThread(DebugEvent.u.CreateProcessInfo.hThread, &DebuggeeContext);

            if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE)) {
                return STATUS_UNSUCCESSFUL;
            }

            break;

        case LOAD_DLL_DEBUG_EVENT:
            if (DebugEvent.u.LoadDll.hFile == NULL || DebugEvent.u.LoadDll.hFile == INVALID_HANDLE_VALUE) {
                goto LDCleanAndContinue;
            }

            if (!NT_SUCCESS(Status = NtQueryObject(DebugEvent.u.LoadDll.hFile, ObjectNameInformation, LoadedModuleNameBuffer, 0x1000, (PULONG)&ReadedLength))) {
                printf("[!] Failed to dump file handle! try other war ...\n");
            }

            if ((!NT_SUCCESS(Status)) || LoadedModuleNameInfo->Name.Length == 0) {
                auto ModuleFileMap = CreateFileMappingA(DebugEvent.u.LoadDll.hFile, NULL, PAGE_READONLY, 0, 1, NULL);
                if (ModuleFileMap == NULL || ModuleFileMap == INVALID_HANDLE_VALUE) {
                    printf("[!] Failed to map file handle! skip this module ...\n");
                    goto LDCleanAndContinue;
                }

                ModuleFileMapedMemory = MapViewOfFile(ModuleFileMap, FILE_MAP_READ, 0, 0, 1);
                if (ModuleFileMap == NULL) {
                    printf("[!] Failed to map file handle! skip this module ...\n");
                    goto LDCleanAndContinue;
                }

                auto ModuleFileNameLength = GetMappedFileNameW(GetCurrentProcess(), ModuleFileMap, reinterpret_cast<LPWSTR>(LoadedModuleNameBuffer), 0x1000 / sizeof(wchar_t));
                if (ModuleFileNameLength == 0) {
                    printf("[!] Failed to map file handle! skip this module ...\n");
                    goto LDCleanAndContinue;
                }

                LoadedModuleNameTmp.Buffer        = reinterpret_cast<LPWSTR>(LoadedModuleNameBuffer);
                LoadedModuleNameTmp.Length        = ModuleFileNameLength;
                LoadedModuleNameTmp.MaximumLength = 0x1000;

                if (!NT_SUCCESS(Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, &LoadedModuleNameTmp, &LoadedModuleName))) {
                    printf("[!] Failed to duplicate unicode string! skip this module ...\n");
                    goto LDCleanAndContinue;
                }
            } else {
                if (!NT_SUCCESS(Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, &LoadedModuleNameInfo->Name, &LoadedModuleName))) {
                    printf("[!] Failed to duplicate unicode string! skip this module ...\n");
                    goto LDCleanAndContinue;
                }
            }

            printf("[*] Dll Load -> %.*ls\n", LoadedModuleName.Length, LoadedModuleName.Buffer);

            if (!NT_SUCCESS(RtlDowncaseUnicodeString(&LoadedModuleNameLowCase, &LoadedModuleName, TRUE))) {
                printf("[!] Failed to downcase unicode string! skip this module ...\n");
                goto LDCleanAndContinue;
            }

            if (wcsstr(LoadedModuleNameLowCase.Buffer, L"syswow64\\ntdll.dll") != NULL) {
                NtdllImageBase = reinterpret_cast<ULONG_PTR>(DebugEvent.u.LoadDll.lpBaseOfDll);
            }

            if (wcsstr(LoadedModuleNameLowCase.Buffer, L"msvcrt.dll") != NULL) {
                if (!ReadProcessMemory(ProcessInfo.hProcess, reinterpret_cast<PVOID>(NtdllImageBase + RvaOfNtQueryInformationProcess), NtQueryInforationProcessBytecodeHooked, NtQueryInforationProcessBytecodeSize, &ReadedLength)) {
                    printf("[!] Can not read process memory!\n");
                    return STATUS_UNSUCCESSFUL;
                }

                auto xx = memcmp(NtQueryInforationProcessBytecodeHooked, NtQueryInforationProcessBytecode, 5);
                if (!WriteProcessMemory(ProcessInfo.hProcess, reinterpret_cast<PVOID>(NtdllImageBase + RvaOfNtQueryInformationProcess), NtQueryInforationProcessBytecode, 5, &ReadedLength)) {
                    printf("[!] Can not read process memory!\n");
                    return STATUS_UNSUCCESSFUL;
                }

                printf("hook restore!\n");
            }

        LDCleanAndContinue:
            if (ModuleFileMapedMemory != NULL) {
                UnmapViewOfFile(ModuleFileMapedMemory);
            }

            if (ModuleFileMap != NULL && ModuleFileMap != INVALID_HANDLE_VALUE) {
                CloseHandle(ModuleFileMap);
            }

            if (LoadedModuleName.Buffer != nullptr) {
                RtlFreeUnicodeString(&LoadedModuleName);
                RtlZeroMemory(&LoadedModuleName, sizeof(UNICODE_STRING));
            }

            RtlZeroMemory(&LoadedModuleNameTmp, sizeof(UNICODE_STRING));
            RtlZeroMemory(LoadedModuleNameBuffer, 0x1000);

            if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE)) {
                return STATUS_UNSUCCESSFUL;
            }

            break;

        case EXIT_THREAD_DEBUG_EVENT:
        case UNLOAD_DLL_DEBUG_EVENT:
        case OUTPUT_DEBUG_STRING_EVENT:
            if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE)) {
                return STATUS_UNSUCCESSFUL;
            }
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            DbgBreakPoint();
            break;
        case RIP_EVENT:
            DbgBreakPoint();
            break;
        }
    }
}