#include <phnt_windows.h>
#include <phnt.h>
#include <stdio.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include "Process.h"

char            NameBuffer[0x1000]   = {};
PUNICODE_STRING MemoryMappedFilename = reinterpret_cast<PUNICODE_STRING>(NameBuffer);

#ifdef _MSC_VER
    #pragma section(".CRT$XLB", long, read)
#endif

typedef VOID(NTAPI *PIMAGE_TLS_CALLBACK)(PVOID DllHandle, DWORD Reason, PVOID Reserved);

VOID NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    HMODULE hSbieDll = GetModuleHandleA("SbieDll.dll");
    if (hSbieDll) {
        printf("[TLS Callback] SbieDll.dll detected: 0x%016llX\n", reinterpret_cast<UINT64>(hSbieDll));
    } else {
        printf("[TLS Callback] SbieDll.dll not found\n");
    }
}

#ifdef _WIN64
    #pragma comment(linker, "/INCLUDE:_tls_used")
#else
    #pragma comment(linker, "/INCLUDE:__tls_used")
#endif

#ifdef _WIN64
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK _tlscallbacks[] = {
    TlsCallback,
    NULL
};
#else
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK _tlscallbacks[] = {
    TlsCallback,
    NULL
};
#endif

int PrintModules(DWORD processID) {
    HMODULE      hMods[1024];
    HANDLE       hProcess;
    DWORD        cbNeeded;
    unsigned int i;

    printf("\nProcess ID: %u\n", processID);

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (NULL == hProcess)
        return 1;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {

                _tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
            }
        }
    }

    CloseHandle(hProcess);

    return 0;
}

VOID CheckSandboxieByGetModuleHandle() {
    printf("Handle of SbieHide.dll is 0x%016llX\n", reinterpret_cast<UINT64>(GetModuleHandleA("SbieHide.dll")));
    printf("Handle of SbieDll.dll is 0x%016llX\n", reinterpret_cast<UINT64>(GetModuleHandleA("SbieDll.dll")));
}

VOID CheckSandboxieBySystemInformation() {
    NTSTATUS status;
    ULONG    bufferSize = 0;
    PVOID    buffer     = NULL;

    status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        printf("[SystemInfo] Failed to get buffer size, status: 0x%08X\n", status);
        return;
    }

    buffer = malloc(bufferSize);
    if (!buffer) {
        printf("[SystemInfo] Failed to allocate memory for module information.\n");
        return;
    }

    status = NtQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[SystemInfo] Failed to query system module information, status: 0x%08X\n", status);
        free(buffer);
        return;
    }

    PRTL_PROCESS_MODULES modules   = (PRTL_PROCESS_MODULES)buffer;
    BOOL                 foundSbie = FALSE;

    printf("[SystemInfo] Total modules: %lu\n", modules->NumberOfModules);

    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        PRTL_PROCESS_MODULE_INFORMATION module     = &modules->Modules[i];
        PCHAR                           moduleName = (PCHAR)module->FullPathName + module->OffsetToFileName;

        if (strstr(moduleName, "Sbie") != 0 || strstr(moduleName, "Sandboxie") != 0) {
            foundSbie = TRUE;
            printf("[SystemInfo] Found %s at base 0x%016llX\n", moduleName, (UINT64)module->ImageBase);
        }
    }

    if (!foundSbie) {
        printf("[SystemInfo] Sbie* not found in system modules.\n");
    }

    free(buffer);

    bufferSize = 0x10000;
    buffer     = malloc(bufferSize);
    if (!buffer) {
        printf("[SystemInfo] Failed to allocate memory for process information.\n");
        return;
    }

    while (TRUE) {
        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            free(buffer);
            bufferSize *= 2;
            buffer = malloc(bufferSize);
            if (!buffer) {
                printf("[SystemInfo] Failed to reallocate memory for process information.\n");
                return;
            }
            continue;
        }

        if (!NT_SUCCESS(status)) {
            printf("[SystemInfo] Failed to query system process information, status: 0x%08X\n", status);
            free(buffer);
            return;
        }

        break;
    }

    PSYSTEM_PROCESS_INFORMATION processInfo      = (PSYSTEM_PROCESS_INFORMATION)buffer;
    BOOL                        foundSbieProcess = FALSE;

    while (TRUE) {
        if (processInfo->ImageName.Buffer != NULL) {
            WCHAR processNameUpper[MAX_PATH] = { 0 };
            wcsncpy_s(processNameUpper, processInfo->ImageName.Buffer, processInfo->ImageName.Length / sizeof(WCHAR));

            for (size_t i = 0; i < wcslen(processNameUpper); i++) {
                processNameUpper[i] = towupper(processNameUpper[i]);
            }

            if (wcsstr(processNameUpper, L"SBIE") != NULL) {
                foundSbieProcess = TRUE;
                printf("[SystemInfo] Found Sandboxie process: %ws (PID: %llu)\n", processInfo->ImageName.Buffer, (UINT64)processInfo->UniqueProcessId);
            }
        }

        if (processInfo->NextEntryOffset == 0) {
            break;
        }

        processInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)processInfo + processInfo->NextEntryOffset);
    }

    if (!foundSbieProcess) {
        printf("[SystemInfo] No Sandboxie related processes found.\n");
    }

    free(buffer);
}

int main() {
    printf("=== Checking Sandboxie presence using different methods ===\n\n");

    printf("[1] Using GetModuleHandle:\n");
    CheckSandboxieByGetModuleHandle();

    printf("\n[2] Using NtQuerySystemInformation:\n");
    CheckSandboxieBySystemInformation();

    printf("\n[3] Listing loaded modules:\n");
    PrintModules(reinterpret_cast<DWORD>(NtCurrentProcessId()));

    printf("\nPress Enter to exit...");
    getchar();
    return 0;
}