#pragma once

#include <phnt_windows.h>
#include <phnt.h>
#include "crc64.h"

HANDLE WINAPI HeapCreateDirect(_In_ DWORD flOptions, _In_ SIZE_T dwInitialSize, _In_ SIZE_T dwMaximumSize);
BOOL WINAPI   VirtualProtectDirect(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
LPVOID WINAPI HeapAllocDirect(_In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ SIZE_T dwBytes);
VOID          ModulePreProcessInitRoutine();
VOID          FindSbieDllFromPeb();

__forceinline void SLock(volatile long *lockFlag) {
    while (true) {
        if (_InterlockedCompareExchange(lockFlag, 1, 0) == 0) {
            break;
        }
        _mm_pause();
    }
    _ReadWriteBarrier();
}

__forceinline void SUnlock(volatile long *lockFlag) {
    _ReadWriteBarrier();
    _InterlockedExchange(lockFlag, 0);
}

__forceinline PVOID GetExportedFunctionAddress(HMODULE ModuleBase, UINT64 FunctionNameHash) {
    PIMAGE_DOS_HEADER       ImageDosHeader        = nullptr;
    PIMAGE_NT_HEADERS       ImageNtHeader         = nullptr;
    PIMAGE_EXPORT_DIRECTORY ImageExportDirectory  = nullptr;
    PCHAR                   FunctionName          = nullptr;
    PDWORD                  AddressOfNames        = nullptr;
    PWORD                   AddressOfNameOrdinals = nullptr;
    PDWORD                  AddressOfFunctions    = nullptr;
    PVOID                   FoundAddress          = nullptr;

    if (ModuleBase != nullptr) {
        ImageDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBase);
        ImageNtHeader  = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PUCHAR>(ModuleBase) + ImageDosHeader->e_lfanew);

        if (ImageNtHeader->OptionalHeader.DataDirectory[0].Size == 0) {
            return nullptr;
        }

        ImageExportDirectory  = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<PUCHAR>(ModuleBase) + ImageNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
        AddressOfNames        = reinterpret_cast<PDWORD>(reinterpret_cast<PUCHAR>(ModuleBase) + ImageExportDirectory->AddressOfNames);
        AddressOfNameOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<PUCHAR>(ModuleBase) + ImageExportDirectory->AddressOfNameOrdinals);
        AddressOfFunctions    = reinterpret_cast<PDWORD>(reinterpret_cast<PUCHAR>(ModuleBase) + ImageExportDirectory->AddressOfFunctions);

        for (DWORD OrdinalsIndex = 0; OrdinalsIndex < ImageExportDirectory->NumberOfNames; OrdinalsIndex++) {
            FunctionName = reinterpret_cast<PCHAR>(reinterpret_cast<PUCHAR>(ModuleBase) + AddressOfNames[OrdinalsIndex]);

            if (Crc64Runtime(0, reinterpret_cast<PBYTE>(FunctionName), strlen(FunctionName)) == FunctionNameHash) {
                FoundAddress = reinterpret_cast<PUCHAR>(ModuleBase) + AddressOfFunctions[AddressOfNameOrdinals[OrdinalsIndex]];
            }
        }
    }

    return FoundAddress;
}
