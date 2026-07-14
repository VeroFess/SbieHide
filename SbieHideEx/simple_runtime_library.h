#pragma once

#include <phnt_windows.h>
#include <phnt.h>
#include "crc64.h"

HANDLE WINAPI   HeapCreateDirect(_In_ DWORD flOptions, _In_ SIZE_T dwInitialSize, _In_ SIZE_T dwMaximumSize);
BOOL WINAPI     VirtualProtectDirect(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
LPVOID WINAPI   HeapAllocDirect(_In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ SIZE_T dwBytes);
extern "C" VOID ModulePreProcessInitRoutine();
VOID            FindSbieDllFromPeb();

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

__forceinline bool IsImageRangeValid(SIZE_T imageSize, ULONG rva, SIZE_T length) {
    return static_cast<SIZE_T>(rva) <= imageSize && length <= imageSize - static_cast<SIZE_T>(rva);
}

__forceinline PVOID GetExportedFunctionAddress(HMODULE ModuleBase, SIZE_T ModuleSize, UINT64 FunctionNameHash) {
    if (ModuleBase == nullptr || ModuleSize < sizeof(IMAGE_NT_HEADERS64)) {
        return nullptr;
    }

    PUCHAR            imageBase = reinterpret_cast<PUCHAR>(ModuleBase);
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
        static_cast<SIZE_T>(dosHeader->e_lfanew) > ModuleSize - sizeof(IMAGE_NT_HEADERS64)) {
        return nullptr;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        ntHeaders->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders->OptionalHeader.SizeOfImage == 0 || ntHeaders->OptionalHeader.SizeOfImage > ModuleSize ||
        ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        return nullptr;
    }

    const SIZE_T               imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    const IMAGE_DATA_DIRECTORY exportData =
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportData.Size < sizeof(IMAGE_EXPORT_DIRECTORY) ||
        !IsImageRangeValid(imageSize, exportData.VirtualAddress, exportData.Size)) {
        return nullptr;
    }

    PIMAGE_EXPORT_DIRECTORY exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        imageBase + exportData.VirtualAddress);
    if (exports->NumberOfNames > imageSize / sizeof(DWORD) ||
        exports->NumberOfFunctions > imageSize / sizeof(DWORD) ||
        !IsImageRangeValid(imageSize, exports->AddressOfNames, static_cast<SIZE_T>(exports->NumberOfNames) * sizeof(DWORD)) ||
        !IsImageRangeValid(imageSize, exports->AddressOfNameOrdinals, static_cast<SIZE_T>(exports->NumberOfNames) * sizeof(WORD)) ||
        !IsImageRangeValid(imageSize, exports->AddressOfFunctions, static_cast<SIZE_T>(exports->NumberOfFunctions) * sizeof(DWORD))) {
        return nullptr;
    }

    PDWORD names     = reinterpret_cast<PDWORD>(imageBase + exports->AddressOfNames);
    PWORD  ordinals  = reinterpret_cast<PWORD>(imageBase + exports->AddressOfNameOrdinals);
    PDWORD functions = reinterpret_cast<PDWORD>(imageBase + exports->AddressOfFunctions);
    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        const ULONG nameRva = names[i];
        if (!IsImageRangeValid(imageSize, nameRva, 1)) {
            continue;
        }

        PCHAR        name          = reinterpret_cast<PCHAR>(imageBase + nameRva);
        const SIZE_T maximumLength = imageSize - nameRva;
        SIZE_T       nameLength    = 0;
        while (nameLength < maximumLength && name[nameLength] != '\0') {
            ++nameLength;
        }
        if (nameLength == maximumLength ||
            Crc64Runtime(0, reinterpret_cast<PBYTE>(name), nameLength) != FunctionNameHash) {
            continue;
        }

        const WORD ordinal = ordinals[i];
        if (ordinal >= exports->NumberOfFunctions) {
            return nullptr;
        }
        const ULONG functionRva = functions[ordinal];
        if (!IsImageRangeValid(imageSize, functionRva, 1)) {
            return nullptr;
        }
        if (functionRva >= exportData.VirtualAddress &&
            static_cast<SIZE_T>(functionRva - exportData.VirtualAddress) < exportData.Size) {
            return nullptr;
        }

        const SIZE_T sectionTableOffset =
            static_cast<SIZE_T>(dosHeader->e_lfanew) +
            FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
            ntHeaders->FileHeader.SizeOfOptionalHeader;
        const SIZE_T sectionTableSize =
            static_cast<SIZE_T>(ntHeaders->FileHeader.NumberOfSections) *
            sizeof(IMAGE_SECTION_HEADER);
        if (sectionTableOffset > imageSize || sectionTableSize > imageSize - sectionTableOffset) {
            return nullptr;
        }

        const auto sections   = reinterpret_cast<PIMAGE_SECTION_HEADER>(imageBase + sectionTableOffset);
        bool       executable = false;
        for (WORD sectionIndex = 0;
             sectionIndex < ntHeaders->FileHeader.NumberOfSections;
             ++sectionIndex) {
            const IMAGE_SECTION_HEADER &section     = sections[sectionIndex];
            const SIZE_T                sectionSize = section.Misc.VirtualSize > section.SizeOfRawData
                                                          ? section.Misc.VirtualSize
                                                          : section.SizeOfRawData;
            if (functionRva >= section.VirtualAddress &&
                static_cast<SIZE_T>(functionRva - section.VirtualAddress) < sectionSize) {
                executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                break;
            }
        }
        if (!executable) {
            return nullptr;
        }
        return imageBase + functionRva;
    }

    return nullptr;
}
