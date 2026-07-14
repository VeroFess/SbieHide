#include "NtdllRemapper.h"
#include "SbieHideLoader.h"

#include <psapi.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <vector>

#pragma comment(lib, "psapi.lib")

namespace {

    constexpr SIZE_T kJumpSize                = 14;
    constexpr BYTE   kJumpTemplate[kJumpSize] = {
        0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    class KnownDllNtdllView final {
        public:
            ~KnownDllNtdllView() {
                if (base_ != nullptr) {
                    NtUnmapViewOfSection(NtCurrentProcess(), base_);
                }
            }

            bool Open() {
                UNICODE_STRING    path       = RTL_CONSTANT_STRING(L"\\KnownDlls\\ntdll.dll");
                OBJECT_ATTRIBUTES attributes = {};
                InitializeObjectAttributes(
                    &attributes, &path, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
                HANDLE   section = nullptr;
                NTSTATUS status  = NtOpenSection(
                    &section, SECTION_MAP_READ | SECTION_QUERY, &attributes);
                if (!NT_SUCCESS(status)) {
                    SetLastError(RtlNtStatusToDosError(status));
                    return false;
                }
                SIZE_T viewSize = 0;
                status          = NtMapViewOfSection(
                    section,
                    NtCurrentProcess(),
                    &base_,
                    0,
                    0,
                    nullptr,
                    &viewSize,
                    ViewShare,
                    0,
                    PAGE_READONLY);
                NtClose(section);
                if (!NT_SUCCESS(status)) {
                    base_ = nullptr;
                    SetLastError(RtlNtStatusToDosError(status));
                    return false;
                }

                const auto dosHeader = static_cast<const IMAGE_DOS_HEADER *>(base_);
                if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
                    dosHeader->e_lfanew <= 0 ||
                    static_cast<ULONG>(dosHeader->e_lfanew) > 0x100000) {
                    SetLastError(ERROR_BAD_EXE_FORMAT);
                    return false;
                }
                const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(
                    static_cast<const BYTE *>(base_) + dosHeader->e_lfanew);
                if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
                    ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
                    ntHeaders->OptionalHeader.SizeOfImage == 0) {
                    SetLastError(ERROR_BAD_EXE_FORMAT);
                    return false;
                }
                size_ = ntHeaders->OptionalHeader.SizeOfImage;
                return true;
            }

            PVOID base() const {
                return base_;
            }
            SIZE_T size() const {
                return size_;
            }

        private:
            PVOID  base_ = nullptr;
            SIZE_T size_ = 0;
    };

    struct PatchRecord {
            PVOID                       target             = nullptr;
            PVOID                       hook               = nullptr;
            std::array<BYTE, kJumpSize> original           = {};
            ULONG                       originalProtection = 0;
            bool                        touched            = false;
    };

    bool ReadExact(HANDLE process, PVOID address, void *buffer, SIZE_T bytes) {
        SIZE_T         read   = 0;
        const NTSTATUS status = NtReadVirtualMemory(process, address, buffer, bytes, &read);
        if (!NT_SUCCESS(status) || read != bytes) {
            SetLastError(NT_SUCCESS(status) ? ERROR_PARTIAL_COPY : RtlNtStatusToDosError(status));
            return false;
        }
        return true;
    }

    bool Protect(HANDLE process, PVOID target, ULONG protection, ULONG *oldProtection) {
        PVOID          address = target;
        SIZE_T         bytes   = kJumpSize;
        const NTSTATUS status  = NtProtectVirtualMemory(process, &address, &bytes, protection, oldProtection);
        if (!NT_SUCCESS(status)) {
            SetLastError(RtlNtStatusToDosError(status));
            return false;
        }
        return true;
    }

    bool WriteExact(HANDLE process, PVOID address, const void *buffer, SIZE_T bytes) {
        SIZE_T         written = 0;
        const NTSTATUS status  = NtWriteVirtualMemory(process, address, const_cast<PVOID>(buffer), bytes, &written);
        if (!NT_SUCCESS(status) || written != bytes) {
            SetLastError(NT_SUCCESS(status) ? ERROR_PARTIAL_COPY : RtlNtStatusToDosError(status));
            return false;
        }
        return true;
    }

    bool Flush(HANDLE process, PVOID address) {
        const NTSTATUS status = NtFlushInstructionCache(process, address, kJumpSize);
        if (!NT_SUCCESS(status)) {
            SetLastError(RtlNtStatusToDosError(status));
            return false;
        }
        return true;
    }

    bool RestoreRecord(HANDLE process, PatchRecord *record) {
        ULONG writableOld = 0;
        bool  success     = Protect(process, record->target, PAGE_EXECUTE_READWRITE, &writableOld);
        if (success)
            success = WriteExact(process, record->target, record->original.data(), record->original.size());
        if (success)
            success = Flush(process, record->target);
        ULONG ignored = 0;
        if (!Protect(process, record->target, record->originalProtection, &ignored))
            success = false;
        if (success)
            record->touched = false;
        return success;
    }

    template<size_t Count>
    bool Rollback(HANDLE process, std::array<PatchRecord, Count> *records, size_t through) {
        bool success = true;
        while (through > 0) {
            PatchRecord &record = (*records)[--through];
            if (record.touched && !RestoreRecord(process, &record))
                success = false;
        }
        return success;
    }

    bool ApplyRecord(HANDLE process, PatchRecord *record) {
        std::array<BYTE, kJumpSize> jump = {};
        std::memcpy(jump.data(), kJumpTemplate, jump.size());
        const ULONG_PTR hookAddress = reinterpret_cast<ULONG_PTR>(record->hook);
        std::memcpy(jump.data() + 6, &hookAddress, sizeof(hookAddress));

        if (!Protect(process, record->target, PAGE_EXECUTE_READWRITE, &record->originalProtection))
            return false;
        record->touched = true; // A failed/partial write must also be rolled back.
        bool success    = WriteExact(process, record->target, jump.data(), jump.size());
        if (success)
            success = Flush(process, record->target);
        ULONG ignored = 0;
        if (!Protect(process, record->target, record->originalProtection, &ignored))
            success = false;
        return success;
    }

    bool FindRemoteNtdll(HANDLE process, PVOID *remoteBase) {
        if (!process || !remoteBase) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return false;
        }
        *remoteBase = nullptr;

        DWORD bytesNeeded = 0;
        if (EnumProcessModulesEx(process, nullptr, 0, &bytesNeeded, LIST_MODULES_64BIT) &&
            bytesNeeded != 0) {
            std::vector<HMODULE> modules(
                (bytesNeeded + sizeof(HMODULE) - 1) / sizeof(HMODULE));
            if (EnumProcessModulesEx(
                    process,
                    modules.data(),
                    static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                    &bytesNeeded,
                    LIST_MODULES_64BIT)) {
                const size_t moduleCount = std::min(
                    modules.size(),
                    static_cast<size_t>(bytesNeeded / sizeof(HMODULE)));
                wchar_t baseName[MAX_PATH] = {};
                for (size_t index = 0; index < moduleCount; ++index) {
                    if (GetModuleBaseNameW(
                            process, modules[index], baseName, _countof(baseName)) != 0 &&
                        _wcsicmp(baseName, L"ntdll.dll") == 0) {
                        *remoteBase = modules[index];
                        return true;
                    }
                }
            }
        }

        // A newly created suspended process has not initialized its loader lists yet.
        // KnownDll mappings are normally shared at the same address, but verify the
        // target mapping before using the local ntdll base as a fallback.
        const HMODULE            localNtdll     = GetModuleHandleW(L"ntdll.dll");
        MEMORY_BASIC_INFORMATION information    = {};
        SIZE_T                   returnedLength = 0;
        const NTSTATUS           status         = NtQueryVirtualMemory(
            process,
            localNtdll,
            MemoryBasicInformation,
            &information,
            sizeof(information),
            &returnedLength);
        if (NT_SUCCESS(status) && returnedLength >= sizeof(information) &&
            information.Type == MEM_IMAGE && information.AllocationBase == localNtdll) {
            *remoteBase = localNtdll;
            return true;
        }

        SetLastError(NT_SUCCESS(status) ? ERROR_MOD_NOT_FOUND : RtlNtStatusToDosError(status));
        return false;
    }

    bool IsExecutableProtection(ULONG protection) {
        const ULONG baseProtection = protection & 0xff;
        return baseProtection == PAGE_EXECUTE ||
               baseProtection == PAGE_EXECUTE_READ ||
               baseProtection == PAGE_EXECUTE_READWRITE ||
               baseProtection == PAGE_EXECUTE_WRITECOPY;
    }

} // namespace

BOOL QueryRemoteNtdllImage(HANDLE process, PVOID *imageBase, PSIZE_T imageSize) {
#ifndef _WIN64
    UNREFERENCED_PARAMETER(process);
    UNREFERENCED_PARAMETER(imageBase);
    UNREFERENCED_PARAMETER(imageSize);
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
#else
    if (!process || !imageBase || !imageSize) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *imageBase = nullptr;
    *imageSize = 0;

    PVOID candidate = nullptr;
    if (!FindRemoteNtdll(process, &candidate)) {
        return FALSE;
    }
    IMAGE_DOS_HEADER remoteDos = {};
    if (!ReadExact(process, candidate, &remoteDos, sizeof(remoteDos)) ||
        remoteDos.e_magic != IMAGE_DOS_SIGNATURE || remoteDos.e_lfanew <= 0 ||
        static_cast<ULONG>(remoteDos.e_lfanew) > 0x100000) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }
    IMAGE_NT_HEADERS64 remoteNt         = {};
    const ULONG_PTR    candidateAddress = reinterpret_cast<ULONG_PTR>(candidate);
    if (candidateAddress > std::numeric_limits<ULONG_PTR>::max() - remoteDos.e_lfanew ||
        !ReadExact(
            process,
            reinterpret_cast<PVOID>(candidateAddress + remoteDos.e_lfanew),
            &remoteNt,
            sizeof(remoteNt)) ||
        remoteNt.Signature != IMAGE_NT_SIGNATURE ||
        remoteNt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        remoteNt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        remoteNt.OptionalHeader.SizeOfImage == 0) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    MEMORY_IMAGE_INFORMATION remoteInformation = {};
    SIZE_T                   returnedLength    = 0;
    const NTSTATUS           queryStatus       = NtQueryVirtualMemory(
        process,
        candidate,
        MemoryImageInformation,
        &remoteInformation,
        sizeof(remoteInformation),
        &returnedLength);
    KnownDllNtdllView cleanNtdll;
    if (!NT_SUCCESS(queryStatus) || returnedLength < sizeof(remoteInformation) ||
        remoteInformation.ImageBase != candidate ||
        remoteInformation.SizeOfImage != remoteNt.OptionalHeader.SizeOfImage ||
        !cleanNtdll.Open() || cleanNtdll.size() != remoteInformation.SizeOfImage) {
        SetLastError(NT_SUCCESS(queryStatus) ? ERROR_BAD_EXE_FORMAT : RtlNtStatusToDosError(queryStatus));
        return FALSE;
    }
    const auto cleanDos = static_cast<const IMAGE_DOS_HEADER *>(cleanNtdll.base());
    const auto cleanNt  = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(
        static_cast<const BYTE *>(cleanNtdll.base()) + cleanDos->e_lfanew);
    if (cleanNt->FileHeader.TimeDateStamp != remoteNt.FileHeader.TimeDateStamp) {
        SetLastError(ERROR_REVISION_MISMATCH);
        return FALSE;
    }

    *imageBase = candidate;
    *imageSize = remoteInformation.SizeOfImage;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
#endif
}

BOOL RemapNtDllInProtectProcessAndPatch(HANDLE process, ULONG_PTR remoteProxyBase, ULONG_PTR localBuffer) {
#ifndef _WIN64
    UNREFERENCED_PARAMETER(process);
    UNREFERENCED_PARAMETER(remoteProxyBase);
    UNREFERENCED_PARAMETER(localBuffer);
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
#else
    if (!process || !remoteProxyBase || !localBuffer) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    KnownDllNtdllView cleanNtdll;
    PVOID             remoteNtdll     = nullptr;
    SIZE_T            remoteNtdllSize = 0;
    if (!cleanNtdll.Open() ||
        !QueryRemoteNtdllImage(process, &remoteNtdll, &remoteNtdllSize)) {
        if (GetLastError() == ERROR_SUCCESS) {
            SetLastError(ERROR_MOD_NOT_FOUND);
        }
        return FALSE;
    }

    struct HookSpec {
            const char *nativeExportName;
            const char *hookExportName;
    };
    const HookSpec specifications[] = {
        { "NtQueryVirtualMemory", "NtQueryVirtualMemoryDetours" },
        { "NtQueryObject", "NtQueryObjectDetours" },
        { "NtQueryInformationFile", "NtQueryInformationFileDetours" },
        { "NtQuerySection", "NtQuerySectionDetours" },
        { "NtQuerySystemInformation", "NtQuerySystemInformationDetours" },
        { "NtQueryInformationProcess", "NtQueryInformationProcessDetours" },
    };
    std::array<PatchRecord, _countof(specifications) + 1> records = {};

    for (size_t index = 0; index < _countof(specifications); ++index) {
        const ULONG hookRva = GetExportOffset(
            reinterpret_cast<PVOID>(localBuffer),
            specifications[index].hookExportName);
        const ULONG targetRva = GetExportOffsetChecked(
            cleanNtdll.base(),
            cleanNtdll.size(),
            specifications[index].nativeExportName,
            kJumpSize);
        if (!hookRva || !targetRva || targetRva > remoteNtdllSize ||
            kJumpSize > remoteNtdllSize - targetRva ||
            remoteProxyBase > std::numeric_limits<ULONG_PTR>::max() - hookRva) {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }
        const ULONG_PTR remoteNtdllAddress = reinterpret_cast<ULONG_PTR>(remoteNtdll);
        if (remoteNtdllAddress > std::numeric_limits<ULONG_PTR>::max() - targetRva) {
            SetLastError(ERROR_ARITHMETIC_OVERFLOW);
            return FALSE;
        }
        records[index].target = reinterpret_cast<PVOID>(remoteNtdllAddress + targetRva);
        records[index].hook   = reinterpret_cast<PVOID>(remoteProxyBase + hookRva);

        MEMORY_BASIC_INFORMATION information    = {};
        SIZE_T                   returnedLength = 0;
        const NTSTATUS           queryStatus    = NtQueryVirtualMemory(
            process,
            records[index].target,
            MemoryBasicInformation,
            &information,
            sizeof(information),
            &returnedLength);
        const ULONG_PTR regionStart   = reinterpret_cast<ULONG_PTR>(information.BaseAddress);
        const ULONG_PTR targetAddress = reinterpret_cast<ULONG_PTR>(records[index].target);
        if (!NT_SUCCESS(queryStatus) || returnedLength < sizeof(information) ||
            information.AllocationBase != remoteNtdll ||
            !IsExecutableProtection(information.Protect) ||
            targetAddress < regionStart || kJumpSize > information.RegionSize ||
            targetAddress - regionStart > information.RegionSize - kJumpSize) {
            SetLastError(NT_SUCCESS(queryStatus) ? ERROR_INVALID_ADDRESS : RtlNtStatusToDosError(queryStatus));
            return FALSE;
        }
        if (!ReadExact(process, records[index].target, records[index].original.data(), records[index].original.size())) {
            return FALSE;
        }
    }
    const size_t bootstrapIndex     = _countof(specifications);
    const ULONG  bootstrapTargetRva = GetExportOffsetChecked(
        cleanNtdll.base(),
        cleanNtdll.size(),
        "LdrLoadDll",
        kJumpSize);
    const ULONG bootstrapHookRva = GetExportOffset(
        reinterpret_cast<PVOID>(localBuffer),
        "LdrLoadDllBootstrapDetours");
    const ULONG targetStorageRva = GetExportOffset(
        reinterpret_cast<PVOID>(localBuffer),
        "LDR_LOAD_DLL_BOOTSTRAP_TARGET");
    const ULONG originalStorageRva = GetExportOffset(
        reinterpret_cast<PVOID>(localBuffer),
        "LDR_LOAD_DLL_BOOTSTRAP_ORIGINAL");
    const ULONG_PTR remoteNtdllAddress = reinterpret_cast<ULONG_PTR>(remoteNtdll);
    if (!bootstrapTargetRva || !bootstrapHookRva || !targetStorageRva ||
        !originalStorageRva || bootstrapTargetRva > remoteNtdllSize ||
        kJumpSize > remoteNtdllSize - bootstrapTargetRva ||
        remoteNtdllAddress > std::numeric_limits<ULONG_PTR>::max() - bootstrapTargetRva ||
        remoteProxyBase > std::numeric_limits<ULONG_PTR>::max() - bootstrapHookRva ||
        remoteProxyBase > std::numeric_limits<ULONG_PTR>::max() - targetStorageRva ||
        remoteProxyBase > std::numeric_limits<ULONG_PTR>::max() - originalStorageRva) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    PatchRecord &bootstrapRecord = records[bootstrapIndex];
    bootstrapRecord.target       = reinterpret_cast<PVOID>(
        remoteNtdllAddress + bootstrapTargetRva);
    bootstrapRecord.hook = reinterpret_cast<PVOID>(
        remoteProxyBase + bootstrapHookRva);
    MEMORY_BASIC_INFORMATION bootstrapInformation    = {};
    SIZE_T                   bootstrapReturnedLength = 0;
    const NTSTATUS           bootstrapQueryStatus    = NtQueryVirtualMemory(
        process,
        bootstrapRecord.target,
        MemoryBasicInformation,
        &bootstrapInformation,
        sizeof(bootstrapInformation),
        &bootstrapReturnedLength);
    const ULONG_PTR bootstrapRegionStart = reinterpret_cast<ULONG_PTR>(
        bootstrapInformation.BaseAddress);
    const ULONG_PTR bootstrapTargetAddress = reinterpret_cast<ULONG_PTR>(
        bootstrapRecord.target);
    if (!NT_SUCCESS(bootstrapQueryStatus) ||
        bootstrapReturnedLength < sizeof(bootstrapInformation) ||
        bootstrapInformation.AllocationBase != remoteNtdll ||
        !IsExecutableProtection(bootstrapInformation.Protect) ||
        bootstrapTargetAddress < bootstrapRegionStart ||
        kJumpSize > bootstrapInformation.RegionSize ||
        bootstrapTargetAddress - bootstrapRegionStart >
            bootstrapInformation.RegionSize - kJumpSize) {
        SetLastError(NT_SUCCESS(bootstrapQueryStatus) ? ERROR_INVALID_ADDRESS : RtlNtStatusToDosError(bootstrapQueryStatus));
        return FALSE;
    }
    if (!ReadExact(
            process,
            bootstrapRecord.target,
            bootstrapRecord.original.data(),
            bootstrapRecord.original.size()) ||
        !WriteExact(
            process,
            reinterpret_cast<PVOID>(remoteProxyBase + targetStorageRva),
            &bootstrapRecord.target,
            sizeof(bootstrapRecord.target)) ||
        !WriteExact(
            process,
            reinterpret_cast<PVOID>(remoteProxyBase + originalStorageRva),
            bootstrapRecord.original.data(),
            bootstrapRecord.original.size())) {
        return FALSE;
    }

    for (size_t index = 0; index < records.size(); ++index) {
        if (!ApplyRecord(process, &records[index])) {
            const DWORD applyError = GetLastError();
            if (!Rollback(process, &records, index + 1)) {
                SetLastError(ERROR_WRITE_FAULT);
            } else {
                SetLastError(applyError);
            }
            return FALSE;
        }
    }

    SetLastError(ERROR_SUCCESS);
    return TRUE;
#endif
}
