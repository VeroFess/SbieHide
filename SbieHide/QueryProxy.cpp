#include "QueryProxy.h"

#include "HiddenNameMatcher.h"
#include "MemoryImageHideInformation.h"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <vector>

namespace {

    using NtQueryVirtualMemoryType      = NTSTATUS(NTAPI *)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
    using NtQueryObjectType             = NTSTATUS(NTAPI *)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    using NtQueryInformationFileType    = NTSTATUS(NTAPI *)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    using NtQuerySectionType            = NTSTATUS(NTAPI *)(HANDLE, SECTION_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
    using NtQuerySystemInformationType  = NTSTATUS(NTAPI *)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    using NtQueryInformationProcessType = NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    using LoadLibraryAType              = HMODULE(WINAPI *)(LPCSTR);
    using LoadLibraryWType              = HMODULE(WINAPI *)(LPCWSTR);

    NtQueryVirtualMemoryType      NtQueryVirtualMemoryOriginal      = nullptr;
    NtQueryObjectType             NtQueryObjectOriginal             = nullptr;
    NtQueryInformationFileType    NtQueryInformationFileOriginal    = nullptr;
    NtQuerySectionType            NtQuerySectionOriginal            = nullptr;
    NtQuerySystemInformationType  NtQuerySystemInformationOriginal  = nullptr;
    NtQueryInformationProcessType NtQueryInformationProcessOriginal = nullptr;
    LoadLibraryAType              LoadLibraryAOriginal              = nullptr;
    LoadLibraryWType              LoadLibraryWOriginal              = nullptr;

    size_t EffectiveLength(size_t suppliedLength, const ULONG *returnLength) {
        if (returnLength != nullptr && *returnLength != 0 && *returnLength <= suppliedLength) {
            return *returnLength;
        }
        return suppliedLength;
    }

    bool IsCurrentProcessHandle(HANDLE processHandle) {
        if (processHandle == NtCurrentProcess()) {
            return true;
        }
        const DWORD processId = GetProcessId(processHandle);
        return processId != 0 && processId == GetCurrentProcessId();
    }

    bool IsRangeInside(
        const void *buffer,
        size_t      bufferLength,
        const void *value,
        size_t      valueLength) {
        if (buffer == nullptr || value == nullptr) {
            return false;
        }

        const ULONG_PTR bufferAddress = reinterpret_cast<ULONG_PTR>(buffer);
        const ULONG_PTR valueAddress  = reinterpret_cast<ULONG_PTR>(value);
        if (valueAddress < bufferAddress) {
            return false;
        }

        const size_t offset = static_cast<size_t>(valueAddress - bufferAddress);
        return offset <= bufferLength && valueLength <= bufferLength - offset;
    }

    bool IsHiddenUnicodeString(
        const UNICODE_STRING &value,
        const void           *containingBuffer,
        size_t                containingBufferLength) {
        if (value.Buffer == nullptr || value.Length == 0 ||
            value.Length % sizeof(wchar_t) != 0 ||
            !IsRangeInside(containingBuffer, containingBufferLength, value.Buffer, value.Length)) {
            return false;
        }

        const size_t characterCount = value.Length / sizeof(wchar_t);
        return IsHiddenName(value.Buffer, characterCount);
    }

    bool HasHiddenObjectName(HANDLE handle) {
        ULONG    requiredLength = 0;
        NTSTATUS status         = NtQueryObjectOriginal(
            handle, ObjectNameInformation, nullptr, 0, &requiredLength);
        if (status != STATUS_INFO_LENGTH_MISMATCH &&
            status != STATUS_BUFFER_TOO_SMALL &&
            status != STATUS_BUFFER_OVERFLOW) {
            return false;
        }
        if (requiredLength < sizeof(OBJECT_NAME_INFORMATION) || requiredLength > 1024 * 1024) {
            return false;
        }

        std::vector<BYTE> buffer(requiredLength);
        status = NtQueryObjectOriginal(
            handle,
            ObjectNameInformation,
            buffer.data(),
            requiredLength,
            &requiredLength);
        if (!NT_SUCCESS(status)) {
            return false;
        }
        const auto nameInformation =
            reinterpret_cast<const OBJECT_NAME_INFORMATION *>(buffer.data());
        return IsHiddenUnicodeString(
            nameInformation->Name, buffer.data(), buffer.size());
    }

    size_t BoundedAnsiLength(const UCHAR *value, size_t capacity) {
        size_t length = 0;
        while (length < capacity && value[length] != '\0') {
            ++length;
        }
        return length;
    }

    bool IsProcessEntryValid(
        const BYTE                        *buffer,
        size_t                             totalLength,
        size_t                             offset,
        const SYSTEM_PROCESS_INFORMATION **entry) {
        const size_t headerLength = FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION, Threads);
        if (offset > totalLength || headerLength > totalLength - offset) {
            return false;
        }

        const auto current = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION *>(buffer + offset);
        if (current->NextEntryOffset != 0 &&
            (current->NextEntryOffset < headerLength ||
             current->NextEntryOffset > totalLength - offset)) {
            return false;
        }

        *entry = current;
        return true;
    }

    void AdjustMovedProcessNamePointers(
        BYTE  *buffer,
        size_t newLength,
        size_t removedLength,
        size_t oldLength) {
        const ULONG_PTR oldMovedStart = reinterpret_cast<ULONG_PTR>(buffer) + removedLength;
        const ULONG_PTR oldMovedEnd   = reinterpret_cast<ULONG_PTR>(buffer) + oldLength;
        size_t          offset        = 0;

        while (offset < newLength) {
            const SYSTEM_PROCESS_INFORMATION *checkedEntry = nullptr;
            if (!IsProcessEntryValid(buffer, newLength, offset, &checkedEntry)) {
                return;
            }

            auto            entry       = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(buffer + offset);
            const ULONG_PTR nameAddress = reinterpret_cast<ULONG_PTR>(entry->ImageName.Buffer);
            if (nameAddress >= oldMovedStart && nameAddress < oldMovedEnd) {
                entry->ImageName.Buffer = reinterpret_cast<PWSTR>(nameAddress - removedLength);
            }

            if (entry->NextEntryOffset == 0) {
                return;
            }
            offset += entry->NextEntryOffset;
        }
    }

    bool IsHiddenProcessEntry(
        const SYSTEM_PROCESS_INFORMATION *entry,
        const BYTE                       *buffer,
        size_t                            totalLength) {
        return IsHiddenUnicodeString(entry->ImageName, buffer, totalLength);
    }

    void FilterProcessInformation(PVOID information, size_t *informationLength, PULONG returnLength) {
        auto   buffer      = static_cast<BYTE *>(information);
        size_t totalLength = *informationLength;

        for (;;) {
            const SYSTEM_PROCESS_INFORMATION *first = nullptr;
            if (!IsProcessEntryValid(buffer, totalLength, 0, &first) ||
                !IsHiddenProcessEntry(first, buffer, totalLength)) {
                break;
            }

            const ULONG removedLength = first->NextEntryOffset;
            if (removedLength == 0) {
                RtlZeroMemory(buffer, totalLength);
                totalLength = 0;
                break;
            }

            const size_t oldLength = totalLength;
            RtlMoveMemory(buffer, buffer + removedLength, oldLength - removedLength);
            totalLength = oldLength - removedLength;
            AdjustMovedProcessNamePointers(buffer, totalLength, removedLength, oldLength);
            RtlZeroMemory(buffer + totalLength, removedLength);
        }

        if (totalLength != 0) {
            size_t                            previousOffset  = 0;
            const SYSTEM_PROCESS_INFORMATION *previousChecked = nullptr;
            if (IsProcessEntryValid(buffer, totalLength, previousOffset, &previousChecked)) {
                while (previousChecked->NextEntryOffset != 0) {
                    const size_t                      currentOffset  = previousOffset + previousChecked->NextEntryOffset;
                    const SYSTEM_PROCESS_INFORMATION *currentChecked = nullptr;
                    if (!IsProcessEntryValid(buffer, totalLength, currentOffset, &currentChecked)) {
                        break;
                    }

                    if (IsHiddenProcessEntry(currentChecked, buffer, totalLength)) {
                        auto previous = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(buffer + previousOffset);
                        if (currentChecked->NextEntryOffset == 0) {
                            previous->NextEntryOffset = 0;
                            break;
                        }
                        if (previous->NextEntryOffset > MAXULONG - currentChecked->NextEntryOffset) {
                            break;
                        }
                        previous->NextEntryOffset += currentChecked->NextEntryOffset;
                        previousChecked = previous;
                        continue;
                    }

                    previousOffset  = currentOffset;
                    previousChecked = currentChecked;
                }
            }
        }

        *informationLength = totalLength;
        if (returnLength != nullptr) {
            *returnLength = static_cast<ULONG>(totalLength);
        }
    }

    void FilterModuleInformation(
        PVOID  information,
        size_t informationLength,
        PULONG returnLength) {
        const size_t modulesOffset = FIELD_OFFSET(RTL_PROCESS_MODULES, Modules);
        if (informationLength < modulesOffset) {
            return;
        }

        auto         modules = static_cast<PRTL_PROCESS_MODULES>(information);
        const size_t availableCount =
            (informationLength - modulesOffset) / sizeof(RTL_PROCESS_MODULE_INFORMATION);
        const size_t moduleCount = std::min<size_t>(
            modules->NumberOfModules, availableCount);
        size_t writeIndex = 0;
        for (size_t readIndex = 0; readIndex < moduleCount; ++readIndex) {
            const auto  &module     = modules->Modules[readIndex];
            const size_t pathLength = BoundedAnsiLength(
                module.FullPathName, sizeof(module.FullPathName));
            if (IsHiddenName(
                    reinterpret_cast<const char *>(module.FullPathName), pathLength)) {
                continue;
            }
            if (writeIndex != readIndex) {
                modules->Modules[writeIndex] = module;
            }
            ++writeIndex;
        }
        if (writeIndex < moduleCount) {
            RtlZeroMemory(
                &modules->Modules[writeIndex],
                (moduleCount - writeIndex) * sizeof(RTL_PROCESS_MODULE_INFORMATION));
        }
        modules->NumberOfModules = static_cast<ULONG>(writeIndex);
        if (returnLength != nullptr) {
            *returnLength = static_cast<ULONG>(
                modulesOffset + writeIndex * sizeof(RTL_PROCESS_MODULE_INFORMATION));
        }
    }

    void FilterExtendedModuleInformation(PVOID information, size_t informationLength) {
        auto   buffer = static_cast<BYTE *>(information);
        size_t offset = 0;

        while (offset < informationLength) {
            if (sizeof(RTL_PROCESS_MODULE_INFORMATION_EX) > informationLength - offset) {
                break;
            }

            auto         module     = reinterpret_cast<PRTL_PROCESS_MODULE_INFORMATION_EX>(buffer + offset);
            const USHORT nextOffset = module->NextOffset;
            const size_t recordSize = nextOffset != 0
                                          ? static_cast<size_t>(nextOffset)
                                          : sizeof(RTL_PROCESS_MODULE_INFORMATION_EX);
            if (recordSize < sizeof(RTL_PROCESS_MODULE_INFORMATION_EX) ||
                recordSize > informationLength - offset) {
                break;
            }
            const size_t pathLength = BoundedAnsiLength(
                module->BaseInfo.FullPathName,
                sizeof(module->BaseInfo.FullPathName));
            if (IsHiddenName(
                    reinterpret_cast<const char *>(module->BaseInfo.FullPathName),
                    pathLength)) {
                RtlZeroMemory(module, recordSize);
                module->NextOffset = nextOffset;
            }

            if (nextOffset == 0) {
                break;
            }
            offset += nextOffset;
        }
    }

    NTSTATUS NTAPI NtQueryVirtualMemoryProxy(
        HANDLE                   processHandle,
        PVOID                    baseAddress,
        MEMORY_INFORMATION_CLASS informationClass,
        PVOID                    information,
        SIZE_T                   informationLength,
        PSIZE_T                  returnLength) {
        if (IsCurrentProcessHandle(processHandle) && IsAddressShouldHide(baseAddress)) {
            switch (informationClass) {
            case MemoryBasicInformation:
            case MemoryMappedFilenameInformation:
            case MemoryRegionInformation:
            case MemoryImageInformation:
            case MemoryRegionInformationEx:
            case MemoryEnclaveImageInformation:
            case MemoryBasicInformationCapped:
                return STATUS_ACCESS_DENIED;
            default:
                break;
            }
        }

        return NtQueryVirtualMemoryOriginal(
            processHandle,
            baseAddress,
            informationClass,
            information,
            informationLength,
            returnLength);
    }

    NTSTATUS NTAPI NtQueryObjectProxy(
        HANDLE                   handle,
        OBJECT_INFORMATION_CLASS informationClass,
        PVOID                    information,
        ULONG                    informationLength,
        PULONG                   returnLength) {
        const NTSTATUS status = NtQueryObjectOriginal(
            handle,
            informationClass,
            information,
            informationLength,
            returnLength);
        if (!NT_SUCCESS(status) || information == nullptr) {
            return status;
        }

        const size_t usedLength = EffectiveLength(informationLength, returnLength);
        if (informationClass == ObjectNameInformation &&
            usedLength >= sizeof(UNICODE_STRING)) {
            const auto nameInformation = static_cast<POBJECT_NAME_INFORMATION>(information);
            if (IsHiddenUnicodeString(nameInformation->Name, information, usedLength)) {
                RtlZeroMemory(information, informationLength);
                return STATUS_ACCESS_DENIED;
            }
        }

        return status;
    }

    NTSTATUS NTAPI NtQueryInformationFileProxy(
        HANDLE                 fileHandle,
        PIO_STATUS_BLOCK       ioStatusBlock,
        PVOID                  information,
        ULONG                  informationLength,
        FILE_INFORMATION_CLASS informationClass) {
        if ((informationClass == FileNameInformation ||
             informationClass == FileAllInformation) &&
            HasHiddenObjectName(fileHandle)) {
            return STATUS_ACCESS_DENIED;
        }
        const NTSTATUS status = NtQueryInformationFileOriginal(
            fileHandle,
            ioStatusBlock,
            information,
            informationLength,
            informationClass);

        if (status == STATUS_PENDING ||
            (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) ||
            information == nullptr || ioStatusBlock == nullptr) {
            return status;
        }

        size_t usedLength = informationLength;
        if (ioStatusBlock != nullptr && ioStatusBlock->Information != 0 &&
            ioStatusBlock->Information <= informationLength) {
            usedLength = ioStatusBlock->Information;
        }

        const wchar_t *fileName            = nullptr;
        ULONG          fileNameLengthBytes = 0;
        size_t         fileNameOffset      = 0;
        if (informationClass == FileNameInformation) {
            fileNameOffset = FIELD_OFFSET(FILE_NAME_INFORMATION, FileName);
            if (usedLength >= fileNameOffset) {
                const auto nameInformation = static_cast<PFILE_NAME_INFORMATION>(information);
                fileName                   = nameInformation->FileName;
                fileNameLengthBytes        = nameInformation->FileNameLength;
            }
        } else if (informationClass == FileAllInformation) {
            fileNameOffset = FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation) +
                             FIELD_OFFSET(FILE_NAME_INFORMATION, FileName);
            if (usedLength >= fileNameOffset) {
                const auto allInformation = static_cast<PFILE_ALL_INFORMATION>(information);
                fileName                  = allInformation->NameInformation.FileName;
                fileNameLengthBytes       = allInformation->NameInformation.FileNameLength;
            }
        }

        if (fileName != nullptr && usedLength >= fileNameOffset) {
            size_t availableNameBytes = usedLength - fileNameOffset;
            size_t checkedNameBytes   = std::min<size_t>(fileNameLengthBytes, availableNameBytes);
            checkedNameBytes -= checkedNameBytes % sizeof(wchar_t);
            if (IsHiddenName(fileName, checkedNameBytes / sizeof(wchar_t))) {
                RtlZeroMemory(information, informationLength);
                ioStatusBlock->Status      = STATUS_ACCESS_DENIED;
                ioStatusBlock->Information = 0;
                return STATUS_ACCESS_DENIED;
            }
        }

        return status;
    }

    NTSTATUS NTAPI NtQuerySectionProxy(
        HANDLE                    sectionHandle,
        SECTION_INFORMATION_CLASS informationClass,
        PVOID                     information,
        SIZE_T                    informationLength,
        PSIZE_T                   returnLength) {
        const NTSTATUS status = NtQuerySectionOriginal(
            sectionHandle,
            informationClass,
            information,
            informationLength,
            returnLength);

        if (!NT_SUCCESS(status) || information == nullptr ||
            informationLength < sizeof(ULONG_PTR)) {
            return status;
        }

        switch (informationClass) {
        case SectionImageInformation:
        case SectionBasicInformation:
        case SectionOriginalBaseInformation:
            if (HasHiddenObjectName(sectionHandle) ||
                IsAddressShouldHide(*static_cast<PULONG_PTR>(information))) {
                RtlZeroMemory(information, informationLength);
                return STATUS_ACCESS_DENIED;
            }
            break;
        default:
            break;
        }

        return status;
    }

    NTSTATUS NTAPI NtQuerySystemInformationProxy(
        SYSTEM_INFORMATION_CLASS informationClass,
        PVOID                    information,
        ULONG                    informationLength,
        PULONG                   returnLength) {
        const NTSTATUS status = NtQuerySystemInformationOriginal(
            informationClass,
            information,
            informationLength,
            returnLength);

        if (!NT_SUCCESS(status) || information == nullptr) {
            return status;
        }

        size_t usedLength = EffectiveLength(informationLength, returnLength);
        switch (informationClass) {
        case SystemProcessInformation:
        case SystemExtendedProcessInformation:
        case SystemFullProcessInformation:
            FilterProcessInformation(information, &usedLength, returnLength);
            break;
        case SystemModuleInformation:
            FilterModuleInformation(information, usedLength, returnLength);
            break;
        case SystemModuleInformationEx:
            FilterExtendedModuleInformation(information, usedLength);
            break;
        default:
            break;
        }

        return status;
    }

    NTSTATUS NTAPI NtQueryInformationProcessProxy(
        HANDLE           processHandle,
        PROCESSINFOCLASS informationClass,
        PVOID            information,
        ULONG            informationLength,
        PULONG           returnLength) {
        const NTSTATUS status = NtQueryInformationProcessOriginal(
            processHandle,
            informationClass,
            information,
            informationLength,
            returnLength);
        if (!NT_SUCCESS(status) || information == nullptr) {
            return status;
        }

        const size_t usedLength = EffectiveLength(informationLength, returnLength);
        if (usedLength < sizeof(UNICODE_STRING)) {
            return status;
        }

        switch (informationClass) {
        case ProcessImageFileName:
        case ProcessImageFileNameWin32:
        case ProcessCommandLineInformation: {
            const auto value = static_cast<PUNICODE_STRING>(information);
            if (IsHiddenUnicodeString(*value, information, usedLength)) {
                RtlZeroMemory(information, informationLength);
                return STATUS_ACCESS_DENIED;
            }
            break;
        }
        default:
            break;
        }

        return status;
    }

    HMODULE WINAPI LoadLibraryAProxy(LPCSTR fileName) {
        if (fileName != nullptr && IsHiddenName(fileName, std::strlen(fileName))) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            return nullptr;
        }
        return LoadLibraryAOriginal(fileName);
    }

    HMODULE WINAPI LoadLibraryWProxy(LPCWSTR fileName) {
        if (fileName != nullptr && IsHiddenName(fileName, std::wcslen(fileName))) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            return nullptr;
        }
        return LoadLibraryWOriginal(fileName);
    }

    HookRegistration QueryProxyHooks[] = {
        { reinterpret_cast<PVOID>(NtQueryVirtualMemory), reinterpret_cast<PVOID>(NtQueryVirtualMemoryProxy), reinterpret_cast<PVOID *>(&NtQueryVirtualMemoryOriginal) },
        { reinterpret_cast<PVOID>(NtQueryObject), reinterpret_cast<PVOID>(NtQueryObjectProxy), reinterpret_cast<PVOID *>(&NtQueryObjectOriginal) },
        { reinterpret_cast<PVOID>(NtQueryInformationFile), reinterpret_cast<PVOID>(NtQueryInformationFileProxy), reinterpret_cast<PVOID *>(&NtQueryInformationFileOriginal) },
        { reinterpret_cast<PVOID>(NtQuerySection), reinterpret_cast<PVOID>(NtQuerySectionProxy), reinterpret_cast<PVOID *>(&NtQuerySectionOriginal) },
        { reinterpret_cast<PVOID>(NtQuerySystemInformation), reinterpret_cast<PVOID>(NtQuerySystemInformationProxy), reinterpret_cast<PVOID *>(&NtQuerySystemInformationOriginal) },
        { reinterpret_cast<PVOID>(NtQueryInformationProcess), reinterpret_cast<PVOID>(NtQueryInformationProcessProxy), reinterpret_cast<PVOID *>(&NtQueryInformationProcessOriginal) },
        { reinterpret_cast<PVOID>(LoadLibraryA), reinterpret_cast<PVOID>(LoadLibraryAProxy), reinterpret_cast<PVOID *>(&LoadLibraryAOriginal) },
        { reinterpret_cast<PVOID>(LoadLibraryW), reinterpret_cast<PVOID>(LoadLibraryWProxy), reinterpret_cast<PVOID *>(&LoadLibraryWOriginal) },
    };

} // namespace

const HookRegistration *GetQueryProxyHooks(size_t *count) {
    *count = ARRAYSIZE(QueryProxyHooks);
    return QueryProxyHooks;
}
