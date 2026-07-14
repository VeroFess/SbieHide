#include <phnt_windows.h>
#include <phnt.h>

#include "hidden_name.h"
#include "simple_runtime_library.h"
#include "syscall_invoker.h"

static __forceinline SIZE_T BoundedReturnedLength(SIZE_T suppliedLength, SIZE_T returnedLength) {
    return returnedLength < suppliedLength ? returnedLength : suppliedLength;
}

static bool IsHiddenFileHandle(HANDLE fileHandle) {
    BYTE     stackBuffer[1024] = {};
    PVOID    buffer            = stackBuffer;
    ULONG    bufferLength      = sizeof(stackBuffer);
    ULONG    returnLength      = 0;
    NTSTATUS status            = invoke_systemcall<NTSTATUS>(
        NtQueryObjectSystemCallIndex,
        fileHandle,
        ObjectNameInformation,
        buffer,
        bufferLength,
        &returnLength);
    bool allocated = false;
    if ((status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL ||
         status == STATUS_BUFFER_OVERFLOW) &&
        returnLength > bufferLength) {
        SIZE_T allocationSize = returnLength;
        buffer                = nullptr;
        status                = invoke_systemcall<NTSTATUS>(
            NtAllocateVirtualMemorySystemCallIndex,
            NtCurrentProcess(),
            &buffer,
            0,
            &allocationSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);
        if (!NT_SUCCESS(status) || buffer == nullptr) {
            return false;
        }
        allocated    = true;
        bufferLength = returnLength;
        status       = invoke_systemcall<NTSTATUS>(
            NtQueryObjectSystemCallIndex,
            fileHandle,
            ObjectNameInformation,
            buffer,
            bufferLength,
            &returnLength);
    }

    bool hidden = false;
    if (NT_SUCCESS(status) && returnLength >= sizeof(OBJECT_NAME_INFORMATION)) {
        const auto nameInformation = reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer);
        hidden                     = nameInformation->Name.Buffer != nullptr &&
                 IsBufferRangeValid(
                     buffer,
                     BoundedReturnedLength(bufferLength, returnLength),
                     nameInformation->Name.Buffer,
                     nameInformation->Name.Length) &&
                 IsHiddenName(
                     nameInformation->Name.Buffer,
                     nameInformation->Name.Length);
    }
    if (allocated) {
        SIZE_T releaseSize = 0;
        invoke_systemcall<NTSTATUS>(
            NtFreeVirtualMemorySystemCallIndex,
            NtCurrentProcess(),
            &buffer,
            &releaseSize,
            MEM_RELEASE);
    }
    return hidden;
}

static __forceinline bool IsCurrentProcessHandle(HANDLE processHandle) {
    if (processHandle == NtCurrentProcess()) {
        return true;
    }
    PROCESS_BASIC_INFORMATION information = {};
    const NTSTATUS            status      = invoke_systemcall<NTSTATUS>(
        NtQueryInformationProcessSystemCallIndex,
        processHandle,
        ProcessBasicInformation,
        &information,
        sizeof(information),
        nullptr);
    return NT_SUCCESS(status) &&
           information.UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess;
}

extern "C" NTSTATUS NTAPI NtQueryVirtualMemoryDetours(
    _In_ HANDLE                                       ProcessHandle,
    _In_opt_ PVOID                                    BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS                     MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T                                       MemoryInformationLength,
    _Out_opt_ PSIZE_T                                 ReturnLength) {

    const bool currentProcess = IsCurrentProcessHandle(ProcessHandle);
    if (currentProcess && IsNtdllAddress(BaseAddress) &&
        MemoryInformationClass == MemoryImageInformation) {
        const NTSTATUS status = invoke_systemcall<NTSTATUS>(
            NtQueryVirtualMemorySystemCallIndex,
            ProcessHandle,
            BaseAddress,
            MemoryInformationClass,
            MemoryInformation,
            MemoryInformationLength,
            ReturnLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (MemoryInformation == nullptr || MemoryInformationLength < sizeof(MEMORY_IMAGE_INFORMATION)) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        PMEMORY_IMAGE_INFORMATION imageInformation = reinterpret_cast<PMEMORY_IMAGE_INFORMATION>(MemoryInformation);
        imageInformation->ImageBase                = NTDLL_BASE_ADDRESS;
        imageInformation->SizeOfImage              = NTDLL_SIZE;
        if (ReturnLength != nullptr) {
            *ReturnLength = sizeof(MEMORY_IMAGE_INFORMATION);
        }
        return STATUS_SUCCESS;
    }

    if (currentProcess && IsHiddenAddress(BaseAddress)) {
        const NTSTATUS status = invoke_systemcall<NTSTATUS>(
            NtQueryVirtualMemorySystemCallIndex,
            ProcessHandle,
            BaseAddress,
            MemoryInformationClass,
            MemoryInformation,
            MemoryInformationLength,
            ReturnLength);
        if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
            return status;
        }
        if (MemoryInformation != nullptr && MemoryInformationLength != 0) {
            RtlZeroMemory(MemoryInformation, MemoryInformationLength);
        }
        return STATUS_ACCESS_DENIED;
    }

    return invoke_systemcall<NTSTATUS>(NtQueryVirtualMemorySystemCallIndex, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

extern "C" NTSTATUS NTAPI NtQueryObjectDetours(
    _In_opt_ HANDLE                                       Handle,
    _In_ OBJECT_INFORMATION_CLASS                         ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG                                            ObjectInformationLength,
    _Out_opt_ PULONG                                      ReturnLength) {

    const NTSTATUS status = invoke_systemcall<NTSTATUS>(NtQueryObjectSystemCallIndex, Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
    if (!NT_SUCCESS(status) || ObjectInformationClass != ObjectNameInformation || ObjectInformation == nullptr) {
        return status;
    }

    const SIZE_T validLength = BoundedReturnedLength(ObjectInformationLength, ReturnLength != nullptr ? *ReturnLength : ObjectInformationLength);
    if (validLength < sizeof(OBJECT_NAME_INFORMATION)) {
        return status;
    }

    const auto nameInformation = reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation);
    if (nameInformation->Name.Buffer != nullptr &&
        IsBufferRangeValid(ObjectInformation, validLength, nameInformation->Name.Buffer, nameInformation->Name.Length) &&
        IsHiddenObjectName(nameInformation->Name.Buffer, nameInformation->Name.Length)) {
        RtlZeroMemory(ObjectInformation, validLength);
        if (ReturnLength != nullptr) {
            *ReturnLength = 0;
        }
        return STATUS_ACCESS_DENIED;
    }

    return status;
}

extern "C" NTSTATUS NTAPI NtQueryInformationFileDetours(
    _In_ HANDLE                      FileHandle,
    _Out_ PIO_STATUS_BLOCK           IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG                       Length,
    _In_ FILE_INFORMATION_CLASS      FileInformationClass) {

    if (IsHiddenFileHandle(FileHandle)) {
        return STATUS_ACCESS_DENIED;
    }

    const NTSTATUS status = invoke_systemcall<NTSTATUS>(NtQueryInformationFileSystemCallIndex, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    if (status == STATUS_PENDING ||
        (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) ||
        FileInformation == nullptr || IoStatusBlock == nullptr) {
        return status;
    }

    const SIZE_T validLength = BoundedReturnedLength(Length, static_cast<SIZE_T>(IoStatusBlock->Information));
    bool         hidden      = false;
    if (FileInformationClass == FileNameInformation &&
        validLength >= FIELD_OFFSET(FILE_NAME_INFORMATION, FileName)) {
        PFILE_NAME_INFORMATION information = reinterpret_cast<PFILE_NAME_INFORMATION>(FileInformation);
        const SIZE_T           nameOffset  = FIELD_OFFSET(FILE_NAME_INFORMATION, FileName);
        SIZE_T                 nameBytes   = BoundedReturnedLength(
            information->FileNameLength, validLength - nameOffset);
        nameBytes -= nameBytes % sizeof(WCHAR);
        hidden = IsHiddenName(information->FileName, nameBytes);
    } else if (FileInformationClass == FileAllInformation && validLength >= FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation.FileName)) {
        PFILE_ALL_INFORMATION information = reinterpret_cast<PFILE_ALL_INFORMATION>(FileInformation);
        const SIZE_T          nameOffset  = FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation.FileName);
        SIZE_T                nameBytes   = BoundedReturnedLength(
            information->NameInformation.FileNameLength, validLength - nameOffset);
        nameBytes -= nameBytes % sizeof(WCHAR);
        hidden = IsHiddenName(information->NameInformation.FileName, nameBytes);
    }

    if (hidden) {
        RtlZeroMemory(FileInformation, validLength);
        IoStatusBlock->Status      = STATUS_ACCESS_DENIED;
        IoStatusBlock->Information = 0;
        return STATUS_ACCESS_DENIED;
    }
    return status;
}

extern "C" NTSTATUS NTAPI NtQuerySectionDetours(
    _In_ HANDLE                                        SectionHandle,
    _In_ SECTION_INFORMATION_CLASS                     SectionInformationClass,
    _Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation,
    _In_ SIZE_T                                        SectionInformationLength,
    _Out_opt_ PSIZE_T                                  ReturnLength) {

    const NTSTATUS status = invoke_systemcall<NTSTATUS>(NtQuerySectionSystemCallIndex, SectionHandle, SectionInformationClass, SectionInformation, SectionInformationLength, ReturnLength);
    if (!NT_SUCCESS(status) || SectionInformation == nullptr) {
        return status;
    }

    const SIZE_T validLength = BoundedReturnedLength(SectionInformationLength, ReturnLength != nullptr ? *ReturnLength : SectionInformationLength);
    bool         hidden      = false;
    switch (SectionInformationClass) {
    case SectionImageInformation:
        hidden = validLength >= sizeof(SECTION_IMAGE_INFORMATION) &&
                 IsHiddenAddress(reinterpret_cast<PSECTION_IMAGE_INFORMATION>(SectionInformation)->TransferAddress);
        break;
    case SectionBasicInformation:
        hidden = validLength >= sizeof(SECTION_BASIC_INFORMATION) &&
                 IsHiddenAddress(reinterpret_cast<PSECTION_BASIC_INFORMATION>(SectionInformation)->BaseAddress);
        break;
    case SectionOriginalBaseInformation:
        hidden = validLength >= sizeof(ULONG_PTR) &&
                 IsHiddenAddress(reinterpret_cast<PVOID>(*reinterpret_cast<PULONG_PTR>(SectionInformation)));
        break;
    default:
        break;
    }

    if (hidden) {
        RtlZeroMemory(SectionInformation, validLength);
        if (ReturnLength != nullptr) {
            *ReturnLength = 0;
        }
        return STATUS_ACCESS_DENIED;
    }
    return status;
}

static VOID FilterProcessInformation(PVOID buffer, SIZE_T bufferLength) {
    const SIZE_T                minimumEntrySize = FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION, Threads);
    SIZE_T                      offset           = 0;
    PSYSTEM_PROCESS_INFORMATION previous         = nullptr;

    while (offset <= bufferLength && minimumEntrySize <= bufferLength - offset) {
        auto current = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
            reinterpret_cast<PUCHAR>(buffer) + offset);
        const ULONG nextOffset      = current->NextEntryOffset;
        const bool  nextOffsetValid = nextOffset == 0 ||
                                     (nextOffset >= minimumEntrySize &&
                                      nextOffset <= bufferLength - offset);
        if (!nextOffsetValid) {
            break;
        }
        const bool hidden = current->ImageName.Buffer != nullptr &&
                            current->ImageName.Length != 0 &&
                            IsBufferRangeValid(
                                buffer,
                                bufferLength,
                                current->ImageName.Buffer,
                                current->ImageName.Length) &&
                            IsHiddenName(
                                current->ImageName.Buffer,
                                current->ImageName.Length);
        if (hidden && previous != nullptr) {
            const SIZE_T hiddenSpan = nextOffset != 0
                                          ? nextOffset
                                          : bufferLength - offset;
            if (nextOffset == 0) {
                previous->NextEntryOffset = 0;
            } else if (previous->NextEntryOffset <= MAXULONG - nextOffset) {
                previous->NextEntryOffset += nextOffset;
            } else {
                break;
            }
            RtlZeroMemory(current, hiddenSpan);
            if (nextOffset == 0) {
                break;
            }
            offset += nextOffset;
            continue;
        }
        if (hidden) {
            RtlZeroMemory(current->ImageName.Buffer, current->ImageName.Length);
            current->ImageName.Length = 0;
            current->UniqueProcessId  = nullptr;
        }
        if (nextOffset == 0) {
            break;
        }
        previous = current;
        offset += nextOffset;
    }
}

static SIZE_T FilterModuleInformation(PVOID buffer, SIZE_T bufferLength) {
    const SIZE_T modulesOffset = FIELD_OFFSET(RTL_PROCESS_MODULES, Modules);
    if (bufferLength < modulesOffset) {
        return bufferLength;
    }

    auto         modules  = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer);
    const SIZE_T capacity = (bufferLength - modulesOffset) /
                            sizeof(RTL_PROCESS_MODULE_INFORMATION);
    const SIZE_T count      = modules->NumberOfModules < capacity
                                  ? modules->NumberOfModules
                                  : capacity;
    SIZE_T       writeIndex = 0;
    for (SIZE_T readIndex = 0; readIndex < count; ++readIndex) {
        const auto source = &modules->Modules[readIndex];
        if (IsHiddenNameAnsi(
                reinterpret_cast<const CHAR *>(source->FullPathName),
                sizeof(source->FullPathName)) ||
            ContainsHiddenSubstring(
                reinterpret_cast<const CHAR *>(source->FullPathName),
                sizeof(source->FullPathName),
                "sbiedrv")) {
            continue;
        }
        if (writeIndex != readIndex) {
            RtlCopyMemory(
                &modules->Modules[writeIndex],
                source,
                sizeof(*source));
        }
        ++writeIndex;
    }
    if (writeIndex < count) {
        RtlZeroMemory(
            &modules->Modules[writeIndex],
            (count - writeIndex) * sizeof(RTL_PROCESS_MODULE_INFORMATION));
    }
    modules->NumberOfModules = static_cast<ULONG>(writeIndex);
    return modulesOffset + writeIndex * sizeof(RTL_PROCESS_MODULE_INFORMATION);
}

static VOID FilterModuleInformationEx(PVOID buffer, SIZE_T bufferLength) {
    SIZE_T                             offset   = 0;
    PRTL_PROCESS_MODULE_INFORMATION_EX previous = nullptr;
    while (offset <= bufferLength &&
           sizeof(RTL_PROCESS_MODULE_INFORMATION_EX) <= bufferLength - offset) {
        auto current = reinterpret_cast<PRTL_PROCESS_MODULE_INFORMATION_EX>(
            reinterpret_cast<PUCHAR>(buffer) + offset);
        const USHORT nextOffset      = current->NextOffset;
        const bool   nextOffsetValid = nextOffset == 0 ||
                                     (nextOffset >= sizeof(*current) &&
                                      nextOffset <= bufferLength - offset);
        if (!nextOffsetValid) {
            break;
        }
        const bool hidden = IsHiddenNameAnsi(
            reinterpret_cast<const CHAR *>(current->BaseInfo.FullPathName),
            sizeof(current->BaseInfo.FullPathName));
        if (hidden && previous != nullptr) {
            const SIZE_T hiddenSpan = nextOffset != 0
                                          ? nextOffset
                                          : bufferLength - offset;
            if (nextOffset == 0) {
                previous->NextOffset = 0;
            } else if (previous->NextOffset <= MAXUSHORT - nextOffset) {
                previous->NextOffset = static_cast<USHORT>(
                    previous->NextOffset + nextOffset);
            } else {
                break;
            }
            RtlZeroMemory(current, hiddenSpan);
            if (nextOffset == 0) {
                break;
            }
            offset += nextOffset;
            continue;
        }
        if (hidden) {
            RtlZeroMemory(&current->BaseInfo, sizeof(current->BaseInfo));
        }
        if (nextOffset == 0) {
            break;
        }
        previous = current;
        offset += nextOffset;
    }
}

extern "C" NTSTATUS NTAPI NtQuerySystemInformationDetours(
    _In_ SYSTEM_INFORMATION_CLASS                         SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG                                            SystemInformationLength,
    _Out_opt_ PULONG                                      ReturnLength) {

    const NTSTATUS status = invoke_systemcall<NTSTATUS>(NtQuerySystemInformationSystemCallIndex, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if (!NT_SUCCESS(status) || SystemInformation == nullptr) {
        return status;
    }

    const SIZE_T validLength = BoundedReturnedLength(SystemInformationLength, ReturnLength != nullptr ? *ReturnLength : SystemInformationLength);
    switch (SystemInformationClass) {
    case SystemProcessInformation:
    case SystemExtendedProcessInformation:
    case SystemFullProcessInformation:
        FilterProcessInformation(SystemInformation, validLength);
        break;
    case SystemModuleInformation:
        if (ReturnLength != nullptr) {
            *ReturnLength = static_cast<ULONG>(
                FilterModuleInformation(SystemInformation, validLength));
        } else {
            FilterModuleInformation(SystemInformation, validLength);
        }
        break;
    case SystemModuleInformationEx:
        FilterModuleInformationEx(SystemInformation, validLength);
        break;
    default:
        break;
    }
    return status;
}

extern "C" NTSTATUS NTAPI NtQueryInformationProcessDetours(
    _In_ HANDLE                                        ProcessHandle,
    _In_ PROCESSINFOCLASS                              ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG                                         ProcessInformationLength,
    _Out_opt_ PULONG                                   ReturnLength) {

    const NTSTATUS status = invoke_systemcall<NTSTATUS>(NtQueryInformationProcessSystemCallIndex, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    if (!NT_SUCCESS(status) || ProcessInformation == nullptr) {
        return status;
    }

    if (ProcessInformationClass != ProcessImageFileName &&
        ProcessInformationClass != ProcessImageFileNameWin32 &&
        ProcessInformationClass != ProcessCommandLineInformation) {
        return status;
    }

    const SIZE_T validLength = BoundedReturnedLength(ProcessInformationLength, ReturnLength != nullptr ? *ReturnLength : ProcessInformationLength);
    if (validLength < sizeof(UNICODE_STRING)) {
        return status;
    }

    PUNICODE_STRING value = reinterpret_cast<PUNICODE_STRING>(ProcessInformation);
    if (value->Buffer != nullptr && value->Length != 0 &&
        IsBufferRangeValid(ProcessInformation, validLength, value->Buffer, value->Length) &&
        IsHiddenName(value->Buffer, value->Length)) {
        RtlZeroMemory(ProcessInformation, validLength);
        if (ReturnLength != nullptr) {
            *ReturnLength = 0;
        }
        return STATUS_ACCESS_DENIED;
    }
    return status;
}
