#include "APIHook.h"
#include "MemoryImageHideInformation.h"

#ifdef _DEBUG
    #ifdef _WIN64
        #pragma comment(lib, "libMinHook.x64.mtd.lib")
    #else
        #pragma comment(lib, "libMinHook.x86.mtd.lib")
    #endif
#else
    #ifdef _WIN64
        #pragma comment(lib, "libMinHook.x64.mt.lib")
    #else
        #pragma comment(lib, "libMinHook.x86.mt.lib")
    #endif
#endif

typedef NTSTATUS(NTAPI *NtQueryVirtualMemoryType)(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength);
NtQueryVirtualMemoryType NtQueryVirtualMemorySaved = nullptr;
typedef NTSTATUS(NTAPI *NtQueryObjectType)(_In_opt_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength);
NtQueryObjectType NtQueryObjectSaved = nullptr;
typedef NTSTATUS(NTAPI *NtQueryInformationFileType)(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
NtQueryInformationFileType NtQueryInformationFileSaved = nullptr;
typedef NTSTATUS(NTAPI *NtQuerySectionType)(_In_ HANDLE SectionHandle, _In_ SECTION_INFORMATION_CLASS SectionInformationClass, _Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation, _In_ SIZE_T SectionInformationLength, _Out_opt_ PSIZE_T ReturnLength);
NtQuerySectionType NtQuerySectionSaved = nullptr;

NTSTATUS NTAPI NtQueryVirtualMemoryProxy(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength) {
    if (IsAddressShouldHide(BaseAddress)) {
        switch (MemoryInformationClass) {
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

    return NtQueryVirtualMemorySaved(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

NTSTATUS NTAPI NtQueryObjectProxy(_In_opt_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength) {
    NTSTATUS Status = STATUS_SUCCESS;

    Status = NtQueryObjectSaved(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

    if (NT_SUCCESS(Status) && ObjectInformationClass == ObjectNameInformation && ObjectInformation != nullptr) {
        UNICODE_STRING ObjectName = {};

        if (!NT_SUCCESS(RtlUpcaseUnicodeString(&ObjectName, &reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name, TRUE))) {
            return Status;
        }

        if (ObjectName.Buffer == NULL || ObjectName.Length == 0) {
            RtlFreeUnicodeString(&ObjectName);
            return Status;
        }

        if (ObjectName.Length < 7) {
            RtlFreeUnicodeString(&ObjectName);
            return Status;
        }

        if ((wcsstr(ObjectName.Buffer, L"SBIEDLL") != 0) || (wcsstr(ObjectName.Buffer, L"SBIEHIDE") != 0)) {
            RtlZeroMemory(reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.Buffer, reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.MaximumLength);
            reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.Length = 0;
            RtlFreeUnicodeString(&ObjectName);
            return STATUS_ACCESS_DENIED;
        }

        RtlFreeUnicodeString(&ObjectName);
    }

    return Status;
}

NTSTATUS NTAPI NtQueryInformationFileProxy(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {
    NTSTATUS               Status          = STATUS_SUCCESS;
    UNICODE_STRING         FileName        = {};
    UNICODE_STRING         UpperFileName   = {};
    PFILE_ALL_INFORMATION  AllInformation  = {};
    PFILE_NAME_INFORMATION NameInformation = {};

    Status = NtQueryInformationFileSaved(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

    if (NT_SUCCESS(Status) && FileInformation != nullptr) {
        switch (FileInformationClass) {
        case FileNameInformation:
            NameInformation = reinterpret_cast<PFILE_NAME_INFORMATION>(FileInformation);

            FileName.Buffer        = NameInformation->FileName;
            FileName.Length        = static_cast<USHORT>(NameInformation->FileNameLength);
            FileName.MaximumLength = static_cast<USHORT>(NameInformation->FileNameLength);

            if (!NT_SUCCESS(RtlUpcaseUnicodeString(&UpperFileName, &FileName, TRUE))) {
                return Status;
            }

            if (UpperFileName.Buffer == NULL || UpperFileName.Length == 0) {
                RtlFreeUnicodeString(&UpperFileName);
                return Status;
            }

            if (UpperFileName.Length < 7) {
                RtlFreeUnicodeString(&UpperFileName);
                return Status;
            }

            if ((wcsstr(UpperFileName.Buffer, L"SBIEDLL") != 0) || (wcsstr(UpperFileName.Buffer, L"SBIEHIDE") != 0)) {
                RtlZeroMemory(FileInformation, Length);
                RtlFreeUnicodeString(&UpperFileName);
                return STATUS_ACCESS_DENIED;
            }

            RtlFreeUnicodeString(&UpperFileName);

            return Status;

        case FileAllInformation:
            AllInformation  = reinterpret_cast<PFILE_ALL_INFORMATION>(FileInformation);
            NameInformation = &AllInformation->NameInformation;

            FileName.Buffer        = NameInformation->FileName;
            FileName.Length        = static_cast<USHORT>(NameInformation->FileNameLength);
            FileName.MaximumLength = static_cast<USHORT>(NameInformation->FileNameLength);

            if (!NT_SUCCESS(RtlUpcaseUnicodeString(&UpperFileName, &FileName, TRUE))) {
                return Status;
            }

            if (UpperFileName.Buffer == NULL || UpperFileName.Length == 0) {
                RtlFreeUnicodeString(&UpperFileName);
                return Status;
            }

            if (UpperFileName.Length < 7) {
                RtlFreeUnicodeString(&UpperFileName);
                return Status;
            }

            if ((wcsstr(UpperFileName.Buffer, L"SBIEDLL") != 0) || (wcsstr(UpperFileName.Buffer, L"SBIEHIDE") != 0)) {
                RtlZeroMemory(FileInformation, Length);
                RtlFreeUnicodeString(&UpperFileName);
                return STATUS_ACCESS_DENIED;
            }

            RtlFreeUnicodeString(&UpperFileName);

            return Status;

        default:
            break;
        }
    }

    return Status;
}

NTSTATUS NTAPI NtQuerySectionProxy(_In_ HANDLE SectionHandle, _In_ SECTION_INFORMATION_CLASS SectionInformationClass, _Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation, _In_ SIZE_T SectionInformationLength, _Out_opt_ PSIZE_T ReturnLength) {
    NTSTATUS Status = STATUS_SUCCESS;

    Status = NtQuerySectionSaved(SectionHandle, SectionInformationClass, SectionInformation, SectionInformationLength, ReturnLength);

    if (NT_SUCCESS(Status) && SectionInformation != nullptr && SectionInformationClass == SectionOriginalBaseInformation) {
        if (IsAddressShouldHide(*reinterpret_cast<PULONG_PTR>(SectionInformation))) {
            ZeroMemory(SectionInformation, SectionInformationLength);
            return STATUS_ACCESS_DENIED;
        }
    }

    return Status;
}

BOOLEAN EnableApiHook() {
    if (MH_Initialize() != MH_OK) {
        return FALSE;
    }

    if (MH_CreateHook(NtQueryVirtualMemory, NtQueryVirtualMemoryProxy, reinterpret_cast<PVOID *>(&NtQueryVirtualMemorySaved)) != MH_OK) {
        return FALSE;
    }

    if (MH_EnableHook(NtQueryVirtualMemory) != MH_OK) {
        return FALSE;
    }

    if (MH_CreateHook(NtQueryObject, NtQueryObjectProxy, reinterpret_cast<PVOID *>(&NtQueryObjectSaved)) != MH_OK) {
        return FALSE;
    }

    if (MH_EnableHook(NtQueryObject) != MH_OK) {
        return FALSE;
    }

    if (MH_CreateHook(NtQueryInformationFile, NtQueryInformationFileProxy, reinterpret_cast<PVOID *>(&NtQueryInformationFileSaved)) != MH_OK) {
        return FALSE;
    }

    if (MH_EnableHook(NtQueryInformationFile) != MH_OK) {
        return FALSE;
    }

    if (MH_CreateHook(NtQuerySection, NtQuerySectionProxy, reinterpret_cast<PVOID *>(&NtQuerySectionSaved)) != MH_OK) {
        return FALSE;
    }

    if (MH_EnableHook(NtQuerySection) != MH_OK) {
        return FALSE;
    }

    return TRUE;
}
