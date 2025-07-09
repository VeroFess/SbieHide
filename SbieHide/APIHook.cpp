#include <phnt_windows.h>
#include <phnt.h>
#include "MemoryImageHideInformation.h"
#include "MinHook.h"

#ifdef _DEBUG
    #error You should build own Minhook library!
#else
    #ifdef _WIN64
        #pragma comment(lib, "libMinHook.x64.lib")
    #else
        #pragma comment(lib, "libMinHook.x86.lib")
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
typedef NTSTATUS(NTAPI *NtQuerySystemInformationType)(_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
NtQuerySystemInformationType NtQuerySystemInformationSaved = nullptr;
typedef NTSTATUS(NTAPI *NtQueryInformationProcessType)(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength);
NtQueryInformationProcessType NtQueryInformationProcessSaved = nullptr;
typedef HMODULE(WINAPI *LoadLibraryAType)(_In_ LPCSTR lpLibFileName);
LoadLibraryAType LoadLibraryASaved = nullptr;
typedef HMODULE(WINAPI *LoadLibraryWType)(_In_ LPCWSTR lpLibFileName);
LoadLibraryWType LoadLibraryWSaved = nullptr;

__forceinline static bool IsHiddenName(wchar_t *string, size_t size) {
    if (size >= 4) {
        for (int i = 0; i <= size - 4; i++) {
            if ((string[i] == L'S' || string[i] == L's') &&
                (string[i + 1] == L'B' || string[i + 1] == L'b') &&
                (string[i + 2] == L'I' || string[i + 2] == L'i') &&
                (string[i + 3] == L'E' || string[i + 3] == L'e')) {
                return true;
            }
        }
    }

    if (size >= 9) {
        for (int i = 0; i <= size - 9; i++) {
            if ((string[i] == L'S' || string[i] == L's') &&
                (string[i + 1] == L'A' || string[i + 1] == L'a') &&
                (string[i + 2] == L'N' || string[i + 2] == L'n') &&
                (string[i + 3] == L'D' || string[i + 3] == L'd') &&
                (string[i + 4] == L'B' || string[i + 4] == L'b') &&
                (string[i + 5] == L'O' || string[i + 5] == L'o') &&
                (string[i + 6] == L'X' || string[i + 6] == L'x') &&
                (string[i + 7] == L'I' || string[i + 7] == L'i') &&
                (string[i + 8] == L'E' || string[i + 8] == L'e')) {
                return true;
            }
        }
    }

    return false;
}

__forceinline static bool IsHiddenNameAnsi(char *string, size_t size) {
    if (size >= 4) {
        for (int i = 0; i <= size - 4; i++) {
            if ((string[i] == 'S' || string[i] == 's') &&
                (string[i + 1] == 'B' || string[i + 1] == 'b') &&
                (string[i + 2] == 'I' || string[i + 2] == 'i') &&
                (string[i + 3] == 'E' || string[i + 3] == 'e')) {
                return true;
            }
        }
    }

    if (size >= 9) {
        for (int i = 0; i <= size - 9; i++) {
            if ((string[i] == 'S' || string[i] == 's') &&
                (string[i + 1] == 'A' || string[i + 1] == 'a') &&
                (string[i + 2] == 'N' || string[i + 2] == 'n') &&
                (string[i + 3] == 'D' || string[i + 3] == 'd') &&
                (string[i + 4] == 'B' || string[i + 4] == 'b') &&
                (string[i + 5] == 'O' || string[i + 5] == 'o') &&
                (string[i + 6] == 'X' || string[i + 6] == 'x') &&
                (string[i + 7] == 'I' || string[i + 7] == 'i') &&
                (string[i + 8] == 'E' || string[i + 8] == 'e')) {
                return true;
            }
        }
    }

    return false;
}

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
        if (NT_SUCCESS(Status) && ObjectInformationClass == ObjectNameInformation && ObjectInformation != nullptr) {
            if (IsHiddenName(reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.Buffer, reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.Length)) {
                memset(ObjectInformation, 0, ObjectInformationLength);
                return STATUS_ACCESS_DENIED;
            }
        }
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
            if (IsHiddenName(reinterpret_cast<PFILE_NAME_INFORMATION>(FileInformation)->FileName, reinterpret_cast<PFILE_NAME_INFORMATION>(FileInformation)->FileNameLength)) {
                memset(FileInformation, 0, Length);
                return STATUS_ACCESS_DENIED;
            }
            break;
        case FileAllInformation:
            if (IsHiddenName(reinterpret_cast<PFILE_ALL_INFORMATION>(FileInformation)->NameInformation.FileName, reinterpret_cast<PFILE_ALL_INFORMATION>(FileInformation)->NameInformation.FileNameLength)) {
                memset(FileInformation, 0, Length);
                return STATUS_ACCESS_DENIED;
            }
            break;
        default:
            break;
        }
    }

    return Status;
}

NTSTATUS NTAPI NtQuerySectionProxy(_In_ HANDLE SectionHandle, _In_ SECTION_INFORMATION_CLASS SectionInformationClass, _Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation, _In_ SIZE_T SectionInformationLength, _Out_opt_ PSIZE_T ReturnLength) {
    NTSTATUS Status = STATUS_SUCCESS;

    Status = NtQuerySectionSaved(SectionHandle, SectionInformationClass, SectionInformation, SectionInformationLength, ReturnLength);

    if (NT_SUCCESS(Status) && SectionInformation != nullptr) {
        switch (SectionInformationClass) {
        case SectionImageInformation:
            if (IsAddressShouldHide(*reinterpret_cast<PULONG_PTR>(SectionInformation))) {
                memset(SectionInformation, 0, SectionInformationLength);
                return STATUS_ACCESS_DENIED;
            }
            break;
        case SectionBasicInformation:
            if (IsAddressShouldHide(*reinterpret_cast<PULONG_PTR>(SectionInformation))) {
                memset(SectionInformation, 0, SectionInformationLength);
                return STATUS_ACCESS_DENIED;
            }
            break;
        case SectionOriginalBaseInformation:
            if (IsAddressShouldHide(*reinterpret_cast<PULONG_PTR>(SectionInformation))) {
                memset(SectionInformation, 0, SectionInformationLength);
                return STATUS_ACCESS_DENIED;
            }
            break;
        }
    }

    return Status;
}

NTSTATUS NTAPI NtQuerySystemInformationProxy(_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength) {
    NTSTATUS Status = NtQuerySystemInformationSaved(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (NT_SUCCESS(Status) && SystemInformation != nullptr) {
        switch (SystemInformationClass) {
        case SystemProcessInformation:
        case SystemExtendedProcessInformation:
        case SystemFullProcessInformation: {
            PSYSTEM_PROCESS_INFORMATION ProcessInfo   = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(SystemInformation);
            PSYSTEM_PROCESS_INFORMATION CurrentEntry  = ProcessInfo;
            PSYSTEM_PROCESS_INFORMATION PreviousEntry = nullptr;

            while (CurrentEntry != nullptr) {
                if (CurrentEntry->ImageName.Buffer != nullptr &&
                    CurrentEntry->ImageName.Length > 0) {

                    if (IsHiddenName(CurrentEntry->ImageName.Buffer, CurrentEntry->ImageName.Length)) {
                        if (PreviousEntry != nullptr) {
                            if (CurrentEntry->NextEntryOffset != 0) {
                                PreviousEntry->NextEntryOffset += CurrentEntry->NextEntryOffset;
                            } else {
                                PreviousEntry->NextEntryOffset = 0;
                            }
                        }
                    }
                }

                PreviousEntry = CurrentEntry;
                if (CurrentEntry->NextEntryOffset == 0) {
                    break;
                }
                CurrentEntry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<PCHAR>(CurrentEntry) + CurrentEntry->NextEntryOffset);
            }
        } break;
        case SystemModuleInformation: {
            PRTL_PROCESS_MODULES ModuleInfo  = reinterpret_cast<PRTL_PROCESS_MODULES>(SystemInformation);
            ULONG                ModuleCount = ModuleInfo->NumberOfModules;

            for (ULONG i = 0; i < ModuleCount; i++) {
                PRTL_PROCESS_MODULE_INFORMATION Module = &ModuleInfo->Modules[i];

                if (IsHiddenNameAnsi(reinterpret_cast<char *>(Module->FullPathName), 256)) {
                    RtlZeroMemory(Module->FullPathName, sizeof(Module->FullPathName));
                    RtlZeroMemory(&Module->OffsetToFileName, sizeof(Module->OffsetToFileName));
                }
            }
        } break;
        case SystemModuleInformationEx: {
            PRTL_PROCESS_MODULE_INFORMATION_EX ModuleInfoEx = reinterpret_cast<PRTL_PROCESS_MODULE_INFORMATION_EX>(SystemInformation);
            ULONG                              ModuleCount  = SystemInformationLength / sizeof(RTL_PROCESS_MODULE_INFORMATION_EX);

            for (ULONG i = 0; i < ModuleCount; i++) {
                PRTL_PROCESS_MODULE_INFORMATION_EX CurrentModule = &ModuleInfoEx[i];

                if (CurrentModule->BaseInfo.FullPathName[0] != '\0') {
                    if (IsHiddenNameAnsi(reinterpret_cast<char *>(CurrentModule->BaseInfo.FullPathName), 256)) {
                        RtlZeroMemory(CurrentModule->BaseInfo.FullPathName, sizeof(CurrentModule->BaseInfo.FullPathName));
                        RtlZeroMemory(&CurrentModule->BaseInfo.OffsetToFileName, sizeof(CurrentModule->BaseInfo));
                    }
                }
            }
        } break;
        }
    }

    return Status;
}

NTSTATUS NTAPI NtQueryInformationProcessProxy(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength) {
    NTSTATUS Status = NtQueryInformationProcessSaved(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

    if (NT_SUCCESS(Status) && ProcessInformation != nullptr) {
        switch (ProcessInformationClass) {
        case ProcessImageFileName:
        case ProcessImageFileNameWin32: {
            PUNICODE_STRING ImageFileName = reinterpret_cast<PUNICODE_STRING>(ProcessInformation);
            if (ImageFileName->Buffer != nullptr && ImageFileName->Length > 0) {
                if (IsHiddenName(ImageFileName->Buffer, ImageFileName->Length)) {
                    RtlZeroMemory(ProcessInformation, ProcessInformationLength);
                    return STATUS_ACCESS_DENIED;
                }
            }
        } break;
        case ProcessCommandLineInformation: {
            PUNICODE_STRING CommandLine = reinterpret_cast<PUNICODE_STRING>(ProcessInformation);
            if (CommandLine->Buffer != nullptr && CommandLine->Length > 0) {
                if (IsHiddenName(CommandLine->Buffer, CommandLine->Length)) {
                    RtlZeroMemory(ProcessInformation, ProcessInformationLength);
                    return STATUS_ACCESS_DENIED;
                }
            }
        } break;
        }
    }

    return Status;
}

HMODULE WINAPI LoadLibraryAProxy(_In_ LPCSTR lpLibFileName) {
    if (lpLibFileName && IsHiddenNameAnsi((CHAR *)lpLibFileName, strlen(lpLibFileName))) {
        LoadLibraryASaved(lpLibFileName);
        return nullptr;
    }
    return LoadLibraryASaved(lpLibFileName);
}

HMODULE WINAPI LoadLibraryWProxy(_In_ LPCWSTR lpLibFileName) {
    if (lpLibFileName && IsHiddenName((LPWSTR)lpLibFileName, wcslen(lpLibFileName))) {
        LoadLibraryWSaved(lpLibFileName);
        return nullptr;
    }
    return LoadLibraryWSaved(lpLibFileName);
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

    if (MH_CreateHook(NtQuerySystemInformation, NtQuerySystemInformationProxy, reinterpret_cast<PVOID *>(&NtQuerySystemInformationSaved)) != MH_OK) {
        return FALSE;
    }

    if (MH_EnableHook(NtQuerySystemInformation) != MH_OK) {
        return FALSE;
    }

    if (MH_CreateHook(NtQueryInformationProcess, NtQueryInformationProcessProxy, reinterpret_cast<PVOID *>(&NtQueryInformationProcessSaved)) != MH_OK) {
        return FALSE;
    }

    if (MH_EnableHook(NtQueryInformationProcess) != MH_OK) {
        return FALSE;
    }

    if (MH_CreateHook(LoadLibraryA, LoadLibraryAProxy, reinterpret_cast<PVOID *>(&LoadLibraryASaved)) != MH_OK) {
        return FALSE;
    }

    if (MH_EnableHook(LoadLibraryA) != MH_OK) {
        return FALSE;
    }

    if (MH_CreateHook(LoadLibraryW, LoadLibraryWProxy, reinterpret_cast<PVOID *>(&LoadLibraryWSaved)) != MH_OK) {
        return FALSE;
    }

    if (MH_EnableHook(LoadLibraryW) != MH_OK) {
        return FALSE;
    }

    return TRUE;
}
