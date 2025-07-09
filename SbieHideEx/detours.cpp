#include <phnt_windows.h>
#include <phnt.h>

#include "detours.h"
#include "syscall_invoker.h"

LDRPCALLTLSINITIALIZERSTYPE LdrpCallTlsInitializersOriginal = nullptr;
LDRLOADDLLTYPE              LdrLoadDllOriginal              = nullptr;

#define IN_HIDDEN_RANGE(Address) (                                                                                \
    ((reinterpret_cast<ULONG64>(Address) >= reinterpret_cast<ULONG64>(SBIEHIDE_BASE_ADDRESS)) &&                  \
     (reinterpret_cast<ULONG64>(Address) <= reinterpret_cast<ULONG64>(SBIEHIDE_BASE_ADDRESS) + SBIEHIDE_SIZE)) || \
    ((reinterpret_cast<ULONG64>(Address) >= reinterpret_cast<ULONG64>(SBIE_BASE_ADDRESS)) &&                      \
     (reinterpret_cast<ULONG64>(Address) <= reinterpret_cast<ULONG64>(SBIE_BASE_ADDRESS) + SBIE_SIZE)))

#define IN_NTDLL_RANGE(Address)                                                             \
    (reinterpret_cast<ULONG64>(Address) >= reinterpret_cast<ULONG64>(NTDLL_BASE_ADDRESS) && \
     reinterpret_cast<ULONG64>(Address) <= reinterpret_cast<ULONG64>(NTDLL_BASE_ADDRESS) + NTDLL_SIZE)

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

extern "C" NTSTATUS NTAPI NtQueryVirtualMemoryDetours(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength) {
    if (!PROCESS_INITIALIZATION_FINISHED) {
        ModulePreProcessInitRoutine();
    }

    if (ProcessHandle == NtCurrentProcess() && IN_NTDLL_RANGE(BaseAddress) && MemoryInformationClass == MemoryImageInformation) {
        reinterpret_cast<PMEMORY_IMAGE_INFORMATION>(MemoryInformation)->ImageBase   = NTDLL_BASE_ADDRESS;
        reinterpret_cast<PMEMORY_IMAGE_INFORMATION>(MemoryInformation)->SizeOfImage = NTDLL_SIZE;

        if (ReturnLength != nullptr) {
            *ReturnLength = sizeof(MEMORY_IMAGE_INFORMATION);
        }

        return STATUS_SUCCESS;
    } else if (IN_HIDDEN_RANGE(BaseAddress)) {
        return STATUS_ACCESS_DENIED;
    }

    return invoke_systemcall<NTSTATUS>(NtQueryVirtualMemorySystemCallIndex, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

extern "C" NTSTATUS NTAPI NtQueryObjectDetours(_In_opt_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength) {
    NTSTATUS Status = STATUS_SUCCESS;

    if (!PROCESS_INITIALIZATION_FINISHED) {
        ModulePreProcessInitRoutine();
    }

    Status = invoke_systemcall<NTSTATUS>(NtQueryObjectSystemCallIndex, Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

    if (NT_SUCCESS(Status) && ObjectInformationClass == ObjectNameInformation && ObjectInformation != nullptr) {
        if (IsHiddenName(reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.Buffer, reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.Length)) {
            memset(ObjectInformation, 0, ObjectInformationLength);
            return STATUS_ACCESS_DENIED;
        }
    }

    return Status;
}

extern "C" NTSTATUS NTAPI NtQueryInformationFileDetours(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {
    NTSTATUS               Status          = STATUS_SUCCESS;
    UNICODE_STRING         FileName        = {};
    UNICODE_STRING         UpperFileName   = {};
    PFILE_ALL_INFORMATION  AllInformation  = {};
    PFILE_NAME_INFORMATION NameInformation = {};

    if (!PROCESS_INITIALIZATION_FINISHED) {
        ModulePreProcessInitRoutine();
    }

    Status = invoke_systemcall<NTSTATUS>(NtQueryInformationFileSystemCallIndex, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

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

extern "C" NTSTATUS NTAPI NtQuerySectionDetours(_In_ HANDLE SectionHandle, _In_ SECTION_INFORMATION_CLASS SectionInformationClass, _Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation, _In_ SIZE_T SectionInformationLength, _Out_opt_ PSIZE_T ReturnLength) {
    NTSTATUS Status = STATUS_SUCCESS;

    if (!PROCESS_INITIALIZATION_FINISHED) {
        ModulePreProcessInitRoutine();
    }

    Status = invoke_systemcall<NTSTATUS>(NtQuerySectionSystemCallIndex, SectionHandle, SectionInformationClass, SectionInformation, SectionInformationLength, ReturnLength);

    if (NT_SUCCESS(Status) && SectionInformation != nullptr) {
        switch (SectionInformationClass) {
        case SectionImageInformation:
            if (IN_HIDDEN_RANGE(reinterpret_cast<PSECTION_IMAGE_INFORMATION>(SectionInformation)->TransferAddress)) {
                memset(SectionInformation, 0, SectionInformationLength);
                return STATUS_ACCESS_DENIED;
            }
            break;
        case SectionBasicInformation:
            if (IN_HIDDEN_RANGE(reinterpret_cast<PSECTION_BASIC_INFORMATION>(SectionInformation)->BaseAddress)) {
                memset(SectionInformation, 0, SectionInformationLength);
                return STATUS_ACCESS_DENIED;
            }
            break;
        case SectionOriginalBaseInformation:
            if (IN_HIDDEN_RANGE(reinterpret_cast<PVOID>(*reinterpret_cast<PULONG_PTR>(SectionInformation)))) {
                memset(SectionInformation, 0, SectionInformationLength);
                return STATUS_ACCESS_DENIED;
            }
            break;
        }
    }

    return Status;
}

extern "C" NTSTATUS NTAPI NtQuerySystemInformationDetours(_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength) {
    if (!PROCESS_INITIALIZATION_FINISHED) {
        ModulePreProcessInitRoutine();
    }

    NTSTATUS Status = invoke_systemcall<NTSTATUS>(NtQuerySystemInformationSystemCallIndex, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

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

extern "C" NTSTATUS NTAPI NtQueryInformationProcessDetours(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength) {
    if (!PROCESS_INITIALIZATION_FINISHED) {
        ModulePreProcessInitRoutine();
    }

    NTSTATUS Status = invoke_systemcall<NTSTATUS>(NtQueryInformationProcessSystemCallIndex, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

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

volatile long PEB_CUSTOM_LOCK = 0;

size_t wcslen_light(PWSTR str) {
    size_t i = 0;
    while (str[i++] != L'0') {}
    return i;
}

NTSTATUS NTAPI LdrLoadDllDetours(_In_opt_ PWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID *DllHandle) {
    PPEB                  ProcessEnvironmentBlock = nullptr;
    PLIST_ENTRY           FirstEntry              = nullptr;
    PLIST_ENTRY           CurrentEntry            = nullptr;
    PLIST_ENTRY           NextEntry               = nullptr;
    PLDR_DATA_TABLE_ENTRY CurrentEntryData        = nullptr;
    NTSTATUS              Status                  = STATUS_SUCCESS;

    Status = LdrLoadDllOriginal(DllPath, DllCharacteristics, DllName, DllHandle);

    if (SBIE_BASE_ADDRESS == 0) {
        FindSbieDllFromPeb();
    }

    ProcessEnvironmentBlock = NtCurrentPeb();

    FirstEntry = CurrentEntry = ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList.Flink;

    while (CurrentEntry->Flink != FirstEntry) {
        CurrentEntryData = CONTAINING_RECORD(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(CurrentEntry), LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (IsHiddenName(CurrentEntryData->BaseDllName.Buffer, CurrentEntryData->BaseDllName.Length)) {
            SLock(&PEB_CUSTOM_LOCK);

            if (FirstEntry == CurrentEntry) {
                FirstEntry = CurrentEntry->Flink;
            }

            NextEntry                                = CurrentEntry->Flink;
            CurrentEntryData->HashLinks.Blink->Flink = CurrentEntryData->HashLinks.Flink;
            CurrentEntryData->HashLinks.Flink->Blink = CurrentEntryData->HashLinks.Blink;

            CurrentEntryData->InLoadOrderLinks.Blink->Flink = CurrentEntryData->InLoadOrderLinks.Flink;
            CurrentEntryData->InLoadOrderLinks.Flink->Blink = CurrentEntryData->InLoadOrderLinks.Blink;

            CurrentEntryData->InMemoryOrderLinks.Blink->Flink = CurrentEntryData->InMemoryOrderLinks.Flink;
            CurrentEntryData->InMemoryOrderLinks.Flink->Blink = CurrentEntryData->InMemoryOrderLinks.Blink;

            CurrentEntryData->InInitializationOrderLinks.Blink->Flink = CurrentEntryData->InInitializationOrderLinks.Flink;
            CurrentEntryData->InInitializationOrderLinks.Flink->Blink = CurrentEntryData->InInitializationOrderLinks.Blink;

            CurrentEntryData->NodeModuleLink.Blink->Flink = CurrentEntryData->NodeModuleLink.Flink;
            CurrentEntryData->NodeModuleLink.Flink->Blink = CurrentEntryData->NodeModuleLink.Blink;

            RtlZeroMemory(CurrentEntryData->BaseDllName.Buffer, CurrentEntryData->BaseDllName.MaximumLength);
            RtlZeroMemory(CurrentEntryData->FullDllName.Buffer, CurrentEntryData->FullDllName.MaximumLength);

            CurrentEntry = NextEntry;

            SUnlock(&PEB_CUSTOM_LOCK);

            continue;
        }

        CurrentEntry = CurrentEntry->Flink;
    }

    if ((DllPath != nullptr && IsHiddenName(DllPath, wcslen_light(DllPath))) || DllName != nullptr && DllName->Buffer != nullptr && IsHiddenName(DllName->Buffer, DllName->Length)) {
        *DllHandle = 0;
        return STATUS_NOT_FOUND;
    }

    return Status;
}

inline bool IsCanonAddr(uint64_t v) {
    return (v <= 0x00007FFFFFFFFFFFULL) ||
           (v >= 0xFFFF800000000000ULL);
}

inline bool IsProbablyPointer(uint64_t v) {
    if (v == 0)
        return false;
    if (!IsCanonAddr(v))
        return false;
    if (v < 0x10000)
        return false;
    return true;
}

static PBYTE  _G_ENTRY_POINT         = 0;
volatile long LDR_CUSTOM_LOCK        = 0;
BYTE          ENTRY_DATA_BACKUP[256] = { 0 };

VOID NTAPI LdrpCallTlsInitializersDetours(IN ULONG_PTR Arg1, IN ULONG_PTR Arg2) {
    ULONG_PTR ImageBase = 0;
    ULONG     Reason    = 0;

    if (Arg1 == reinterpret_cast<ULONG_PTR>(NtCurrentPeb()->ImageBaseAddress)) {
        ImageBase = Arg1;
        Reason    = static_cast<ULONG>(Arg2);
    } else if (Arg2 == reinterpret_cast<ULONG_PTR>(NtCurrentPeb()->ImageBaseAddress)) {
        ImageBase = Arg2;
        Reason    = static_cast<ULONG>(Arg1);
    } else if (IsProbablyPointer(Arg1)) {
        if (IsProbablyPointer(reinterpret_cast<ULONG_PTR>(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(Arg1)->DllBase))) {
            ImageBase = reinterpret_cast<ULONG_PTR>(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(Arg1)->DllBase);
        } else {
            ImageBase = Arg1;
        }
        Reason = static_cast<ULONG>(Arg2);
    } else if (IsProbablyPointer(Arg2)) {
        if (IsProbablyPointer(reinterpret_cast<ULONG_PTR>(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(Arg2)->DllBase))) {
            ImageBase = reinterpret_cast<ULONG_PTR>(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(Arg2)->DllBase);
        } else {
            ImageBase = Arg2;
        }
        Reason = static_cast<ULONG>(Arg1);
    } else {
        __fastfail(FAST_FAIL_INVALID_ARG);
    }

    if ((Reason == DLL_PROCESS_ATTACH || Reason == DLL_THREAD_ATTACH) && ImageBase == reinterpret_cast<ULONG_PTR>(NtCurrentPeb()->ImageBaseAddress)) {
        BOOL  shouldFix  = FALSE;
        PVOID backupPage = nullptr;

        if (_G_ENTRY_POINT == 0) {
            _G_ENTRY_POINT = reinterpret_cast<PBYTE>(NtCurrentPeb()->ImageBaseAddress) + reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(NtCurrentPeb()->ImageBaseAddress) + reinterpret_cast<PIMAGE_DOS_HEADER>(NtCurrentPeb()->ImageBaseAddress)->e_lfanew)->OptionalHeader.AddressOfEntryPoint;
        }

        for (int i = 0; i < ENTRY_DATA_SIZE; i++) {
            if (_G_ENTRY_POINT[i] != ENTRY_DATA[i]) {
                shouldFix = TRUE;
            }
        }

        if (shouldFix) {
            SLock(&LDR_CUSTOM_LOCK);

            DWORD SavedProtect = 0;

            VirtualProtectDirect(_G_ENTRY_POINT, ENTRY_DATA_SIZE, PAGE_EXECUTE_READWRITE, &SavedProtect);
            RtlCopyMemory(ENTRY_DATA_BACKUP, _G_ENTRY_POINT, ENTRY_DATA_SIZE);
            RtlCopyMemory(_G_ENTRY_POINT, ENTRY_DATA, ENTRY_DATA_SIZE);
            VirtualProtectDirect(_G_ENTRY_POINT, ENTRY_DATA_SIZE, SavedProtect, &SavedProtect);

            LdrpCallTlsInitializersOriginal(Arg1, Arg2);

            VirtualProtectDirect(_G_ENTRY_POINT, ENTRY_DATA_SIZE, PAGE_EXECUTE_READWRITE, &SavedProtect);
            RtlCopyMemory(_G_ENTRY_POINT, ENTRY_DATA_BACKUP, ENTRY_DATA_SIZE);
            VirtualProtectDirect(_G_ENTRY_POINT, ENTRY_DATA_SIZE, SavedProtect, &SavedProtect);

            SUnlock(&LDR_CUSTOM_LOCK);
        }
    } else {
        LdrpCallTlsInitializersOriginal(Arg1, Arg2);
    }

    if (SBIE_BASE_ADDRESS == 0) {
        FindSbieDllFromPeb();
    }
}