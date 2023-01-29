#include "MemoryImageHideInformation.h"
#include <list>
#include <string>

std::list<MemoryImageHideInformation> MemoryImageHideInformationList;
std::string                           CurrentModuleName;

BOOLEAN InitMemoryImageHideInformation() {
    PPEB                  ProcessEnvironmentBlock = nullptr;
    PLDR_DATA_TABLE_ENTRY FirstEntry              = nullptr;
    PLDR_DATA_TABLE_ENTRY CurrentEntry            = nullptr;
    BOOLEAN               IsSandboxieModuleFound  = FALSE;
    BOOLEAN               IsCurrentModuleFound    = FALSE;

    ProcessEnvironmentBlock = NtCurrentPeb();
    FirstEntry = CurrentEntry = CONTAINING_RECORD(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink), LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    while (reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(CONTAINING_RECORD(CurrentEntry->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)) != FirstEntry) {

        if (_wcsnicmp(CurrentEntry->BaseDllName.Buffer, L"sbiedll.dll", CurrentEntry->BaseDllName.Length) == 0 || _wcsnicmp(CurrentEntry->BaseDllName.Buffer, L"sbiedll", CurrentEntry->BaseDllName.Length) == 0) {
            MemoryImageHideInformationList.push_back(MemoryImageHideInformation(reinterpret_cast<ULONG_PTR>(CurrentEntry->DllBase), reinterpret_cast<ULONG_PTR>(CurrentEntry->DllBase) + CurrentEntry->SizeOfImage));
            IsSandboxieModuleFound = TRUE;
        }

        if ((reinterpret_cast<ULONG_PTR>(CurrentEntry->DllBase) < reinterpret_cast<ULONG_PTR>(InitMemoryImageHideInformation)) && ((reinterpret_cast<ULONG_PTR>(CurrentEntry->DllBase) + CurrentEntry->SizeOfImage) > reinterpret_cast<ULONG_PTR>(InitMemoryImageHideInformation))) {
            MemoryImageHideInformationList.push_back(MemoryImageHideInformation(reinterpret_cast<ULONG_PTR>(CurrentEntry->DllBase), reinterpret_cast<ULONG_PTR>(CurrentEntry->DllBase) + CurrentEntry->SizeOfImage));
            IsCurrentModuleFound = TRUE;
        }

        CurrentEntry = CONTAINING_RECORD(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(CurrentEntry->InMemoryOrderLinks.Flink), LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    }

    return (IsSandboxieModuleFound == TRUE) && (IsCurrentModuleFound == TRUE);
}

BOOLEAN IsAddressShouldHide(ULONG_PTR Address) {
    for (auto &Information : MemoryImageHideInformationList) {
        if (Information.ImageStartAddress <= Address && Information.ImageEndAddress >= Address) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN IsAddressShouldHide(PVOID Address) {
    return IsAddressShouldHide(reinterpret_cast<ULONG_PTR>(Address));
}
