#include "HideFromPEB.h"
#include "MemoryImageHideInformation.h"

VOID EraseModuleNameFromPeb() {
    PPEB                  ProcessEnvironmentBlock = nullptr;
    PLIST_ENTRY           FirstEntry              = nullptr;
    PLIST_ENTRY           CurrentEntry            = nullptr;
    PLIST_ENTRY           NextEntry               = nullptr;
    PLDR_DATA_TABLE_ENTRY CurrentEntryData        = nullptr;

    RtlAcquirePebLock();

    ProcessEnvironmentBlock = NtCurrentPeb();

    FirstEntry = CurrentEntry = ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList.Flink;

    while (CurrentEntry->Flink != FirstEntry) {
        CurrentEntryData = CONTAINING_RECORD(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(CurrentEntry), LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (IsAddressShouldHide(CurrentEntryData->DllBase)) {
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
            continue;
        }

        CurrentEntry = CurrentEntry->Flink;
    }

    RtlReleasePebLock();
}