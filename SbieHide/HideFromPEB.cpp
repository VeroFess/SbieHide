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
            NextEntry                                = CurrentEntry->Flink;
            CurrentEntryData->HashLinks.Blink->Flink = CurrentEntryData->HashLinks.Flink;
            CurrentEntryData->HashLinks.Flink->Blink = CurrentEntryData->HashLinks.Blink;
            CurrentEntry->Blink->Flink               = CurrentEntry->Flink;
            CurrentEntry->Flink->Blink               = CurrentEntry->Blink;

            RtlZeroMemory(CurrentEntryData->BaseDllName.Buffer, CurrentEntryData->BaseDllName.MaximumLength);
            RtlZeroMemory(CurrentEntryData->FullDllName.Buffer, CurrentEntryData->FullDllName.MaximumLength);
            RtlZeroMemory(CurrentEntryData, sizeof(PLDR_DATA_TABLE_ENTRY));

            CurrentEntry = NextEntry;
            continue;
        }

        CurrentEntry = CurrentEntry->Flink;
    }

    FirstEntry = CurrentEntry = ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink;

    while (CurrentEntry->Flink != FirstEntry) {
        CurrentEntryData = CONTAINING_RECORD(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(CurrentEntry), LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (IsAddressShouldHide(CurrentEntryData->DllBase)) {
            NextEntry                  = CurrentEntry->Flink;
            CurrentEntry->Blink->Flink = CurrentEntry->Flink;
            CurrentEntry->Flink->Blink = CurrentEntry->Blink;

            RtlZeroMemory(CurrentEntryData->BaseDllName.Buffer, CurrentEntryData->BaseDllName.MaximumLength);
            RtlZeroMemory(CurrentEntryData->FullDllName.Buffer, CurrentEntryData->FullDllName.MaximumLength);
            RtlZeroMemory(CurrentEntryData, sizeof(PLDR_DATA_TABLE_ENTRY));

            CurrentEntry = NextEntry;
            continue;
        }

        CurrentEntry = CurrentEntry->Flink;
    }

    FirstEntry = CurrentEntry = ProcessEnvironmentBlock->Ldr->InInitializationOrderModuleList.Flink;

    while (CurrentEntry->Flink != FirstEntry) {
        CurrentEntryData = CONTAINING_RECORD(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(CurrentEntry), LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);

        if (IsAddressShouldHide(CurrentEntryData->DllBase)) {
            NextEntry                  = CurrentEntry->Flink;
            CurrentEntry->Blink->Flink = CurrentEntry->Flink;
            CurrentEntry->Flink->Blink = CurrentEntry->Blink;

            RtlZeroMemory(CurrentEntryData->BaseDllName.Buffer, CurrentEntryData->BaseDllName.MaximumLength);
            RtlZeroMemory(CurrentEntryData->FullDllName.Buffer, CurrentEntryData->FullDllName.MaximumLength);
            RtlZeroMemory(CurrentEntryData, sizeof(PLDR_DATA_TABLE_ENTRY));

            CurrentEntry = NextEntry;
            continue;
        }

        CurrentEntry = CurrentEntry->Flink;
    }

    RtlReleasePebLock();
}