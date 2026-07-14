#include <phnt_windows.h>
#include <phnt.h>
#include "MemoryImageHideInformation.h"

BOOLEAN EraseModuleNameFromPeb() {
    const PPEB peb = NtCurrentPeb();
    if (peb == nullptr || peb->Ldr == nullptr) {
        return FALSE;
    }

    // Called only from DLL_PROCESS_ATTACH initialization, where the native
    // loader lock is already held. Do not introduce a second PEB/loader lock.
    bool        removedAny = false;
    PLIST_ENTRY head       = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY current    = head->Flink;
    while (current != nullptr && current != head) {
        PLIST_ENTRY next  = current->Flink;
        const auto  entry = CONTAINING_RECORD(
            current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (IsAddressShouldHide(entry->DllBase)) {
            const auto unlink = [](PLIST_ENTRY link) {
                if (link->Blink != nullptr && link->Flink != nullptr) {
                    link->Blink->Flink = link->Flink;
                    link->Flink->Blink = link->Blink;
                }
            };
            unlink(&entry->HashLinks);
            unlink(&entry->InLoadOrderLinks);
            unlink(&entry->InMemoryOrderLinks);
            unlink(&entry->InInitializationOrderLinks);
            unlink(&entry->NodeModuleLink);
            if (entry->BaseDllName.Buffer != nullptr) {
                RtlZeroMemory(entry->BaseDllName.Buffer, entry->BaseDllName.MaximumLength);
            }
            if (entry->FullDllName.Buffer != nullptr) {
                RtlZeroMemory(entry->FullDllName.Buffer, entry->FullDllName.MaximumLength);
            }
            removedAny = true;
        }
        current = next;
    }

    return removedAny ? TRUE : FALSE;
}