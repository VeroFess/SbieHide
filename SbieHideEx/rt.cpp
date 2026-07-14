#include <phnt_windows.h>
#include <phnt.h>
#include "buffer.h"
#include "syscall_invoker.h"

HANDLE WINAPI HeapCreateDirect(_In_ DWORD flOptions, _In_ SIZE_T dwInitialSize, _In_ SIZE_T dwMaximumSize) {
    UNREFERENCED_PARAMETER(flOptions);
    UNREFERENCED_PARAMETER(dwInitialSize);
    UNREFERENCED_PARAMETER(dwMaximumSize);
    return reinterpret_cast<HANDLE>(1);
}

BOOL WINAPI VirtualProtectDirect(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect) {
    return NT_SUCCESS(invoke_systemcall<NTSTATUS>(NtProtectVirtualMemorySystemCallIndex, NtCurrentProcess(), &lpAddress, &dwSize, flNewProtect, lpflOldProtect));
}

LPVOID WINAPI HeapAllocDirect(_In_ HANDLE heap, _In_ DWORD flags, _In_ SIZE_T bytes) {
    UNREFERENCED_PARAMETER(heap);
    UNREFERENCED_PARAMETER(flags);

    LPVOID         address = nullptr;
    const NTSTATUS status  = invoke_systemcall<NTSTATUS>(
        NtAllocateVirtualMemorySystemCallIndex,
        NtCurrentProcess(),
        &address,
        0,
        &bytes,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    return NT_SUCCESS(status) ? address : nullptr;
}

VOID FindSbieDllFromPeb() {
    PPEB processEnvironmentBlock = NtCurrentPeb();
    if (processEnvironmentBlock == nullptr || processEnvironmentBlock->Ldr == nullptr) {
        return;
    }

    PLIST_ENTRY head         = &processEnvironmentBlock->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY currentEntry = head->Flink;
    while (currentEntry != nullptr && currentEntry != head) {
        PLDR_DATA_TABLE_ENTRY entry          = CONTAINING_RECORD(currentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        const USHORT          characterCount = entry->BaseDllName.Length / sizeof(WCHAR);
        if (entry->BaseDllName.Buffer != nullptr &&
            (entry->BaseDllName.Length % sizeof(WCHAR)) == 0 && characterCount >= 7) {
            for (USHORT i = 0; i + 7 <= characterCount; ++i) {
                const WCHAR *name = entry->BaseDllName.Buffer + i;
                if ((name[0] == L's' || name[0] == L'S') &&
                    (name[1] == L'b' || name[1] == L'B') &&
                    (name[2] == L'i' || name[2] == L'I') &&
                    (name[3] == L'e' || name[3] == L'E') &&
                    (name[4] == L'd' || name[4] == L'D') &&
                    (name[5] == L'l' || name[5] == L'L') &&
                    (name[6] == L'l' || name[6] == L'L')) {
                    SBIE_SIZE = entry->SizeOfImage;
                    _ReadWriteBarrier();
                    SBIE_BASE_ADDRESS = entry->DllBase;
                    return;
                }
            }
        }
        currentEntry = currentEntry->Flink;
    }
}