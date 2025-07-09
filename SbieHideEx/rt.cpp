#include <phnt_windows.h>
#include <phnt.h>
#include "buffer.h"
#include "syscall_invoker.h"

HANDLE WINAPI HeapCreateDirect(_In_ DWORD flOptions, _In_ SIZE_T dwInitialSize, _In_ SIZE_T dwMaximumSize) {
    return (HANDLE)0x1;
}

BOOL WINAPI VirtualProtectDirect(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect) {
    return NT_SUCCESS(invoke_systemcall<NTSTATUS>(NtProtectVirtualMemorySystemCallIndex, NtCurrentProcess(), &lpAddress, &dwSize, flNewProtect, lpflOldProtect));
}

LPVOID WINAPI HeapAllocDirect(_In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ SIZE_T dwBytes) {
    LPVOID Addr = 0;
    invoke_systemcall<NTSTATUS>(NtAllocateVirtualMemorySystemCallIndex, NtCurrentProcess(), &Addr, 0, &dwBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return Addr;
}

VOID FindSbieDllFromPeb() {
    PPEB                  ProcessEnvironmentBlock = nullptr;
    PLIST_ENTRY           FirstEntry              = nullptr;
    PLIST_ENTRY           CurrentEntry            = nullptr;
    PLDR_DATA_TABLE_ENTRY CurrentEntryData        = nullptr;

    ProcessEnvironmentBlock = NtCurrentPeb();

    FirstEntry = CurrentEntry = ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink;

    while (CurrentEntry->Flink != FirstEntry) {
        CurrentEntryData = CONTAINING_RECORD(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(CurrentEntry), LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (CurrentEntryData->BaseDllName.Length < 7)
            continue;

        for (USHORT i = 0; i <= CurrentEntryData->BaseDllName.Length - 7; ++i) {
            if ((CurrentEntryData->BaseDllName.Buffer[i + 0] == L's' || CurrentEntryData->BaseDllName.Buffer[i + 0] == L'S') && (CurrentEntryData->BaseDllName.Buffer[i + 1] == L'b' || CurrentEntryData->BaseDllName.Buffer[i + 1] == L'B') && (CurrentEntryData->BaseDllName.Buffer[i + 2] == L'i' || CurrentEntryData->BaseDllName.Buffer[i + 2] == L'I') && (CurrentEntryData->BaseDllName.Buffer[i + 3] == L'e' || CurrentEntryData->BaseDllName.Buffer[i + 3] == L'E') && (CurrentEntryData->BaseDllName.Buffer[i + 4] == L'd' || CurrentEntryData->BaseDllName.Buffer[i + 4] == L'D') && (CurrentEntryData->BaseDllName.Buffer[i + 5] == L'l' || CurrentEntryData->BaseDllName.Buffer[i + 5] == L'L') && (CurrentEntryData->BaseDllName.Buffer[i + 6] == L'l' || CurrentEntryData->BaseDllName.Buffer[i + 6] == L'L')) {
                SBIE_BASE_ADDRESS = CurrentEntryData->DllBase;
                SBIE_SIZE         = CurrentEntryData->SizeOfImage;
                return;
            }
        }

        CurrentEntry = CurrentEntry->Flink;
    }
}