#include <phnt_windows.h>
#include <phnt.h>

#include "detours.h"
#include "hidden_name.h"
#include "minhook.h"
#include "syscall_invoker.h"

LDRPCALLTLSINITIALIZERSTYPE LdrpCallTlsInitializersOriginal = nullptr;
LDRLOADDLLTYPE              LdrLoadDllOriginal              = nullptr;
LDRGETDLLHANDLEEXTYPE       LdrGetDllHandleExOriginal       = nullptr;
LDRGETDLLHANDLETYPE         LdrGetDllHandleOriginal         = nullptr;
GETMODULEHANDLEWTYPE        GetModuleHandleWOriginal        = nullptr;

static volatile LONG GET_MODULE_HANDLE_HOOK_STATE = 0;
static PBYTE         ENTRY_POINT                  = nullptr;

typedef NTSTATUS(NTAPI *NTFLUSHINSTRUCTIONCACHETYPE)(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ SIZE_T Length);

static __forceinline VOID RefreshSbieAddress() {
    if (SBIE_BASE_ADDRESS == nullptr) {
        FindSbieDllFromPeb();
    }
}

static VOID HideModulesFromPebLocked() {
    PPEB peb = NtCurrentPeb();
    if (peb == nullptr || peb->Ldr == nullptr) {
        return;
    }
    PLIST_ENTRY head    = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;
    while (current != nullptr && current != head) {
        PLIST_ENTRY next  = current->Flink;
        const auto  entry = CONTAINING_RECORD(
            current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer != nullptr &&
            IsHiddenName(entry->BaseDllName.Buffer, entry->BaseDllName.Length)) {
            const auto unlink = [](PLIST_ENTRY link) {
                if (link->Blink != nullptr && link->Flink != nullptr) {
                    link->Blink->Flink = link->Flink;
                    link->Flink->Blink = link->Blink;
                }
            };
            unlink(&entry->HashLinks);
            unlink(&entry->InMemoryOrderLinks);
            if (entry->BaseDllName.Buffer != nullptr) {
                RtlZeroMemory(entry->BaseDllName.Buffer, entry->BaseDllName.MaximumLength);
            }
            if (entry->FullDllName.Buffer != nullptr) {
                RtlZeroMemory(entry->FullDllName.Buffer, entry->FullDllName.MaximumLength);
            }
        }
        current = next;
    }
}

static bool EqualsKernelBase(const UNICODE_STRING &name) {
    static const WCHAR expected[] = L"kernelbase.dll";
    if (name.Buffer == nullptr || name.Length != sizeof(expected) - sizeof(WCHAR)) {
        return false;
    }
    for (SIZE_T index = 0; index < _countof(expected) - 1; ++index) {
        WCHAR value = name.Buffer[index];
        if (value >= L'A' && value <= L'Z') {
            value = static_cast<WCHAR>(value + (L'a' - L'A'));
        }
        if (value != expected[index]) {
            return false;
        }
    }
    return true;
}

static VOID InstallOptionalHooksForLoadedModulesLocked() {
    if (_InterlockedCompareExchange(&GET_MODULE_HANDLE_HOOK_STATE, 1, 0) != 0) {
        return;
    }
    PPEB peb = NtCurrentPeb();
    if (peb == nullptr || peb->Ldr == nullptr) {
        _InterlockedExchange(&GET_MODULE_HANDLE_HOOK_STATE, 0);
        return;
    }
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY current = head->Flink;
         current != nullptr && current != head;
         current = current->Flink) {
        const auto entry = CONTAINING_RECORD(
            current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!EqualsKernelBase(entry->BaseDllName)) {
            continue;
        }
        PVOID target = GetExportedFunctionAddress(
            static_cast<HMODULE>(entry->DllBase),
            entry->SizeOfImage,
            GetModuleHandleWHash);
        if (target == nullptr ||
            MH_CreateHook(
                target,
                &GetModuleHandleWDetours,
                reinterpret_cast<void **>(&GetModuleHandleWOriginal)) != MH_OK ||
            GetModuleHandleWOriginal == nullptr ||
            MH_EnableHook(target) != MH_OK) {
            _InterlockedExchange(&GET_MODULE_HANDLE_HOOK_STATE, 0);
            return;
        }
        _InterlockedExchange(&GET_MODULE_HANDLE_HOOK_STATE, 2);
        return;
    }
    // KernelBase may be absent during the earliest bootstrap. Non-ntdll hooks
    // are never live-patched later; ntdll hooks remain the guaranteed path.
    _InterlockedExchange(&GET_MODULE_HANDLE_HOOK_STATE, 0);
}

VOID HideLoadedModules() {
    const auto lockLoader = reinterpret_cast<LDRLOCKLOADERLOCKTYPE>(
        GetExportedFunctionAddress(
            reinterpret_cast<HMODULE>(NTDLL_BASE_ADDRESS), NTDLL_SIZE, LdrLockLoaderLockHash));
    const auto unlockLoader = reinterpret_cast<LDRUNLOCKLOADERLOCKTYPE>(
        GetExportedFunctionAddress(
            reinterpret_cast<HMODULE>(NTDLL_BASE_ADDRESS), NTDLL_SIZE, LdrUnlockLoaderLockHash));
    if (lockLoader == nullptr || unlockLoader == nullptr) {
        return;
    }
    PVOID cookie = nullptr;
    if (!NT_SUCCESS(lockLoader(0, nullptr, &cookie))) {
        return;
    }
    InstallOptionalHooksForLoadedModulesLocked();
    RefreshSbieAddress();
    HideModulesFromPebLocked();
    if (!NT_SUCCESS(unlockLoader(0, cookie))) {
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }
}

HMODULE WINAPI GetModuleHandleWDetours(_In_opt_ LPCWSTR moduleName) {
    if (moduleName != nullptr) {
        SIZE_T length = 0;
        while (length < 32768 && moduleName[length] != L'\0') {
            ++length;
        }
        if (length < 32768 &&
            IsHiddenName(moduleName, length * sizeof(WCHAR))) {
            NtCurrentTeb()->LastErrorValue = ERROR_MOD_NOT_FOUND;
            return nullptr;
        }
    }
    return GetModuleHandleWOriginal(moduleName);
}

NTSTATUS NTAPI LdrGetDllHandleDetours(
    _In_opt_ PCWSTR       DllPath,
    _In_opt_ PULONG       DllCharacteristics,
    _In_ PCUNICODE_STRING DllName,
    _Out_ PVOID          *DllHandle) {
    _InterlockedIncrement(&LDR_GET_DLL_HANDLE_HIT_COUNT);
    if (DllName != nullptr && DllName->Buffer != nullptr &&
        IsHiddenName(DllName->Buffer, DllName->Length)) {
        _InterlockedIncrement(&LDR_GET_DLL_HANDLE_HIDE_COUNT);
        if (DllHandle != nullptr) {
            *DllHandle = nullptr;
        }
        return STATUS_DLL_NOT_FOUND;
    }
    return LdrGetDllHandleOriginal(
        DllPath, DllCharacteristics, DllName, DllHandle);
}

NTSTATUS NTAPI LdrGetDllHandleExDetours(
    _In_ ULONG            Flags,
    _In_opt_ PCWSTR       DllPath,
    _In_opt_ PULONG       DllCharacteristics,
    _In_ PCUNICODE_STRING DllName,
    _Out_ PVOID          *DllHandle) {
    _InterlockedIncrement(&LDR_GET_DLL_HANDLE_HIT_COUNT);
    if (DllName != nullptr && DllName->Buffer != nullptr &&
        IsHiddenName(DllName->Buffer, DllName->Length)) {
        _InterlockedIncrement(&LDR_GET_DLL_HANDLE_HIDE_COUNT);
        if (DllHandle != nullptr) {
            *DllHandle = nullptr;
        }
        return STATUS_DLL_NOT_FOUND;
    }
    return LdrGetDllHandleExOriginal(
        Flags, DllPath, DllCharacteristics, DllName, DllHandle);
}

NTSTATUS NTAPI LdrLoadDllDetours(_In_opt_ PWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID *DllHandle) {
    const NTSTATUS status = LdrLoadDllOriginal(DllPath, DllCharacteristics, DllName, DllHandle);

    const auto lockLoader = reinterpret_cast<LDRLOCKLOADERLOCKTYPE>(
        GetExportedFunctionAddress(
            reinterpret_cast<HMODULE>(NTDLL_BASE_ADDRESS), NTDLL_SIZE, LdrLockLoaderLockHash));
    const auto unlockLoader = reinterpret_cast<LDRUNLOCKLOADERLOCKTYPE>(
        GetExportedFunctionAddress(
            reinterpret_cast<HMODULE>(NTDLL_BASE_ADDRESS), NTDLL_SIZE, LdrUnlockLoaderLockHash));
    PPEB peb = NtCurrentPeb();
    if (lockLoader == nullptr || unlockLoader == nullptr || peb == nullptr || peb->Ldr == nullptr) {
        return status;
    }

    PVOID cookie = nullptr;
    if (!NT_SUCCESS(lockLoader(0, nullptr, &cookie))) {
        return status;
    }

    RefreshSbieAddress();

    HideModulesFromPebLocked();

    if (!NT_SUCCESS(unlockLoader(0, cookie))) {
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }
    return status;
}

static PBYTE GetValidatedEntryPoint() {
    if (ENTRY_DATA_SIZE == 0 || ENTRY_DATA_SIZE > sizeof(ENTRY_DATA)) {
        return nullptr;
    }

    PBYTE imageBase = reinterpret_cast<PBYTE>(NtCurrentPeb()->ImageBaseAddress);
    if (imageBase == nullptr) {
        return nullptr;
    }

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
        static_cast<ULONG>(dosHeader->e_lfanew) > 0x100000) {
        return nullptr;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return nullptr;
    }

    const ULONG imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    const ULONG entryRva  = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    if (entryRva == 0 || entryRva >= imageSize || ENTRY_DATA_SIZE > imageSize - entryRva) {
        return nullptr;
    }
    return imageBase + entryRva;
}

static ULONG GetTlsReason(ULONG_PTR arg1, ULONG_PTR arg2) {
    if (arg1 <= DLL_THREAD_DETACH) {
        return static_cast<ULONG>(arg1);
    }
    if (arg2 <= DLL_THREAD_DETACH) {
        return static_cast<ULONG>(arg2);
    }
    return MAXULONG;
}

VOID NTAPI LdrpCallTlsInitializersDetours(IN ULONG_PTR Arg1, IN ULONG_PTR Arg2) {
    if (LdrpCallTlsInitializersOriginal == nullptr) {
        __fastfail(FAST_FAIL_INVALID_ARG);
    }

    const ULONG reason = GetTlsReason(Arg1, Arg2);
    if (reason != DLL_PROCESS_ATTACH && reason != DLL_THREAD_ATTACH) {
        LdrpCallTlsInitializersOriginal(Arg1, Arg2);
        RefreshSbieAddress();
        return;
    }
    RefreshSbieAddress();
    HideModulesFromPebLocked();
    if (ENTRY_POINT == nullptr) {
        ENTRY_POINT = GetValidatedEntryPoint();
    }
    const auto flushInstructionCache =
        reinterpret_cast<NTFLUSHINSTRUCTIONCACHETYPE>(GetExportedFunctionAddress(
            reinterpret_cast<HMODULE>(NTDLL_BASE_ADDRESS),
            NTDLL_SIZE,
            NtFlushInstructionCacheHash));
    if (ENTRY_POINT == nullptr || flushInstructionCache == nullptr) {
        LdrpCallTlsInitializersOriginal(Arg1, Arg2);
        RefreshSbieAddress();
        return;
    }

    bool entryAlreadyMatches = true;
    for (SIZE_T index = 0; index < ENTRY_DATA_SIZE; ++index) {
        if (ENTRY_POINT[index] != ENTRY_DATA[index]) {
            entryAlreadyMatches = false;
            break;
        }
    }
    if (entryAlreadyMatches) {
        LdrpCallTlsInitializersOriginal(Arg1, Arg2);
        RefreshSbieAddress();
        return;
    }

    BYTE  entryBackup[sizeof(ENTRY_DATA)] = {};
    DWORD savedProtect                    = 0;
    if (!VirtualProtectDirect(
            ENTRY_POINT, ENTRY_DATA_SIZE, PAGE_EXECUTE_READWRITE, &savedProtect)) {
        LdrpCallTlsInitializersOriginal(Arg1, Arg2);
        RefreshSbieAddress();
        return;
    }
    RtlCopyMemory(entryBackup, ENTRY_POINT, ENTRY_DATA_SIZE);
    RtlCopyMemory(ENTRY_POINT, ENTRY_DATA, ENTRY_DATA_SIZE);
    const NTSTATUS initialFlushStatus = flushInstructionCache(
        NtCurrentProcess(), ENTRY_POINT, ENTRY_DATA_SIZE);
    DWORD      ignoredProtect         = 0;
    const BOOL initialProtectRestored = VirtualProtectDirect(
        ENTRY_POINT, ENTRY_DATA_SIZE, savedProtect, &ignoredProtect);
    if (!NT_SUCCESS(initialFlushStatus) || !initialProtectRestored) {
        const BOOL rollbackWritable = !initialProtectRestored ||
                                      VirtualProtectDirect(
                                          ENTRY_POINT,
                                          ENTRY_DATA_SIZE,
                                          PAGE_EXECUTE_READWRITE,
                                          &ignoredProtect);
        if (!rollbackWritable) {
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
        RtlCopyMemory(ENTRY_POINT, entryBackup, ENTRY_DATA_SIZE);
        const NTSTATUS rollbackFlushStatus = flushInstructionCache(
            NtCurrentProcess(), ENTRY_POINT, ENTRY_DATA_SIZE);
        const BOOL rollbackProtectRestored = VirtualProtectDirect(
            ENTRY_POINT, ENTRY_DATA_SIZE, savedProtect, &ignoredProtect);
        if (!NT_SUCCESS(rollbackFlushStatus) || !rollbackProtectRestored) {
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
        LdrpCallTlsInitializersOriginal(Arg1, Arg2);
        RefreshSbieAddress();
        return;
    }

    LdrpCallTlsInitializersOriginal(Arg1, Arg2);

    DWORD callbackProtect = 0;
    if (!VirtualProtectDirect(
            ENTRY_POINT, ENTRY_DATA_SIZE, PAGE_EXECUTE_READWRITE, &callbackProtect)) {
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }
    RtlCopyMemory(ENTRY_POINT, entryBackup, ENTRY_DATA_SIZE);
    const NTSTATUS restoreFlushStatus = flushInstructionCache(
        NtCurrentProcess(), ENTRY_POINT, ENTRY_DATA_SIZE);
    const BOOL restoreProtectSucceeded = VirtualProtectDirect(
        ENTRY_POINT, ENTRY_DATA_SIZE, savedProtect, &ignoredProtect);
    RefreshSbieAddress();
    if (!NT_SUCCESS(restoreFlushStatus) || !restoreProtectSucceeded) {
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }
}
