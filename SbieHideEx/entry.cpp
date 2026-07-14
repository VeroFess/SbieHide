#include <phnt_windows.h>
#include <phnt.h>

#include "address_finder.h"
#include "simple_runtime_library.h"
#include "syscall_invoker.h"
#include "minhook.h"
#include "detours.h"
#include "query_detours.h"

extern "C" volatile LONG  MODULE_INITIALIZATION_STATE         = 0;
extern "C" volatile LONG  MODULE_INITIALIZATION_FAILURE_STAGE = 0;
extern "C" volatile LONG  LDR_GET_DLL_HANDLE_HIT_COUNT        = 0;
extern "C" volatile LONG  LDR_GET_DLL_HANDLE_HIDE_COUNT       = 0;
extern "C" volatile LONG *MODULE_INITIALIZATION_SIGNAL        = nullptr;
extern "C" PVOID          LDR_LOAD_DLL_BOOTSTRAP_TARGET       = nullptr;
extern "C" BYTE           LDR_LOAD_DLL_BOOTSTRAP_ORIGINAL[14] = {};
extern "C" PVOID          LDR_LOAD_DLL_BOOTSTRAP_CHAIN        = nullptr;
extern "C" volatile LONG  LDR_LOAD_DLL_BOOTSTRAP_STATE        = 0;

static VOID PublishInitializationState(LONG state) {
    _InterlockedExchange(&MODULE_INITIALIZATION_STATE, state);
    volatile LONG *signal = MODULE_INITIALIZATION_SIGNAL;
    if (signal != nullptr) {
        _InterlockedExchange(signal + 1, MODULE_INITIALIZATION_FAILURE_STAGE);
        _InterlockedExchange(signal, state);
    }
}

static VOID FailInitialization(
    PVOID tlsTarget,
    PVOID loadDllTarget,
    BOOL  tlsCreated,
    BOOL  loadDllCreated,
    BOOL  tlsEnabled,
    BOOL  loadDllEnabled,
    BOOL  initializedByThisModule) {
    BOOL loadDllDisabled = !loadDllEnabled;
    BOOL tlsDisabled     = !tlsEnabled;
    if (loadDllEnabled) {
        const MH_STATUS status = MH_DisableHook(loadDllTarget);
        loadDllDisabled        = status == MH_OK || status == MH_ERROR_DISABLED;
    }
    if (tlsEnabled) {
        const MH_STATUS status = MH_DisableHook(tlsTarget);
        tlsDisabled            = status == MH_OK || status == MH_ERROR_DISABLED;
    }

    BOOL loadDllRemoved = !loadDllCreated;
    BOOL tlsRemoved     = !tlsCreated;
    if (loadDllCreated && loadDllDisabled) {
        const MH_STATUS status = MH_RemoveHook(loadDllTarget);
        loadDllRemoved         = status == MH_OK || status == MH_ERROR_NOT_CREATED;
        if (loadDllRemoved) {
            LdrLoadDllOriginal = nullptr;
        }
    }
    if (tlsCreated && tlsDisabled) {
        const MH_STATUS status = MH_RemoveHook(tlsTarget);
        tlsRemoved             = status == MH_OK || status == MH_ERROR_NOT_CREATED;
        if (tlsRemoved) {
            LdrpCallTlsInitializersOriginal = nullptr;
        }
    }
    if (initializedByThisModule && loadDllRemoved && tlsRemoved) {
        MH_Uninitialize();
    }

    PROCESS_INITIALIZATION_FINISHED = FALSE;
    PublishInitializationState(3);
}

static VOID AbandonPublishedInitialization(
    PVOID tlsTarget,
    PVOID loadDllTarget,
    PVOID getDllHandleTarget,
    PVOID getDllTarget) {
    // Disable new entries, but keep trampolines and Original pointers alive
    // for callbacks already in flight.
    if (getDllTarget != nullptr) {
        MH_DisableHook(getDllTarget);
    }
    if (getDllHandleTarget != nullptr) {
        MH_DisableHook(getDllHandleTarget);
    }
    MH_DisableHook(loadDllTarget);
    MH_DisableHook(tlsTarget);
    PROCESS_INITIALIZATION_FINISHED = FALSE;
    PublishInitializationState(3);
}

struct QueryHookRegistration {
        ULONG64 hash;
        PVOID   detour;
        PVOID   target;
        BOOL    created;
        BOOL    enabled;
};

static VOID RollBackQueryHooks(
    QueryHookRegistration *hooks,
    SIZE_T                 hookCount) {
    for (SIZE_T index = hookCount; index > 0; --index) {
        QueryHookRegistration &hook = hooks[index - 1];
        if (hook.enabled) {
            MH_DisableHook(hook.target);
            hook.enabled = FALSE;
        }
        if (hook.created) {
            MH_RemoveHook(hook.target);
            hook.created = FALSE;
        }
    }
}

static BOOL InstallQueryHooks() {
    QueryHookRegistration hooks[] = {
        { Crc64(0, "NtQueryVirtualMemory"), reinterpret_cast<PVOID>(&NtQueryVirtualMemoryDetours) },
        { Crc64(0, "NtQueryObject"), reinterpret_cast<PVOID>(&NtQueryObjectDetours) },
        { Crc64(0, "NtQueryInformationFile"), reinterpret_cast<PVOID>(&NtQueryInformationFileDetours) },
        { Crc64(0, "NtQuerySection"), reinterpret_cast<PVOID>(&NtQuerySectionDetours) },
        { Crc64(0, "NtQuerySystemInformation"), reinterpret_cast<PVOID>(&NtQuerySystemInformationDetours) },
        { Crc64(0, "NtQueryInformationProcess"), reinterpret_cast<PVOID>(&NtQueryInformationProcessDetours) }
    };
    for (SIZE_T index = 0; index < _countof(hooks); ++index) {
        hooks[index].target = GetExportedFunctionAddress(
            reinterpret_cast<HMODULE>(NTDLL_BASE_ADDRESS),
            NTDLL_SIZE,
            hooks[index].hash);
        if (hooks[index].target == nullptr) {
            RollBackQueryHooks(hooks, _countof(hooks));
            return FALSE;
        }
        const BYTE *targetBytes  = static_cast<const BYTE *>(hooks[index].target);
        ULONG_PTR   directTarget = 0;
        if (targetBytes[0] == 0xff && targetBytes[1] == 0x25 &&
            targetBytes[2] == 0 && targetBytes[3] == 0 &&
            targetBytes[4] == 0 && targetBytes[5] == 0) {
            RtlCopyMemory(&directTarget, targetBytes + 6, sizeof(directTarget));
        }
        if (directTarget == reinterpret_cast<ULONG_PTR>(hooks[index].detour)) {
            hooks[index].target = nullptr;
            continue;
        }
        if (MH_CreateHook(hooks[index].target, hooks[index].detour, nullptr) != MH_OK) {
            RollBackQueryHooks(hooks, _countof(hooks));
            return FALSE;
        }
        hooks[index].created = TRUE;
    }
    for (SIZE_T index = 0; index < _countof(hooks); ++index) {
        if (hooks[index].target == nullptr) {
            continue;
        }
        if (MH_EnableHook(hooks[index].target) != MH_OK) {
            RollBackQueryHooks(hooks, _countof(hooks));
            return FALSE;
        }
        hooks[index].enabled = TRUE;
    }
    return TRUE;
}

extern "C" VOID ModulePreProcessInitRoutine() {
    for (;;) {
        const long previousState = _InterlockedCompareExchange(&MODULE_INITIALIZATION_STATE, 1, 0);
        if (previousState == 0) {
            break;
        }
        if (previousState == 2 || previousState == 3) {
            return;
        }
        while (_InterlockedCompareExchange(
                   &MODULE_INITIALIZATION_STATE, 1, 1) == 1) {
            _mm_pause();
        }
    }

    PVOID tlsTarget               = nullptr;
    PVOID loadDllTarget           = nullptr;
    PVOID getDllHandleTarget      = nullptr;
    PVOID getDllTarget            = nullptr;
    BOOL  tlsCreated              = FALSE;
    BOOL  loadDllCreated          = FALSE;
    BOOL  tlsEnabled              = FALSE;
    BOOL  loadDllEnabled          = FALSE;
    BOOL  initializedByThisModule = FALSE;

    PVOID ldrShutdownThread = GetExportedFunctionAddress(
        reinterpret_cast<HMODULE>(NTDLL_BASE_ADDRESS), NTDLL_SIZE, LdrShutdownThreadHash);
    if (ldrShutdownThread == nullptr) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 1);
        FailInitialization(tlsTarget, loadDllTarget, tlsCreated, loadDllCreated, tlsEnabled, loadDllEnabled, initializedByThisModule);
        return;
    }
    tlsTarget = FindLdrpCallTlsInitializers(
        ldrShutdownThread, NTDLL_BASE_ADDRESS, NTDLL_SIZE);
    if (tlsTarget == nullptr) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 2);
        FailInitialization(tlsTarget, loadDllTarget, tlsCreated, loadDllCreated, tlsEnabled, loadDllEnabled, initializedByThisModule);
        return;
    }
    loadDllTarget = GetExportedFunctionAddress(
        reinterpret_cast<HMODULE>(NTDLL_BASE_ADDRESS), NTDLL_SIZE, LdrLoadDllHash);
    if (loadDllTarget == nullptr) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 3);
        FailInitialization(tlsTarget, loadDllTarget, tlsCreated, loadDllCreated, tlsEnabled, loadDllEnabled, initializedByThisModule);
        return;
    }
    getDllHandleTarget = GetExportedFunctionAddress(
        reinterpret_cast<HMODULE>(NTDLL_BASE_ADDRESS), NTDLL_SIZE, LdrGetDllHandleExHash);
    if (getDllHandleTarget == nullptr) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 3);
        FailInitialization(tlsTarget, loadDllTarget, tlsCreated, loadDllCreated, tlsEnabled, loadDllEnabled, initializedByThisModule);
        return;
    }
    getDllTarget = GetExportedFunctionAddress(
        reinterpret_cast<HMODULE>(NTDLL_BASE_ADDRESS), NTDLL_SIZE, LdrGetDllHandleHash);
    if (getDllTarget == nullptr) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 3);
        FailInitialization(tlsTarget, loadDllTarget, tlsCreated, loadDllCreated, tlsEnabled, loadDllEnabled, initializedByThisModule);
        return;
    }

    MH_STATUS status = MH_Initialize();
    if (status == MH_OK) {
        initializedByThisModule = TRUE;
    } else if (status != MH_ERROR_ALREADY_INITIALIZED) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 4);
        FailInitialization(tlsTarget, loadDllTarget, tlsCreated, loadDllCreated, tlsEnabled, loadDllEnabled, initializedByThisModule);
        return;
    }

    status = MH_CreateHook(tlsTarget, &LdrpCallTlsInitializersDetours, reinterpret_cast<void **>(&LdrpCallTlsInitializersOriginal));
    if (status != MH_OK || LdrpCallTlsInitializersOriginal == nullptr) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 5);
        FailInitialization(tlsTarget, loadDllTarget, tlsCreated, loadDllCreated, tlsEnabled, loadDllEnabled, initializedByThisModule);
        return;
    }
    tlsCreated = TRUE;

    status = MH_CreateHook(loadDllTarget, &LdrLoadDllDetours, reinterpret_cast<void **>(&LdrLoadDllOriginal));
    if (status != MH_OK || LdrLoadDllOriginal == nullptr) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 6);
        FailInitialization(tlsTarget, loadDllTarget, tlsCreated, loadDllCreated, tlsEnabled, loadDllEnabled, initializedByThisModule);
        return;
    }
    loadDllCreated = TRUE;

    status = MH_CreateHook(
        getDllHandleTarget,
        &LdrGetDllHandleExDetours,
        reinterpret_cast<void **>(&LdrGetDllHandleExOriginal));
    if (status != MH_OK || LdrGetDllHandleExOriginal == nullptr) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 9);
        AbandonPublishedInitialization(tlsTarget, loadDllTarget, getDllHandleTarget, getDllTarget);
        return;
    }

    status = MH_CreateHook(
        getDllTarget,
        &LdrGetDllHandleDetours,
        reinterpret_cast<void **>(&LdrGetDllHandleOriginal));
    if (status != MH_OK || LdrGetDllHandleOriginal == nullptr) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 11);
        AbandonPublishedInitialization(tlsTarget, loadDllTarget, getDllHandleTarget, getDllTarget);
        return;
    }

    status = MH_EnableHook(tlsTarget);
    if (status != MH_OK) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 7);
        AbandonPublishedInitialization(tlsTarget, loadDllTarget, getDllHandleTarget, getDllTarget);
        return;
    }
    tlsEnabled = TRUE;
    status     = MH_EnableHook(loadDllTarget);
    if (status != MH_OK) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 8);
        AbandonPublishedInitialization(tlsTarget, loadDllTarget, getDllHandleTarget, getDllTarget);
        return;
    }
    loadDllEnabled = TRUE;
    status         = MH_EnableHook(getDllHandleTarget);
    if (status != MH_OK) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 10);
        AbandonPublishedInitialization(tlsTarget, loadDllTarget, getDllHandleTarget, getDllTarget);
        return;
    }
    status = MH_EnableHook(getDllTarget);
    if (status != MH_OK) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 12);
        AbandonPublishedInitialization(tlsTarget, loadDllTarget, getDllHandleTarget, getDllTarget);
        return;
    }
    if (!InstallQueryHooks()) {
        _InterlockedExchange(&MODULE_INITIALIZATION_FAILURE_STAGE, 13);
        AbandonPublishedInitialization(
            tlsTarget, loadDllTarget, getDllHandleTarget, getDllTarget);
        return;
    }
    HideLoadedModules();

    _ReadWriteBarrier();
    PROCESS_INITIALIZATION_FINISHED = TRUE;
    PublishInitializationState(2);
}

extern "C" VOID PrepareLdrLoadDllBootstrap() {
    const LONG previousState = _InterlockedCompareExchange(
        &LDR_LOAD_DLL_BOOTSTRAP_STATE, 1, 0);
    if (previousState == 2) {
        return;
    }
    if (previousState != 0) {
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }

    PVOID target = LDR_LOAD_DLL_BOOTSTRAP_TARGET;
    if (target == nullptr) {
        _InterlockedExchange(&LDR_LOAD_DLL_BOOTSTRAP_STATE, 3);
        __fastfail(FAST_FAIL_INVALID_ARG);
    }

    DWORD oldProtect = 0;
    if (!VirtualProtectDirect(
            target,
            sizeof(LDR_LOAD_DLL_BOOTSTRAP_ORIGINAL),
            PAGE_EXECUTE_READWRITE,
            &oldProtect)) {
        _InterlockedExchange(&LDR_LOAD_DLL_BOOTSTRAP_STATE, 3);
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }
    RtlCopyMemory(
        target,
        LDR_LOAD_DLL_BOOTSTRAP_ORIGINAL,
        sizeof(LDR_LOAD_DLL_BOOTSTRAP_ORIGINAL));
    const auto flushInstructionCache =
        reinterpret_cast<NTSTATUS(NTAPI *)(HANDLE, PVOID, SIZE_T)>(
            GetExportedFunctionAddress(
                reinterpret_cast<HMODULE>(NTDLL_BASE_ADDRESS),
                NTDLL_SIZE,
                NtFlushInstructionCacheHash));
    const NTSTATUS flushStatus        = flushInstructionCache != nullptr
                                            ? flushInstructionCache(
                                           NtCurrentProcess(),
                                           target,
                                           sizeof(LDR_LOAD_DLL_BOOTSTRAP_ORIGINAL))
                                            : STATUS_PROCEDURE_NOT_FOUND;
    DWORD          ignoredProtect     = 0;
    const BOOL     protectionRestored = VirtualProtectDirect(
        target,
        sizeof(LDR_LOAD_DLL_BOOTSTRAP_ORIGINAL),
        oldProtect,
        &ignoredProtect);
    if (!NT_SUCCESS(flushStatus) || !protectionRestored) {
        _InterlockedExchange(&LDR_LOAD_DLL_BOOTSTRAP_STATE, 3);
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }

    ModulePreProcessInitRoutine();
    LDR_LOAD_DLL_BOOTSTRAP_CHAIN = reinterpret_cast<PVOID>(LdrLoadDllOriginal);
    if (LDR_LOAD_DLL_BOOTSTRAP_CHAIN == nullptr ||
        _InterlockedCompareExchange(&MODULE_INITIALIZATION_STATE, 2, 2) != 2) {
        _InterlockedExchange(&LDR_LOAD_DLL_BOOTSTRAP_STATE, 3);
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }
    _InterlockedExchange(&LDR_LOAD_DLL_BOOTSTRAP_STATE, 2);
}
