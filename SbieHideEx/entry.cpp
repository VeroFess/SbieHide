#include <phnt_windows.h>
#include <phnt.h>

#include "address_finder.h"
#include "simple_runtime_library.h"
#include "syscall_invoker.h"
#include "minhook.h"
#include "detours.h"

VOID ModulePreProcessInitRoutine() {
    PROCESS_INITIALIZATION_FINISHED = TRUE;

    PVOID     LdrpCallTlsInitializersAddress = nullptr;
    PVOID     LdrShutdownThreadAddress       = nullptr;
    PVOID     LdrLoadDllAddress              = nullptr;
    MH_STATUS HookStatus                     = MH_OK;

    if ((LdrShutdownThreadAddress = GetExportedFunctionAddress(reinterpret_cast<HMODULE>(NTDLL_BASE_ADDRESS), LdrShutdownThreadHash)) == nullptr) {
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }

    if ((LdrpCallTlsInitializersAddress = FindLdrpCallTlsInitializers(LdrShutdownThreadAddress)) == nullptr) {
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }

    if ((LdrLoadDllAddress = GetExportedFunctionAddress(reinterpret_cast<HMODULE>(NTDLL_BASE_ADDRESS), LdrLoadDllHash)) == nullptr) {
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }

    HookStatus = MH_Initialize();

    if (!(HookStatus == MH_OK || HookStatus == MH_ERROR_ALREADY_INITIALIZED)) {
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }

    if (HookStatus == MH_OK) {
        //if ((HookStatus = MH_CreateHook(reinterpret_cast<LPVOID>(LdrpCallTlsInitializersAddress), &LdrpCallTlsInitializersDetours, reinterpret_cast<void **>(&LdrpCallTlsInitializersOriginal))) != MH_OK) {
        //    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        //}

        //if ((HookStatus = MH_EnableHook(reinterpret_cast<LPVOID>(LdrpCallTlsInitializersAddress))) != MH_OK) {
        //    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        //}

        //if ((HookStatus = MH_CreateHook(reinterpret_cast<LPVOID>(LdrLoadDllAddress), &LdrLoadDllDetours, reinterpret_cast<void **>(&LdrLoadDllOriginal))) != MH_OK) {
        //    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        //}

        //if ((HookStatus = MH_EnableHook(reinterpret_cast<LPVOID>(LdrLoadDllAddress))) != MH_OK) {
        //    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        //}
    }
}