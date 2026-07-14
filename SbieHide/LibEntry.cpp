#include <phnt_windows.h>
#include <phnt.h>

#include "APIHook.h"
#include "HideFromPEB.h"
#include "MemoryImageHideInformation.h"

#include <cwctype>

namespace {

    volatile LONG g_initializationState = 0;
    bool          g_skipCurrentProcess  = false;

    bool EqualsInsensitive(
        const wchar_t *value,
        size_t         valueLength,
        const wchar_t *expected,
        size_t         expectedLength) {
        if (value == nullptr || valueLength != expectedLength) {
            return false;
        }
        for (size_t index = 0; index < valueLength; ++index) {
            if (std::towlower(value[index]) != std::towlower(expected[index])) {
                return false;
            }
        }
        return true;
    }

    bool ShouldSkipCurrentProcess() {
        const PPEB peb = NtCurrentPeb();
        if (peb == nullptr || peb->ProcessParameters == nullptr) {
            return false;
        }

        const UNICODE_STRING &imagePath = peb->ProcessParameters->ImagePathName;
        if (imagePath.Buffer == nullptr || imagePath.Length % sizeof(wchar_t) != 0) {
            return false;
        }

        const size_t characterCount = imagePath.Length / sizeof(wchar_t);
        size_t       fileNameOffset = 0;
        for (size_t index = 0; index < characterCount; ++index) {
            if (imagePath.Buffer[index] == L'\\' || imagePath.Buffer[index] == L'/') {
                fileNameOffset = index + 1;
            }
        }

        const wchar_t *fileName       = imagePath.Buffer + fileNameOffset;
        const size_t   fileNameLength = characterCount - fileNameOffset;
        return EqualsInsensitive(fileName, fileNameLength, L"SandboxieRpcSs.exe", 18) ||
               EqualsInsensitive(fileName, fileNameLength, L"SandboxieDcomLaunch.exe", 23);
    }

    BOOLEAN InitializePlugin() {
        LONG state = InterlockedCompareExchange(&g_initializationState, 1, 0);
        if (state == 2) {
            return TRUE;
        }
        if (state == 3) {
            return FALSE;
        }
        if (state == 1) {
            while ((state = InterlockedCompareExchange(&g_initializationState, 1, 1)) == 1) {
                YieldProcessor();
            }
            return state == 2 ? TRUE : FALSE;
        }

        BOOLEAN success = InitMemoryImageHideInformation();
        if (success) {
            success = EnableApiHook();
        }
        if (success) {
            HMODULE    pinnedModule = nullptr;
            const BOOL pinned       = GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                reinterpret_cast<LPCWSTR>(&InitializePlugin),
                &pinnedModule);
            success = pinned ? TRUE : FALSE;
            if (!success) {
                DisableApiHook();
            }
        }
        if (success) {
            success = EraseModuleNameFromPeb();
        }

        InterlockedExchange(&g_initializationState, success ? 2 : 3);
        return success;
    }

} // namespace

extern "C" __declspec(dllexport) int GetHookAPIs(PVOID, PVOID, PVOID) {
    return 0x01;
}

extern "C" __declspec(dllexport) int NotifyShims(PVOID, PVOID) {
    if (g_skipCurrentProcess) {
        return 0x01;
    }
    return InitializePlugin() ? 0x01 : 0x00;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    g_skipCurrentProcess = ShouldSkipCurrentProcess();
    if (!g_skipCurrentProcess) {
        InitializePlugin();
    }
    return TRUE;
}