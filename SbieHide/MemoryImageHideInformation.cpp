#include "MemoryImageHideInformation.h"

#include <array>
#include <cwctype>
#include <limits>

namespace {

    constexpr size_t kMaximumHiddenModuleCount = 4;

    std::array<MemoryImageHideInformation, kMaximumHiddenModuleCount> g_hiddenModules {};
    size_t                                                            g_hiddenModuleCount   = 0;
    volatile LONG                                                     g_initializationState = 0;

    bool EqualsInsensitiveAscii(
        const UNICODE_STRING &value,
        const wchar_t        *expected,
        size_t                expectedLength) {
        if (value.Buffer == nullptr || value.Length % sizeof(wchar_t) != 0) {
            return false;
        }

        const size_t characterCount = value.Length / sizeof(wchar_t);
        if (characterCount != expectedLength) {
            return false;
        }

        for (size_t index = 0; index < characterCount; ++index) {
            if (std::towlower(value.Buffer[index]) != std::towlower(expected[index])) {
                return false;
            }
        }
        return true;
    }

    bool IsSandboxieModule(const UNICODE_STRING &baseName) {
        return EqualsInsensitiveAscii(baseName, L"sbiedll.dll", 11) ||
               EqualsInsensitiveAscii(baseName, L"sbiedll", 7);
    }

    bool ContainsAddress(const LDR_DATA_TABLE_ENTRY &module, ULONG_PTR address) {
        const ULONG_PTR start = reinterpret_cast<ULONG_PTR>(module.DllBase);
        if (module.SizeOfImage == 0 || start > std::numeric_limits<ULONG_PTR>::max() - module.SizeOfImage) {
            return false;
        }
        return start <= address && address < start + module.SizeOfImage;
    }

    void AddModuleRange(const LDR_DATA_TABLE_ENTRY &module) {
        if (g_hiddenModuleCount >= g_hiddenModules.size() || module.SizeOfImage == 0) {
            return;
        }

        const ULONG_PTR start = reinterpret_cast<ULONG_PTR>(module.DllBase);
        if (start > std::numeric_limits<ULONG_PTR>::max() - module.SizeOfImage) {
            return;
        }

        const ULONG_PTR end = start + module.SizeOfImage;
        for (size_t index = 0; index < g_hiddenModuleCount; ++index) {
            if (g_hiddenModules[index].ImageStartAddress == start &&
                g_hiddenModules[index].ImageEndAddress == end) {
                return;
            }
        }
        g_hiddenModules[g_hiddenModuleCount++] = { start, end };
    }

    BOOLEAN DiscoverHiddenModules() {
        const PPEB peb = NtCurrentPeb();
        if (peb == nullptr || peb->Ldr == nullptr) {
            return FALSE;
        }

        bool              sandboxieFound     = false;
        bool              currentModuleFound = false;
        const ULONG_PTR   currentAddress     = reinterpret_cast<ULONG_PTR>(InitMemoryImageHideInformation);
        const PLIST_ENTRY head               = &peb->Ldr->InMemoryOrderModuleList;

        for (PLIST_ENTRY link = head->Flink; link != head; link = link->Flink) {
            const auto module = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (IsSandboxieModule(module->BaseDllName)) {
                AddModuleRange(*module);
                sandboxieFound = true;
            }
            if (ContainsAddress(*module, currentAddress)) {
                AddModuleRange(*module);
                currentModuleFound = true;
            }
        }

        return sandboxieFound && currentModuleFound ? TRUE : FALSE;
    }

} // namespace

BOOLEAN InitMemoryImageHideInformation() {
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

    const BOOLEAN result = DiscoverHiddenModules();
    InterlockedExchange(&g_initializationState, result ? 2 : 3);
    return result;
}

BOOLEAN IsAddressShouldHide(ULONG_PTR address) {
    if (InterlockedCompareExchange(&g_initializationState, 0, 0) != 2) {
        return FALSE;
    }
    for (size_t index = 0; index < g_hiddenModuleCount; ++index) {
        if (g_hiddenModules[index].ImageStartAddress <= address &&
            address < g_hiddenModules[index].ImageEndAddress) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN IsAddressShouldHide(const void *address) {
    return IsAddressShouldHide(reinterpret_cast<ULONG_PTR>(address));
}
