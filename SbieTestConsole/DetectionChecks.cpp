#include "DetectionChecks.h"

#include <phnt_windows.h>
#include <phnt.h>
#include <psapi.h>

#include <algorithm>
#include <cstdio>
#include <cwctype>
#include <limits>
#include <vector>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

namespace {

    template<typename Character>
    Character ToLowerAscii(Character value) {
        const Character upperA = static_cast<Character>('A');
        const Character upperZ = static_cast<Character>('Z');
        if (value >= upperA && value <= upperZ) {
            return static_cast<Character>(value + (static_cast<Character>('a') - upperA));
        }
        return value;
    }

    template<typename Character, size_t PatternSize>
    bool ContainsInsensitive(
        const Character *value,
        size_t           valueLength,
        const Character (&pattern)[PatternSize]) {
        const size_t patternLength = PatternSize - 1;
        if (value == nullptr || valueLength < patternLength) {
            return false;
        }

        for (size_t start = 0; start <= valueLength - patternLength; ++start) {
            size_t index = 0;
            while (index < patternLength &&
                   ToLowerAscii(value[start + index]) == ToLowerAscii(pattern[index])) {
                ++index;
            }
            if (index == patternLength) {
                return true;
            }
        }
        return false;
    }

    bool IsSandboxieName(const wchar_t *value, size_t characterCount) {
        return ContainsInsensitive(value, characterCount, L"sbiedll") ||
               ContainsInsensitive(value, characterCount, L"sbiehide") ||
               ContainsInsensitive(value, characterCount, L"sbiedrv") ||
               ContainsInsensitive(value, characterCount, L"sbiesvc") ||
               ContainsInsensitive(value, characterCount, L"sbiectrl") ||
               ContainsInsensitive(value, characterCount, L"sandboxie");
    }

    bool IsSandboxieName(const char *value, size_t byteCount) {
        return ContainsInsensitive(value, byteCount, "sbiedll") ||
               ContainsInsensitive(value, byteCount, "sbiehide") ||
               ContainsInsensitive(value, byteCount, "sbiedrv") ||
               ContainsInsensitive(value, byteCount, "sbiesvc") ||
               ContainsInsensitive(value, byteCount, "sbiectrl") ||
               ContainsInsensitive(value, byteCount, "sandboxie");
    }

    size_t BoundedLength(const UCHAR *value, size_t capacity) {
        size_t length = 0;
        while (length < capacity && value[length] != '\0') {
            ++length;
        }
        return length;
    }

    bool QuerySystemInformation(
        SYSTEM_INFORMATION_CLASS informationClass,
        std::vector<BYTE>       *buffer,
        ULONG                   *usedLength) {
        if (buffer == nullptr || usedLength == nullptr) {
            return false;
        }

        ULONG    required = 0;
        NTSTATUS status   = NtQuerySystemInformation(
            informationClass, nullptr, 0, &required);
        if (status == STATUS_ACCESS_DENIED) {
            buffer->clear();
            *usedLength = 0;
            return true;
        }
        if (status != STATUS_INFO_LENGTH_MISMATCH &&
            status != STATUS_BUFFER_TOO_SMALL) {
            std::printf(
                "[FAIL] NtQuerySystemInformation(%u) size query: 0x%08lX\n",
                static_cast<unsigned>(informationClass),
                static_cast<unsigned long>(status));
            return false;
        }

        size_t capacity = std::max<size_t>(required, 64 * 1024);
        for (unsigned attempt = 0; attempt < 8; ++attempt) {
            if (capacity > std::numeric_limits<ULONG>::max()) {
                return false;
            }
            buffer->assign(capacity, 0);
            required = 0;
            status   = NtQuerySystemInformation(
                informationClass,
                buffer->data(),
                static_cast<ULONG>(buffer->size()),
                &required);
            if (status == STATUS_ACCESS_DENIED) {
                buffer->clear();
                *usedLength = 0;
                return true;
            }
            if (NT_SUCCESS(status)) {
                if (required == 0 || required > buffer->size()) {
                    std::printf(
                        "[FAIL] NtQuerySystemInformation(%u) returned invalid length %lu.\n",
                        static_cast<unsigned>(informationClass),
                        required);
                    return false;
                }
                *usedLength = required;
                return true;
            }
            if (status != STATUS_INFO_LENGTH_MISMATCH &&
                status != STATUS_BUFFER_TOO_SMALL) {
                std::printf(
                    "[FAIL] NtQuerySystemInformation(%u): 0x%08lX\n",
                    static_cast<unsigned>(informationClass),
                    static_cast<unsigned long>(status));
                return false;
            }
            capacity = std::max<size_t>(capacity * 2, required);
        }
        return false;
    }

    int CheckPluginCanary() {
        const HANDLE eventHandle = CreateEventW(
            nullptr, FALSE, FALSE, L"Local\\sbiehide.canary");
        if (eventHandle == nullptr) {
            std::printf("[FAIL] Unable to create plugin canary object: %lu.\n", GetLastError());
            return 1;
        }

        BYTE           objectBuffer[1024] = {};
        ULONG          returnLength       = 0;
        const NTSTATUS status             = NtQueryObject(
            eventHandle,
            ObjectNameInformation,
            objectBuffer,
            sizeof(objectBuffer),
            &returnLength);
        CloseHandle(eventHandle);
        if (status != STATUS_ACCESS_DENIED) {
            std::printf(
                "[FAIL] SbieHide hook canary was not intercepted (0x%08lX).\n",
                static_cast<unsigned long>(status));
            return 1;
        }
        std::printf("[PASS] SbieHide hook canary confirmed active interception.\n");
        return 0;
    }

    int CheckModuleHandles() {
        int            failures = 0;
        const wchar_t *names[]  = { L"SbieDll.dll", L"SbieHide.dll" };
        for (const wchar_t *name : names) {
            const HMODULE module = GetModuleHandleW(name);
            if (module != nullptr) {
                std::wprintf(L"[FAIL] GetModuleHandleW(%ls) exposed %p.\n", name, module);
                ++failures;
            } else {
                std::wprintf(L"[PASS] GetModuleHandleW(%ls) is hidden.\n", name);
            }
        }
        return failures;
    }

    int CheckLoadLibraryContract() {
        SetLastError(ERROR_SUCCESS);
        const HMODULE module = LoadLibraryW(L"SbieDll.dll");
        const DWORD   error  = GetLastError();
        if (module != nullptr) {
            std::printf("[FAIL] LoadLibraryW exposed SbieDll.dll at %p.\n", module);
            FreeLibrary(module);
            return 1;
        }
        if (error != ERROR_MOD_NOT_FOUND && error != ERROR_DLL_NOT_FOUND) {
            std::printf("[FAIL] LoadLibraryW returned unexpected error %lu.\n", error);
            return 1;
        }
        std::printf("[PASS] LoadLibraryW hides SbieDll.dll with error %lu.\n", error);
        return 0;
    }

    int CheckCurrentProcessModules() {
        DWORD bytesNeeded = 0;
        if (!EnumProcessModulesEx(
                GetCurrentProcess(), nullptr, 0, &bytesNeeded, LIST_MODULES_ALL) ||
            bytesNeeded == 0) {
            std::printf("[FAIL] EnumProcessModulesEx size query failed: %lu.\n", GetLastError());
            return 1;
        }

        std::vector<HMODULE> modules(
            (bytesNeeded + sizeof(HMODULE) - 1) / sizeof(HMODULE));
        if (!EnumProcessModulesEx(
                GetCurrentProcess(),
                modules.data(),
                static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                &bytesNeeded,
                LIST_MODULES_ALL)) {
            std::printf("[FAIL] EnumProcessModulesEx failed: %lu.\n", GetLastError());
            return 1;
        }
        if (bytesNeeded > modules.size() * sizeof(HMODULE)) {
            std::printf("[FAIL] EnumProcessModulesEx result grew during enumeration.\n");
            return 1;
        }

        const size_t         count = bytesNeeded / sizeof(HMODULE);
        std::vector<wchar_t> path(32768, L'\0');
        int                  failures = 0;
        for (size_t index = 0; index < count; ++index) {
            const DWORD length = GetModuleFileNameExW(
                GetCurrentProcess(),
                modules[index],
                path.data(),
                static_cast<DWORD>(path.size()));
            if (length == 0) {
                std::printf("[FAIL] PSAPI failed to resolve module %zu: %lu.\n", index, GetLastError());
                ++failures;
            } else {
                size_t nameOffset = 0;
                for (size_t character = 0; character < length; ++character) {
                    if (path[character] == L'\\' || path[character] == L'/') {
                        nameOffset = character + 1;
                    }
                }
                if (IsSandboxieName(path.data() + nameOffset, length - nameOffset)) {
                    std::wprintf(
                        L"[FAIL] PSAPI exposed module: %.*ls\n",
                        static_cast<int>(length - nameOffset),
                        path.data() + nameOffset);
                    ++failures;
                }
            }
        }
        if (failures == 0) {
            std::printf("[PASS] PSAPI module enumeration contains no Sandboxie names.\n");
        }
        return failures;
    }

    int CheckSystemModules() {
        std::vector<BYTE> buffer;
        ULONG             usedLength = 0;
        if (!QuerySystemInformation(SystemModuleInformation, &buffer, &usedLength)) {
            return 10;
        }

        const size_t modulesOffset = FIELD_OFFSET(RTL_PROCESS_MODULES, Modules);
        if (usedLength == 0) {
            std::printf("[PASS] System module enumeration is access denied.\n");
            return 0;
        }
        if (usedLength < modulesOffset) {
            std::printf("[FAIL] SystemModuleInformation returned a truncated header.\n");
            return 11;
        }

        const auto   modules   = reinterpret_cast<const RTL_PROCESS_MODULES *>(buffer.data());
        const size_t available = (usedLength - modulesOffset) /
                                 sizeof(RTL_PROCESS_MODULE_INFORMATION);
        if (modules->NumberOfModules > available) {
            std::printf("[FAIL] SystemModuleInformation count exceeds returned buffer.\n");
            return 12;
        }
        int failures = 0;
        for (size_t index = 0; index < modules->NumberOfModules; ++index) {
            const auto  &module = modules->Modules[index];
            const size_t length = BoundedLength(
                module.FullPathName, sizeof(module.FullPathName));
            const size_t nameOffset = module.OffsetToFileName < length
                                          ? module.OffsetToFileName
                                          : 0;
            if (IsSandboxieName(
                    reinterpret_cast<const char *>(module.FullPathName) + nameOffset,
                    length - nameOffset)) {
                std::printf(
                    "[FAIL] SystemModuleInformation exposed: %.*s\n",
                    static_cast<int>(length - nameOffset),
                    module.FullPathName + nameOffset);
                ++failures;
            }
        }
        if (failures == 0) {
            std::printf("[PASS] System module enumeration contains no Sandboxie names.\n");
        }
        return failures;
    }

    int CheckSystemProcesses() {
        std::vector<BYTE> buffer;
        ULONG             usedLength = 0;
        if (!QuerySystemInformation(SystemProcessInformation, &buffer, &usedLength)) {
            return 1;
        }

        size_t offset   = 0;
        int    failures = 0;
        while (offset < usedLength) {
            if (sizeof(SYSTEM_PROCESS_INFORMATION) > usedLength - offset) {
                std::printf("[FAIL] SystemProcessInformation contains a truncated entry.\n");
                return failures + 1;
            }
            const auto process = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION *>(
                buffer.data() + offset);
            if (process->ImageName.Buffer != nullptr &&
                process->ImageName.Length % sizeof(wchar_t) == 0) {
                const size_t characterCount = process->ImageName.Length / sizeof(wchar_t);
                if (IsSandboxieName(process->ImageName.Buffer, characterCount)) {
                    std::wprintf(L"[FAIL] SystemProcessInformation exposed: %.*ls\n", static_cast<int>(characterCount), process->ImageName.Buffer);
                    ++failures;
                }
            }
            if (process->NextEntryOffset == 0) {
                break;
            }
            if (process->NextEntryOffset > usedLength - offset) {
                std::printf("[FAIL] SystemProcessInformation contains an invalid NextEntryOffset.\n");
                return failures + 1;
            }
            offset += process->NextEntryOffset;
        }
        if (failures == 0) {
            std::printf("[PASS] Process enumeration contains no Sandboxie names.\n");
        }
        return failures;
    }

} // namespace

int RunDetectionChecks(unsigned *failureMask) {
    const int results[] = {
        CheckPluginCanary(),
        CheckModuleHandles(),
        CheckLoadLibraryContract(),
        CheckCurrentProcessModules(),
        CheckSystemModules(),
        CheckSystemProcesses()
    };
    int      failures = 0;
    unsigned mask     = 0;
    for (size_t index = 0; index < _countof(results); ++index) {
        failures += results[index];
        if (results[index] != 0) {
            mask |= 1u << index;
        }
    }
    if (failureMask != nullptr) {
        *failureMask = mask;
    }
    std::printf("Detection checks completed with %d failure(s).\n", failures);
    return failures;
}

int RunDetectionChecks() {
    return RunDetectionChecks(nullptr);
}
