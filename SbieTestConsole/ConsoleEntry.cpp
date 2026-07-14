#include "DetectionChecks.h"

#include <phnt_windows.h>
#include <phnt.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>

namespace {

    volatile LONG g_tlsSandboxieVisible       = 0;
    volatile LONG g_tlsCallbackRan            = 0;
    volatile LONG g_tlsThreadCallbackRan      = 0;
    volatile LONG g_tlsThreadSandboxieVisible = 0;
    volatile LONG g_tlsEntrypointIntact       = 0;

    bool IsSbieDllVisibleInPeb() {
        constexpr wchar_t expected[] = L"sbiedll.dll";
        const PPEB        peb        = NtCurrentPeb();
        if (peb == nullptr || peb->Ldr == nullptr) {
            return false;
        }
        const PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
        for (PLIST_ENTRY current = head->Flink;
             current != nullptr && current != head;
             current = current->Flink) {
            const auto entry = CONTAINING_RECORD(
                current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            const UNICODE_STRING &name = entry->BaseDllName;
            if (name.Buffer == nullptr || name.Length != sizeof(expected) - sizeof(wchar_t)) {
                continue;
            }
            size_t index = 0;
            for (; index < _countof(expected) - 1; ++index) {
                wchar_t value = name.Buffer[index];
                if (value >= L'A' && value <= L'Z') {
                    value = static_cast<wchar_t>(value + (L'a' - L'A'));
                }
                if (value != expected[index]) {
                    break;
                }
            }
            if (index == _countof(expected) - 1) {
                return true;
            }
        }
        return false;
    }

    bool IsSyntheticEntrypointIntact() {
#ifdef _WIN64
        const auto imageBase = reinterpret_cast<const BYTE *>(NtCurrentPeb()->ImageBaseAddress);
        if (imageBase == nullptr) {
            return false;
        }
        const auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(imageBase);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew <= 0 ||
            static_cast<ULONG>(dosHeader->e_lfanew) > 0x100000) {
            return false;
        }
        const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(
            imageBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
            ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            ntHeaders->OptionalHeader.AddressOfEntryPoint == 0 ||
            ntHeaders->OptionalHeader.AddressOfEntryPoint + 16 >
                ntHeaders->OptionalHeader.SizeOfImage) {
            return false;
        }
        const BYTE *entryPoint = imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
        for (SIZE_T index = 0; index < 16; ++index) {
            if (entryPoint[index] != 0x90) {
                return false;
            }
        }
#endif
        return true;
    }

    bool IsVmpProbeRequested() {
        const PPEB peb = NtCurrentPeb();
        if (peb == nullptr || peb->ProcessParameters == nullptr) {
            return false;
        }
        const UNICODE_STRING &commandLine    = peb->ProcessParameters->CommandLine;
        constexpr wchar_t     probeSwitch[]  = L"--vmp-integrity-probe";
        const SIZE_T          characterCount = commandLine.Length / sizeof(wchar_t);
        const SIZE_T          switchLength   = _countof(probeSwitch) - 1;
        if (commandLine.Buffer == nullptr || characterCount < switchLength) {
            return false;
        }
        for (SIZE_T offset = 0; offset + switchLength <= characterCount; ++offset) {
            SIZE_T index = 0;
            while (index < switchLength &&
                   commandLine.Buffer[offset + index] == probeSwitch[index]) {
                ++index;
            }
            if (index == switchLength) {
                return true;
            }
        }
        return false;
    }

    bool GetVmpProbeEvidencePath(wchar_t *path, SIZE_T capacity) {
        const PPEB peb = NtCurrentPeb();
        if (path == nullptr || capacity == 0 || peb == nullptr ||
            peb->ProcessParameters == nullptr) {
            return false;
        }
        const UNICODE_STRING &commandLine    = peb->ProcessParameters->CommandLine;
        constexpr wchar_t     probeSwitch[]  = L"--vmp-integrity-probe";
        const SIZE_T          characterCount = commandLine.Length / sizeof(wchar_t);
        const SIZE_T          switchLength   = _countof(probeSwitch) - 1;
        if (commandLine.Buffer == nullptr || characterCount < switchLength) {
            return false;
        }
        for (SIZE_T offset = 0; offset + switchLength <= characterCount; ++offset) {
            SIZE_T index = 0;
            while (index < switchLength &&
                   commandLine.Buffer[offset + index] == probeSwitch[index]) {
                ++index;
            }
            if (index != switchLength) {
                continue;
            }
            SIZE_T cursor = offset + switchLength;
            while (cursor < characterCount &&
                   (commandLine.Buffer[cursor] == L' ' ||
                    commandLine.Buffer[cursor] == L'\t')) {
                ++cursor;
            }
            const bool quoted = cursor < characterCount &&
                                commandLine.Buffer[cursor] == L'"';
            if (quoted) {
                ++cursor;
            }
            SIZE_T outputLength = 0;
            while (cursor < characterCount && outputLength + 1 < capacity) {
                const wchar_t value = commandLine.Buffer[cursor];
                if ((quoted && value == L'"') ||
                    (!quoted && (value == L' ' || value == L'\t'))) {
                    break;
                }
                path[outputLength++] = value;
                ++cursor;
            }
            path[outputLength] = L'\0';
            return outputLength != 0;
        }
        return false;
    }

    void SignalVmpTamperEvidence() {
        wchar_t eventPath[512] = {};
        if (!GetVmpProbeEvidencePath(eventPath, _countof(eventPath))) {
            return;
        }
        UNICODE_STRING eventName = {};
        RtlInitUnicodeString(&eventName, eventPath);
        OBJECT_ATTRIBUTES attributes = {};
        InitializeObjectAttributes(
            &attributes,
            &eventName,
            OBJ_CASE_INSENSITIVE,
            nullptr,
            nullptr);
        HANDLE evidenceEvent = nullptr;
        if (NT_SUCCESS(NtOpenEvent(
                &evidenceEvent,
                EVENT_MODIFY_STATE,
                &attributes))) {
            NtSetEvent(evidenceEvent, nullptr);
            NtClose(evidenceEvent);
        }
    }

    void NTAPI TlsCallback(PVOID, DWORD reason, PVOID) {
        bool visible = IsSbieDllVisibleInPeb();
        if (reason == DLL_THREAD_ATTACH) {
            UNICODE_STRING name   = RTL_CONSTANT_STRING(L"SbieDll.dll");
            PVOID          module = nullptr;
            visible               = NT_SUCCESS(LdrGetDllHandleEx(
                LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT,
                nullptr,
                nullptr,
                &name,
                &module));
        }
        if (reason == DLL_PROCESS_ATTACH) {
            InterlockedExchange(&g_tlsCallbackRan, 1);
            const bool vmpProbe = IsVmpProbeRequested();
            if (IsSyntheticEntrypointIntact()) {
                InterlockedExchange(&g_tlsEntrypointIntact, 1);
            } else if (vmpProbe) {
                SignalVmpTamperEvidence();
                RtlExitUserProcess(static_cast<NTSTATUS>(0x1796));
            }
            if (visible) {
                InterlockedExchange(&g_tlsSandboxieVisible, 1);
            }
        } else if (reason == DLL_THREAD_ATTACH) {
            InterlockedExchange(&g_tlsThreadCallbackRan, 1);
            if (visible) {
                InterlockedExchange(&g_tlsThreadSandboxieVisible, 1);
            }
        }
    }

    DWORD WINAPI TlsProbeThread(PVOID) {
        return ERROR_SUCCESS;
    }

    int WriteMarkerText(const wchar_t *path, const char *text, DWORD textLength) {
        const HANDLE file = CreateFileW(
            path,
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            return static_cast<int>(GetLastError());
        }
        DWORD       written = 0;
        const BOOL  success = WriteFile(file, text, textLength, &written, nullptr);
        const DWORD error   = success && written == textLength
                                  ? ERROR_SUCCESS
                                  : (GetLastError() != ERROR_SUCCESS ? GetLastError() : ERROR_WRITE_FAULT);
        CloseHandle(file);
        return static_cast<int>(error);
    }

    struct CoreDescriptor {
            PBYTE          base;
            volatile LONG *state;
            volatile LONG *failureStage;
            volatile LONG *ldrGetDllHandleHits;
            volatile LONG *ldrGetDllHandleHides;
            VOID(NTAPI *bootstrap)();
    };

    bool ReadCoreDescriptorFile(const wchar_t *path, CoreDescriptor *descriptor) {
        if (descriptor == nullptr) {
            return false;
        }
        *descriptor       = {};
        const HANDLE file = CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            return false;
        }
        char       buffer[128] = {};
        DWORD      bytesRead   = 0;
        const BOOL success     = ReadFile(
            file, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
        CloseHandle(file);
        if (!success || bytesRead == 0 || bytesRead >= sizeof(buffer)) {
            return false;
        }
        unsigned long long baseValue    = 0;
        unsigned long      stateRva     = 0;
        unsigned long      failureRva   = 0;
        unsigned long      bootstrapRva = 0;
        unsigned long      hitCountRva  = 0;
        unsigned long      hideCountRva = 0;
        if (std::sscanf(
                buffer,
                "%llX %lX %lX %lX %lX %lX",
                &baseValue,
                &stateRva,
                &failureRva,
                &bootstrapRva,
                &hitCountRva,
                &hideCountRva) != 6 ||
            baseValue == 0 || stateRva == 0 || failureRva == 0 ||
            bootstrapRva == 0 || hitCountRva == 0 || hideCountRva == 0) {
            return false;
        }
        const ULONG_PTR base             = static_cast<ULONG_PTR>(baseValue);
        descriptor->base                 = reinterpret_cast<PBYTE>(base);
        descriptor->state                = reinterpret_cast<volatile LONG *>(base + stateRva);
        descriptor->failureStage         = reinterpret_cast<volatile LONG *>(base + failureRva);
        descriptor->bootstrap            = reinterpret_cast<VOID(NTAPI *)()>(base + bootstrapRva);
        descriptor->ldrGetDllHandleHits  = reinterpret_cast<volatile LONG *>(base + hitCountRva);
        descriptor->ldrGetDllHandleHides = reinterpret_cast<volatile LONG *>(base + hideCountRva);
        return true;
    }

    int WriteMarkerAfterParentExit(const wchar_t *path, const wchar_t *coreBasePath) {
        auto fail = [path](DWORD error) {
            Sleep(1000);
            char      diagnostic[64] = {};
            const int length         = std::snprintf(
                diagnostic, sizeof(diagnostic), "SbieHideEx child error %lu.\r\n", error);
            if (length > 0) {
                WriteMarkerText(path, diagnostic, static_cast<DWORD>(length));
            }
            return static_cast<int>(error);
        };
        if (InterlockedCompareExchange(&g_tlsCallbackRan, 0, 0) == 0) {
            return fail(ERROR_INVALID_DATA);
        }
        if (InterlockedCompareExchange(&g_tlsEntrypointIntact, 0, 0) == 0) {
            return fail(ERROR_CRC);
        }
        if (InterlockedCompareExchange(&g_tlsSandboxieVisible, 0, 0) != 0) {
            return fail(ERROR_ACCESS_DENIED);
        }
        PROCESS_BASIC_INFORMATION processInformation = {};
        const NTSTATUS            status             = NtQueryInformationProcess(
            NtCurrentProcess(),
            ProcessBasicInformation,
            &processInformation,
            sizeof(processInformation),
            nullptr);
        if (!NT_SUCCESS(status) || processInformation.InheritedFromUniqueProcessId == 0) {
            return fail(NT_SUCCESS(status) ? ERROR_INVALID_DATA : RtlNtStatusToDosError(status));
        }

        CoreDescriptor core = {};
        if (!ReadCoreDescriptorFile(coreBasePath, &core)) {
            return fail(ERROR_INVALID_DATA);
        }
        if (InterlockedCompareExchange(core.state, 2, 2) != 2) {
            const LONG stage = InterlockedCompareExchange(core.failureStage, 0, 0);
            return fail(ERROR_DLL_INIT_FAILED + (stage > 0 ? stage : 0));
        }

        unsigned  detectionFailureMask = 0;
        const int detectionFailures    = RunDetectionChecks(&detectionFailureMask);
        if (detectionFailures != 0) {
            char      diagnostic[96] = {};
            const int length         = std::snprintf(
                diagnostic,
                sizeof(diagnostic),
                "SbieHideEx detection failures %d (mask 0x%02X).\r\n",
                detectionFailures,
                detectionFailureMask);
            if (length > 0) {
                WriteMarkerText(path, diagnostic, static_cast<DWORD>(length));
            }
            return ERROR_INVALID_DATA + detectionFailures;
        }

        InterlockedExchange(&g_tlsThreadCallbackRan, 0);
        InterlockedExchange(&g_tlsThreadSandboxieVisible, 0);
        const HANDLE tlsProbe = CreateThread(
            nullptr, 0, TlsProbeThread, nullptr, 0, nullptr);
        if (tlsProbe == nullptr) {
            return fail(GetLastError());
        }
        const DWORD probeWait = WaitForSingleObject(tlsProbe, 5000);
        CloseHandle(tlsProbe);
        if (probeWait != WAIT_OBJECT_0 ||
            InterlockedCompareExchange(&g_tlsThreadCallbackRan, 0, 0) == 0) {
            return fail(probeWait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_INVALID_DATA);
        }
        if (InterlockedCompareExchange(&g_tlsThreadSandboxieVisible, 0, 0) != 0) {
            const LONG hits  = InterlockedCompareExchange(core.ldrGetDllHandleHits, 0, 0);
            const LONG hides = InterlockedCompareExchange(core.ldrGetDllHandleHides, 0, 0);
            return fail(ERROR_ACCESS_DENIED + (hits == 0 ? 100 : (hides == 0 ? 101 : 0)));
        }

        const HANDLE parent = OpenProcess(
            SYNCHRONIZE,
            FALSE,
            HandleToUlong(processInformation.InheritedFromUniqueProcessId));
        if (parent != nullptr) {
            const DWORD waitResult = WaitForSingleObject(parent, 15000);
            CloseHandle(parent);
            if (waitResult != WAIT_OBJECT_0) {
                return fail(waitResult == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError());
            }
        } else if (GetLastError() != ERROR_INVALID_PARAMETER) {
            return fail(GetLastError());
        }

        Sleep(250);
        constexpr char kMarker[] = "SbieHideEx child reached its entry point.\r\n";
        return WriteMarkerText(path, kMarker, static_cast<DWORD>(sizeof(kMarker) - 1));
    }

    int WriteVmpIntegrityProbe(const wchar_t *evidenceEventName) {
        UNREFERENCED_PARAMETER(evidenceEventName);
        if (InterlockedCompareExchange(&g_tlsCallbackRan, 0, 0) == 0) {
            return ERROR_INVALID_DATA;
        }
        return InterlockedCompareExchange(&g_tlsEntrypointIntact, 0, 0) != 0
                   ? ERROR_SUCCESS
                   : ERROR_CRC;
    }

} // namespace

#ifdef _MSC_VER
    #pragma section(".CRT$XLB", long, read)
    #ifdef _WIN64
        #pragma comment(linker, "/INCLUDE:_tls_used")
        #pragma comment(linker, "/INCLUDE:g_tlsCallback")
    #else
        #pragma comment(linker, "/INCLUDE:__tls_used")
        #pragma comment(linker, "/INCLUDE:_g_tlsCallback")
    #endif
extern "C" __declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK g_tlsCallback = TlsCallback;
#endif

int wmain(int argc, wchar_t *argv[]) {
    if (argc == 5 &&
        std::wcscmp(argv[1], L"--write-marker-after-parent-exit") == 0 &&
        std::wcscmp(argv[3], L"--core-base-file") == 0) {
        return WriteMarkerAfterParentExit(argv[2], argv[4]);
    }
    if (argc == 3 && std::wcscmp(argv[1], L"--vmp-integrity-probe") == 0) {
        return WriteVmpIntegrityProbe(argv[2]);
    }
    if (argc != 1 && !(argc == 2 && std::wcscmp(argv[1], L"--self-test") == 0)) {
        std::fwprintf(
            stderr,
            L"Usage: %ls [--self-test | --vmp-integrity-probe <path> | "
            L"--write-marker-after-parent-exit <path> --core-base-file <path>]\n",
            argv[0]);
        return ERROR_INVALID_PARAMETER;
    }

    std::printf("SbieHide automated detection smoke test\n");

    int failures = RunDetectionChecks();
    if (InterlockedCompareExchange(&g_tlsCallbackRan, 0, 0) == 0) {
        std::printf("[FAIL] Executable TLS callback did not run.\n");
        ++failures;
    } else {
        std::printf("[PASS] Executable TLS callback ran.\n");
    }
    if (InterlockedCompareExchange(&g_tlsSandboxieVisible, 0, 0) != 0) {
        std::printf("[INFO] SbieDll.dll was visible at TLS time; use SbieHideEx for that path.\n");
    } else {
        std::printf("[PASS] SbieDll.dll was already hidden from TLS callbacks.\n");
    }

    std::printf("Smoke test result: %s (%d failure(s)).\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}