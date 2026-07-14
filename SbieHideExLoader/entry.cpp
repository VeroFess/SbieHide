#include "NtdllRemapper.h"
#include "ProcessLauncher.h"
#include "SbieHideLoader.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

    bool GetExecutablePath(std::wstring *path) {
        if (!path)
            return false;
        std::vector<wchar_t> buffer(512);
        for (;;) {
            SetLastError(ERROR_SUCCESS);
            const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
            if (length == 0)
                return false;
            if (length < buffer.size() - 1 || (length < buffer.size() && GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
                path->assign(buffer.data(), length);
                return true;
            }
            if (buffer.size() >= 32768) {
                SetLastError(ERROR_FILENAME_EXCED_RANGE);
                return false;
            }
            buffer.resize(buffer.size() * 2);
        }
    }

    bool DefaultModulePath(std::wstring *path) {
        if (!GetExecutablePath(path))
            return false;
        const size_t slash = path->find_last_of(L"\\/");
        if (slash == std::wstring::npos) {
            SetLastError(ERROR_BAD_PATHNAME);
            return false;
        }
        path->resize(slash + 1);
        path->append(L"SbieHideEx.dll");
        return true;
    }

    bool WriteCoreBaseFile(
        const std::wstring &path,
        ULONG_PTR           coreBase,
        PVOID               localImage) {
        if (path.empty()) {
            return true;
        }
        const ULONG stateRva     = GetExportOffset(localImage, "MODULE_INITIALIZATION_STATE");
        const ULONG failureRva   = GetExportOffset(localImage, "MODULE_INITIALIZATION_FAILURE_STAGE");
        const ULONG bootstrapRva = GetExportOffset(localImage, "ModulePreProcessInitRoutine");
        const ULONG hitCountRva  = GetExportOffset(localImage, "LDR_GET_DLL_HANDLE_HIT_COUNT");
        const ULONG hideCountRva = GetExportOffset(localImage, "LDR_GET_DLL_HANDLE_HIDE_COUNT");
        if (!stateRva || !failureRva || !bootstrapRva || !hitCountRva || !hideCountRva) {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return false;
        }
        char      text[128] = {};
        const int length    = std::snprintf(
            text,
            sizeof(text),
            "%llX %lX %lX %lX %lX %lX",
            static_cast<unsigned long long>(coreBase),
            stateRva,
            failureRva,
            bootstrapRva,
            hitCountRva,
            hideCountRva);
        if (length <= 0 || length >= sizeof(text)) {
            SetLastError(ERROR_INVALID_DATA);
            return false;
        }
        const HANDLE file = CreateFileW(
            path.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            return false;
        }
        DWORD      written = 0;
        const BOOL success = WriteFile(
            file, text, static_cast<DWORD>(length), &written, nullptr);
        const DWORD error = success && written == static_cast<DWORD>(length)
                                ? ERROR_SUCCESS
                                : (GetLastError() != ERROR_SUCCESS
                                       ? GetLastError()
                                       : ERROR_WRITE_FAULT);
        CloseHandle(file);
        SetLastError(error);
        return error == ERROR_SUCCESS;
    }

    void PrintUsage(const wchar_t *program) {
        std::fwprintf(
            stderr,
            L"Usage: %ls [--verify-initialization] [--write-core-base <path>] [--module <SbieHideEx.dll>] <target.exe> [arguments...]\n",
            program);
    }

    bool HasSingleInitialThread(HANDLE process) {
        HANDLE current     = nullptr;
        ULONG  threadCount = 0;
        for (;;) {
            HANDLE         next   = nullptr;
            const NTSTATUS status = NtGetNextThread(
                process,
                current,
                THREAD_QUERY_LIMITED_INFORMATION,
                0,
                0,
                &next);
            if (current != nullptr) {
                NtClose(current);
                current = nullptr;
            }
            if (status == STATUS_NO_MORE_ENTRIES) {
                return threadCount == 1;
            }
            if (!NT_SUCCESS(status) || next == nullptr) {
                if (next != nullptr) {
                    NtClose(next);
                }
                SetLastError(NT_SUCCESS(status) ? ERROR_INVALID_HANDLE : RtlNtStatusToDosError(status));
                return false;
            }
            current = next;
            ++threadCount;
            if (threadCount > 1) {
                NtClose(current);
                SetLastError(ERROR_INVALID_STATE);
                return false;
            }
        }
    }

} // namespace

int wmain(int argc, wchar_t *argv[]) {
#ifndef _WIN64
    std::fwprintf(stderr, L"SbieHideExLoader supports x64 targets only.\n");
    return ERROR_NOT_SUPPORTED;
#else
    std::wstring modulePath;
    bool         verifyInitialization = false;
    std::wstring coreBasePath;
    int          targetIndex = 1;
    while (targetIndex < argc) {
        if (wcscmp(argv[targetIndex], L"--verify-initialization") == 0) {
            verifyInitialization = true;
            ++targetIndex;
            continue;
        }
        if (wcscmp(argv[targetIndex], L"--write-core-base") == 0) {
            if (!coreBasePath.empty() || targetIndex + 2 >= argc) {
                PrintUsage(argv[0]);
                return ERROR_INVALID_PARAMETER;
            }
            coreBasePath = argv[targetIndex + 1];
            targetIndex += 2;
            continue;
        }
        if (wcscmp(argv[targetIndex], L"--module") == 0) {
            if (!modulePath.empty() || targetIndex + 2 >= argc) {
                PrintUsage(argv[0]);
                return ERROR_INVALID_PARAMETER;
            }
            modulePath = argv[targetIndex + 1];
            targetIndex += 2;
            continue;
        }
        break;
    }
    if (modulePath.empty() && !DefaultModulePath(&modulePath)) {
        const DWORD error = GetLastError();
        std::fwprintf(stderr, L"Unable to locate adjacent SbieHideEx.dll (error %lu).\n", error);
        return static_cast<int>(error ? error : ERROR_BAD_PATHNAME);
    }

    if (targetIndex >= argc) {
        PrintUsage(argv[0]);
        return ERROR_INVALID_PARAMETER;
    }

    std::vector<std::wstring> childArguments;
    for (int index = targetIndex; index < argc; ++index) {
        childArguments.emplace_back(argv[index]);
    }

    loader::SuspendedProcess child;
    const DWORD              createError = loader::CreateSuspendedProcess(childArguments.front(), childArguments, &child);
    if (createError != ERROR_SUCCESS) {
        std::fwprintf(stderr, L"Unable to create suspended child process (error %lu).\n", createError);
        return static_cast<int>(createError);
    }

    const auto failChild = [&child](DWORD error) {
        const DWORD abortError = child.Abort();
        if (abortError != ERROR_SUCCESS) {
            std::fwprintf(
                stderr,
                L"Unable to confirm suspended child termination (error %lu).\n",
                abortError);
            return static_cast<int>(abortError);
        }
        return static_cast<int>(error != ERROR_SUCCESS ? error : ERROR_GEN_FAILURE);
    };

    ULONG_PTR remoteModule = 0;
    PVOID     localImage   = nullptr;
    if (!MapCoreLibraryToProtectedProcessW(modulePath.c_str(), child.process(), &remoteModule, &localImage)) {
        const DWORD error = GetLastError();
        std::fwprintf(stderr, L"Unable to map %ls (error %lu).\n", modulePath.c_str(), error);
        return failChild(error != ERROR_SUCCESS ? error : ERROR_BAD_EXE_FORMAT);
    }

    const auto releaseLocal = [&localImage]() {
        if (localImage) {
            std::free(localImage);
            localImage = nullptr;
        }
    };

    if (!WriteCoreBaseFile(coreBasePath, remoteModule, localImage)) {
        const DWORD error = GetLastError();
        releaseLocal();
        return failChild(error != ERROR_SUCCESS ? error : ERROR_WRITE_FAULT);
    }

    std::wprintf(L"Core library mapped at 0x%p.\n", reinterpret_cast<void *>(remoteModule));
    if (!RemapNtDllInProtectProcessAndPatch(child.process(), remoteModule, reinterpret_cast<ULONG_PTR>(localImage))) {
        const DWORD error = GetLastError();
        std::fwprintf(stderr, L"Unable to patch child ntdll transactionally (error %lu).\n", error);
        releaseLocal();
        return failChild(error != ERROR_SUCCESS ? error : ERROR_WRITE_FAULT);
    }

    HANDLE         initializationSection       = nullptr;
    volatile LONG *initializationSignal        = nullptr;
    const auto     releaseInitializationSignal = [&]() {
        if (initializationSignal != nullptr) {
            UnmapViewOfFile(const_cast<LONG *>(initializationSignal));
            initializationSignal = nullptr;
        }
        if (initializationSection != nullptr) {
            CloseHandle(initializationSection);
            initializationSection = nullptr;
        }
    };
    if (verifyInitialization) {
        const ULONG signalRva = GetExportOffset(localImage, "MODULE_INITIALIZATION_SIGNAL");
        if (!signalRva) {
            releaseLocal();
            return failChild(ERROR_PROC_NOT_FOUND);
        }
        initializationSection = CreateFileMappingW(
            INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 4096, nullptr);
        if (initializationSection == nullptr) {
            const DWORD error = GetLastError();
            releaseLocal();
            return failChild(error);
        }
        initializationSignal    = static_cast<volatile LONG *>(MapViewOfFile(
            initializationSection, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 4096));
        PVOID    remoteSignal   = nullptr;
        SIZE_T   signalViewSize = 4096;
        NTSTATUS signalStatus   = initializationSignal != nullptr
                                      ? NtMapViewOfSection(
                                          initializationSection,
                                          child.process(),
                                          &remoteSignal,
                                          0,
                                          0,
                                          nullptr,
                                          &signalViewSize,
                                          ViewShare,
                                          0,
                                          PAGE_READWRITE)
                                      : STATUS_NO_MEMORY;
        SIZE_T   bytesWritten   = 0;
        if (NT_SUCCESS(signalStatus)) {
            signalStatus = NtWriteVirtualMemory(
                child.process(),
                reinterpret_cast<PVOID>(remoteModule + signalRva),
                &remoteSignal,
                sizeof(remoteSignal),
                &bytesWritten);
        }
        if (!NT_SUCCESS(signalStatus) || bytesWritten != sizeof(remoteSignal)) {
            const DWORD error = NT_SUCCESS(signalStatus)
                                    ? ERROR_PARTIAL_COPY
                                    : RtlNtStatusToDosError(signalStatus);
            releaseInitializationSignal();
            releaseLocal();
            return failChild(error);
        }
    }

    if (!HasSingleInitialThread(child.process())) {
        const DWORD error = GetLastError();
        releaseInitializationSignal();
        releaseLocal();
        return failChild(error != ERROR_SUCCESS ? error : ERROR_INVALID_STATE);
    }

    const NTSTATUS resumeStatus = NtResumeProcess(child.process());
    if (!NT_SUCCESS(resumeStatus)) {
        const DWORD error = RtlNtStatusToDosError(resumeStatus);
        std::fwprintf(stderr, L"Unable to resume child process (NTSTATUS 0x%08lX, error %lu).\n", static_cast<unsigned long>(resumeStatus), error);
        releaseInitializationSignal();
        releaseLocal();
        return failChild(error != ERROR_SUCCESS ? error : ERROR_GEN_FAILURE);
    }

    if (verifyInitialization) {
        bool ready = false;
        for (unsigned attempt = 0; attempt < 100; ++attempt) {
            const LONG state = InterlockedCompareExchange(
                const_cast<LONG *>(initializationSignal), 0, 0);
            if (state == 2) {
                ready = true;
                break;
            }
            if (state >= 3) {
                const LONG failureStage = InterlockedCompareExchange(
                    const_cast<LONG *>(initializationSignal + 1), 0, 0);
                std::fwprintf(
                    stderr,
                    L"SbieHideEx initialization failed at stage %ld.\n",
                    failureStage);
                releaseInitializationSignal();
                releaseLocal();
                return failChild(ERROR_DLL_INIT_FAILED);
            }
            Sleep(50);
        }
        if (!ready) {
            releaseInitializationSignal();
            releaseLocal();
            return failChild(ERROR_TIMEOUT);
        }
    }
    releaseInitializationSignal();

    child.Commit(); // PR #8: a successfully resumed child must never be terminated by cleanup.
    releaseLocal();
    std::wprintf(L"Successfully started child process %lu.\n", child.process_id());
    return 0;
#endif
}
