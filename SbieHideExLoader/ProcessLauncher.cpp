#include "ProcessLauncher.h"
#include "CommandLine.h"

#include <phnt.h>

#include <utility>

namespace loader {

    SuspendedProcess::SuspendedProcess() noexcept
        : process_(nullptr), thread_(nullptr), processId_(0), committed_(false) {}

    SuspendedProcess::~SuspendedProcess() {
        Reset();
    }

    SuspendedProcess::SuspendedProcess(SuspendedProcess &&other) noexcept
        : process_(other.process_), thread_(other.thread_), processId_(other.processId_), committed_(other.committed_) {
        other.process_   = nullptr;
        other.thread_    = nullptr;
        other.processId_ = 0;
        other.committed_ = true;
    }

    SuspendedProcess &SuspendedProcess::operator=(SuspendedProcess &&other) noexcept {
        if (this != &other) {
            Reset();
            process_         = other.process_;
            thread_          = other.thread_;
            processId_       = other.processId_;
            committed_       = other.committed_;
            other.process_   = nullptr;
            other.thread_    = nullptr;
            other.processId_ = 0;
            other.committed_ = true;
        }
        return *this;
    }

    DWORD SuspendedProcess::Abort() noexcept {
        if (!process_ || committed_) {
            return ERROR_SUCCESS;
        }
        if (!TerminateProcess(process_, ERROR_PROCESS_ABORTED)) {
            const DWORD error = GetLastError();
            if (WaitForSingleObject(process_, 0) != WAIT_OBJECT_0) {
                return error != ERROR_SUCCESS ? error : ERROR_PROCESS_ABORTED;
            }
        } else if (WaitForSingleObject(process_, 5000) != WAIT_OBJECT_0) {
            return ERROR_TIMEOUT;
        }
        committed_ = true;
        return ERROR_SUCCESS;
    }

    void SuspendedProcess::Reset() noexcept {
        if (process_ && !committed_) {
            Abort();
        }
        if (thread_) {
            CloseHandle(thread_);
        }
        if (process_) {
            CloseHandle(process_);
        }
        process_   = nullptr;
        thread_    = nullptr;
        processId_ = 0;
        committed_ = false;
    }

    DWORD CreateSuspendedProcess(const std::wstring &application, const std::vector<std::wstring> &arguments, SuspendedProcess *child) {
        if (!child || application.empty() || arguments.empty()) {
            return ERROR_INVALID_PARAMETER;
        }
        child->Reset();

        STARTUPINFOW startup             = {};
        startup.cb                       = sizeof(startup);
        PROCESS_INFORMATION  information = {};
        std::wstring         commandLine = BuildCommandLine(arguments);
        std::vector<wchar_t> writable(commandLine.begin(), commandLine.end());
        writable.push_back(L'\0');

        const BOOL created = CreateProcessW(
            application.c_str(), writable.data(), nullptr, nullptr, FALSE,
            CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED,
            nullptr, nullptr, &startup, &information);
        const DWORD createError = created ? ERROR_SUCCESS : GetLastError();
        if (!created) {
            return createError;
        }

        child->process_   = information.hProcess;
        child->thread_    = information.hThread;
        child->processId_ = information.dwProcessId;
        child->committed_ = false;
        return ERROR_SUCCESS;
    }

} // namespace loader
