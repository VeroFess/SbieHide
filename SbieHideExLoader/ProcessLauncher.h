#pragma once

#include <phnt_windows.h>
#include <string>
#include <vector>

namespace loader {

    class SuspendedProcess {
        public:
            SuspendedProcess() noexcept;
            ~SuspendedProcess();
            SuspendedProcess(const SuspendedProcess &)            = delete;
            SuspendedProcess &operator=(const SuspendedProcess &) = delete;
            SuspendedProcess(SuspendedProcess &&other) noexcept;
            SuspendedProcess &operator=(SuspendedProcess &&other) noexcept;

            HANDLE process() const noexcept {
                return process_;
            }
            HANDLE thread() const noexcept {
                return thread_;
            }
            DWORD process_id() const noexcept {
                return processId_;
            }
            void Commit() noexcept {
                committed_ = true;
            }
            DWORD Abort() noexcept;
            void  Reset() noexcept;

        private:
            friend DWORD CreateSuspendedProcess(const std::wstring &, const std::vector<std::wstring> &, SuspendedProcess *);
            HANDLE       process_;
            HANDLE       thread_;
            DWORD        processId_;
            bool         committed_;
    };

    DWORD CreateSuspendedProcess(const std::wstring &application, const std::vector<std::wstring> &arguments, SuspendedProcess *child);

} // namespace loader
