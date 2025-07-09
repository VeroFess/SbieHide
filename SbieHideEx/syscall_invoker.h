#pragma once

#include <phnt_windows.h>
#include <phnt.h>
#include <cstddef>
#include <cstdint>

extern int    NtFreeVirtualMemorySystemCallIndex;
extern int    NtQueryVirtualMemorySystemCallIndex;
extern int    NtQuerySystemInformationSystemCallIndex;
extern int    NtAllocateVirtualMemorySystemCallIndex;
extern int    NtDelayExecutionSystemCallIndex;
extern int    NtProtectVirtualMemorySystemCallIndex;
extern int    NtQueryInformationProcessSystemCallIndex;
extern int    NtQuerySectionSystemCallIndex;
extern int    NtQueryInformationFileSystemCallIndex;
extern int    NtQueryObjectSystemCallIndex;
extern BYTE   ENTRY_DATA[256];
extern SIZE_T ENTRY_DATA_SIZE;
extern PVOID  NTDLL_BASE_ADDRESS;
extern SIZE_T NTDLL_SIZE;
extern PVOID  SBIEHIDE_BASE_ADDRESS;
extern SIZE_T SBIEHIDE_SIZE;
extern PVOID  SBIE_BASE_ADDRESS;
extern SIZE_T SBIE_SIZE;
extern BOOL   PROCESS_INITIALIZATION_FINISHED;

extern "C" void *_invoke_systemcall_internal_asm();

template<typename... Args>
static __forceinline auto _invoke_systemcall_internal(Args... args) -> uintptr_t {
    auto _invoke_systemcall_internal_asm_function = reinterpret_cast<uintptr_t (*)(Args...)>(_invoke_systemcall_internal_asm);
    return _invoke_systemcall_internal_asm_function(args...);
}

template<std::size_t argc, typename>
struct argument_remapper {
        template<typename First, typename Second, typename Third, typename Fourth, typename... Pack>
        static auto _invoke_systemcall(std::uint32_t idx, First first, Second second, Third third, Fourth fourth, Pack... pack) -> uintptr_t {
            return _invoke_systemcall_internal(first, second, third, fourth, idx, nullptr, pack...);
        }
};

template<std::size_t Argc>
struct argument_remapper<Argc, std::enable_if_t<Argc <= 4>> {
        template<typename First = void *, typename Second = void *, typename Third = void *, typename Fourth = void *>
        static auto _invoke_systemcall(std::uint32_t idx, First first = First {}, Second second = Second {}, Third third = Third {}, Fourth fourth = Fourth {}) -> uintptr_t {
            return _invoke_systemcall_internal(first, second, third, fourth, idx, nullptr);
        }
};

template<typename Return, typename... Args>
static __forceinline auto invoke_systemcall(std::uint32_t idx, Args... args) -> Return {
    using mapper = argument_remapper<sizeof...(Args), void>;
    return static_cast<Return>(mapper::_invoke_systemcall(idx, args...));
}
