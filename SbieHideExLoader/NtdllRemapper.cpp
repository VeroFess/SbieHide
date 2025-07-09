#include "NtdllRemapper.h"
#include "SbieHideLoader.h"
#include <algorithm>

constexpr unsigned char FunctionHookTrampoline[] = {
    /* +00 */ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    /* +06 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

bool InstallRemoteJumpHook(HANDLE ProcessHandle, PVOID TargetFunction, PVOID HookFunction) {
    unsigned char              Trampoline[sizeof(FunctionHookTrampoline)];
    MEMORY_BASIC_INFORMATION64 MemoryInfo   = {};
    SIZE_T                     ReturnLen    = 0;
    NTSTATUS                   Status       = 0;
    PVOID                      RegionBase   = nullptr;
    SIZE_T                     RegionSize   = 0;
    ULONG                      OldProtect   = 0;
    SIZE_T                     BytesWritten = 0;
    ULONG                      TempProtect  = 0;
    bool                       bSuccess     = false;

    if (!ProcessHandle || !TargetFunction || !HookFunction)
        return false;

    memcpy(Trampoline, FunctionHookTrampoline, sizeof(FunctionHookTrampoline));
    *reinterpret_cast<ULONG_PTR *>(Trampoline + 6) = reinterpret_cast<ULONG_PTR>(HookFunction);

    Status = NtQueryVirtualMemory(ProcessHandle, TargetFunction, MemoryBasicInformation, &MemoryInfo, sizeof(MemoryInfo), &ReturnLen);
    if (!NT_SUCCESS(Status))
        return false;

    RegionBase = reinterpret_cast<PVOID>(MemoryInfo.BaseAddress);
    RegionSize = static_cast<SIZE_T>(MemoryInfo.RegionSize);

    Status = NtProtectVirtualMemory(ProcessHandle, &RegionBase, &RegionSize, PAGE_EXECUTE_READWRITE, &OldProtect);
    if (!NT_SUCCESS(Status))
        return false;

    Status = NtWriteVirtualMemory(ProcessHandle, TargetFunction, Trampoline, static_cast<ULONG>(sizeof(Trampoline)), &BytesWritten);

    bSuccess = NT_SUCCESS(Status) && (BytesWritten == sizeof(Trampoline));

    NtFlushInstructionCache(ProcessHandle, TargetFunction, sizeof(Trampoline));

    NtProtectVirtualMemory(ProcessHandle, &RegionBase, &RegionSize, OldProtect, &TempProtect);

    return bSuccess;
}

BOOL RemapNtDllInProtectProcessAndPatch(HANDLE ProcessHandle, ULONG_PTR RemoteProxyBase, ULONG_PTR LocalBuffer) {
    BOOL bResult = TRUE;

#define MakeHook(F)                                                                                                                                                 \
    if (!InstallRemoteJumpHook(ProcessHandle, F, reinterpret_cast<PVOID>(RemoteProxyBase + GetExportOffset(reinterpret_cast<PVOID>(LocalBuffer), #F "Detours")))) { \
        bResult = FALSE;                                                                                                                                            \
        goto CleanAndExit;                                                                                                                                          \
    }

    MakeHook(NtQueryVirtualMemory);
    MakeHook(NtQueryObject);
    MakeHook(NtQueryInformationFile);
    MakeHook(NtQuerySection);
    MakeHook(NtQuerySystemInformation);
    MakeHook(NtQueryInformationProcess);

CleanAndExit:
    return bResult;
}