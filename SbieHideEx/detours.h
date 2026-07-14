#pragma once

#include <phnt_windows.h>
#include <phnt.h>

#include "simple_runtime_library.h"

typedef VOID(NTAPI *LDRPCALLTLSINITIALIZERSTYPE)(IN ULONG_PTR Arg1, IN ULONG_PTR Arg2);
typedef NTSTATUS(NTAPI *LDRLOADDLLTYPE)(_In_opt_ PWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID *DllHandle);
typedef NTSTATUS(NTAPI *LDRLOCKLOADERLOCKTYPE)(_In_ ULONG Flags, _Out_opt_ PULONG Disposition, _Out_ PVOID *Cookie);
typedef NTSTATUS(NTAPI *LDRUNLOCKLOADERLOCKTYPE)(_In_ ULONG Flags, _In_ PVOID Cookie);
typedef NTSTATUS(NTAPI *LDRGETDLLHANDLEEXTYPE)(_In_ ULONG Flags, _In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PCUNICODE_STRING DllName, _Out_ PVOID *DllHandle);
typedef NTSTATUS(NTAPI *LDRGETDLLHANDLETYPE)(_In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PCUNICODE_STRING DllName, _Out_ PVOID *DllHandle);
typedef HMODULE(WINAPI *GETMODULEHANDLEWTYPE)(_In_opt_ LPCWSTR ModuleName);

constexpr ULONG64 LdrShutdownThreadHash       = Crc64(0, "LdrShutdownThread");
constexpr ULONG64 LdrLoadDllHash              = Crc64(0, "LdrLoadDll");
constexpr ULONG64 NtFlushInstructionCacheHash = Crc64(0, "NtFlushInstructionCache");
constexpr ULONG64 LdrLockLoaderLockHash       = Crc64(0, "LdrLockLoaderLock");
constexpr ULONG64 LdrUnlockLoaderLockHash     = Crc64(0, "LdrUnlockLoaderLock");
constexpr ULONG64 LdrGetDllHandleExHash       = Crc64(0, "LdrGetDllHandleEx");
constexpr ULONG64 LdrGetDllHandleHash         = Crc64(0, "LdrGetDllHandle");
constexpr ULONG64 GetModuleHandleWHash        = Crc64(0, "GetModuleHandleW");

extern LDRPCALLTLSINITIALIZERSTYPE LdrpCallTlsInitializersOriginal;
extern LDRLOADDLLTYPE              LdrLoadDllOriginal;
extern LDRGETDLLHANDLEEXTYPE       LdrGetDllHandleExOriginal;
extern LDRGETDLLHANDLETYPE         LdrGetDllHandleOriginal;
extern GETMODULEHANDLEWTYPE        GetModuleHandleWOriginal;
extern "C" volatile LONG           LDR_GET_DLL_HANDLE_HIT_COUNT;
extern "C" volatile LONG           LDR_GET_DLL_HANDLE_HIDE_COUNT;

VOID           HideLoadedModules();
VOID NTAPI     LdrpCallTlsInitializersDetours(IN ULONG_PTR Arg1, IN ULONG_PTR Arg2);
NTSTATUS NTAPI LdrLoadDllDetours(_In_opt_ PWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID *DllHandle);
NTSTATUS NTAPI LdrGetDllHandleExDetours(_In_ ULONG Flags, _In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PCUNICODE_STRING DllName, _Out_ PVOID *DllHandle);
NTSTATUS NTAPI LdrGetDllHandleDetours(_In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PCUNICODE_STRING DllName, _Out_ PVOID *DllHandle);
HMODULE WINAPI GetModuleHandleWDetours(_In_opt_ LPCWSTR ModuleName);