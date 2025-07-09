#pragma once

#include <phnt_windows.h>
#include <phnt.h>

#include "simple_runtime_library.h"

typedef VOID(NTAPI *LDRPCALLTLSINITIALIZERSTYPE)(IN ULONG_PTR Arg1, IN ULONG_PTR Arg2);
typedef NTSTATUS(NTAPI *LDRLOADDLLTYPE)(_In_opt_ PWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID *DllHandle);

constexpr ULONG64 LdrShutdownThreadHash = Crc64(0, "LdrShutdownThread");
constexpr ULONG64 LdrLoadDllHash        = Crc64(0, "LdrLoadDll");

extern LDRPCALLTLSINITIALIZERSTYPE LdrpCallTlsInitializersOriginal;
extern LDRLOADDLLTYPE              LdrLoadDllOriginal;

VOID NTAPI     LdrpCallTlsInitializersDetours(IN ULONG_PTR Arg1, IN ULONG_PTR Arg2);
NTSTATUS NTAPI LdrLoadDllDetours(_In_opt_ PWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID *DllHandle);