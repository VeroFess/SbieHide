#pragma once

#include <phnt_windows.h>
#include <phnt.h>

BOOL  MapCoreLibraryToProtectedProcessW(PCWSTR CoreLibraryPath, HANDLE ProtectedProcessHandle, PULONG_PTR MappedImageBase, PPVOID LocalBuffer);
BOOL  MapCoreLibraryToProtectedProcess(PCCH CoreLibraryPath, HANDLE ProtectedProcessHandle, PULONG_PTR MappedImageBase, PPVOID LocalBuffer);
ULONG GetExportOffset(_In_ PVOID ImageBase, _In_ PCCH ExportName);
ULONG GetExportOffsetChecked(_In_ PVOID ImageBase, _In_ SIZE_T ImageSize, _In_ PCCH ExportName, _In_ SIZE_T MinimumSize);
