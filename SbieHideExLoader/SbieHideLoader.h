#pragma once

#include <phnt_windows.h>
#include <phnt.h>

BOOL  MapCoreLibraryToProtectedProcess(PCCH CoreLibraryPath, HANDLE ProtectedProcessHandle, PULONG_PTR MappedImageBase, PPVOID LocalBuffer);
ULONG GetExportOffset(_In_ PVOID ImageBase, _In_ PCCH ExportName);