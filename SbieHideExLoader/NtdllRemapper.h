#pragma once

#include <phnt_windows.h>
#include <phnt.h>

BOOL QueryRemoteNtdllImage(HANDLE ProcessHandle, PVOID *ImageBase, PSIZE_T ImageSize);
BOOL RemapNtDllInProtectProcessAndPatch(HANDLE ProcessHandle, ULONG_PTR RemoteProxyBase, ULONG_PTR LocalBuffer);
