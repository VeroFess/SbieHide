#pragma once

#pragma once

#include <phnt_windows.h>
#include <phnt.h>

BOOL RemapNtDllInProtectProcessAndPatch(HANDLE ProcessHandle, ULONG_PTR RemoteProxyBase, ULONG_PTR LocalBuffer);
