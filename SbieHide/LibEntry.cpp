#pragma once

#include <phnt_windows.h>
#include <phnt.h>
#include "APIHook.h"
#include "MemoryImageHideInformation.h"
#include "HideFromPEB.h"

extern "C" __declspec(dllexport) int GetHookAPIs(PVOID a, PVOID b, PVOID c) {
    return 0x01;
}

extern "C" __declspec(dllexport) int NotifyShims(PVOID a, PVOID b) {
    InitMemoryImageHideInformation();
    EraseModuleNameFromPeb();
    EnableApiHook();

    return 0x01;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    BOOL skipHook = FALSE;
    PPEB peb      = NtCurrentPeb();

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		if (peb && peb->ProcessParameters)
		{
			UNICODE_STRING* processName = &peb->ProcessParameters->ImagePathName;
			if (processName->Buffer && processName->Length > 0)
			{
				WCHAR* fileName = processName->Buffer;
				for (USHORT i = 0; i < processName->Length / sizeof(WCHAR); i++)
				{
					if (processName->Buffer[i] == L'\\' || processName->Buffer[i] == L'/')
						fileName = &processName->Buffer[i + 1];
				}

				if (_wcsicmp(fileName, L"SandboxieRpcSs.exe") == 0 ||
					_wcsicmp(fileName, L"SandboxieDcomLaunch.exe") == 0)
				{
					skipHook = TRUE;
				}
			}
		}

		if (!skipHook)
		{
			InitMemoryImageHideInformation();
			EraseModuleNameFromPeb();
			EnableApiHook();
		}
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}