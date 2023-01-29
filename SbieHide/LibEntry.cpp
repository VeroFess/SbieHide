#include "MINT.h"
#include "APIHook.h"
#include "MemoryImageHideInformation.h"
#include "HideFromPEB.h"


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
        InitMemoryImageHideInformation();

		EraseModuleNameFromPeb();

		EnableApiHook();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}