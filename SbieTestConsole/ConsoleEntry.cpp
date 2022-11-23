#include "MINT.h"
#include <stdio.h>

char NameBuffer[0x1000] = {};
PUNICODE_STRING MemoryMappedFilename = reinterpret_cast<PUNICODE_STRING>(NameBuffer);

VOID CheckSandboxieByGetModuleHandle() {
	printf("Handle of SbieHide.dll is 0x%016llX\n", reinterpret_cast<UINT64>(GetModuleHandleA("SbieHide.dll")));
	printf("Handle of SbieDll.dll is 0x%016llX\n", reinterpret_cast<UINT64>(GetModuleHandleA("SbieDll.dll")));
}

VOID CheckSandboxieByQueryVirtualMemoryMappedFilename() {
	SIZE_T ReturnedLength = 0;
	NTSTATUS Status = STATUS_SUCCESS;
	HMODULE SbieDllAddress = GetModuleHandleA("SbieDll.dll");

	if (SbieDllAddress == NULL) {
		printf("disable EraseModuleNameFromPeb(L\"SbieDll.dll\"); in sbiehide first!\n");
		return;
	}

	Status = NtQueryVirtualMemory(NtCurrentProcess(), GetModuleHandleA("SbieHide.dll"), MemoryMappedFilenameInformation, NameBuffer, 0x1000, &ReturnedLength);
	
	if (Status != STATUS_ACCESS_DENIED) {
		printf("Sbiedll found! check hook\n");
	}
	else {
		printf("Test pass\n");
	}
}

int main() {
	CheckSandboxieByGetModuleHandle();
	CheckSandboxieByQueryVirtualMemoryMappedFilename();

	getchar();
	return 0;
}