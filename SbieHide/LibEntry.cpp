#include "MINT.h"
#include "MinHook.h"

#ifdef _DEBUG
#ifdef _WIN64
#pragma comment(lib, "libMinHook.x64.mtd.lib")
#else
#pragma comment(lib, "libMinHook.x86.mtd.lib")
#endif
#else
#ifdef _WIN64
#pragma comment(lib, "libMinHook.x64.mt.lib")
#else
#pragma comment(lib, "libMinHook.x86.mt.lib")
#endif
#endif

typedef NTSTATUS(NTAPI* NtQueryVirtualMemoryType)(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength);
NtQueryVirtualMemoryType NtQueryVirtualMemorySaved = nullptr;
typedef NTSTATUS(NTAPI* NtQueryObjectType)(_In_opt_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength);
NtQueryObjectType NtQueryObjectSaved = nullptr;

VOID EraseModuleNameFromPeb(PCWCH ModuleToHide) {
	PPEB                      ProcessEnvironmentBlock = nullptr;
	PLDR_DATA_TABLE_ENTRY     FirstEntry = nullptr;
	PLDR_DATA_TABLE_ENTRY     CurrentEntry = nullptr;

	ProcessEnvironmentBlock = NtCurrentPeb();
	FirstEntry = CurrentEntry = CONTAINING_RECORD(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink), LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

	while (reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(CONTAINING_RECORD(CurrentEntry->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)) != FirstEntry) {
		if (_wcsnicmp(CurrentEntry->BaseDllName.Buffer, ModuleToHide, CurrentEntry->BaseDllName.Length) == 0) {
			RtlZeroMemory(CurrentEntry->BaseDllName.Buffer, CurrentEntry->BaseDllName.MaximumLength);
			CurrentEntry->BaseDllName.Length = 0;
			RtlZeroMemory(CurrentEntry->FullDllName.Buffer, CurrentEntry->FullDllName.MaximumLength);
			CurrentEntry->FullDllName.Length = 0;
			CurrentEntry->BaseNameHashValue = 0;
		}

		CurrentEntry = CONTAINING_RECORD(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(CurrentEntry->InMemoryOrderLinks.Flink), LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	}
}


NTSTATUS NTAPI NtQueryVirtualMemoryProxy(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength) {
	NTSTATUS Status = STATUS_SUCCESS;

	Status = NtQueryVirtualMemorySaved(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

	if (NT_SUCCESS(Status) && MemoryInformationClass == MemoryMappedFilenameInformation) {
		UNICODE_STRING MemoryMappedFilename = {};

		if (!NT_SUCCESS(RtlUpcaseUnicodeString(&MemoryMappedFilename, reinterpret_cast<PUNICODE_STRING>(MemoryInformation), TRUE))) {
			return Status;
		}

		if (MemoryMappedFilename.Buffer == NULL || MemoryMappedFilename.Length == 0) {
			RtlFreeUnicodeString(&MemoryMappedFilename);
			return Status;
		}

		if ((wcsstr(MemoryMappedFilename.Buffer, L"SBIEDLL") != 0) || (wcsstr(MemoryMappedFilename.Buffer, L"SBIEHIDE") != 0)) {
			RtlZeroMemory(reinterpret_cast<PUNICODE_STRING>(MemoryInformation)->Buffer, reinterpret_cast<PUNICODE_STRING>(MemoryInformation)->MaximumLength);
			reinterpret_cast<PUNICODE_STRING>(MemoryInformation)->Length = 0;
		}

		RtlFreeUnicodeString(&MemoryMappedFilename);

		return STATUS_ACCESS_DENIED;
	}

	return Status;
}

NTSTATUS NTAPI NtQueryObjectProxy(_In_opt_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength) {
	NTSTATUS Status = STATUS_SUCCESS;

	Status = NtQueryObjectSaved(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

	if (NT_SUCCESS(Status) && ObjectInformationClass == ObjectNameInformation) {
		UNICODE_STRING ObjectName = {};

		if (!NT_SUCCESS(RtlUpcaseUnicodeString(&ObjectName, &reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name, TRUE))) {
			return Status;
		}

		if (ObjectName.Buffer == NULL || ObjectName.Length == 0) {
			RtlFreeUnicodeString(&ObjectName);
			return Status;
		}

		if ((wcsstr(ObjectName.Buffer, L"SBIEDLL") != 0) || (wcsstr(ObjectName.Buffer, L"SBIEHIDE") != 0)) {
			RtlZeroMemory(reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.Buffer, reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.MaximumLength);
			reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.Length = 0;
		}

		RtlFreeUnicodeString(&ObjectName);

		return STATUS_ACCESS_DENIED;
	}

	return Status;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		if (MH_Initialize() != MH_OK) {
			return FALSE;
		}

		if (MH_CreateHook(NtQueryVirtualMemory, NtQueryVirtualMemoryProxy, reinterpret_cast<PVOID*>(&NtQueryVirtualMemorySaved)) != MH_OK) {
			return FALSE;
		}

		if (MH_EnableHook(NtQueryVirtualMemory) != MH_OK) {
			return FALSE;
		}

		if (MH_CreateHook(NtQueryObject, NtQueryObjectProxy, reinterpret_cast<PVOID*>(&NtQueryObjectSaved)) != MH_OK) {
			return FALSE;
		}

		if (MH_EnableHook(NtQueryObject) != MH_OK) {
			return FALSE;
		}

		EraseModuleNameFromPeb(L"SbieHide.dll");
		EraseModuleNameFromPeb(L"SbieDll.dll");
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}