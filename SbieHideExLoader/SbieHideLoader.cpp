#include "SbieHideLoader.h"
#include <stdio.h>

#include <psapi.h>
#include <cstdint>
#include <algorithm>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

BOOL FixLocalImageReloc(PVOID RemoteBase, LPVOID LocalBuffer) {
    PIMAGE_DOS_HEADER     DosHeader           = nullptr;
    PIMAGE_NT_HEADERS     NtHeader            = nullptr;
    PIMAGE_SECTION_HEADER SectionBegin        = nullptr;
    PIMAGE_SECTION_HEADER SectionEntity       = nullptr;
    PVOID                 BaseAddressToModify = nullptr;
    SIZE_T                SizeToModify        = 0;
    ULONG                 OldProtect          = 0;
    NTSTATUS              Status              = STATUS_SUCCESS;

    DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(LocalBuffer);
    if (DosHeader->e_magic != 0x5A4D) {
        return FALSE;
    }

    NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PUCHAR>(LocalBuffer) + DosHeader->e_lfanew);
    if (NtHeader->Signature != 0x00004550) {
        return FALSE;
    }

    if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) {
        return TRUE;
    }

    PIMAGE_BASE_RELOCATION RelocData     = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PUCHAR>(LocalBuffer) + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    PBYTE                  LocationDelta = reinterpret_cast<PBYTE>((reinterpret_cast<ULONG64>(RemoteBase) - NtHeader->OptionalHeader.ImageBase));

    while (RelocData->VirtualAddress) {
        UINT  AmountOfEntries = (RelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD RelativeInfo    = reinterpret_cast<PWORD>(RelocData + 1);

        for (UINT i = 0; i != AmountOfEntries; ++i, ++RelativeInfo) {
            if ((((*RelativeInfo) >> 0x0C) == IMAGE_REL_BASED_DIR64)) {
                UINT_PTR *Patch = reinterpret_cast<UINT_PTR *>(reinterpret_cast<PUCHAR>(LocalBuffer) + RelocData->VirtualAddress + ((*RelativeInfo) & 0xFFF));
                *Patch += reinterpret_cast<UINT_PTR>(LocationDelta);
            }
        }

        RelocData = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reinterpret_cast<BYTE *>(RelocData) + RelocData->SizeOfBlock);
    }

    return TRUE;
}

NTSTATUS CopyMemoryBlockToAddress(HANDLE ProtectedProcessHandle, PVOID LocalAddress, PVOID RemoteAddress, SIZE_T Size) {
    SIZE_T   RealWrite = 0;
    NTSTATUS Status    = STATUS_SUCCESS;

    if (!NT_SUCCESS(Status = NtWriteVirtualMemory(ProtectedProcessHandle, RemoteAddress, LocalAddress, Size, &RealWrite))) {
        goto CleanAndExit;
    }

    if (RealWrite != Size) {
        Status = STATUS_INCOMPATIBLE_FILE_MAP;
    }

CleanAndExit:
    return Status;
}

BOOL MapCoreLibraryToTargetProcessInternal(HANDLE ProtectedProcessHandle, PVOID RemoteBase, LPVOID LocalBuffer) {
    PIMAGE_DOS_HEADER     DosHeader     = nullptr;
    PIMAGE_NT_HEADERS     NtHeader      = nullptr;
    PIMAGE_SECTION_HEADER SectionBegin  = nullptr;
    PIMAGE_SECTION_HEADER SectionEntity = nullptr;
    PVOID                 LocalAddress  = nullptr;
    PVOID                 RemoteAddress = nullptr;
    SIZE_T                Size          = 0;
    NTSTATUS              Status        = STATUS_SUCCESS;

    DosHeader    = reinterpret_cast<PIMAGE_DOS_HEADER>(LocalBuffer);
    NtHeader     = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PUCHAR>(LocalBuffer) + DosHeader->e_lfanew);
    SectionBegin = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PUCHAR>(LocalBuffer) + DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    for (int SectionIndex = 0; SectionIndex < NtHeader->FileHeader.NumberOfSections; SectionIndex++) {
        SectionEntity = &SectionBegin[SectionIndex];
        LocalAddress  = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(LocalBuffer) + SectionEntity->VirtualAddress);
        RemoteAddress = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(RemoteBase) + SectionEntity->VirtualAddress);
        Size          = std::max(SectionEntity->Misc.VirtualSize, SectionEntity->SizeOfRawData);

        Status = CopyMemoryBlockToAddress(ProtectedProcessHandle, LocalAddress, RemoteAddress, Size);

        if (!NT_SUCCESS(Status)) {
            return FALSE;
        }
    }

    return NT_SUCCESS(Status);
}

static BOOL GetRemoteProcessMainModuleInformation(_In_ HANDLE RemoteProcessHandle, _Out_ HMODULE *RemoteImageBase, _Out_ MODULEINFO *RemoteModuleInfo, _Out_writes_(MAX_PATH) CHAR RemoteImagePath[MAX_PATH]) {
    DWORD ReturnLength = 0;

    if (!EnumProcessModulesEx(RemoteProcessHandle, RemoteImageBase, sizeof(*RemoteImageBase), &ReturnLength,
#ifdef _WIN64
                              LIST_MODULES_64BIT | LIST_MODULES_32BIT
#else
                              LIST_MODULES_32BIT
#endif
                              )) {
        return FALSE;
    }

    if (!GetModuleInformation(RemoteProcessHandle, *RemoteImageBase, RemoteModuleInfo, sizeof(*RemoteModuleInfo))) {
        return FALSE;
    }

    if (!GetModuleFileNameExA(RemoteProcessHandle, *RemoteImageBase, RemoteImagePath, MAX_PATH)) {
        return FALSE;
    }

    return TRUE;
}

BOOL CaptureRemoteEntrypointBytes(HANDLE ProtectedProcessHandle, PUCHAR EntryBuffer, PSIZE_T EntrySize) {
    NTSTATUS              Status                    = STATUS_SUCCESS;
    HMODULE               RemoteImageBase           = nullptr;
    MODULEINFO            RemoteModuleInfo          = {};
    CHAR                  RemoteImagePath[MAX_PATH] = {};
    HMODULE               LocalImageHandle          = nullptr;
    PVOID                 LocalWriteableImageBuffer = nullptr;
    PIMAGE_DOS_HEADER     LocalImageDosHeader       = nullptr;
    PIMAGE_NT_HEADERS     LocalImageNtHeader        = nullptr;
    PIMAGE_SECTION_HEADER LocalImageSectionBegin    = nullptr;
    PIMAGE_SECTION_HEADER LocalImageSectionEntity   = nullptr;
    SIZE_T                LocalImageSize            = 0;
    DWORD                 EntryPointRva             = 0;
    SIZE_T                RemainingBytesInSection   = 0;
    SIZE_T                BytesToCopy               = 0;
    SIZE_T                SectionIndex              = 0;
    DWORD                 ReturnLength              = 0;

    if (!GetRemoteProcessMainModuleInformation(ProtectedProcessHandle, &RemoteImageBase, &RemoteModuleInfo, RemoteImagePath)) {
        Status = STATUS_INVALID_PARAMETER;
        goto CleanAndExit;
    }

    if ((LocalImageHandle = LoadLibraryExA(RemoteImagePath, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE)) == NULL) {
        Status = STATUS_DLL_NOT_FOUND;
        goto CleanAndExit;
    }

    LocalImageDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(LocalImageHandle);
    LocalImageNtHeader  = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<PUCHAR>(LocalImageHandle) + LocalImageDosHeader->e_lfanew);

    LocalImageSize = LocalImageNtHeader->OptionalHeader.SizeOfImage;

    if ((LocalWriteableImageBuffer = malloc(LocalImageSize)) == nullptr) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanAndExit;
    }

    memcpy(LocalWriteableImageBuffer, reinterpret_cast<PVOID>(LocalImageHandle), LocalImageSize);

    if (!FixLocalImageReloc(RemoteImageBase, LocalWriteableImageBuffer)) {
        Status = STATUS_INVALID_IMAGE_WIN_64;
        goto CleanAndExit;
    }

    EntryPointRva          = LocalImageNtHeader->OptionalHeader.AddressOfEntryPoint;
    LocalImageSectionBegin = IMAGE_FIRST_SECTION(LocalImageNtHeader);

    for (SectionIndex = 0;
         SectionIndex < LocalImageNtHeader->FileHeader.NumberOfSections;
         SectionIndex++) {

        LocalImageSectionEntity = &LocalImageSectionBegin[SectionIndex];

        if (EntryPointRva >= LocalImageSectionEntity->VirtualAddress &&
            EntryPointRva < LocalImageSectionEntity->VirtualAddress + LocalImageSectionEntity->Misc.VirtualSize) {

            RemainingBytesInSection =
                LocalImageSectionEntity->VirtualAddress +
                LocalImageSectionEntity->Misc.VirtualSize -
                EntryPointRva;

            break;
        }
    }

    BytesToCopy = RemainingBytesInSection < 256 ? RemainingBytesInSection : 256;

    memcpy(EntryBuffer, reinterpret_cast<PUCHAR>(LocalWriteableImageBuffer) + EntryPointRva, BytesToCopy);

    *EntrySize = static_cast<ULONG>(BytesToCopy);

CleanAndExit:
    if (LocalWriteableImageBuffer != nullptr) {
        free(LocalWriteableImageBuffer);
    }

    if (LocalImageHandle != NULL) {
        FreeLibrary(LocalImageHandle);
    }

    return NT_SUCCESS(Status);
}

static uint32_t GetSyscallIndex(PVOID Function) {
    uint32_t index = 0;
    if (reinterpret_cast<PUCHAR>(Function)[0] == 0x4C && reinterpret_cast<PUCHAR>(Function)[1] == 0x8B && reinterpret_cast<PUCHAR>(Function)[2] == 0xD1 && reinterpret_cast<PUCHAR>(Function)[3] == 0xB8) {
        memcpy(&index, &reinterpret_cast<PUCHAR>(Function)[4], 4);
    }
    return index;
}

ULONG GetExportOffset(_In_ PVOID ImageBase, _In_ PCCH ExportName) {
    PIMAGE_DOS_HEADER       ImageDosHeader        = nullptr;
    PIMAGE_NT_HEADERS       ImageNtHeader         = nullptr;
    PIMAGE_EXPORT_DIRECTORY ImageExportDirectory  = nullptr;
    ULONG                   ExportRva             = 0;
    ULONG                   Index                 = 0;
    ULONG                   ExportDirectorySize   = 0;
    PULONG                  AddressOfNames        = nullptr;
    PULONG                  AddressOfFunctions    = nullptr;
    PUSHORT                 AddressOfNameOrdinals = nullptr;

    ImageDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase);
    if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    ImageNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<PUCHAR>(ImageBase) + ImageDosHeader->e_lfanew);

    if (ImageNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    ExportRva           = ImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ExportDirectorySize = ImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (ExportRva == 0 || ExportDirectorySize == 0) {
        return 0;
    }

    ImageExportDirectory  = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<PUCHAR>(ImageBase) + ExportRva);
    AddressOfNames        = reinterpret_cast<PULONG>(reinterpret_cast<PUCHAR>(ImageBase) + ImageExportDirectory->AddressOfNames);
    AddressOfFunctions    = reinterpret_cast<PULONG>(reinterpret_cast<PUCHAR>(ImageBase) + ImageExportDirectory->AddressOfFunctions);
    AddressOfNameOrdinals = reinterpret_cast<PUSHORT>(reinterpret_cast<PUCHAR>(ImageBase) + ImageExportDirectory->AddressOfNameOrdinals);

    for (Index = 0; Index < ImageExportDirectory->NumberOfNames; Index++) {
        PCCH CurrentName = reinterpret_cast<PCCH>(
            reinterpret_cast<PUCHAR>(ImageBase) + AddressOfNames[Index]);

        if (_stricmp(CurrentName, ExportName) == 0) {
            USHORT Ordinal = AddressOfNameOrdinals[Index];
            ULONG  FuncRva = AddressOfFunctions[Ordinal];
            return FuncRva;
        }
    }

    return 0;
}

BOOL MapCoreLibraryToProtectedProcess(PCCH CoreLibraryPath, HANDLE ProtectedProcessHandle, PULONG_PTR MappedImageBase, PPVOID LocalBuffer) {
    HMODULE                  CoreLibraryHandle                     = 0;
    MEMORY_IMAGE_INFORMATION LocalCoreLibraryImageInformation      = {};
    MEMORY_IMAGE_INFORMATION NtDllImageInformation                 = {};
    PVOID                    LocalWriteableCoreLibraryImageBuffer  = nullptr;
    SIZE_T                   LocalWriteableCoreLibraryCopyOffset   = 0;
    MEMORY_BASIC_INFORMATION LocalCoreLibraryMemoryBaseInformatiom = {};
    PVOID                    InjectedCoreLibraryBaseAddress        = 0;
    SIZE_T                   InjectedCoreLibraryAllocatedSize      = 0;
    PIMAGE_DOS_HEADER        LocalCoreLibraryDosHeader             = nullptr;
    PIMAGE_NT_HEADERS        LocalCoreLibraryNtHeader              = nullptr;
    PIMAGE_SECTION_HEADER    LocalCoreLibrarySectionBegin          = nullptr;
    PIMAGE_SECTION_HEADER    LocalCoreLibrarySectionEntity         = nullptr;
    INT                      NumberOfUsedVerifySlot                = 0;
    SIZE_T                   ReturnLength                          = 0;
    PUCHAR                   EntryBuffer                           = nullptr;
    SIZE_T                   EntrySize                             = 0;
    NTSTATUS                 Status                                = STATUS_SUCCESS;

    if ((CoreLibraryHandle = LoadLibraryExA(CoreLibraryPath, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE)) == nullptr) {
        goto CleanAndExit;
    }

    if (!NT_SUCCESS(Status = NtQueryVirtualMemory(NtCurrentProcess(), CoreLibraryHandle, MemoryImageInformation, &LocalCoreLibraryImageInformation, sizeof(MEMORY_IMAGE_INFORMATION), &ReturnLength))) {
        goto CleanAndExit;
    }

    if (!NT_SUCCESS(Status = NtQueryVirtualMemory(NtCurrentProcess(), NtQueryVirtualMemory, MemoryImageInformation, &NtDllImageInformation, sizeof(MEMORY_IMAGE_INFORMATION), &ReturnLength))) {
        goto CleanAndExit;
    }

    if ((LocalWriteableCoreLibraryImageBuffer = malloc(LocalCoreLibraryImageInformation.SizeOfImage)) == nullptr) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanAndExit;
    }

    do {
        if (!NT_SUCCESS(Status = NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<PUCHAR>(LocalCoreLibraryImageInformation.ImageBase) + LocalWriteableCoreLibraryCopyOffset, MemoryBasicInformation, &LocalCoreLibraryMemoryBaseInformatiom, sizeof(MEMORY_BASIC_INFORMATION), &ReturnLength))) {
            goto CleanAndExit;
        }

        if (LocalCoreLibraryMemoryBaseInformatiom.State == MEM_COMMIT) {
            memcpy(reinterpret_cast<PUCHAR>(LocalWriteableCoreLibraryImageBuffer) + LocalWriteableCoreLibraryCopyOffset, reinterpret_cast<PUCHAR>(LocalCoreLibraryImageInformation.ImageBase) + LocalWriteableCoreLibraryCopyOffset, LocalCoreLibraryMemoryBaseInformatiom.RegionSize);
        }

        LocalWriteableCoreLibraryCopyOffset += LocalCoreLibraryMemoryBaseInformatiom.RegionSize;
    } while (LocalWriteableCoreLibraryCopyOffset < LocalCoreLibraryImageInformation.SizeOfImage);

    InjectedCoreLibraryAllocatedSize = LocalCoreLibraryImageInformation.SizeOfImage;

    if (!NT_SUCCESS(Status = NtAllocateVirtualMemory(ProtectedProcessHandle, &InjectedCoreLibraryBaseAddress, 0, &InjectedCoreLibraryAllocatedSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))) {
        goto CleanAndExit;
    }

    if (InjectedCoreLibraryAllocatedSize < LocalCoreLibraryImageInformation.SizeOfImage) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanAndExit;
    }

    {
        EntryBuffer = reinterpret_cast<PUCHAR>(malloc(256));
        if (EntryBuffer == nullptr) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto CleanAndExit;
        }

        CaptureRemoteEntrypointBytes(ProtectedProcessHandle, EntryBuffer, &EntrySize);
        memcpy(reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(LocalWriteableCoreLibraryImageBuffer) + GetExportOffset(LocalWriteableCoreLibraryImageBuffer, "ENTRY_DATA")), EntryBuffer, EntrySize);
        memcpy(reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(LocalWriteableCoreLibraryImageBuffer) + GetExportOffset(LocalWriteableCoreLibraryImageBuffer, "ENTRY_DATA_SIZE")), &EntrySize, sizeof(SIZE_T));
        memcpy(reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(LocalWriteableCoreLibraryImageBuffer) + GetExportOffset(LocalWriteableCoreLibraryImageBuffer, "NTDLL_BASE_ADDRESS")), &NtDllImageInformation.ImageBase, sizeof(PVOID));
        memcpy(reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(LocalWriteableCoreLibraryImageBuffer) + GetExportOffset(LocalWriteableCoreLibraryImageBuffer, "NTDLL_SIZE")), &NtDllImageInformation.SizeOfImage, sizeof(SIZE_T));
        memcpy(reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(LocalWriteableCoreLibraryImageBuffer) + GetExportOffset(LocalWriteableCoreLibraryImageBuffer, "SBIEHIDE_BASE_ADDRESS")), &InjectedCoreLibraryBaseAddress, sizeof(PVOID));
        memcpy(reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(LocalWriteableCoreLibraryImageBuffer) + GetExportOffset(LocalWriteableCoreLibraryImageBuffer, "SBIEHIDE_SIZE")), &LocalCoreLibraryImageInformation.SizeOfImage, sizeof(SIZE_T));

#define SET_SYSCALL_INDEX(S)                                                                                                                                                                                      \
    {                                                                                                                                                                                                             \
        int S##Index = 0;                                                                                                                                                                                         \
        S##Index     = GetSyscallIndex(S);                                                                                                                                                                        \
        memcpy(reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(LocalWriteableCoreLibraryImageBuffer) + GetExportOffset(LocalWriteableCoreLibraryImageBuffer, #S "SystemCallIndex")), &S##Index, sizeof(int)); \
    }

        SET_SYSCALL_INDEX(NtFreeVirtualMemory);
        SET_SYSCALL_INDEX(NtQueryVirtualMemory);
        SET_SYSCALL_INDEX(NtQuerySystemInformation);
        SET_SYSCALL_INDEX(NtAllocateVirtualMemory);
        SET_SYSCALL_INDEX(NtDelayExecution);
        SET_SYSCALL_INDEX(NtProtectVirtualMemory);
        SET_SYSCALL_INDEX(NtQueryInformationProcess);
        SET_SYSCALL_INDEX(NtQuerySection);
        SET_SYSCALL_INDEX(NtQueryInformationFile);
        SET_SYSCALL_INDEX(NtQueryObject);

        free(EntryBuffer);
    }

    if (!FixLocalImageReloc(InjectedCoreLibraryBaseAddress, LocalWriteableCoreLibraryImageBuffer)) {
        Status = STATUS_INVALID_IMAGE_WIN_64;
        goto CleanAndExit;
    }

    if (!MapCoreLibraryToTargetProcessInternal(ProtectedProcessHandle, InjectedCoreLibraryBaseAddress, LocalWriteableCoreLibraryImageBuffer)) {
        Status = STATUS_UNEXPECTED_MM_MAP_ERROR;
        goto CleanAndExit;
    }

CleanAndExit:
    if (LocalWriteableCoreLibraryImageBuffer != nullptr) {
        *LocalBuffer = LocalWriteableCoreLibraryImageBuffer;
    }

    if (CoreLibraryHandle != NULL) {
        FreeLibrary(CoreLibraryHandle);
    }

    *MappedImageBase = reinterpret_cast<ULONG_PTR>(InjectedCoreLibraryBaseAddress);

    return NT_SUCCESS(Status);
}