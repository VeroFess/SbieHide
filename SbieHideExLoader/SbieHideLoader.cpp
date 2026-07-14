#include "SbieHideLoader.h"
#include "PeImageView.h"
#include "NtdllRemapper.h"

#include <psapi.h>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <limits>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

namespace {

    class LoadedImage {
        public:
            LoadedImage() noexcept
                : module_(nullptr) {}
            ~LoadedImage() {
                if (module_)
                    FreeLibrary(module_);
            }
            bool Load(PCWSTR path) {
                module_ = LoadLibraryExW(path, nullptr, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
                return module_ != nullptr;
            }
            HMODULE get() const noexcept {
                return module_;
            }

        private:
            HMODULE module_;
    };

    class MappedSystemImage {
        public:
            MappedSystemImage() noexcept
                : view_(nullptr), size_(0) {}
            ~MappedSystemImage() {
                if (view_) {
                    NtUnmapViewOfSection(NtCurrentProcess(), view_);
                }
            }

            bool Load(PCWSTR fileName) {
                if (fileName == nullptr || *fileName == L'\0') {
                    SetLastError(ERROR_INVALID_PARAMETER);
                    return false;
                }
                const std::wstring objectPath = std::wstring(L"\\KnownDlls\\") + fileName;
                UNICODE_STRING     path       = {};
                RtlInitUnicodeString(&path, objectPath.c_str());
                OBJECT_ATTRIBUTES attributes = {};
                InitializeObjectAttributes(
                    &attributes, &path, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

                HANDLE   section = nullptr;
                NTSTATUS status  = NtOpenSection(
                    &section, SECTION_MAP_READ | SECTION_QUERY, &attributes);
                if (!NT_SUCCESS(status)) {
                    SetLastError(RtlNtStatusToDosError(status));
                    return false;
                }

                SIZE_T viewSize = 0;
                status          = NtMapViewOfSection(
                    section,
                    NtCurrentProcess(),
                    &view_,
                    0,
                    0,
                    nullptr,
                    &viewSize,
                    ViewShare,
                    0,
                    PAGE_READONLY);
                NtClose(section);
                if (!NT_SUCCESS(status)) {
                    view_ = nullptr;
                    SetLastError(RtlNtStatusToDosError(status));
                    return false;
                }

                const auto dos = static_cast<const IMAGE_DOS_HEADER *>(view_);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
                    static_cast<ULONG>(dos->e_lfanew) > 0x100000) {
                    Reset(ERROR_BAD_EXE_FORMAT);
                    return false;
                }
                const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(
                    static_cast<const BYTE *>(view_) + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE ||
                    nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
                    nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
                    nt->OptionalHeader.SizeOfImage == 0) {
                    Reset(ERROR_BAD_EXE_FORMAT);
                    return false;
                }
                size_ = nt->OptionalHeader.SizeOfImage;
                return true;
            }

            PVOID base() const noexcept {
                return view_;
            }
            SIZE_T size() const noexcept {
                return size_;
            }

        private:
            void Reset(DWORD error) noexcept {
                if (view_) {
                    NtUnmapViewOfSection(NtCurrentProcess(), view_);
                    view_ = nullptr;
                }
                size_ = 0;
                SetLastError(error);
            }

            PVOID  view_;
            SIZE_T size_;
    };

    bool QueryImage(HANDLE process, PVOID address, MEMORY_IMAGE_INFORMATION *information) {
        SIZE_T         returned = 0;
        const NTSTATUS status   = NtQueryVirtualMemory(process, address, MemoryImageInformation, information, sizeof(*information), &returned);
        if (!NT_SUCCESS(status)) {
            SetLastError(RtlNtStatusToDosError(status));
            return false;
        }
        return information->ImageBase && information->SizeOfImage;
    }

    bool CopyLoadedImage(const loader::PeImageView &source, void *destination, size_t destinationSize) {
        if (!destination || destinationSize < source.size() ||
            source.nt()->OptionalHeader.SizeOfHeaders > destinationSize)
            return false;
        std::memcpy(destination, source.base(), source.nt()->OptionalHeader.SizeOfHeaders);
        for (WORD index = 0; index < source.section_count(); ++index) {
            const auto  &section = source.sections()[index];
            const size_t bytes   = std::max<size_t>(section.Misc.VirtualSize, section.SizeOfRawData);
            if (!bytes)
                continue;
            if (section.VirtualAddress > destinationSize || bytes > destinationSize - section.VirtualAddress)
                return false;
            std::memcpy(static_cast<BYTE *>(destination) + section.VirtualAddress, source.base() + section.VirtualAddress, bytes);
        }
        return true;
    }

    bool ReadRemoteExact(HANDLE process, const void *remote, void *local, SIZE_T bytes) {
        SIZE_T         read   = 0;
        const NTSTATUS status = NtReadVirtualMemory(
            process, const_cast<void *>(remote), local, bytes, &read);
        if (!NT_SUCCESS(status) || read != bytes) {
            SetLastError(NT_SUCCESS(status) ? ERROR_PARTIAL_COPY : RtlNtStatusToDosError(status));
            return false;
        }
        return true;
    }

    bool WriteRemoteExact(HANDLE process, PVOID remote, const void *local, SIZE_T bytes) {
        SIZE_T         written = 0;
        const NTSTATUS status  = NtWriteVirtualMemory(process, remote, const_cast<PVOID>(local), bytes, &written);
        if (!NT_SUCCESS(status) || written != bytes) {
            SetLastError(NT_SUCCESS(status) ? ERROR_PARTIAL_COPY : RtlNtStatusToDosError(status));
            return false;
        }
        return true;
    }

    bool DecodeSyscallIndex(const void *function, int *index) {
#ifdef _WIN64
        if (!function || !index)
            return false;
        const auto code = static_cast<const BYTE *>(function);
        if (code[0] != 0x4c || code[1] != 0x8b || code[2] != 0xd1 || code[3] != 0xb8) {
            return false;
        }
        std::memcpy(index, code + 4, sizeof(*index));
        return *index > 0;
#else
        UNREFERENCED_PARAMETER(function);
        UNREFERENCED_PARAMETER(index);
        return false;
#endif
    }

    bool WriteExport(loader::PeImageView *image, const char *name, const void *value, size_t bytes) {
        const DWORD rva = image->ExportRva(name, bytes);
        if (!rva) {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return false;
        }
        std::memcpy(image->base() + rva, value, bytes);
        return true;
    }

    bool CaptureRemoteEntrypointBytes(HANDLE process, BYTE *entry, SIZE_T capacity, SIZE_T *entrySize) {
        if (!process || !entry || !capacity || !entrySize) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return false;
        }
        *entrySize = 0;

        PROCESS_BASIC_INFORMATION basicInformation = {};
        NTSTATUS                  status           = NtQueryInformationProcess(
            process,
            ProcessBasicInformation,
            &basicInformation,
            sizeof(basicInformation),
            nullptr);
        if (!NT_SUCCESS(status) || basicInformation.PebBaseAddress == nullptr) {
            SetLastError(NT_SUCCESS(status) ? ERROR_BAD_EXE_FORMAT : RtlNtStatusToDosError(status));
            return false;
        }

        PVOID       remoteBase       = nullptr;
        const void *imageBaseAddress = reinterpret_cast<const BYTE *>(
                                           basicInformation.PebBaseAddress) +
                                       FIELD_OFFSET(PEB, ImageBaseAddress);
        if (!ReadRemoteExact(process, imageBaseAddress, &remoteBase, sizeof(remoteBase)) ||
            remoteBase == nullptr) {
            return false;
        }

        IMAGE_DOS_HEADER dosHeader = {};
        if (!ReadRemoteExact(process, remoteBase, &dosHeader, sizeof(dosHeader)) ||
            dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0 ||
            static_cast<ULONG>(dosHeader.e_lfanew) > 0x100000) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return false;
        }

        IMAGE_NT_HEADERS64 ntHeaders       = {};
        const void        *remoteNtHeaders = static_cast<const BYTE *>(remoteBase) + dosHeader.e_lfanew;
        if (!ReadRemoteExact(process, remoteNtHeaders, &ntHeaders, sizeof(ntHeaders)) ||
            ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
            ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            ntHeaders.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64) ||
            ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            ntHeaders.OptionalHeader.SizeOfImage == 0 ||
            ntHeaders.FileHeader.NumberOfSections == 0 ||
            ntHeaders.FileHeader.NumberOfSections > 96) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return false;
        }

        const SIZE_T sectionBytes = static_cast<SIZE_T>(
                                        ntHeaders.FileHeader.NumberOfSections) *
                                    sizeof(IMAGE_SECTION_HEADER);
        std::vector<IMAGE_SECTION_HEADER> sections(ntHeaders.FileHeader.NumberOfSections);
        const void                       *remoteSections = static_cast<const BYTE *>(remoteNtHeaders) +
                                     offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                                     ntHeaders.FileHeader.SizeOfOptionalHeader;
        if (!ReadRemoteExact(process, remoteSections, sections.data(), sectionBytes)) {
            return false;
        }

        const DWORD entryRva  = ntHeaders.OptionalHeader.AddressOfEntryPoint;
        SIZE_T      available = 0;
        for (const IMAGE_SECTION_HEADER &section : sections) {
            const SIZE_T sectionSize = std::max<SIZE_T>(
                section.Misc.VirtualSize, section.SizeOfRawData);
            if (entryRva >= section.VirtualAddress &&
                static_cast<ULONGLONG>(entryRva) <
                    static_cast<ULONGLONG>(section.VirtualAddress) + sectionSize) {
                available = sectionSize - (entryRva - section.VirtualAddress);
                break;
            }
        }
        if (entryRva == 0 || entryRva >= ntHeaders.OptionalHeader.SizeOfImage ||
            available == 0) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return false;
        }

        *entrySize = std::min<SIZE_T>(
            capacity,
            std::min<SIZE_T>(available, ntHeaders.OptionalHeader.SizeOfImage - entryRva));
        if (*entrySize == 0 || !ReadRemoteExact(
                                   process,
                                   static_cast<const BYTE *>(remoteBase) + entryRva,
                                   entry,
                                   *entrySize)) {
            *entrySize = 0;
            return false;
        }
        return true;
    }

    ULONG SectionProtection(DWORD characteristics) {
        const bool executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool readable   = (characteristics & IMAGE_SCN_MEM_READ) != 0;
        const bool writable   = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        if (executable) {
            if (writable)
                return PAGE_EXECUTE_READWRITE;
            if (readable)
                return PAGE_EXECUTE_READ;
            return PAGE_EXECUTE;
        }
        if (writable)
            return PAGE_READWRITE;
        if (readable)
            return PAGE_READONLY;
        return PAGE_NOACCESS;
    }

    bool ProtectRemoteImage(HANDLE process, PVOID remoteBase, const loader::PeImageView &image) {
        SYSTEM_INFO systemInformation = {};
        GetSystemInfo(&systemInformation);
        const SIZE_T pageSize = systemInformation.dwPageSize;
        if (pageSize == 0 || image.size() > std::numeric_limits<SIZE_T>::max() - (pageSize - 1)) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return false;
        }

        const SIZE_T       pageCount = (image.size() + pageSize - 1) / pageSize;
        std::vector<DWORD> pageCharacteristics(pageCount, 0);
        std::vector<bool>  pageUsed(pageCount, false);
        auto               markPages = [&](SIZE_T offset, SIZE_T extent, DWORD characteristics) {
            if (offset > image.size() || extent > image.size() - offset || extent == 0)
                return false;
            const SIZE_T firstPage = offset / pageSize;
            const SIZE_T lastPage  = (offset + extent - 1) / pageSize;
            for (SIZE_T page = firstPage; page <= lastPage; ++page) {
                pageUsed[page] = true;
                pageCharacteristics[page] |= characteristics;
            }
            return true;
        };

        if (!markPages(
                0,
                image.nt()->OptionalHeader.SizeOfHeaders,
                IMAGE_SCN_MEM_READ)) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return false;
        }
        for (WORD index = 0; index < image.section_count(); ++index) {
            const auto  &section = image.sections()[index];
            const SIZE_T extent  = std::max<SIZE_T>(
                section.Misc.VirtualSize, section.SizeOfRawData);
            if (extent != 0 && !markPages(
                                   section.VirtualAddress,
                                   extent,
                                   section.Characteristics)) {
                SetLastError(ERROR_BAD_EXE_FORMAT);
                return false;
            }
        }

        PVOID    address    = remoteBase;
        SIZE_T   bytes      = image.size();
        ULONG    oldProtect = 0;
        NTSTATUS status     = NtProtectVirtualMemory(
            process, &address, &bytes, PAGE_NOACCESS, &oldProtect);
        if (!NT_SUCCESS(status)) {
            SetLastError(RtlNtStatusToDosError(status));
            return false;
        }

        SIZE_T page = 0;
        while (page < pageCount) {
            if (!pageUsed[page]) {
                ++page;
                continue;
            }
            const ULONG  protection = SectionProtection(pageCharacteristics[page]);
            const SIZE_T firstPage  = page;
            while (++page < pageCount && pageUsed[page] &&
                   SectionProtection(pageCharacteristics[page]) == protection) {
            }
            address = static_cast<BYTE *>(remoteBase) + firstPage * pageSize;
            bytes   = (page - firstPage) * pageSize;
            status  = NtProtectVirtualMemory(
                process, &address, &bytes, protection, &oldProtect);
            if (!NT_SUCCESS(status)) {
                SetLastError(RtlNtStatusToDosError(status));
                return false;
            }
        }
        status = NtFlushInstructionCache(process, remoteBase, image.size());
        if (!NT_SUCCESS(status)) {
            SetLastError(RtlNtStatusToDosError(status));
            return false;
        }
        return true;
    }

    void FreeRemote(HANDLE process, PVOID *base) {
        if (!base || !*base)
            return;

        PVOID          address = *base;
        SIZE_T         size    = 0;
        const NTSTATUS status  = NtFreeVirtualMemory(process, &address, &size, MEM_RELEASE);
        if (NT_SUCCESS(status)) {
            *base = nullptr;
        } else {
            SetLastError(RtlNtStatusToDosError(status));
        }
    }

} // namespace

ULONG GetExportOffsetChecked(_In_ PVOID imageBase, _In_ SIZE_T imageSize, _In_ PCCH exportName, _In_ SIZE_T minimumSize) {
    loader::PeImageView image;
    return image.Open(imageBase, imageSize) ? image.ExportRva(exportName, minimumSize) : 0;
}

ULONG GetExportOffset(_In_ PVOID imageBase, _In_ PCCH exportName) {
    if (!imageBase || !exportName)
        return 0;
    auto dos = static_cast<PIMAGE_DOS_HEADER>(imageBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        return 0;
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(static_cast<BYTE *>(imageBase) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;
    return GetExportOffsetChecked(imageBase, nt->OptionalHeader.SizeOfImage, exportName, 1);
}

BOOL MapCoreLibraryToProtectedProcessW(PCWSTR path, HANDLE process, PULONG_PTR mappedImageBase, PPVOID localBuffer) {
    if (!path || !process || !mappedImageBase || !localBuffer) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *mappedImageBase = 0;
    *localBuffer     = nullptr;
#ifndef _WIN64
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
#else
    LoadedImage module;
    if (!module.Load(path))
        return FALSE;

    MEMORY_IMAGE_INFORMATION sourceInfo = {};
    if (!QueryImage(NtCurrentProcess(), module.get(), &sourceInfo))
        return FALSE;
    loader::PeImageView source;
    if (!source.Open(sourceInfo.ImageBase, sourceInfo.SizeOfImage)) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    void *staging = std::calloc(1, source.size());
    if (!staging) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    loader::PeImageView image;
    if (!CopyLoadedImage(source, staging, source.size()) || !image.Open(staging, source.size())) {
        std::free(staging);
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    PVOID  remoteNtdllBase = nullptr;
    SIZE_T remoteNtdllSize = 0;
    if (!QueryRemoteNtdllImage(process, &remoteNtdllBase, &remoteNtdllSize)) {
        std::free(staging);
        return FALSE;
    }

    std::array<BYTE, 256> entry     = {};
    SIZE_T                entrySize = 0;
    if (!CaptureRemoteEntrypointBytes(process, entry.data(), entry.size(), &entrySize)) {
        std::free(staging);
        return FALSE;
    }

    const char  *dataExports[] = { "ENTRY_DATA", "ENTRY_DATA_SIZE", "NTDLL_BASE_ADDRESS", "NTDLL_SIZE",
                                   "SBIEHIDE_BASE_ADDRESS", "SBIEHIDE_SIZE" };
    const size_t dataSizes[]   = { entry.size(), sizeof(entrySize), sizeof(PVOID), sizeof(SIZE_T), sizeof(PVOID), sizeof(SIZE_T) };
    for (size_t index = 0; index < _countof(dataExports); ++index) {
        if (!image.ExportRva(dataExports[index], dataSizes[index])) {
            std::free(staging);
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }
    }

    struct SyscallSlot {
            const char *configurationName;
            const char *apiName;
    };
    const SyscallSlot syscalls[] = {
        { "NtFreeVirtualMemorySystemCallIndex", "NtFreeVirtualMemory" },
        { "NtQueryVirtualMemorySystemCallIndex", "NtQueryVirtualMemory" },
        { "NtQuerySystemInformationSystemCallIndex", "NtQuerySystemInformation" },
        { "NtAllocateVirtualMemorySystemCallIndex", "NtAllocateVirtualMemory" },
        { "NtDelayExecutionSystemCallIndex", "NtDelayExecution" },
        { "NtProtectVirtualMemorySystemCallIndex", "NtProtectVirtualMemory" },
        { "NtQueryInformationProcessSystemCallIndex", "NtQueryInformationProcess" },
        { "NtQuerySectionSystemCallIndex", "NtQuerySection" },
        { "NtQueryInformationFileSystemCallIndex", "NtQueryInformationFile" },
        { "NtQueryObjectSystemCallIndex", "NtQueryObject" },
    };

    MappedSystemImage   cleanNtdll;
    loader::PeImageView cleanNtdllView;
    if (!cleanNtdll.Load(L"ntdll.dll") ||
        !cleanNtdllView.Open(cleanNtdll.base(), cleanNtdll.size())) {
        std::free(staging);
        if (GetLastError() == ERROR_SUCCESS)
            SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    std::array<int, _countof(syscalls)> indices = {};
    for (size_t index = 0; index < _countof(syscalls); ++index) {
        const DWORD apiRva = cleanNtdllView.ExportRva(syscalls[index].apiName, 8);
        if (!image.ExportRva(syscalls[index].configurationName, sizeof(int)) ||
            !apiRva || !DecodeSyscallIndex(cleanNtdllView.base() + apiRva, &indices[index])) {
            std::free(staging);
            SetLastError(ERROR_INVALID_FUNCTION);
            return FALSE;
        }
    }

    PVOID    remoteBase = reinterpret_cast<PVOID>(image.nt()->OptionalHeader.ImageBase);
    SIZE_T   remoteSize = image.size();
    NTSTATUS status     = NtAllocateVirtualMemory(
        process,
        &remoteBase,
        0,
        &remoteSize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        remoteBase = nullptr;
        remoteSize = image.size();
        status     = NtAllocateVirtualMemory(
            process,
            &remoteBase,
            0,
            &remoteSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
    }
    if (!NT_SUCCESS(status) || !remoteBase || remoteSize < image.size()) {
        if (remoteBase)
            FreeRemote(process, &remoteBase);
        std::free(staging);
        SetLastError(NT_SUCCESS(status) ? ERROR_NOT_ENOUGH_MEMORY : RtlNtStatusToDosError(status));
        return FALSE;
    }

    bool configured = WriteExport(&image, "ENTRY_DATA", entry.data(), entry.size()) &&
                      WriteExport(&image, "ENTRY_DATA_SIZE", &entrySize, sizeof(entrySize)) &&
                      WriteExport(&image, "NTDLL_BASE_ADDRESS", &remoteNtdllBase, sizeof(PVOID)) &&
                      WriteExport(&image, "NTDLL_SIZE", &remoteNtdllSize, sizeof(SIZE_T)) &&
                      WriteExport(&image, "SBIEHIDE_BASE_ADDRESS", &remoteBase, sizeof(PVOID)) &&
                      WriteExport(&image, "SBIEHIDE_SIZE", &sourceInfo.SizeOfImage, sizeof(SIZE_T));
    for (size_t index = 0; configured && index < _countof(syscalls); ++index) {
        configured = WriteExport(
            &image,
            syscalls[index].configurationName,
            &indices[index],
            sizeof(indices[index]));
    }
    if (!configured || !image.ApplyRelocations(
                           static_cast<ULONG_PTR>(image.nt()->OptionalHeader.ImageBase),
                           reinterpret_cast<ULONG_PTR>(remoteBase))) {
        FreeRemote(process, &remoteBase);
        std::free(staging);
        if (GetLastError() == ERROR_SUCCESS)
            SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    bool written = WriteRemoteExact(process, remoteBase, staging, image.nt()->OptionalHeader.SizeOfHeaders);
    for (WORD index = 0; written && index < image.section_count(); ++index) {
        const auto  &section = image.sections()[index];
        const SIZE_T bytes   = std::max<SIZE_T>(section.Misc.VirtualSize, section.SizeOfRawData);
        if (!bytes)
            continue;
        written = WriteRemoteExact(process, static_cast<BYTE *>(remoteBase) + section.VirtualAddress, static_cast<BYTE *>(staging) + section.VirtualAddress, bytes);
    }
    if (!written || !ProtectRemoteImage(process, remoteBase, image)) {
        FreeRemote(process, &remoteBase);
        std::free(staging);
        return FALSE;
    }

    *mappedImageBase = reinterpret_cast<ULONG_PTR>(remoteBase);
    *localBuffer     = staging;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
#endif
}

BOOL MapCoreLibraryToProtectedProcess(PCCH path, HANDLE process, PULONG_PTR mappedImageBase, PPVOID localBuffer) {
    if (!path) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    const int required = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, path, -1, nullptr, 0);
    if (!required)
        return FALSE;
    std::wstring wide(static_cast<size_t>(required), L'\0');
    if (!MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, path, -1, &wide[0], required))
        return FALSE;
    return MapCoreLibraryToProtectedProcessW(wide.c_str(), process, mappedImageBase, localBuffer);
}
