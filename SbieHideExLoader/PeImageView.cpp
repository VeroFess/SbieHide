#include "PeImageView.h"

#include <cstring>
#include <limits>

namespace loader {

    PeImageView::PeImageView() noexcept
        : base_(nullptr), size_(0), nt_(nullptr), sections_(nullptr) {}

    bool PeImageView::Range(size_t offset, size_t bytes) const noexcept {
        return offset <= size_ && bytes <= size_ - offset;
    }

    void *PeImageView::Rva(DWORD rva, size_t bytes, bool allowZero) const noexcept {
        if ((!allowZero && rva == 0) || !Range(rva, bytes))
            return nullptr;
        return base_ + rva;
    }

    bool PeImageView::Open(void *image, size_t imageSize) noexcept {
        base_     = nullptr;
        size_     = 0;
        nt_       = nullptr;
        sections_ = nullptr;
        if (!image || imageSize < sizeof(IMAGE_DOS_HEADER))
            return false;

        base_          = static_cast<BYTE *>(image);
        size_          = imageSize;
        const auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base_);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            return false;
        const size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
        if (!Range(ntOffset, sizeof(IMAGE_NT_HEADERS64)))
            return false;

        nt_ = reinterpret_cast<PIMAGE_NT_HEADERS64>(base_ + ntOffset);
        if (nt_->Signature != IMAGE_NT_SIGNATURE ||
            nt_->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            nt_->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64) ||
            nt_->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            nt_->OptionalHeader.SizeOfImage == 0 ||
            nt_->OptionalHeader.SizeOfImage > size_ ||
            nt_->OptionalHeader.SizeOfHeaders == 0 ||
            nt_->OptionalHeader.SizeOfHeaders > nt_->OptionalHeader.SizeOfImage ||
            nt_->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            return false;
        }
        size_ = nt_->OptionalHeader.SizeOfImage;

        const size_t sectionOffset = ntOffset + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                                     nt_->FileHeader.SizeOfOptionalHeader;
        const size_t sectionBytes = static_cast<size_t>(nt_->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (!Range(sectionOffset, sectionBytes) || sectionOffset + sectionBytes > nt_->OptionalHeader.SizeOfHeaders) {
            return false;
        }
        sections_ = reinterpret_cast<PIMAGE_SECTION_HEADER>(base_ + sectionOffset);
        for (WORD index = 0; index < nt_->FileHeader.NumberOfSections; ++index) {
            const auto  &section = sections_[index];
            const size_t extent  = section.Misc.VirtualSize > section.SizeOfRawData
                                       ? section.Misc.VirtualSize
                                       : section.SizeOfRawData;
            if (extent && (section.VirtualAddress == 0 || !Range(section.VirtualAddress, extent))) {
                return false;
            }
        }
        return true;
    }

    bool PeImageView::CStringAt(DWORD rva, const char **value) const noexcept {
        if (!value)
            return false;
        const char *text = static_cast<const char *>(Rva(rva, 1));
        if (!text)
            return false;
        const size_t remaining = size_ - rva;
        if (!std::memchr(text, '\0', remaining))
            return false;
        *value = text;
        return true;
    }

    DWORD PeImageView::ExportRva(const char *name, size_t minimumSize) const noexcept {
        if (!nt_ || !name || !*name || minimumSize == 0)
            return 0;
        const auto &directory = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!directory.VirtualAddress || directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
            return 0;
        auto exports = static_cast<PIMAGE_EXPORT_DIRECTORY>(Rva(directory.VirtualAddress, directory.Size));
        if (!exports || exports->NumberOfFunctions == 0 || exports->NumberOfNames == 0)
            return 0;

        const size_t nameBytes     = static_cast<size_t>(exports->NumberOfNames) * sizeof(DWORD);
        const size_t ordinalBytes  = static_cast<size_t>(exports->NumberOfNames) * sizeof(WORD);
        const size_t functionBytes = static_cast<size_t>(exports->NumberOfFunctions) * sizeof(DWORD);
        auto         names         = static_cast<const DWORD *>(Rva(exports->AddressOfNames, nameBytes));
        auto         ordinals      = static_cast<const WORD *>(Rva(exports->AddressOfNameOrdinals, ordinalBytes));
        auto         functions     = static_cast<const DWORD *>(Rva(exports->AddressOfFunctions, functionBytes));
        if (!names || !ordinals || !functions)
            return 0;

        for (DWORD index = 0; index < exports->NumberOfNames; ++index) {
            const char *current = nullptr;
            if (!CStringAt(names[index], &current))
                return 0;
            if (_stricmp(current, name) != 0)
                continue;
            const WORD ordinal = ordinals[index];
            if (ordinal >= exports->NumberOfFunctions)
                return 0;
            const DWORD functionRva = functions[ordinal];
            if (functionRva >= directory.VirtualAddress &&
                functionRva < static_cast<ULONGLONG>(directory.VirtualAddress) + directory.Size) {
                return 0; // Forwarded exports are not valid mapping slots or detours.
            }
            return Rva(functionRva, minimumSize) ? functionRva : 0;
        }
        return 0;
    }

    bool PeImageView::ApplyRelocations(ULONG_PTR currentBase, ULONG_PTR newBase) const noexcept {
        if (!nt_ || !currentBase || !newBase)
            return false;
        const LONGLONG delta = static_cast<LONGLONG>(newBase - currentBase);
        if (delta == 0)
            return true;

        if ((nt_->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0)
            return false;
        const auto &directory = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!directory.VirtualAddress || directory.Size < sizeof(IMAGE_BASE_RELOCATION))
            return false;
        BYTE *cursor = static_cast<BYTE *>(Rva(directory.VirtualAddress, directory.Size));
        if (!cursor)
            return false;
        size_t consumed = 0;
        while (consumed < directory.Size) {
            if (directory.Size - consumed < sizeof(IMAGE_BASE_RELOCATION))
                return false;
            auto block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(cursor + consumed);
            if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                block->SizeOfBlock > directory.Size - consumed ||
                ((block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(WORD)) != 0) {
                return false;
            }
            const size_t count   = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto         entries = reinterpret_cast<const WORD *>(block + 1);
            for (size_t index = 0; index < count; ++index) {
                const WORD type = entries[index] >> 12;
                if (type == IMAGE_REL_BASED_ABSOLUTE)
                    continue;
                if (type != IMAGE_REL_BASED_DIR64)
                    return false;
                const ULONGLONG target = static_cast<ULONGLONG>(block->VirtualAddress) + (entries[index] & 0x0fff);
                if (target > std::numeric_limits<DWORD>::max())
                    return false;
                auto slot = static_cast<ULONGLONG *>(Rva(static_cast<DWORD>(target), sizeof(ULONGLONG)));
                if (!slot)
                    return false;
                *slot = static_cast<ULONGLONG>(static_cast<LONGLONG>(*slot) + delta);
            }
            consumed += block->SizeOfBlock;
        }
        return consumed == directory.Size;
    }

} // namespace loader
