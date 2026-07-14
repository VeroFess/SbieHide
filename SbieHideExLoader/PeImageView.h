#pragma once

#include <phnt_windows.h>
#include <cstddef>

namespace loader {

    class PeImageView {
        public:
            PeImageView() noexcept;

            bool  Open(void *image, size_t imageSize) noexcept;
            void *Rva(DWORD rva, size_t bytes, bool allowZero = false) const noexcept;
            DWORD ExportRva(const char *name, size_t minimumSize = 1) const noexcept;
            bool  ApplyRelocations(ULONG_PTR currentBase, ULONG_PTR newBase) const noexcept;

            PIMAGE_NT_HEADERS64 nt() const noexcept {
                return nt_;
            }
            PIMAGE_SECTION_HEADER sections() const noexcept {
                return sections_;
            }
            WORD section_count() const noexcept {
                return nt_ ? nt_->FileHeader.NumberOfSections : 0;
            }
            size_t size() const noexcept {
                return size_;
            }
            BYTE *base() const noexcept {
                return base_;
            }

        private:
            bool Range(size_t offset, size_t bytes) const noexcept;
            bool CStringAt(DWORD rva, const char **value) const noexcept;

            BYTE                 *base_;
            size_t                size_;
            PIMAGE_NT_HEADERS64   nt_;
            PIMAGE_SECTION_HEADER sections_;
    };

} // namespace loader
