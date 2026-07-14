#pragma once

#include <phnt_windows.h>
#include <phnt.h>

struct MemoryImageHideInformation {
        ULONG_PTR ImageStartAddress = 0;
        ULONG_PTR ImageEndAddress   = 0;

        constexpr MemoryImageHideInformation() = default;
        constexpr MemoryImageHideInformation(ULONG_PTR start, ULONG_PTR end)
            : ImageStartAddress(start), ImageEndAddress(end) {}
};

BOOLEAN InitMemoryImageHideInformation();
BOOLEAN IsAddressShouldHide(ULONG_PTR address);
BOOLEAN IsAddressShouldHide(const void *address);