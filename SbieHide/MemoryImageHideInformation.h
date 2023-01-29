#pragma once
#include "MINT.h"

struct MemoryImageHideInformation {
	ULONG_PTR ImageStartAddress;
	ULONG_PTR ImageEndAddress;

	MemoryImageHideInformation(ULONG_PTR Start, ULONG_PTR End) {
		ImageStartAddress = Start;
		ImageEndAddress = End;
	}
};

BOOLEAN InitMemoryImageHideInformation();
BOOLEAN IsAddressShouldHide(ULONG_PTR Address);
BOOLEAN IsAddressShouldHide(PVOID Address);