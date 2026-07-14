#pragma once

#include <phnt_windows.h>
#include <phnt.h>

PVOID FindLdrpCallTlsInitializers(PVOID LdrShutdownThreadAddress, PVOID ImageBase, SIZE_T ImageSize);
