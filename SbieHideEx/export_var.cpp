#include <phnt_windows.h>
#include <phnt.h>

#include <isa_availability.h>
#include "simple_runtime_library.h"

BOOL              PROCESS_INITIALIZATION_FINISHED          = FALSE;
PVOID             NTDLL_BASE_ADDRESS                       = 0;
SIZE_T            NTDLL_SIZE                               = 0;
PVOID             SBIEHIDE_BASE_ADDRESS                    = 0;
SIZE_T            SBIEHIDE_SIZE                            = 0;
PVOID             SBIE_BASE_ADDRESS                        = 0;
SIZE_T            SBIE_SIZE                                = 0;
BYTE              ENTRY_DATA[256]                          = { 0 };
SIZE_T            ENTRY_DATA_SIZE                          = 0;
int               NtFreeVirtualMemorySystemCallIndex       = 0;
int               NtQueryVirtualMemorySystemCallIndex      = 0;
int               NtQuerySystemInformationSystemCallIndex  = 0;
int               NtAllocateVirtualMemorySystemCallIndex   = 0;
int               NtDelayExecutionSystemCallIndex          = 0;
int               NtProtectVirtualMemorySystemCallIndex    = 0;
int               NtQueryInformationProcessSystemCallIndex = 0;
int               NtQuerySectionSystemCallIndex            = 0;
int               NtQueryInformationFileSystemCallIndex    = 0;
int               NtQueryObjectSystemCallIndex             = 0;
extern "C" BOOL   __favor                                  = __FAVOR_ATOM;
extern "C" BOOL   __isa_available                          = __ISA_AVAILABLE_X86;
extern "C" SIZE_T __memset_nt_threshold                    = 256;
extern "C" SIZE_T __memset_fast_string_threshold           = 16;