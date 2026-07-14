#pragma once

#include <phnt_windows.h>
#include <phnt.h>

extern "C" NTSTATUS NTAPI NtQueryVirtualMemoryDetours(
    HANDLE                   processHandle,
    PVOID                    baseAddress,
    MEMORY_INFORMATION_CLASS informationClass,
    PVOID                    information,
    SIZE_T                   informationLength,
    PSIZE_T                  returnLength);
extern "C" NTSTATUS NTAPI NtQueryObjectDetours(
    HANDLE                   handle,
    OBJECT_INFORMATION_CLASS informationClass,
    PVOID                    information,
    ULONG                    informationLength,
    PULONG                   returnLength);
extern "C" NTSTATUS NTAPI NtQueryInformationFileDetours(
    HANDLE                 fileHandle,
    PIO_STATUS_BLOCK       ioStatusBlock,
    PVOID                  information,
    ULONG                  informationLength,
    FILE_INFORMATION_CLASS informationClass);
extern "C" NTSTATUS NTAPI NtQuerySectionDetours(
    HANDLE                    sectionHandle,
    SECTION_INFORMATION_CLASS informationClass,
    PVOID                     information,
    SIZE_T                    informationLength,
    PSIZE_T                   returnLength);
extern "C" NTSTATUS NTAPI NtQuerySystemInformationDetours(
    SYSTEM_INFORMATION_CLASS informationClass,
    PVOID                    information,
    ULONG                    informationLength,
    PULONG                   returnLength);
extern "C" NTSTATUS NTAPI NtQueryInformationProcessDetours(
    HANDLE           processHandle,
    PROCESSINFOCLASS informationClass,
    PVOID            information,
    ULONG            informationLength,
    PULONG           returnLength);
