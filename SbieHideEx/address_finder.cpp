#include <phnt_windows.h>
#include <phnt.h>
#include "Zydis.h"

#include "address_finder.h"

static PRUNTIME_FUNCTION FindRuntimeFunction(
    PRUNTIME_FUNCTION runtimeFunctions,
    SIZE_T            runtimeFunctionCount,
    SIZE_T            imageSize,
    ULONG             rva) {
    for (SIZE_T index = 0; index < runtimeFunctionCount; ++index) {
        PRUNTIME_FUNCTION runtime = &runtimeFunctions[index];
        if (runtime->BeginAddress <= rva && rva < runtime->EndAddress &&
            runtime->BeginAddress < runtime->EndAddress &&
            runtime->EndAddress <= imageSize) {
            return runtime;
        }
    }
    return nullptr;
}

static BOOL RuntimeReferencesMarker(
    PUCHAR            imageBase,
    PRUNTIME_FUNCTION runtime,
    PVOID             markerAddress) {
    PUCHAR cursor    = imageBase + runtime->BeginAddress;
    SIZE_T remaining = runtime->EndAddress - runtime->BeginAddress;
    while (remaining != 0) {
        ZydisDisassembledInstruction instruction = {};
        if (!ZYAN_SUCCESS(ZydisDisassemble(
                ZYDIS_MACHINE_MODE_LONG_64,
                reinterpret_cast<ZyanU64>(cursor),
                cursor,
                remaining,
                &instruction)) ||
            instruction.info.length == 0 || instruction.info.length > remaining) {
            return FALSE;
        }
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_LEA) {
            BOOL    hasR8             = FALSE;
            ZyanU64 referencedAddress = 0;
            for (ZyanU8 operandIndex = 0;
                 operandIndex < instruction.info.operand_count;
                 ++operandIndex) {
                const auto &operand = instruction.operands[operandIndex];
                if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    operand.reg.value == ZYDIS_REGISTER_R8) {
                    hasR8 = TRUE;
                } else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    ZydisCalcAbsoluteAddress(
                        &instruction.info,
                        &operand,
                        reinterpret_cast<ZyanU64>(cursor),
                        &referencedAddress);
                }
            }
            if (hasR8 &&
                referencedAddress == reinterpret_cast<ZyanU64>(markerAddress)) {
                return TRUE;
            }
        }
        cursor += instruction.info.length;
        remaining -= instruction.info.length;
    }
    return FALSE;
}

static BOOL IsImageRangeValid(PVOID imageBaseValue, SIZE_T imageSize, ULONG_PTR addressValue, SIZE_T length) {
    const ULONG_PTR imageBase = reinterpret_cast<ULONG_PTR>(imageBaseValue);
    if (addressValue < imageBase) {
        return FALSE;
    }
    const SIZE_T offset = static_cast<SIZE_T>(addressValue - imageBase);
    return offset <= imageSize && length <= imageSize - offset;
}

PVOID FindLdrpCallTlsInitializers(PVOID LdrShutdownThreadAddress, PVOID ImageBase, SIZE_T ImageSize) {
    static const CHAR marker[] = "LdrpCallTlsInitializers";
    if (ImageBase == nullptr || ImageSize < sizeof(IMAGE_NT_HEADERS64)) {
        return nullptr;
    }

    const auto imageBase = reinterpret_cast<PUCHAR>(ImageBase);
    const auto dos       = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
        static_cast<SIZE_T>(dos->e_lfanew) > ImageSize - sizeof(IMAGE_NT_HEADERS64)) {
        return nullptr;
    }
    const auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->OptionalHeader.SizeOfImage == 0 ||
        nt->OptionalHeader.SizeOfImage > ImageSize ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        return nullptr;
    }

    const SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    const SIZE_T sectionTableOffset =
        static_cast<SIZE_T>(dos->e_lfanew) +
        FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
        nt->FileHeader.SizeOfOptionalHeader;
    const SIZE_T sectionTableSize =
        static_cast<SIZE_T>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (sectionTableOffset > imageSize || sectionTableSize > imageSize - sectionTableOffset) {
        return nullptr;
    }
    const auto sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        imageBase + sectionTableOffset);

    PCHAR markerAddress = nullptr;
    for (WORD sectionIndex = 0;
         sectionIndex < nt->FileHeader.NumberOfSections && markerAddress == nullptr;
         ++sectionIndex) {
        const IMAGE_SECTION_HEADER &section = sections[sectionIndex];
        if ((section.Characteristics & IMAGE_SCN_MEM_READ) == 0 ||
            section.VirtualAddress >= imageSize) {
            continue;
        }
        SIZE_T sectionSize = section.Misc.VirtualSize > section.SizeOfRawData
                                 ? section.Misc.VirtualSize
                                 : section.SizeOfRawData;
        if (sectionSize > imageSize - section.VirtualAddress) {
            sectionSize = imageSize - section.VirtualAddress;
        }
        PCHAR sectionBytes = reinterpret_cast<PCHAR>(
            imageBase + section.VirtualAddress);
        for (SIZE_T offset = 0; offset + sizeof(marker) - 1 <= sectionSize; ++offset) {
            SIZE_T markerIndex = 0;
            while (markerIndex < sizeof(marker) - 1 &&
                   sectionBytes[offset + markerIndex] == marker[markerIndex]) {
                ++markerIndex;
            }
            if (markerIndex == sizeof(marker) - 1) {
                markerAddress = sectionBytes + offset;
                break;
            }
        }
    }
    if (markerAddress == nullptr) {
        return nullptr;
    }

    const IMAGE_DATA_DIRECTORY exceptionDirectory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exceptionDirectory.Size < sizeof(RUNTIME_FUNCTION) ||
        !IsImageRangeValid(
            ImageBase,
            imageSize,
            reinterpret_cast<ULONG_PTR>(imageBase + exceptionDirectory.VirtualAddress),
            exceptionDirectory.Size)) {
        return nullptr;
    }
    const auto runtimeFunctions = reinterpret_cast<PRUNTIME_FUNCTION>(
        imageBase + exceptionDirectory.VirtualAddress);
    const SIZE_T runtimeFunctionCount =
        exceptionDirectory.Size / sizeof(RUNTIME_FUNCTION);

    const ULONG_PTR shutdownAddress = reinterpret_cast<ULONG_PTR>(
        LdrShutdownThreadAddress);
    if (!IsImageRangeValid(ImageBase, imageSize, shutdownAddress, 1)) {
        return nullptr;
    }
    const ULONG shutdownRva = static_cast<ULONG>(
        shutdownAddress - reinterpret_cast<ULONG_PTR>(ImageBase));
    PRUNTIME_FUNCTION shutdownRuntime = FindRuntimeFunction(
        runtimeFunctions,
        runtimeFunctionCount,
        imageSize,
        shutdownRva);
    if (shutdownRuntime == nullptr) {
        return nullptr;
    }

    PVOID  found     = nullptr;
    PUCHAR cursor    = imageBase + shutdownRuntime->BeginAddress;
    SIZE_T remaining = shutdownRuntime->EndAddress - shutdownRuntime->BeginAddress;
    while (remaining != 0) {
        ZydisDisassembledInstruction instruction = {};
        if (!ZYAN_SUCCESS(ZydisDisassemble(
                ZYDIS_MACHINE_MODE_LONG_64,
                reinterpret_cast<ZyanU64>(cursor),
                cursor,
                remaining,
                &instruction)) ||
            instruction.info.length == 0 || instruction.info.length > remaining) {
            return nullptr;
        }
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL) {
            for (ZyanU8 operandIndex = 0;
                 operandIndex < instruction.info.operand_count;
                 ++operandIndex) {
                const auto &operand = instruction.operands[operandIndex];
                if (operand.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    continue;
                }
                ZyanU64 callTarget = 0;
                if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                        &instruction.info,
                        &operand,
                        reinterpret_cast<ZyanU64>(cursor),
                        &callTarget)) ||
                    !IsImageRangeValid(ImageBase, imageSize, callTarget, 1)) {
                    continue;
                }
                const ULONG targetRva = static_cast<ULONG>(
                    callTarget - reinterpret_cast<ZyanU64>(imageBase));
                PRUNTIME_FUNCTION candidateRuntime = FindRuntimeFunction(
                    runtimeFunctions,
                    runtimeFunctionCount,
                    imageSize,
                    targetRva);
                if (candidateRuntime == nullptr ||
                    !RuntimeReferencesMarker(imageBase, candidateRuntime, markerAddress)) {
                    continue;
                }
                PVOID candidate = imageBase + candidateRuntime->BeginAddress;
                if (found != nullptr && found != candidate) {
                    return nullptr;
                }
                found = candidate;
            }
        }
        cursor += instruction.info.length;
        remaining -= instruction.info.length;
    }
    return found;
}
