#include <phnt_windows.h>
#include <phnt.h>
#include "Zydis.h"


BOOL VerifyFunctionIsLdrpCallTlsInitializers(PVOID LdrpCallTlsInitializersAddress) {
    PUCHAR                       FunctionPointer = reinterpret_cast<PUCHAR>(LdrpCallTlsInitializersAddress);
    ZyanU64                      StringPointer   = NULL;
    SIZE_T                       FunctionSize    = 0x500;
    ZyanUSize                    Offset          = 0;
    ZydisDisassembledInstruction instruction     = {};
    BOOL                         FoundLeaR8      = FALSE;

    while (ZYAN_SUCCESS(ZydisDisassemble(ZYDIS_MACHINE_MODE_LONG_64, reinterpret_cast<ZyanU64>(FunctionPointer), FunctionPointer, FunctionSize - Offset, &instruction))) {
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_LEA) {
            FoundLeaR8 = FALSE;

            for (int i = 0; i < ZYDIS_MAX_OPERAND_COUNT; i++) {
                if (instruction.operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER && instruction.operands[i].reg.value == ZYDIS_REGISTER_R8) {
                    FoundLeaR8 = TRUE;
                    break;
                }
            }

            if (!FoundLeaR8) {
                goto NextInst;
            }

            for (int i = 0; i < ZYDIS_MAX_OPERAND_COUNT; i++) {
                if (!(instruction.operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)) {
                    continue;
                }

                if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction.info, &instruction.operands[i], reinterpret_cast<ZyanU64>(FunctionPointer), &StringPointer))) {
                    continue;
                }

                if (reinterpret_cast<PCHAR>(StringPointer)[0x00] == 'L' && reinterpret_cast<PCHAR>(StringPointer)[0x01] == 'd' && reinterpret_cast<PCHAR>(StringPointer)[0x02] == 'r' && reinterpret_cast<PCHAR>(StringPointer)[0x03] == 'p' && reinterpret_cast<PCHAR>(StringPointer)[0x04] == 'C' && reinterpret_cast<PCHAR>(StringPointer)[0x05] == 'a' && reinterpret_cast<PCHAR>(StringPointer)[0x06] == 'l' && reinterpret_cast<PCHAR>(StringPointer)[0x07] == 'l' && reinterpret_cast<PCHAR>(StringPointer)[0x08] == 'T' && reinterpret_cast<PCHAR>(StringPointer)[0x09] == 'l' && reinterpret_cast<PCHAR>(StringPointer)[0x0A] == 's' && reinterpret_cast<PCHAR>(StringPointer)[0x0B] == 'I' && reinterpret_cast<PCHAR>(StringPointer)[0x0C] == 'n' && reinterpret_cast<PCHAR>(StringPointer)[0x0D] == 'i' && reinterpret_cast<PCHAR>(StringPointer)[0x0E] == 't' && reinterpret_cast<PCHAR>(StringPointer)[0x0F] == 'i' && reinterpret_cast<PCHAR>(StringPointer)[0x10] == 'a' && reinterpret_cast<PCHAR>(StringPointer)[0x11] == 'l' && reinterpret_cast<PCHAR>(StringPointer)[0x12] == 'i' && reinterpret_cast<PCHAR>(StringPointer)[0x13] == 'z' && reinterpret_cast<PCHAR>(StringPointer)[0x14] == 'e' && reinterpret_cast<PCHAR>(StringPointer)[0x15] == 'r' && reinterpret_cast<PCHAR>(StringPointer)[0x16] == 's') {
                    return TRUE;
                }
            }
        }

    NextInst:
        Offset += instruction.info.length;
        FunctionPointer += instruction.info.length;
    }

    return FALSE;
}

PVOID FindLdrpCallTlsInitializers(PVOID LdrShutdownThreadAddress) {
    PUCHAR                       FunctionPointer       = reinterpret_cast<PUCHAR>(LdrShutdownThreadAddress);
    ZyanU64                      CalleeFunctionPointer = NULL;
    SIZE_T                       FunctionSize          = 0x500;
    ZyanUSize                    Offset                = 0;
    ZydisDisassembledInstruction instruction           = {};

    while (ZYAN_SUCCESS(ZydisDisassemble(ZYDIS_MACHINE_MODE_LONG_64, reinterpret_cast<ZyanU64>(FunctionPointer), FunctionPointer, FunctionSize - Offset, &instruction))) {
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL) {
            for (int i = 0; i < ZYDIS_MAX_OPERAND_COUNT; i++) {
                if (!(instruction.operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)) {
                    continue;
                }

                if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction.info, &instruction.operands[i], reinterpret_cast<ZyanU64>(FunctionPointer), &CalleeFunctionPointer))) {
                    continue;
                }

                if (VerifyFunctionIsLdrpCallTlsInitializers(reinterpret_cast<PVOID>(CalleeFunctionPointer))) {
                    return reinterpret_cast<PVOID>(CalleeFunctionPointer);
                }
            }
        }

        Offset += instruction.info.length;
        FunctionPointer += instruction.info.length;
    }

    return FALSE;
}