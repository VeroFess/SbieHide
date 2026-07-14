#pragma once

#include <phnt_windows.h>
#include <phnt.h>

#include "syscall_invoker.h"

__forceinline bool IsAddressInHalfOpenRange(const void *address, const void *rangeBase, SIZE_T rangeSize) {
    const ULONG_PTR value = reinterpret_cast<ULONG_PTR>(address);
    const ULONG_PTR base  = reinterpret_cast<ULONG_PTR>(rangeBase);

    return address != nullptr && rangeBase != nullptr && rangeSize != 0 && value >= base &&
           static_cast<SIZE_T>(value - base) < rangeSize;
}

__forceinline bool IsHiddenAddress(const void *address) {
    return IsAddressInHalfOpenRange(address, SBIEHIDE_BASE_ADDRESS, SBIEHIDE_SIZE) ||
           IsAddressInHalfOpenRange(address, SBIE_BASE_ADDRESS, SBIE_SIZE);
}

__forceinline bool IsNtdllAddress(const void *address) {
    return IsAddressInHalfOpenRange(address, NTDLL_BASE_ADDRESS, NTDLL_SIZE);
}

__forceinline bool IsBufferRangeValid(const void *buffer, SIZE_T bufferSize, const void *range, SIZE_T rangeSize) {
    if (buffer == nullptr || range == nullptr) {
        return false;
    }

    const ULONG_PTR bufferAddress = reinterpret_cast<ULONG_PTR>(buffer);
    const ULONG_PTR rangeAddress  = reinterpret_cast<ULONG_PTR>(range);
    if (rangeAddress < bufferAddress) {
        return false;
    }

    const SIZE_T offset = static_cast<SIZE_T>(rangeAddress - bufferAddress);
    return offset <= bufferSize && rangeSize <= bufferSize - offset;
}

template<typename Character>
__forceinline Character ToLowerHiddenAscii(Character value) {
    if (value >= static_cast<Character>('A') && value <= static_cast<Character>('Z')) {
        return static_cast<Character>(
            value + (static_cast<Character>('a') - static_cast<Character>('A')));
    }
    return value;
}

template<typename Character>
__forceinline bool IsHiddenComponentSeparator(Character value) {
    return value == static_cast<Character>('\\') ||
           value == static_cast<Character>('/') ||
           value == static_cast<Character>(':');
}

template<typename Character, SIZE_T PatternSize>
__forceinline bool ContainsHiddenToken(
    const Character *value,
    SIZE_T           valueLength,
    const Character (&pattern)[PatternSize]) {
    const SIZE_T patternLength = PatternSize - 1;
    if (value == nullptr || valueLength < patternLength) {
        return false;
    }
    for (SIZE_T start = 0; start <= valueLength - patternLength; ++start) {
        if (start != 0 && !IsHiddenComponentSeparator(value[start - 1])) {
            continue;
        }
        SIZE_T index = 0;
        while (index < patternLength &&
               ToLowerHiddenAscii(value[start + index]) ==
                   ToLowerHiddenAscii(pattern[index])) {
            ++index;
        }
        const SIZE_T end = start + patternLength;
        if (index == patternLength &&
            (end == valueLength || IsHiddenComponentSeparator(value[end]) ||
             value[end] == static_cast<Character>('.'))) {
            return true;
        }
    }
    return false;
}

template<typename Character, SIZE_T PatternSize>
__forceinline bool ContainsHiddenSubstring(
    const Character *value,
    SIZE_T           valueLength,
    const Character (&pattern)[PatternSize]) {
    const SIZE_T patternLength = PatternSize - 1;
    if (value == nullptr || valueLength < patternLength) {
        return false;
    }
    for (SIZE_T start = 0; start <= valueLength - patternLength; ++start) {
        SIZE_T index = 0;
        while (index < patternLength &&
               ToLowerHiddenAscii(value[start + index]) ==
                   ToLowerHiddenAscii(pattern[index])) {
            ++index;
        }
        if (index == patternLength) {
            return true;
        }
    }
    return false;
}

__forceinline bool IsHiddenName(const WCHAR *string, SIZE_T byteLength) {
    if (string == nullptr || (byteLength % sizeof(WCHAR)) != 0) {
        return false;
    }
    const SIZE_T characterCount = byteLength / sizeof(WCHAR);
    return ContainsHiddenToken(string, characterCount, L"sbiedll") ||
           ContainsHiddenToken(string, characterCount, L"sbiehide") ||
           ContainsHiddenToken(string, characterCount, L"sbiesvc") ||
           ContainsHiddenToken(string, characterCount, L"sbiedrv") ||
           ContainsHiddenToken(string, characterCount, L"sbiectrl") ||
           ContainsHiddenToken(string, characterCount, L"sandboxierpcss") ||
           ContainsHiddenToken(string, characterCount, L"sandboxiedcomlaunch");
}

__forceinline bool IsHiddenObjectName(const WCHAR *string, SIZE_T byteLength) {
    if (IsHiddenName(string, byteLength)) {
        return true;
    }
    if (string == nullptr || (byteLength % sizeof(WCHAR)) != 0) {
        return false;
    }
    return ContainsHiddenSubstring(
        string,
        byteLength / sizeof(WCHAR),
        L"\\rpc control\\sbiesvcport");
}

__forceinline bool IsHiddenNameAnsi(const CHAR *string, SIZE_T byteLength) {
    if (string == nullptr) {
        return false;
    }
    SIZE_T boundedLength = 0;
    while (boundedLength < byteLength && string[boundedLength] != '\0') {
        ++boundedLength;
    }
    return ContainsHiddenToken(string, boundedLength, "sbiedll") ||
           ContainsHiddenToken(string, boundedLength, "sbiehide") ||
           ContainsHiddenToken(string, boundedLength, "sbiesvc") ||
           ContainsHiddenToken(string, boundedLength, "sbiedrv") ||
           ContainsHiddenToken(string, boundedLength, "sbiectrl") ||
           ContainsHiddenToken(string, boundedLength, "sandboxierpcss") ||
           ContainsHiddenToken(string, boundedLength, "sandboxiedcomlaunch");
}
