#include "HiddenNameMatcher.h"

namespace {

    template<typename Character>
    Character ToLowerAscii(Character value) {
        const Character upperA = static_cast<Character>('A');
        const Character upperZ = static_cast<Character>('Z');
        if (value >= upperA && value <= upperZ) {
            return static_cast<Character>(value + (static_cast<Character>('a') - upperA));
        }
        return value;
    }

    template<typename Character>
    bool IsComponentSeparator(Character value) {
        return value == static_cast<Character>('\\') ||
               value == static_cast<Character>('/') ||
               value == static_cast<Character>(':');
    }

    template<typename Character, size_t PatternSize>
    bool ContainsComponent(
        const Character *value,
        size_t           valueLength,
        const Character (&pattern)[PatternSize]) {
        const size_t patternLength = PatternSize - 1;
        if (value == nullptr || valueLength < patternLength) {
            return false;
        }

        for (size_t start = 0; start <= valueLength - patternLength; ++start) {
            if (start != 0 && !IsComponentSeparator(value[start - 1])) {
                continue;
            }
            size_t index = 0;
            while (index < patternLength &&
                   ToLowerAscii(value[start + index]) == ToLowerAscii(pattern[index])) {
                ++index;
            }
            const size_t end = start + patternLength;
            if (index == patternLength &&
                (end == valueLength || IsComponentSeparator(value[end]) ||
                 value[end] == static_cast<Character>('.'))) {
                return true;
            }
        }
        return false;
    }

} // namespace

bool IsHiddenName(const wchar_t *value, size_t characterCount) {
    return ContainsComponent(value, characterCount, L"sbiedll") ||
           ContainsComponent(value, characterCount, L"sbiehide") ||
           ContainsComponent(value, characterCount, L"sbiesvc") ||
           ContainsComponent(value, characterCount, L"sbiedrv") ||
           ContainsComponent(value, characterCount, L"sbiectrl") ||
           ContainsComponent(value, characterCount, L"sandboxierpcss") ||
           ContainsComponent(value, characterCount, L"sandboxiedcomlaunch");
}

bool IsHiddenName(const char *value, size_t byteCount) {
    return ContainsComponent(value, byteCount, "sbiedll") ||
           ContainsComponent(value, byteCount, "sbiehide") ||
           ContainsComponent(value, byteCount, "sbiesvc") ||
           ContainsComponent(value, byteCount, "sbiedrv") ||
           ContainsComponent(value, byteCount, "sbiectrl") ||
           ContainsComponent(value, byteCount, "sandboxierpcss") ||
           ContainsComponent(value, byteCount, "sandboxiedcomlaunch");
}
