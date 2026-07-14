#include "CommandLine.h"

namespace loader {

    std::wstring QuoteCommandLineArgument(const std::wstring &argument) {
        if (!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
            return argument;
        }

        std::wstring result(1, L'\"');
        size_t       backslashes = 0;
        for (wchar_t ch : argument) {
            if (ch == L'\\') {
                ++backslashes;
                continue;
            }
            if (ch == L'\"') {
                result.append(backslashes * 2 + 1, L'\\');
                result.push_back(L'\"');
            } else {
                result.append(backslashes, L'\\');
                result.push_back(ch);
            }
            backslashes = 0;
        }
        result.append(backslashes * 2, L'\\');
        result.push_back(L'\"');
        return result;
    }

    std::wstring BuildCommandLine(const std::vector<std::wstring> &arguments) {
        std::wstring result;
        for (const auto &argument : arguments) {
            if (!result.empty()) {
                result.push_back(L' ');
            }
            result.append(QuoteCommandLineArgument(argument));
        }
        return result;
    }

} // namespace loader
