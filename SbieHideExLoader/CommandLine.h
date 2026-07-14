#pragma once

#include <string>
#include <vector>

namespace loader {

    std::wstring QuoteCommandLineArgument(const std::wstring &argument);
    std::wstring BuildCommandLine(const std::vector<std::wstring> &arguments);

} // namespace loader
