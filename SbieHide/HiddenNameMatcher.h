#pragma once

#include <cstddef>

bool IsHiddenName(const wchar_t *value, size_t characterCount);
bool IsHiddenName(const char *value, size_t byteCount);
