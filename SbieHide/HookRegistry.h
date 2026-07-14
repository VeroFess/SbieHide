#pragma once

#include <phnt_windows.h>
#include <phnt.h>
#include <cstddef>

struct HookRegistration {
        PVOID  Target;
        PVOID  Detour;
        PVOID *Original;
};

BOOLEAN EnableRegisteredHooks();
void    DisableRegisteredHooks();
