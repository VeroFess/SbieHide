#include "APIHook.h"
#include "HookRegistry.h"

BOOLEAN EnableApiHook() {
    return EnableRegisteredHooks();
}

void DisableApiHook() {
    DisableRegisteredHooks();
}
