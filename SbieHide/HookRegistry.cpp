#include "HookRegistry.h"
#include "QueryProxy.h"
#include "MinHook.h"

namespace {

    SRWLOCK HookLock     = SRWLOCK_INIT;
    bool    HooksEnabled = false;

    void RollBackUnpublishedHooks(
        const HookRegistration *hooks,
        size_t                  createdCount,
        bool                    uninitializeMinHook) {
        bool allRemoved = true;
        for (size_t index = createdCount; index > 0; --index) {
            const HookRegistration &hook   = hooks[index - 1];
            const MH_STATUS         status = MH_RemoveHook(hook.Target);
            if (status == MH_OK || status == MH_ERROR_NOT_CREATED) {
                *hook.Original = nullptr;
            } else {
                allRemoved = false;
            }
        }
        if (uninitializeMinHook && allRemoved) {
            MH_Uninitialize();
        }
    }

    bool DisablePublishedHooks(
        const HookRegistration *hooks,
        size_t                  hookCount) {
        bool allDisabled = true;
        for (size_t index = 0; index < hookCount; ++index) {
            const MH_STATUS status = MH_DisableHook(hooks[index].Target);
            if (status != MH_OK && status != MH_ERROR_DISABLED &&
                status != MH_ERROR_NOT_CREATED) {
                allDisabled = false;
            }
        }
        // Keep trampoline storage and Original pointers alive for callbacks that
        // entered before the disable operation completed.
        return allDisabled;
    }

} // namespace

BOOLEAN EnableRegisteredHooks() {
    AcquireSRWLockExclusive(&HookLock);

    if (HooksEnabled) {
        ReleaseSRWLockExclusive(&HookLock);
        return TRUE;
    }

    const MH_STATUS initializeStatus = MH_Initialize();
    const bool      ownsMinHook      = initializeStatus == MH_OK;
    if (!ownsMinHook && initializeStatus != MH_ERROR_ALREADY_INITIALIZED) {
        ReleaseSRWLockExclusive(&HookLock);
        return FALSE;
    }

    size_t                  hookCount    = 0;
    const HookRegistration *hooks        = GetQueryProxyHooks(&hookCount);
    size_t                  createdCount = 0;

    for (; createdCount < hookCount; ++createdCount) {
        const HookRegistration &hook = hooks[createdCount];
        if (MH_CreateHook(hook.Target, hook.Detour, hook.Original) != MH_OK) {
            RollBackUnpublishedHooks(hooks, createdCount, ownsMinHook);
            ReleaseSRWLockExclusive(&HookLock);
            return FALSE;
        }
    }

    for (size_t index = 0; index < hookCount; ++index) {
        if (MH_QueueEnableHook(hooks[index].Target) != MH_OK) {
            RollBackUnpublishedHooks(hooks, createdCount, ownsMinHook);
            ReleaseSRWLockExclusive(&HookLock);
            return FALSE;
        }
    }

    if (MH_ApplyQueued() != MH_OK) {
        const bool disabled = DisablePublishedHooks(hooks, hookCount);
        if (disabled) {
            RollBackUnpublishedHooks(hooks, createdCount, ownsMinHook);
        }
        ReleaseSRWLockExclusive(&HookLock);
        return FALSE;
    }

    HooksEnabled = true;
    ReleaseSRWLockExclusive(&HookLock);
    return TRUE;
}

void DisableRegisteredHooks() {
    AcquireSRWLockExclusive(&HookLock);
    if (!HooksEnabled) {
        ReleaseSRWLockExclusive(&HookLock);
        return;
    }

    size_t                  hookCount = 0;
    const HookRegistration *hooks     = GetQueryProxyHooks(&hookCount);
    if (DisablePublishedHooks(hooks, hookCount)) {
        HooksEnabled = false;
    }
    ReleaseSRWLockExclusive(&HookLock);
}
