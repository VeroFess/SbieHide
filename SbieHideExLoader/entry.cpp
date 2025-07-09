#include "SbieHideLoader.h"
#include "NtdllRemapper.h"
#include <stdio.h>
#include <string>

int main(int argc, char* argv[]) {
    STARTUPINFOA        StartupInfo              = {};
    PROCESS_INFORMATION ProcessInformation       = {};
    HANDLE              LPCServerThreadHandle    = NULL;
    BOOL                IsProcessCreateDone      = FALSE;
    ULONG_PTR           CoreLibraryMappedAddress = 0;
    PVOID               CoreLibraryLocalAddress  = 0;
    DWORD               LPCServerThreadId        = 0;
    char                CoreLibraryPath[MAX_PATH] = {};
    char                DebuggerTraceLog[256]    = {};
    std::string         CommandLine;
    HANDLE              ParentProcess = NULL;
    STARTUPINFOEXA      StartupInfoEx = {};
    SIZE_T              AttributeListSize = 0;

    // Check if we have at least one argument (target executable)
    if (argc < 2) {
        printf("Usage: %s <target_executable> [arguments...]\n", argv[0]);
        return 1;
    }

    // Get current executable directory and construct CoreLibraryPath
    GetModuleFileNameA(NULL, CoreLibraryPath, MAX_PATH);
    char* lastSlash = strrchr(CoreLibraryPath, '\\');
    if (lastSlash) {
        *(lastSlash + 1) = '\0';
        strcat_s(CoreLibraryPath, "SbieHideEx.dll");
    }

    // Build command line from arguments
    CommandLine = argv[1];
    for (int i = 2; i < argc; i++) {
        CommandLine += " ";
        CommandLine += argv[i];
    }

    // Get parent process handle for spoofing
    ParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, GetCurrentProcessId());
    if (!ParentProcess) {
        ParentProcess = GetCurrentProcess();
    }

    // Setup extended startup info for parent process spoofing
    StartupInfoEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    InitializeProcThreadAttributeList(NULL, 1, 0, &AttributeListSize);
    StartupInfoEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, AttributeListSize);
    InitializeProcThreadAttributeList(StartupInfoEx.lpAttributeList, 1, 0, &AttributeListSize);
    UpdateProcThreadAttribute(StartupInfoEx.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ParentProcess, sizeof(HANDLE), NULL, NULL);

    if (!(IsProcessCreateDone = CreateProcessA(argv[1], const_cast<char*>(CommandLine.c_str()), NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &StartupInfoEx.StartupInfo, &ProcessInformation))) {
        printf("Unable to create child process with error code %08X, the process is about to exit...\n", GetLastError());
        goto CleanAndExit;
    }

    if (!MapCoreLibraryToProtectedProcess(CoreLibraryPath, ProcessInformation.hProcess, &CoreLibraryMappedAddress, &CoreLibraryLocalAddress)) {
        printf("Unable to map core library into child process, the process is about to exit...\n");
        goto CleanAndExit;
    }

    printf("The core library is loaded at address 0x%016llX.\n", CoreLibraryMappedAddress);
    printf("Windbg debug command: .reload /f /i %s=0x%016llX\n", CoreLibraryPath, CoreLibraryMappedAddress);

    sprintf_s(DebuggerTraceLog, "Windbg debug command: .reload /f /i %s=0x%016llX\n", CoreLibraryPath, CoreLibraryMappedAddress);
    OutputDebugStringA(DebuggerTraceLog);

    if (!RemapNtDllInProtectProcessAndPatch(ProcessInformation.hProcess, CoreLibraryMappedAddress, reinterpret_cast<ULONG_PTR>(CoreLibraryLocalAddress))) {
        printf("Unable to remap NTDLL in a safe manner, the process is about to exit...\n");
        goto CleanAndExit;
    }

    free(CoreLibraryLocalAddress);

    if (!NT_SUCCESS(NtResumeProcess(ProcessInformation.hProcess))) {
        printf("Unable to resume child process execution, the process is about to exit...\n");
        goto CleanAndExit;
    }

    printf("Successfully started the child process!\n");

    printf("Press any key to exit the console...\n");

    getchar();

CleanAndExit:
    if (StartupInfoEx.lpAttributeList) {
        DeleteProcThreadAttributeList(StartupInfoEx.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, StartupInfoEx.lpAttributeList);
    }

    if (ParentProcess && ParentProcess != GetCurrentProcess()) {
        CloseHandle(ParentProcess);
    }

    if (LPCServerThreadHandle != NULL) {
        TerminateThread(LPCServerThreadHandle, 0);
        CloseHandle(LPCServerThreadHandle);
    }

    if (ProcessInformation.hProcess != NULL) {
        TerminateProcess(ProcessInformation.hProcess, 0);
        CloseHandle(ProcessInformation.hProcess);
    }

    if (ProcessInformation.hThread != NULL) {
        CloseHandle(ProcessInformation.hThread);
    }

    printf("[*][L] Press enter to exit\n");

    getchar();
}