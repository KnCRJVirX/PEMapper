#include <stdio.h>
#include <windows.h>

static inline char* reason2text(DWORD reason)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH: return "DLL_PROCESS_ATTACH";
    case DLL_THREAD_ATTACH:  return "DLL_THREAD_ATTACH";
    case DLL_THREAD_DETACH:  return "DLL_THREAD_DETACH";
    case DLL_PROCESS_DETACH: return "DLL_PROCESS_DETACH";
    default:                 return "Unknown reason";
    }
    return NULL;
}

VOID WorkFunc(LPVOID fdwReason) {
    char tmpStr[1024] = {0};
    sprintf(tmpStr, "Process ID: %u, Thread ID: %u, Reason: %s", GetCurrentProcessId(),
                                                                 GetCurrentThreadId(), 
                                                                 reason2text((DWORD)HandleToLong(fdwReason)));
    MessageBoxA(NULL, tmpStr, "Inject success", MB_OK);
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH || fdwReason == DLL_PROCESS_DETACH) {
        DisableThreadLibraryCalls(hinstDLL);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkFunc, (LPVOID)LongToHandle(fdwReason), 0, NULL);
    }
    return TRUE;
}