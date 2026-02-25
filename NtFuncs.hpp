#ifndef NTFUNCS_H
#define NTFUNCS_H

#include <Windows.h>
#include <winternl.h>
#include <cstdint>

namespace PEMapper {
namespace Syscall {

typedef _Function_class_(PS_APC_ROUTINE)
VOID NTAPI PS_APC_ROUTINE(
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );
typedef PS_APC_ROUTINE* PPS_APC_ROUTINE;
#define QUEUE_USER_APC_SPECIAL_USER_APC ((HANDLE)0x1)
using _NtQueueApcThreadEx_t = NTSTATUS(*)(HANDLE ThreadHandle, HANDLE ReserveHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
static inline _NtQueueApcThreadEx_t _NtQueueApcThreadEx = nullptr;
NTSTATUS NtQueueApcThreadEx(HANDLE ThreadHandle, 
                            HANDLE ReserveHandle, 
                            PPS_APC_ROUTINE ApcRoutine, 
                            PVOID ApcArgument1, 
                            PVOID ApcArgument2, 
                            PVOID ApcArgument3)
{
    if (!_NtQueueApcThreadEx) {
        HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
        _NtQueueApcThreadEx = (_NtQueueApcThreadEx_t)GetProcAddress(hNtDll, "NtQueueApcThreadEx");
    }
    return _NtQueueApcThreadEx(ThreadHandle, ReserveHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}

} // namespace Syscall

using Syscall::PPS_APC_ROUTINE;
static inline DWORD QueueSpecialUserAPC(PPS_APC_ROUTINE pfnAPC, HANDLE hThread, PVOID Arg1, PVOID Arg2, PVOID Arg3) {
    return NT_SUCCESS(Syscall::NtQueueApcThreadEx(hThread, QUEUE_USER_APC_SPECIAL_USER_APC, pfnAPC, Arg1, Arg2, Arg3));
}

} // namespace PEMapper

#endif