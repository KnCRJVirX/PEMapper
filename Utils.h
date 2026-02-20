#ifndef GET_INFO_UTILS
#define GET_INFO_UTILS

#include <stdint.h>
#include <windows.h>
#include <winternl.h>

// PEB_LDR_DATA的完整定义
typedef struct _PEB_LDR_DATA_FULL   /* Size=0x58 */
{
    /* 0x0000 */ uint32_t Length;
    /* 0x0004 */ unsigned char Initialized;
    unsigned char Padding[3];
    /* 0x0008 */ void* SsHandle;
    /* 0x0010 */ LIST_ENTRY InLoadOrderModuleList;
    /* 0x0020 */ LIST_ENTRY InMemoryOrderModuleList;
    /* 0x0030 */ LIST_ENTRY InInitializationOrderModuleList;
    /* 0x0040 */ void* EntryInProgress;
    /* 0x0048 */ unsigned char ShutdownInProgress;
    unsigned char Padding2[3];
    /* 0x0050 */ void* ShutdownThreadId;
} PEB_LDR_DATA_FULL;

// LDR_DATA_TABLE_ENTRY 的完整定义
typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;             // 0x00
    LIST_ENTRY InMemoryOrderLinks;           // 0x10
    LIST_ENTRY InInitializationOrderLinks;   // 0x20
    PVOID DllBase;                           // 0x30
    PVOID EntryPoint;                        // 0x38
    ULONG SizeOfImage;                       // 0x40
    UNICODE_STRING FullDllName;              // 0x48
    UNICODE_STRING BaseDllName;              // 0x58
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

struct _LEAP_SECOND_DATA   /* Size=0x10 */
{
    /* 0x0000 */ unsigned char Enabled;
    /* 0x0004 */ uint32_t Count;
    /* 0x0008 */ _LARGE_INTEGER Data[1];
};

typedef struct _PEB_FULL   /* Size=0x7c8 */
{
    /* 0x0000 */ unsigned char InheritedAddressSpace;
    /* 0x0001 */ unsigned char ReadImageFileExecOptions;
    /* 0x0002 */ unsigned char BeingDebugged;
    /* 0x0003 */ unsigned char BitFieldFlags;
    /* 0x0004 */ unsigned char Padding0[4];
    /* 0x0008 */ void* Mutant;
    /* 0x0010 */ void* ImageBaseAddress;
    /* 0x0018 */ _PEB_LDR_DATA_FULL* Ldr;
    /* 0x0020 */ _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    /* 0x0028 */ void* SubSystemData;
    /* 0x0030 */ void* ProcessHeap;
    /* 0x0038 */ _RTL_CRITICAL_SECTION* FastPebLock;
    /* 0x0040 */ _SLIST_HEADER* AtlThunkSListPtr;
    /* 0x0048 */ void* IFEOKey;
    /* 0x0050 */ uint32_t CrossProcessFlags;
    /* 0x0054 */ unsigned char Padding1[4];
    /* 0x0058 */ void* KernelCallbackTable;
    /* 0x0060 */ uint32_t SystemReserved;
    /* 0x0064 */ uint32_t AtlThunkSListPtr32;
    /* 0x0068 */ void* ApiSetMap;
    /* 0x0070 */ uint32_t TlsExpansionCounter;
    /* 0x0074 */ unsigned char Padding2[4];
    /* 0x0078 */ void* TlsBitmap;
    /* 0x0080 */ uint32_t TlsBitmapBits[2];
    /* 0x0088 */ void* ReadOnlySharedMemoryBase;
    /* 0x0090 */ void* SharedData;
    /* 0x0098 */ void** ReadOnlyStaticServerData;
    /* 0x00a0 */ void* AnsiCodePageData;
    /* 0x00a8 */ void* OemCodePageData;
    /* 0x00b0 */ void* UnicodeCaseTableData;
    /* 0x00b8 */ uint32_t NumberOfProcessors;
    /* 0x00bc */ uint32_t NtGlobalFlag;
    /* 0x00c0 */ _LARGE_INTEGER CriticalSectionTimeout;
    /* 0x00c8 */ uint64_t HeapSegmentReserve;
    /* 0x00d0 */ uint64_t HeapSegmentCommit;
    /* 0x00d8 */ uint64_t HeapDeCommitTotalFreeThreshold;
    /* 0x00e0 */ uint64_t HeapDeCommitFreeBlockThreshold;
    /* 0x00e8 */ uint32_t NumberOfHeaps;
    /* 0x00ec */ uint32_t MaximumNumberOfHeaps;
    /* 0x00f0 */ void** ProcessHeaps;
    /* 0x00f8 */ void* GdiSharedHandleTable;
    /* 0x0100 */ void* ProcessStarterHelper;
    /* 0x0108 */ uint32_t GdiDCAttributeList;
    /* 0x010c */ unsigned char Padding3[4];
    /* 0x0110 */ _RTL_CRITICAL_SECTION* LoaderLock;
    /* 0x0118 */ uint32_t OSMajorVersion;
    /* 0x011c */ uint32_t OSMinorVersion;
    /* 0x0120 */ uint16_t OSBuildNumber;
    /* 0x0122 */ uint16_t OSCSDVersion;
    /* 0x0124 */ uint32_t OSPlatformId;
    /* 0x0128 */ uint32_t ImageSubsystem;
    /* 0x012c */ uint32_t ImageSubsystemMajorVersion;
    /* 0x0130 */ uint32_t ImageSubsystemMinorVersion;
    /* 0x0134 */ unsigned char Padding4[4];
    /* 0x0138 */ uint64_t ActiveProcessAffinityMask;
    /* 0x0140 */ uint32_t GdiHandleBuffer[60];
    /* 0x0230 */ void* PostProcessInitRoutine;
    /* 0x0238 */ void* TlsExpansionBitmap;
    /* 0x0240 */ uint32_t TlsExpansionBitmapBits[32];
    /* 0x02c0 */ uint32_t SessionId;
    /* 0x02c4 */ unsigned char Padding5[4];
    /* 0x02c8 */ _ULARGE_INTEGER AppCompatFlags;
    /* 0x02d0 */ _ULARGE_INTEGER AppCompatFlagsUser;
    /* 0x02d8 */ void* pShimData;
    /* 0x02e0 */ void* AppCompatInfo;
    /* 0x02e8 */ _UNICODE_STRING CSDVersion;
    /* 0x02f8 */ void* ActivationContextData;
    /* 0x0300 */ void* ProcessAssemblyStorageMap;
    /* 0x0308 */ void* SystemDefaultActivationContextData;
    /* 0x0310 */ void* SystemAssemblyStorageMap;
    /* 0x0318 */ uint64_t MinimumStackCommit;
    /* 0x0320 */ void* SparePointers[4];
    /* 0x0340 */ uint32_t SpareUlongs[5];
    uint32_t PaddingSpareUlongs;
    /* 0x0358 */ void* WerRegistrationData;
    /* 0x0360 */ void* WerShipAssertPtr;
    /* 0x0368 */ void* pUnused;
    /* 0x0370 */ void* pImageHeaderHash;
    /* 0x0378 */ uint32_t TracingFlags;
    /* 0x037c */ unsigned char Padding6[4];
    /* 0x0380 */ uint64_t CsrServerReadOnlySharedMemoryBase;
    /* 0x0388 */ uint64_t TppWorkerpListLock;
    /* 0x0390 */ _LIST_ENTRY TppWorkerpList;
    /* 0x03a0 */ void* WaitOnAddressHashTable[128];
    /* 0x07a0 */ void* TelemetryCoverageHeader;
    /* 0x07a8 */ uint32_t CloudFileFlags;
    /* 0x07ac */ uint32_t CloudFileDiagFlags;
    /* 0x07b0 */ char PlaceholderCompatibilityMode;
    /* 0x07b1 */ char PlaceholderCompatibilityModeReserved[7];
    /* 0x07b8 */ _LEAP_SECOND_DATA* LeapSecondData;
    /* 0x07c0 */ uint32_t LeapSecondFlags;
    /* 0x07c4 */ uint32_t NtGlobalFlag2;
} PEB_FULL, *PPEB_FULL;

#endif