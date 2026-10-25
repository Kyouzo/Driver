#pragma once
#include <ntifs.h>
#include <ntintsafe.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <stdarg.h>
#include <intrin.h>

#define POOL_TAG                    'emls'
#define PAGE_SIZE                   0x1000
#define PAGE_MASK                   0xFFF
#define DIRECTORY_TABLE_BASE_OFFSET 0x28

extern "C" {
    NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
    NTKERNELAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);
    NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
    NTKERNELAPI NTSTATUS NTAPI PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);
    NTKERNELAPI PVOID NTAPI MmGetVirtualForPhysical(PHYSICAL_ADDRESS PhysicalAddress);
    NTKERNELAPI NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
    NTKERNELAPI PVOID NTAPI MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName);
    NTSYSAPI NTSTATUS NTAPI ZwFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);
}

typedef NTSTATUS(NTAPI* PIO_CREATE_DRIVER)(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);

typedef NTSTATUS(*PPS_LOOKUP_PROCESS_BY_PROCESS_ID)(
    HANDLE ProcessId,
    PEPROCESS* Process
    );

extern RTL_OSVERSIONINFOW Version;
extern PPS_LOOKUP_PROCESS_BY_PROCESS_ID PsLookupProcessByProcessIdPtr;

typedef struct _PID_PACK {
    UINT32 pid;
    WCHAR name[1024];
} PID_PACK, * P_PID_PACK;

typedef struct _MODULE_PACK_KM {
    UINT32 pid;
    UINT64 baseAddress;
    WCHAR moduleName[1024];
} MODULE_PACK_KM, * PMODULE_PACK_KM;

typedef struct _PEB_PACK_KM {
    UINT32 pid;
    UINT64 peb;
} PEB_PACK_KM, * PPEB_PACK_KM;

typedef struct _Request {
    HANDLE process_id;
    HANDLE WriteRequest;
    PVOID target;
    PVOID buffer;
    SIZE_T size;
} Request, * PRequest;

typedef struct _BatchReadHeader {
    HANDLE process_id;
    UINT32 num_requests;
    SIZE_T total_buffer_size;
} BatchReadHeader, * PBatchReadHeader;

typedef struct _BatchReadRequest {
    DWORD64 address;
    SIZE_T size;
    SIZE_T offset_in_buffer;
} BatchReadRequest, * PBatchReadRequest;
