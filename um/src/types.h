#pragma once
#include <Windows.h>
#include <cstdint>
#pragma warning(disable : 4005)
#include <ntstatus.h>
#pragma warning(default : 4005)

// Matches km/src/types.h _Request
typedef struct _Request {
    HANDLE  process_id;
    HANDLE  WriteRequest;
    PVOID   target;
    PVOID   buffer;
    SIZE_T  size;
} Request, *PRequest;

// Matches km/src/handlers/inject.h _KernelInjectRequest
// Buffer layout: [KernelInjectRequest | dll_bytes | shellcode_bytes]
typedef struct _KernelInjectRequest {
    HANDLE  process_id;
    SIZE_T  dll_size;
    SIZE_T  shell_size;
    UINT64  fn_LoadLibraryA;
    UINT64  fn_GetProcAddress;
    PVOID   mapped_base;    // output: set by driver on success
} KernelInjectRequest, *PKernelInjectRequest;

// Matches km/src/handlers/inject.h _KM_MANUAL_MAP_DATA
// Passed as parameter to the loader shellcode via RtlCreateUserThread
typedef struct _MANUAL_MAP_DATA {
    PVOID   ImageBase;
    PVOID   NtHeaders;          // PIMAGE_NT_HEADERS inside the mapped image
    UINT64  pLoadLibraryA;
    UINT64  pGetProcAddress;
    UINT64  pDllMain;           // shellcode sets this to 1 when done
} MANUAL_MAP_DATA, *PMANUAL_MAP_DATA;
