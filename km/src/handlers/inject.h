#pragma once
#include "../types.h"

// Layout must match MANUAL_MAP_DATA in the loader's inject/mm.h (all 8-byte pointers, same order)
typedef struct _KM_MANUAL_MAP_DATA {
    PVOID  ImageBase;
    PVOID  NtHeaders;        // PIMAGE_NT_HEADERS inside the remote image
    UINT64 pLoadLibraryA;
    UINT64 pGetProcAddress;
    UINT64 pDllMain;         // filled by shellcode as confirmation
} KM_MANUAL_MAP_DATA;

// IOCTL input/output struct — followed in the buffer by dll_size DLL bytes then shell_size shellcode bytes
typedef struct _KernelInjectRequest {
    HANDLE  process_id;
    SIZE_T  dll_size;
    SIZE_T  shell_size;
    UINT64  fn_LoadLibraryA;
    UINT64  fn_GetProcAddress;
    PVOID   mapped_base;     // output: set by driver on success
} KernelInjectRequest, *PKernelInjectRequest;

typedef NTSTATUS(NTAPI* PFN_RtlCreateUserThread)(
    HANDLE              ProcessHandle,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN             CreateSuspended,
    ULONG               StackZeroBits,
    SIZE_T              StackReserve,
    SIZE_T              StackCommit,
    PVOID               StartAddress,
    PVOID               Parameter,
    PHANDLE             ThreadHandle,
    PVOID               ClientId
);

NTSTATUS handle_kernel_inject(PIRP irp, PIO_STACK_LOCATION stack, SIZE_T* info) {
    *info = 0;

    const ULONG in_len = stack->Parameters.DeviceIoControl.InputBufferLength;
    if (in_len < sizeof(KernelInjectRequest))
        return STATUS_BUFFER_TOO_SMALL;

    auto* req = static_cast<PKernelInjectRequest>(irp->AssociatedIrp.SystemBuffer);
    if (!req->process_id || !req->dll_size || !req->shell_size)
        return STATUS_INVALID_PARAMETER;

    if (in_len < sizeof(KernelInjectRequest) + req->dll_size + req->shell_size)
        return STATUS_BUFFER_TOO_SMALL;

    auto* dll_data   = reinterpret_cast<PUCHAR>(req + 1);
    auto* shell_data = dll_data + req->dll_size;

    if (req->dll_size < sizeof(IMAGE_DOS_HEADER)) return STATUS_INVALID_IMAGE_FORMAT;
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(dll_data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;
    if ((ULONG)(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > req->dll_size) return STATUS_INVALID_IMAGE_FORMAT;
    auto* nt_hdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(dll_data + dos->e_lfanew);
    if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;

    PEPROCESS target_proc = nullptr;
    NTSTATUS st = PsLookupProcessByProcessId(req->process_id, &target_proc);
    if (!NT_SUCCESS(st)) return st;

    HANDLE hProc = nullptr;
    st = ObOpenObjectByPointer(target_proc, OBJ_KERNEL_HANDLE, nullptr,
                               PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProc);
    if (!NT_SUCCESS(st)) {
        ObDereferenceObject(target_proc);
        return st;
    }

    req->mapped_base = nullptr;

    PVOID image_base  = nullptr;
    PVOID loader_base = nullptr;
    KAPC_STATE apc    = {};
    bool injected     = false;

    KeStackAttachProcess(target_proc, &apc);

    do {
        SIZE_T img_sz  = nt_hdrs->OptionalHeader.SizeOfImage;
        image_base     = reinterpret_cast<PVOID>(nt_hdrs->OptionalHeader.ImageBase);
        st = ZwAllocateVirtualMemory(NtCurrentProcess(), &image_base, 0, &img_sz,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(st)) {
            img_sz     = nt_hdrs->OptionalHeader.SizeOfImage;
            image_base = nullptr;
            st = ZwAllocateVirtualMemory(NtCurrentProcess(), &image_base, 0, &img_sz,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }
        if (!NT_SUCCESS(st)) break;

        RtlCopyMemory(image_base, dll_data, nt_hdrs->OptionalHeader.SizeOfHeaders);

        auto* sec = IMAGE_FIRST_SECTION(nt_hdrs);
        for (WORD i = 0; i < nt_hdrs->FileHeader.NumberOfSections; i++) {
            if (sec[i].SizeOfRawData)
                RtlCopyMemory(static_cast<PUCHAR>(image_base) + sec[i].VirtualAddress,
                              dll_data + sec[i].PointerToRawData,
                              sec[i].SizeOfRawData);
        }

        SIZE_T ldr_sz = sizeof(KM_MANUAL_MAP_DATA) + req->shell_size;
        st = ZwAllocateVirtualMemory(NtCurrentProcess(), &loader_base, 0, &ldr_sz,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(st)) break;

        KM_MANUAL_MAP_DATA mmd   = {};
        mmd.ImageBase            = image_base;
        mmd.NtHeaders            = static_cast<PUCHAR>(image_base) + dos->e_lfanew;
        mmd.pLoadLibraryA        = req->fn_LoadLibraryA;
        mmd.pGetProcAddress      = req->fn_GetProcAddress;
        RtlCopyMemory(loader_base, &mmd, sizeof(mmd));

        PVOID shell_va = static_cast<PUCHAR>(loader_base) + sizeof(KM_MANUAL_MAP_DATA);
        RtlCopyMemory(shell_va, shell_data, req->shell_size);
        ZwFlushInstructionCache(NtCurrentProcess(), shell_va, req->shell_size);
    } while (false);

    KeUnstackDetachProcess(&apc);

    if (NT_SUCCESS(st) && image_base && loader_base) {
        PVOID shell_va = static_cast<PUCHAR>(loader_base) + sizeof(KM_MANUAL_MAP_DATA);

        UNICODE_STRING fn_name = RTL_CONSTANT_STRING(L"RtlCreateUserThread");
        auto pfn = reinterpret_cast<PFN_RtlCreateUserThread>(MmGetSystemRoutineAddress(&fn_name));

        if (pfn) {
            HANDLE hThread = nullptr;
            st = pfn(hProc, nullptr, FALSE, 0, 0, 0, shell_va, loader_base, &hThread, nullptr);
            if (NT_SUCCESS(st) && hThread) {
                LARGE_INTEGER timeout; timeout.QuadPart = -80000000LL;
                ZwWaitForSingleObject(hThread, FALSE, &timeout);
                ZwClose(hThread);
                injected = true;
            }
        } else {
            st = STATUS_NOT_FOUND;
        }

        KeStackAttachProcess(target_proc, &apc);
        SIZE_T f = 0;
        ZwFreeVirtualMemory(NtCurrentProcess(), &loader_base, &f, MEM_RELEASE);
        KeUnstackDetachProcess(&apc);
    }

    if (!injected && image_base) {
        KeStackAttachProcess(target_proc, &apc);
        SIZE_T f = 0;
        ZwFreeVirtualMemory(NtCurrentProcess(), &image_base, &f, MEM_RELEASE);
        KeUnstackDetachProcess(&apc);
        image_base = nullptr;
    }

    ZwClose(hProc);
    ObDereferenceObject(target_proc);

    if (injected) {
        req->mapped_base = image_base;
        *info = sizeof(KernelInjectRequest);
        return STATUS_SUCCESS;
    }
    return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
}
