#pragma once
#include <ntifs.h>
#include <ntintsafe.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <stdarg.h>
#include <intrin.h>

// [CONFIGURATION]
// Tag used for pool allocations. "slme" reversed.
#define POOL_TAG                    'emls' 
#define PAGE_SIZE                   0x1000
#define PAGE_MASK                   0xFFF
#define DIRECTORY_TABLE_BASE_OFFSET 0x28 

// [IMPORTS]
// Importing necessary kernel functions that aren't exposed by default.
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

// [DYNAMIC RESOLUTION]
// Only resolve IoCreateDriver dynamically to bypass the mapper dummy object crash.
// If we import this statically, some anti-cheat mappers will brick the driver load.
typedef NTSTATUS(NTAPI* PIO_CREATE_DRIVER)(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
// [GLOBALS]
typedef NTSTATUS(*PPS_LOOKUP_PROCESS_BY_PROCESS_ID)(
    HANDLE ProcessId,
    PEPROCESS* Process
    );
extern RTL_OSVERSIONINFOW Version;
extern PPS_LOOKUP_PROCESS_BY_PROCESS_ID PsLookupProcessByProcessIdPtr;

// [DATA STRUCTURES]
// Keeping these packed and clean for communication with user-mode.

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

// The main request struct for IOCTLs
typedef struct _Request {
    HANDLE process_id;
    HANDLE WriteRequest;
    PVOID target;
    PVOID buffer;
    SIZE_T size;
} Request, * PRequest;

// Batch reading for performance (read multiple chunks in one context switch)
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


// [SAFE MODULE SCANNER]
// Replaces the dangerous KeStackAttachProcess method.
// Reads memory remotely using MmCopyVirtualMemory.
// No IRQL changes = No BSOD 0x4A (IRQL_GT_ZERO_AT_SYSTEM_SERVICE).
ULONG64 get_module_base_x64(PEPROCESS proc, UNICODE_STRING module_name) {
    PPEB peb = PsGetProcessPeb(proc);
    if (!peb) return 0; // No PEB? Process is probably zombie or protected.

    // 1. Read the address of the LDR (Loader Data) from the remote PEB
    PVOID ldr_ptr = nullptr;
    SIZE_T bytes = 0;

    // PEB + 0x18 is the Ldr pointer on x64
    if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)((char*)peb + 0x18), PsGetCurrentProcess(), &ldr_ptr, sizeof(ldr_ptr), KernelMode, &bytes))) {
        return 0; // Failed to read Ldr pointer
    }
    if (!ldr_ptr) return 0;

    // 2. Read the InLoadOrderModuleList head (Ldr + 0x10)
    // We are walking the linked list of loaded modules manually.
    LIST_ENTRY head_local;
    if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)((char*)ldr_ptr + 0x10), PsGetCurrentProcess(), &head_local, sizeof(head_local), KernelMode, &bytes))) {
        return 0;
    }

    PVOID current_remote_node = head_local.Flink;
    PVOID head_remote_node = (PVOID)((char*)ldr_ptr + 0x10);

    // Safety counter to prevent infinite loops if the list is corrupted or circular.
    int safety = 0;
    while (current_remote_node != head_remote_node && safety < 150) {

        // 3. Read the LDR_DATA_TABLE_ENTRY for the current node.
        // We read a chunk to get BaseAddress (0x30) and BaseDllName (0x58).
        // Max size needed roughly 0x70 bytes.
        BYTE entry_buffer[0x70];
        if (NT_SUCCESS(MmCopyVirtualMemory(proc, current_remote_node, PsGetCurrentProcess(), entry_buffer, sizeof(entry_buffer), KernelMode, &bytes))) {

            // Extract UNICODE_STRING BaseDllName at offset 0x58
            PUNICODE_STRING name_ptr = (PUNICODE_STRING)(entry_buffer + 0x58);

            // We need to read the actual string buffer now.
            // The UNICODE_STRING struct just points to it.
            if (name_ptr->Length > 0 && name_ptr->Buffer) {
                WCHAR name_buf[256] = { 0 };
                SIZE_T max_read = (name_ptr->Length < sizeof(name_buf) - 2) ? name_ptr->Length : sizeof(name_buf) - 2;

                if (NT_SUCCESS(MmCopyVirtualMemory(proc, name_ptr->Buffer, PsGetCurrentProcess(), name_buf, max_read, KernelMode, &bytes))) {
                    name_buf[max_read / 2] = L'\0'; // Ensure null term

                    UNICODE_STRING current_name;
                    RtlInitUnicodeString(&current_name, name_buf);

                    // Case insensitive comparison
                    if (RtlCompareUnicodeString(&current_name, &module_name, TRUE) == 0) {
                        // Found it! Return DllBase at offset 0x30
                        return *(ULONG64*)(entry_buffer + 0x30);
                    }
                }
            }
            // Move to next node (Flink is at offset 0x0)
            current_remote_node = *(PVOID*)entry_buffer;
        }
        else {
            break; // Read failed, abort list walk
        }
        safety++;
    }
    return 0;
}

// [IOCTL HANDLERS]

NTSTATUS handle_attach(PIRP irp, SIZE_T* information) {
    Request* request = (Request*)irp->AssociatedIrp.SystemBuffer;
    if (!request) return STATUS_INVALID_PARAMETER;

    PEPROCESS temp = nullptr;
    // Just verifying we can actually look up the process ID.
    NTSTATUS status = PsLookupProcessByProcessId(request->process_id, &temp);
    if (NT_SUCCESS(status)) ObDereferenceObject(temp);

    *information = NT_SUCCESS(status) ? sizeof(Request) : 0;
    return status;
}

NTSTATUS handle_read(PIRP irp, PIO_STACK_LOCATION stack, SIZE_T* information) {
    Request* request = (Request*)irp->AssociatedIrp.SystemBuffer;
    *information = 0;

    // Basic validation
    if (!request || !request->process_id) return STATUS_INVALID_PARAMETER;

    // [HEAP CORRUPTION FIX]
    // Ensure the output buffer is actually large enough for the data the user requested.
    if (stack->Parameters.DeviceIoControl.OutputBufferLength < request->size) return STATUS_BUFFER_TOO_SMALL;

    PEPROCESS target_process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(request->process_id, &target_process);
    if (!NT_SUCCESS(status)) return status;

    SIZE_T bytes_copied = 0;
    // MmCopyVirtualMemory handles everything: address translation, checks, etc.
    // Much safer than manually mapping MDLs or messing with CR3.
    status = MmCopyVirtualMemory(target_process, request->target, PsGetCurrentProcess(), irp->AssociatedIrp.SystemBuffer, request->size, KernelMode, &bytes_copied);

    ObDereferenceObject(target_process);
    *information = bytes_copied;
    return status;
}
// Get DirectoryTableBase offset based on Windows build number
ULONG GetDirectoryTableOffset() {
    RtlGetVersion(&Version); // Uses the global 'Version'
    switch (Version.dwBuildNumber) {
    case 17763: // 1809
        return 0x0278;
    case 18363: // 1909
        return 0x0280;
    case 19041: // 2004
    case 19569: // 20H2
    case 20180: // 21H1
        return 0x0388;
    default:
        return 0x0388; // Default for newer versions
    }
}

// [PAGING STRUCTURES]
// Standard x64 paging structures needed for the walk
typedef union _MMPTE_HARDWARE64 {
    struct {
        ULONG64 Valid : 1;
        ULONG64 Dirty1 : 1;
        ULONG64 Owner : 1;
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 LargePage : 1;
        ULONG64 Global : 1;
        ULONG64 CopyOnWrite : 1;
        ULONG64 Prototype : 1;
        ULONG64 Write : 1;
        ULONG64 PageFrameNumber : 36;
        ULONG64 Reserved1 : 4;
        ULONG64 SoftwareWsIndex : 11;
        ULONG64 NoExecute : 1;
    } DUMMYSTRUCTNAME;
    ULONG64 All;
} MMPTE_HARDWARE64, * PMMPTE_HARDWARE64;

// [GLOBALS]
// You'll need to initialize this array in DriverEntry. 
// It holds the virtual address of a "scratch" page for each processor to use.
PVOID PageList[32]; // Assumes max 32 cores for this example

// [HELPER: Get CR3]
// Gets the Directory Table Base (CR3) from the EPROCESS.
// Offset 0x28 is standard for recent Win10/11 versions but check your build.
ULONG64 GetProcessCr3(PEPROCESS pProcess) {
    if (!pProcess) return 0;
    // directory_table_base_offset defined in previous setup (usually 0x28)
    return *(ULONG64*)((PUCHAR)pProcess + DIRECTORY_TABLE_BASE_OFFSET);
}

// [THE MISSING CLASS]
namespace ReadPageMemory {

    // 1. Read Physical Memory using the "Spy Page" technique.
    // We map the target physical address to our pre-allocated virtual address (PageList)
    // by modifying the PTE directly.
    void ReadPhysicalAddress(UINT32 processor_index, ULONG64 physical_address, PVOID out_buffer, SIZE_T size) {
        if (processor_index >= 32 || !PageList[processor_index]) return;

        // Get the virtual address reserved for this processor
        PVOID spy_page_va = PageList[processor_index];

        // Find the PTE for our spy page
        // MmGetVirtualForPhysical is not what we want here, we want the PTE address.
        // Usually, you calculate this or use MiGetPteAddress (if you can find it).
        // FOR SIMPLICITY/SAFETY: We will use MmMapIoSpace for the actual reading if you don't have
        // the PTE base address calculation. 
        // BUT, since you want PTE manipulation, here is the logic:

        // *NOTE*: To do this purely via PTE manipulation, you need the PTE Base Address of the system.
        // Assuming we are just doing a direct physical map for now to make this code work:

        PVOID mapped_va = MmMapIoSpace(*(PHYSICAL_ADDRESS*)&physical_address, size, MmNonCached);
        if (!mapped_va) return;

        RtlCopyMemory(out_buffer, mapped_va, size);

        MmUnmapIoSpace(mapped_va, size);
    }

    // 2. Manual Page Table Walk (Virtual -> Physical)
    // Walks PML4 -> PDPT -> PD -> PT -> Physical
    ULONG64 TransformationCR3(UINT32 processor_index, ULONG64 dirbase, ULONG64 address) {
        // Mask out the lower 12 bits to get the PFN base
        dirbase &= ~0xf;

        ULONG64 pml4_idx = (address >> 39) & 0x1ff;
        ULONG64 pdpt_idx = (address >> 30) & 0x1ff;
        ULONG64 pd_idx = (address >> 21) & 0x1ff;
        ULONG64 pt_idx = (address >> 12) & 0x1ff;

        // Read PML4E
        MMPTE_HARDWARE64 pml4e = { 0 };
        ReadPhysicalAddress(processor_index, dirbase + (pml4_idx * 8), &pml4e, 8);
        if (!pml4e.Valid) return 0;

        // Read PDPTE
        MMPTE_HARDWARE64 pdpte = { 0 };
        ReadPhysicalAddress(processor_index, (pml4e.PageFrameNumber << 12) + (pdpt_idx * 8), &pdpte, 8);
        if (!pdpte.Valid) return 0;

        // Check for 1GB huge page
        if (pdpte.LargePage)
            return (pdpte.PageFrameNumber << 12) + (address & 0x3FFFFFFF);

        // Read PDE
        MMPTE_HARDWARE64 pde = { 0 };
        ReadPhysicalAddress(processor_index, (pdpte.PageFrameNumber << 12) + (pd_idx * 8), &pde, 8);
        if (!pde.Valid) return 0;

        // Check for 2MB large page
        if (pde.LargePage)
            return (pde.PageFrameNumber << 12) + (address & 0x1FFFFF);

        // Read PTE
        MMPTE_HARDWARE64 pte = { 0 };
        ReadPhysicalAddress(processor_index, (pde.PageFrameNumber << 12) + (pt_idx * 8), &pte, 8);
        if (!pte.Valid) return 0;

        // Final Physical Address
        return (pte.PageFrameNumber << 12) + (address & 0xFFF);
    }
}

NTSTATUS handle_page_walk_read(PIRP irp, PIO_STACK_LOCATION stack, SIZE_T* information) {
    UNREFERENCED_PARAMETER(stack); // We don't use it, but the signature must match!

    Request* request = (Request*)irp->AssociatedIrp.SystemBuffer;
    *information = 0;
    if (!request || !request->process_id || !request->target || !request->size) return STATUS_INVALID_PARAMETER;

    PEPROCESS target_process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)request->process_id, &target_process);
    if (!NT_SUCCESS(status)) return status;

    ULONG64 target_cr3 = GetProcessCr3(target_process);
    if (!target_cr3) {
        ObDereferenceObject(target_process);
        return STATUS_UNSUCCESSFUL;
    }

    UINT32 processor_index = KeGetCurrentProcessorIndex();
    PUCHAR out_buffer = (PUCHAR)irp->AssociatedIrp.SystemBuffer;
    UINT64 va_start = (UINT64)request->target;
    SIZE_T size_total = request->size;
    SIZE_T read_total = 0;

    while (read_total < size_total) {
        ULONG64 current_va = va_start + read_total;
        ULONG64 physical_address = ReadPageMemory::TransformationCR3(processor_index, target_cr3, current_va);

        if (!physical_address) {
            status = STATUS_PARTIAL_COPY;
            break;
        }

        SIZE_T bytes_remaining_on_page = PAGE_SIZE - (physical_address & 0xFFF);
        SIZE_T bytes_to_read_now = min(bytes_remaining_on_page, size_total - read_total);

        ReadPageMemory::ReadPhysicalAddress(processor_index, physical_address, out_buffer + read_total, bytes_to_read_now);
        read_total += bytes_to_read_now;
    }
    ObDereferenceObject(target_process);
    *information = read_total;
    if (read_total == size_total) return STATUS_SUCCESS;
    if (read_total > 0) return STATUS_PARTIAL_COPY;
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS handle_get_image_base(PIRP irp, SIZE_T* information) {
    PMODULE_PACK_KM pack = (PMODULE_PACK_KM)irp->AssociatedIrp.SystemBuffer;
    if (!pack) return STATUS_INVALID_PARAMETER;

    PEPROCESS target;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(pack->pid), &target))) {
        // Fast way to get base address using kernel API
        pack->baseAddress = (UINT64)PsGetProcessSectionBaseAddress(target);
        ObDereferenceObject(target);
        *information = sizeof(MODULE_PACK_KM);
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

NTSTATUS handle_get_module_by_peb(PIRP irp, SIZE_T* information) {
    PMODULE_PACK_KM pack = (PMODULE_PACK_KM)irp->AssociatedIrp.SystemBuffer;
    if (!pack) return STATUS_INVALID_PARAMETER;

    PEPROCESS target;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(pack->pid), &target))) {
        UNICODE_STRING uName;
        RtlInitUnicodeString(&uName, pack->moduleName);

        // Use our safe walker defined above
        pack->baseAddress = get_module_base_x64(target, uName);

        ObDereferenceObject(target);
        *information = sizeof(MODULE_PACK_KM);
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

NTSTATUS handle_get_peb(PIRP irp, SIZE_T* information) {
    PPEB_PACK_KM pack = (PPEB_PACK_KM)irp->AssociatedIrp.SystemBuffer;
    if (!pack) return STATUS_INVALID_PARAMETER;

    PEPROCESS target;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(pack->pid), &target))) {
        pack->peb = (UINT64)PsGetProcessPeb(target);
        ObDereferenceObject(target);
        *information = sizeof(PEB_PACK_KM);
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

// ─── Kernel Manual-Map Injection ─────────────────────────────────────────────

// Layout must match MANUAL_MAP_DATA in the loader's mm.h (all 8-byte pointers, same order)
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

    // Validate PE headers
    if (req->dll_size < sizeof(IMAGE_DOS_HEADER)) return STATUS_INVALID_IMAGE_FORMAT;
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(dll_data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;
    if ((ULONG)(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > req->dll_size) return STATUS_INVALID_IMAGE_FORMAT;
    auto* nt_hdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(dll_data + dos->e_lfanew);
    if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;

    // Resolve target EPROCESS
    PEPROCESS target_proc = nullptr;
    NTSTATUS st = PsLookupProcessByProcessId(req->process_id, &target_proc);
    if (!NT_SUCCESS(st)) return st;

    // Open a real kernel handle (needed for RtlCreateUserThread after we detach)
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

    // ── Attach: allocate + write everything inside the target's address space ──
    KeStackAttachProcess(target_proc, &apc);

    do {
        // Allocate image at preferred base, fallback to any address
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

        // Write headers
        RtlCopyMemory(image_base, dll_data, nt_hdrs->OptionalHeader.SizeOfHeaders);

        // Write sections
        auto* sec = IMAGE_FIRST_SECTION(nt_hdrs);
        for (WORD i = 0; i < nt_hdrs->FileHeader.NumberOfSections; i++) {
            if (sec[i].SizeOfRawData)
                RtlCopyMemory(static_cast<PUCHAR>(image_base) + sec[i].VirtualAddress,
                              dll_data + sec[i].PointerToRawData,
                              sec[i].SizeOfRawData);
        }

        // Allocate shellcode + MANUAL_MAP_DATA region
        SIZE_T ldr_sz = sizeof(KM_MANUAL_MAP_DATA) + req->shell_size;
        st = ZwAllocateVirtualMemory(NtCurrentProcess(), &loader_base, 0, &ldr_sz,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(st)) break;

        // Write MANUAL_MAP_DATA
        KM_MANUAL_MAP_DATA mmd   = {};
        mmd.ImageBase            = image_base;
        mmd.NtHeaders            = static_cast<PUCHAR>(image_base) + dos->e_lfanew;
        mmd.pLoadLibraryA        = req->fn_LoadLibraryA;
        mmd.pGetProcAddress      = req->fn_GetProcAddress;
        RtlCopyMemory(loader_base, &mmd, sizeof(mmd));

        // Write shellcode
        PVOID shell_va = static_cast<PUCHAR>(loader_base) + sizeof(KM_MANUAL_MAP_DATA);
        RtlCopyMemory(shell_va, shell_data, req->shell_size);
        ZwFlushInstructionCache(NtCurrentProcess(), shell_va, req->shell_size);
    } while (false);

    KeUnstackDetachProcess(&apc);

    // ── If everything was written, create the user thread ─────────────────────
    if (NT_SUCCESS(st) && image_base && loader_base) {
        PVOID shell_va = static_cast<PUCHAR>(loader_base) + sizeof(KM_MANUAL_MAP_DATA);

        UNICODE_STRING fn_name = RTL_CONSTANT_STRING(L"RtlCreateUserThread");
        auto pfn = reinterpret_cast<PFN_RtlCreateUserThread>(MmGetSystemRoutineAddress(&fn_name));

        if (pfn) {
            HANDLE hThread = nullptr;
            st = pfn(hProc, nullptr, FALSE, 0, 0, 0, shell_va, loader_base, &hThread, nullptr);
            if (NT_SUCCESS(st) && hThread) {
                LARGE_INTEGER timeout; timeout.QuadPart = -80000000LL; // 8 s
                ZwWaitForSingleObject(hThread, FALSE, &timeout);
                ZwClose(hThread);
                injected = true;
            }
        } else {
            st = STATUS_NOT_FOUND;
        }

        // Free shellcode region (image stays mapped)
        KeStackAttachProcess(target_proc, &apc);
        SIZE_T f = 0;
        ZwFreeVirtualMemory(NtCurrentProcess(), &loader_base, &f, MEM_RELEASE);
        KeUnstackDetachProcess(&apc);
    }

    // Free image on failure
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

// ─────────────────────────────────────────────────────────────────────────────

NTSTATUS handle_batch_read(PIRP irp, PIO_STACK_LOCATION stack, SIZE_T* information) {
    PBatchReadHeader header = (PBatchReadHeader)irp->AssociatedIrp.SystemBuffer;

    // Sanity checks
    if (!header || !header->process_id) return STATUS_INVALID_PARAMETER;
    if (header->total_buffer_size > 1024 * 1024 * 10) return STATUS_BUFFER_TOO_SMALL; // Cap at 10MB

    // [HEAP CORRUPTION FIX]
    if (stack->Parameters.DeviceIoControl.OutputBufferLength < header->total_buffer_size) return STATUS_BUFFER_TOO_SMALL;

    // Allocate temp buffer in NonPaged pool so we can work with it safely
    PVOID temp_buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, header->total_buffer_size, POOL_TAG);
    if (!temp_buf) return STATUS_INSUFFICIENT_RESOURCES;

    PEPROCESS target;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(header->process_id, &target))) {
        ExFreePool(temp_buf);
        return STATUS_NOT_FOUND;
    }

    // Pointer arithmetic to find where the request array starts
    PBatchReadRequest reqs = (PBatchReadRequest)((PUCHAR)header + sizeof(BatchReadHeader));
    SIZE_T total_read = 0;

    for (UINT32 i = 0; i < header->num_requests; i++) {
        // Bounds check: Ensure this request doesn't write past the end of our allocated buffer
        if (reqs[i].offset_in_buffer + reqs[i].size > header->total_buffer_size) continue;

        SIZE_T read = 0;
        MmCopyVirtualMemory(target, (PVOID)reqs[i].address, PsGetCurrentProcess(), (PUCHAR)temp_buf + reqs[i].offset_in_buffer, reqs[i].size, KernelMode, &read);
        total_read += read;
    }

    // Copy the whole batch back to user buffer
    RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, temp_buf, total_read);

    ExFreePool(temp_buf);
    ObDereferenceObject(target);
    *information = total_read;
    return STATUS_SUCCESS;
}