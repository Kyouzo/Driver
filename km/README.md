# Driver

A Windows kernel-mode driver exposing cross-process memory operations and DLL injection via a buffered IOCTL interface. Uses `IoCreateDriver` resolved dynamically through `MmGetSystemRoutineAddress`, bypassing the standard service registry requirement — the standard entry point for manually-mapped drivers.

## Features

- **Cross-process memory read** via `MmCopyVirtualMemory` — IRQL-safe, no MDL overhead, avoids `KeStackAttachProcess`
- **Batch read** — multiple scattered VA ranges serviced in a single context switch, with an intermediate non-paged pool buffer (capped at 10 MB)
- **Physical page-walk read** — manual CR3 → PML4 → PDPT → PD → PT traversal; handles 1 GB and 2 MB large pages; physical access via `MmMapIoSpace`
- **Module enumeration** — walks the target PEB's `InLoadOrderModuleList` remotely using `MmCopyVirtualMemory`, case-insensitive match
- **Image base lookup** via `PsGetProcessSectionBaseAddress`
- **PEB retrieval** via `PsGetProcessPeb`
- **Kernel manual-map injection** — allocates + writes DLL and shellcode into the target process via `KeStackAttachProcess`, executes via `RtlCreateUserThread`, cleans up the shellcode region after the thread returns

## Requirements

- Windows 10 / 11 — x64 or ARM64
- Visual Studio 2022 with the **Windows Driver Kit (WDK)** installed
- A method to load an unsigned driver (test-signing mode, a signed vulnerable-driver mapper, or DSE patch)

## Building

1. Open `Driver.sln` in Visual Studio.
2. Select a configuration: `Debug|x64`, `Release|x64`, or the ARM64 variants.
3. If your usermode shared headers live elsewhere, update **Additional Include Directories** in the `km` project's C/C++ properties to point at that path.
4. Build — output lands in `build\km.sys` and `build\km.inf`.

The project targets `WindowsKernelModeDriver10.0` with `stdcpp20` and links against `ntoskrnl.lib`.

## IOCTL Reference

Open a handle to the device with `CreateFileW(L"\\\\.\\slimegetem", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr)`.

All IOCTLs use `METHOD_BUFFERED` with `FILE_SPECIAL_ACCESS`.

| Name | Code | Input / Output | Description |
|------|------|----------------|-------------|
| `attach` | `0x850` | `Request` in/out | Validates that a PID exists via `PsLookupProcessByProcessId`. |
| `read` | `0x851` | `Request` in/out; output buffer receives bytes | Reads `size` bytes from `target` in the process identified by `process_id` using `MmCopyVirtualMemory`. |
| `get_module_by_peb` | `0x853` | `MODULE_PACK_KM` in/out | Walks the PEB's `InLoadOrderModuleList` remotely and returns the base address of the named module. |
| `get_image_base` | `0x854` | `MODULE_PACK_KM` in/out | Returns the main executable image base via `PsGetProcessSectionBaseAddress`. |
| `get_peb` | `0x855` | `PEB_PACK_KM` in/out | Returns the PEB address for the given PID via `PsGetProcessPeb`. |
| `batch_read` | `0x860` | `BatchReadHeader` + `BatchReadRequest[]` in; packed buffer out | Reads multiple scattered VA ranges in a single IOCTL call. Capped at 10 MB total. |
| `page_walk_read` | `0x981` | `Request` in/out | Reads via a manual x64 page-table walk (CR3 from EPROCESS + `0x28`) using `MmMapIoSpace` for physical access. Handles large pages. Requires `PageList` to be initialized. |
| `kernel_inject` | `0x990` | `KernelInjectRequest` + DLL bytes + shellcode bytes in; `mapped_base` out | Manual-maps a DLL into the target process from kernel space and executes via `RtlCreateUserThread`. Shellcode region freed after thread returns. |

## Data Structures

```c
typedef struct _Request {
    HANDLE process_id;
    HANDLE WriteRequest;
    PVOID  target;          // source VA in target process
    PVOID  buffer;          // destination VA in calling process
    SIZE_T size;
} Request;

typedef struct _MODULE_PACK_KM {
    UINT32 pid;
    UINT64 baseAddress;     // output
    WCHAR  moduleName[1024];
} MODULE_PACK_KM;

typedef struct _PEB_PACK_KM {
    UINT32 pid;
    UINT64 peb;             // output
} PEB_PACK_KM;

typedef struct _BatchReadHeader {
    HANDLE  process_id;
    UINT32  num_requests;
    SIZE_T  total_buffer_size;
} BatchReadHeader;

typedef struct _BatchReadRequest {
    DWORD64 address;
    SIZE_T  size;
    SIZE_T  offset_in_buffer; // byte offset into the output buffer
} BatchReadRequest;

typedef struct _KernelInjectRequest {
    HANDLE  process_id;
    SIZE_T  dll_size;
    SIZE_T  shell_size;
    UINT64  fn_LoadLibraryA;
    UINT64  fn_GetProcAddress;
    PVOID   mapped_base;    // output: set by driver on success
} KernelInjectRequest;

// Layout of the data region written before the shellcode.
// Must match MANUAL_MAP_DATA in your loader's mm.h (all 8-byte pointers, same order).
typedef struct _KM_MANUAL_MAP_DATA {
    PVOID  ImageBase;
    PVOID  NtHeaders;       // PIMAGE_NT_HEADERS inside the remote image
    UINT64 pLoadLibraryA;
    UINT64 pGetProcAddress;
    UINT64 pDllMain;        // filled by shellcode as completion signal
} KM_MANUAL_MAP_DATA;
```

### batch_read buffer layout

```
[ BatchReadHeader ][ BatchReadRequest[0] ][ BatchReadRequest[1] ] ... [ BatchReadRequest[N-1] ]
```

The output buffer receives all read regions packed at the offsets each request specifies.

### kernel_inject buffer layout

```
[ KernelInjectRequest ][ DLL bytes (dll_size) ][ shellcode bytes (shell_size) ]
```

## Project Structure

```
Driver/
├── Driver.sln
├── km/
│   ├── src/
│   │   ├── main.cpp          # DriverEntry, IoCreateDriver bootstrap, IOCTL dispatch
│   │   ├── helpers.h         # Aggregated include — pulls in all sub-headers
│   │   ├── types.h           # Shared structs, kernel API externs, POOL_TAG, page defines
│   │   ├── paging.h          # MMPTE_HARDWARE64, page-walk logic, GetProcessCr3
│   │   └── handlers/
│   │       ├── process.h     # attach, get_image_base, get_module_by_peb, get_peb
│   │       ├── memory.h      # read, page_walk_read, batch_read
│   │       └── inject.h      # KernelInjectRequest, KM_MANUAL_MAP_DATA, kernel_inject
│   ├── km.vcxproj
│   └── km.inf
└── build/
    ├── km.sys            # Compiled driver binary
    ├── um_d.lib          # Usermode import library
    └── km.inf
```

## Notes

- The device name (`slimegetem`) and driver name can be changed in `main.cpp` to avoid string-based detection.
- `IoCreateDriver` is resolved dynamically via `MmGetSystemRoutineAddress` to prevent crashes when loaded through mappers that supply a dummy driver object — static import would dereference an invalid object on driver unload.
- The `DirectoryTableBase` offset used by the page-walk path is set to `0x28` (EPROCESS + 0x28, the `DIRECTORY_TABLE_BASE_OFFSET` constant in `types.h`); `GetDirectoryTableOffset()` in `paging.h` returns build-specific values (0x0278 / 0x0280 / 0x0388) for different Windows builds — for use with `UserDirectoryTableBase` or other per-build offsets.
- The `page_walk_read` path requires `PageList[processor_index]` to be populated with pre-allocated non-paged virtual pages (one per logical processor) before the first call. This initialization is not included in the current codebase.
- `kernel_inject` uses `KeStackAttachProcess` to allocate and write into the target's address space; the shellcode region is freed after `RtlCreateUserThread` returns (8-second wait). The mapped DLL image is left in the target process.
- The IOCTL codes `get_pid` (0x852), `get_logs` (0x865), `nt_read` (0x980), `page_walk_write` (0x982), and `free_virtual_memory` (0x995) are defined but have no handler in the current dispatch table.