#pragma once
#include "types.h"

// IOCTL codes — must match km/src/main.cpp driver::codes
#define IOCTL_ATTACH        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x850, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_READ          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x851, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_KERNEL_INJECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x990, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

class c_driver
{
public:
    c_driver() = default;

    ~c_driver()
    {
        if (h_driver != INVALID_HANDLE_VALUE)
            CloseHandle(h_driver);
    }

    bool open()
    {
        h_driver = CreateFileW(
            L"\\\\.\\slimegetem",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        return h_driver != INVALID_HANDLE_VALUE;
    }

    bool is_open() const { return h_driver != INVALID_HANDLE_VALUE; }

    NTSTATUS attach(DWORD pid)
    {
        Request req = {};
        req.process_id = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid));
        return send_ioctl(IOCTL_ATTACH, &req, sizeof(req), nullptr, 0);
    }

    // Builds the flat buffer [KernelInjectRequest | dll_bytes | shell_bytes] and sends it.
    // Returns mapped_base in the target on success, nullptr on failure.
    PVOID kernel_inject(DWORD pid, PVOID dll_data, SIZE_T dll_size, PVOID shell_data, SIZE_T shell_size)
    {
        SIZE_T   total = sizeof(KernelInjectRequest) + dll_size + shell_size;
        auto*    buf   = static_cast<PUCHAR>(VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!buf) return nullptr;

        auto* req            = reinterpret_cast<PKernelInjectRequest>(buf);
        req->process_id      = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid));
        req->dll_size        = dll_size;
        req->shell_size      = shell_size;
        req->fn_LoadLibraryA  = reinterpret_cast<UINT64>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA"));
        req->fn_GetProcAddress = reinterpret_cast<UINT64>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcAddress"));
        req->mapped_base     = nullptr;

        memcpy(buf + sizeof(KernelInjectRequest), dll_data, dll_size);
        memcpy(buf + sizeof(KernelInjectRequest) + dll_size, shell_data, shell_size);

        // METHOD_BUFFERED: same buffer for in/out so the driver's written mapped_base comes back
        DWORD bytes_ret = 0;
        BOOL  ok = DeviceIoControl(h_driver, IOCTL_KERNEL_INJECT,
                                   buf, static_cast<DWORD>(total),
                                   buf, static_cast<DWORD>(total),
                                   &bytes_ret, NULL);

        PVOID mapped = (ok && bytes_ret >= sizeof(KernelInjectRequest)) ? req->mapped_base : nullptr;
        VirtualFree(buf, 0, MEM_RELEASE);
        return mapped;
    }

    static c_driver& get()
    {
        static c_driver instance;
        return instance;
    }

private:
    HANDLE h_driver = INVALID_HANDLE_VALUE;

    NTSTATUS send_ioctl(ULONG code, PVOID in_buf, DWORD in_sz, PVOID out_buf, DWORD out_sz)
    {
        if (h_driver == INVALID_HANDLE_VALUE)
            return STATUS_DEVICE_DOES_NOT_EXIST;

        DWORD bytes = 0;
        if (!DeviceIoControl(h_driver, code, in_buf, in_sz, out_buf, out_sz, &bytes, NULL))
            return STATUS_UNSUCCESSFUL;

        return STATUS_SUCCESS;
    }

    c_driver(const c_driver&)            = delete;
    c_driver& operator=(const c_driver&) = delete;
};

inline c_driver& driver() { return c_driver::get(); }
