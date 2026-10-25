#pragma once
#include <cstdio>
#include "driver.h"
#include "shellcode.h"

// Waits until the window with the given class name appears, then returns its PID + thread ID.
// Mirrors face-injector-v2/inject/utils.h get_process_id_and_thread_id_by_window_class.
static DWORD get_process_id_and_thread_id_by_window_class(LPCSTR class_name, PDWORD p_thread_id)
{
    DWORD process_id = 0;
    while (!process_id)
    {
        *p_thread_id = GetWindowThreadProcessId(FindWindowA(class_name, NULL), &process_id);
        Sleep(20);
    }
    return process_id;
}

static PVOID read_dll_from_disk(LPCWSTR dll_path, SIZE_T* out_size)
{
    HANDLE h = CreateFileW(dll_path, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return nullptr;

    LARGE_INTEGER file_sz = {};
    if (!GetFileSizeEx(h, &file_sz) || file_sz.QuadPart == 0)
    {
        CloseHandle(h);
        return nullptr;
    }

    *out_size = static_cast<SIZE_T>(file_sz.QuadPart);
    PVOID buf = VirtualAlloc(NULL, *out_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { CloseHandle(h); return nullptr; }

    DWORD read = 0;
    if (!ReadFile(h, buf, static_cast<DWORD>(*out_size), &read, NULL) ||
        *reinterpret_cast<PUSHORT>(buf) != IMAGE_DOS_SIGNATURE)
    {
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseHandle(h);
        return nullptr;
    }

    CloseHandle(h);
    return buf;
}

// Drop-in replacement for face-injector-v2's face_injecor_v2().
// Finds the target process via window class, then uses the BS driver's
// kernel_inject IOCTL (0x990) to manual-map the DLL.
void face_injecor_v2(LPCSTR window_class_name, LPCWSTR dll_path)
{
    // read DLL
    SIZE_T dll_size = 0;
    PVOID  dll_image = read_dll_from_disk(dll_path, &dll_size);
    if (!dll_image)
    {
        printf("invalid dll\n");
        return;
    }

    // wait for target window
    DWORD thread_id  = 0;
    DWORD process_id = get_process_id_and_thread_id_by_window_class(window_class_name, &thread_id);

    printf("process_id: 0x%X\n", process_id);
    printf("thread_id:  0x%X\n", thread_id);

    // shellcode extents — works for /Od (debug) and release with /GL disabled
    SIZE_T shell_size = reinterpret_cast<uintptr_t>(loader_main_end) -
                        reinterpret_cast<uintptr_t>(loader_main);

    printf("shell_size: 0x%zX\n", shell_size);

    // send to driver: alloc + map + inject thread
    PVOID mapped = driver().kernel_inject(process_id,
                                          dll_image,  dll_size,
                                          reinterpret_cast<PVOID>(loader_main), shell_size);

    VirtualFree(dll_image, 0, MEM_RELEASE);

    if (mapped)
        printf("inject success! mapped_base: 0x%p\n", mapped);
    else
        printf("inject failed (kernel_inject returned null)\n");
}
