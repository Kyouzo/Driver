// shellcode.cpp — PIC x64 loader that runs as a thread in the target process.
//
// Section ordering guarantee:
//   loader_main  -> #pragma code_seg(".ldr$b")
//   loader_main_end -> #pragma code_seg(".ldr$e")
//
// The MSVC linker merges .ldr$* sections in alphabetical order of the suffix:
//   .ldr$b  (begin) always precedes  .ldr$e  (end)
// This is the same mechanism the CRT uses for .CRT$XCA/.CRT$XCZ and the kernel
// uses for INIT_SECTION / PAGE_SECTION.  It works regardless of /Gy or /ZI.
//
// shell_size = (uintptr_t)loader_main_end - (uintptr_t)loader_main
//   = bytes of loader_main + any linker alignment padding before .ldr$e
// Sending a few extra pad bytes to the driver is harmless; they never execute.

#include "shellcode.h"
#include <Windows.h>

#pragma runtime_checks("", off)
#pragma strict_gs_check(off)
#pragma optimize("", off)

using pfn_LoadLibraryA_t   = HMODULE(WINAPI*)(LPCSTR);
using pfn_GetProcAddress_t = FARPROC(WINAPI*)(HMODULE, LPCSTR);
using pfn_DllMain_t        = BOOL(WINAPI*)(HINSTANCE, DWORD, PVOID);

// ---- loader lives in .ldr$b ------------------------------------------------
#pragma code_seg(".ldr$b")

void __stdcall loader_main(PMANUAL_MAP_DATA pData)
{
    if (!pData)
        return;

    auto* image_base = static_cast<PUCHAR>(pData->ImageBase);
    auto* nt         = reinterpret_cast<PIMAGE_NT_HEADERS>(pData->NtHeaders);
    auto  LoadLibA   = reinterpret_cast<pfn_LoadLibraryA_t>(pData->pLoadLibraryA);
    auto  GetProcA   = reinterpret_cast<pfn_GetProcAddress_t>(pData->pGetProcAddress);

    // --- Fix base relocations ---
    LONGLONG delta = reinterpret_cast<LONGLONG>(image_base)
                   - static_cast<LONGLONG>(nt->OptionalHeader.ImageBase);

    auto& reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta != 0 && reloc_dir.Size)
    {
        auto* reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(image_base + reloc_dir.VirtualAddress);
        while (reloc->VirtualAddress)
        {
            UINT32 count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto*  list  = reinterpret_cast<PWORD>(reloc + 1);
            for (UINT32 i = 0; i < count; i++)
            {
                if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64)
                {
                    auto* patch = reinterpret_cast<PULONGLONG>(
                        image_base + reloc->VirtualAddress + (list[i] & 0xFFF));
                    *patch += static_cast<ULONGLONG>(delta);
                }
            }
            reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<PUCHAR>(reloc) + reloc->SizeOfBlock);
        }
    }

    // --- Resolve imports ---
    auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size)
    {
        auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
            image_base + import_dir.VirtualAddress);

        while (desc->Name)
        {
            auto    mod_name = reinterpret_cast<LPCSTR>(image_base + desc->Name);
            HMODULE hMod     = LoadLibA(mod_name);

            auto* iat = reinterpret_cast<PIMAGE_THUNK_DATA>(image_base + desc->FirstThunk);
            auto* oft = desc->OriginalFirstThunk
                      ? reinterpret_cast<PIMAGE_THUNK_DATA>(image_base + desc->OriginalFirstThunk)
                      : iat;

            while (iat->u1.AddressOfData)
            {
                if (IMAGE_SNAP_BY_ORDINAL64(oft->u1.Ordinal))
                {
                    iat->u1.Function = reinterpret_cast<ULONGLONG>(
                        GetProcA(hMod, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL64(oft->u1.Ordinal))));
                }
                else
                {
                    auto* ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        image_base + oft->u1.AddressOfData);
                    iat->u1.Function = reinterpret_cast<ULONGLONG>(GetProcA(hMod, ibn->Name));
                }
                iat++;
                oft++;
            }
            desc++;
        }
    }

    // --- Call DllMain ---
    if (nt->OptionalHeader.AddressOfEntryPoint)
    {
        auto fn_main = reinterpret_cast<pfn_DllMain_t>(
            image_base + nt->OptionalHeader.AddressOfEntryPoint);
        fn_main(reinterpret_cast<HINSTANCE>(image_base), DLL_PROCESS_ATTACH, nullptr);
    }

    pData->pDllMain = 1;
}

// ---- sentinel lives in .ldr$e — always after .ldr$b -----------------------
#pragma code_seg(".ldr$e")

void loader_main_end() {}

// reset code segment
#pragma code_seg()
#pragma optimize("", on)
#pragma runtime_checks("", on)
