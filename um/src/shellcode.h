#pragma once
#include "types.h"

// Loader shellcode that runs inside the target process as a new thread.
// Receives PMANUAL_MAP_DATA as first argument (rcx, Windows x64 ABI).
// Responsibilities: fix base relocations, resolve imports, call DllMain.
//
// Compilation requirements for PIC correctness:
//   /GS-           no security cookie (non-PIC __security_check_cookie call)
//   /RTCs- /RTCu-  no RTC checks (non-PIC helpers)
//   /Od            disable optimizations (prevents unexpected codegen)
//
// The loader_stub_end sentinel immediately follows loader_main in the object.
// shell_size = (uintptr_t)loader_stub_end - (uintptr_t)loader_main

#pragma runtime_checks("", off)
#pragma strict_gs_check(off)
#pragma optimize("", off)

using pfn_LoadLibraryA_t   = HMODULE(WINAPI*)(LPCSTR);
using pfn_GetProcAddress_t = FARPROC(WINAPI*)(HMODULE, LPCSTR);
using pfn_DllMain_t        = BOOL(WINAPI*)(HINSTANCE, DWORD, PVOID);

void __stdcall loader_main(PMANUAL_MAP_DATA pData)
{
    if (!pData)
        return;

    auto* image_base = static_cast<PUCHAR>(pData->ImageBase);
    auto* nt         = reinterpret_cast<PIMAGE_NT_HEADERS>(pData->NtHeaders);
    auto  LoadLibA   = reinterpret_cast<pfn_LoadLibraryA_t>(pData->pLoadLibraryA);
    auto  GetProcA   = reinterpret_cast<pfn_GetProcAddress_t>(pData->pGetProcAddress);

    // --- Fix base relocations -----------------------------------------------
    LONGLONG delta = reinterpret_cast<LONGLONG>(image_base) - static_cast<LONGLONG>(nt->OptionalHeader.ImageBase);
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

    // --- Resolve imports ----------------------------------------------------
    auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (import_dir.Size)
    {
        auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(image_base + import_dir.VirtualAddress);

        while (desc->Name)
        {
            auto  mod_name = reinterpret_cast<LPCSTR>(image_base + desc->Name);
            HMODULE hMod   = LoadLibA(mod_name);

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
                    auto* ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(image_base + oft->u1.AddressOfData);
                    iat->u1.Function = reinterpret_cast<ULONGLONG>(GetProcA(hMod, ibn->Name));
                }

                iat++;
                oft++;
            }

            desc++;
        }
    }

    // --- Call DllMain -------------------------------------------------------
    if (nt->OptionalHeader.AddressOfEntryPoint)
    {
        auto fn_main = reinterpret_cast<pfn_DllMain_t>(image_base + nt->OptionalHeader.AddressOfEntryPoint);
        fn_main(reinterpret_cast<HINSTANCE>(image_base), DLL_PROCESS_ATTACH, nullptr);
    }

    // signal completion to the driver (via KM_MANUAL_MAP_DATA::pDllMain)
    pData->pDllMain = 1;
}

static void __declspec(noinline) loader_main_end() { }

#pragma optimize("", on)
#pragma runtime_checks("", on)
