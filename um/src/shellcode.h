#pragma once
#include "types.h"

// Loader shellcode declarations — implementation is in shellcode.cpp.
// Both functions are placed in the ".ldr" section via #pragma code_seg so that
//   shell_size = (uintptr_t)loader_main_end - (uintptr_t)loader_main
// is the exact byte-count of loader_main with no foreign code in between.

void __stdcall loader_main(PMANUAL_MAP_DATA pData);
void           loader_main_end();
