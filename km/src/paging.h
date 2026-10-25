#pragma once
#include "types.h"

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

PVOID PageList[32];

ULONG GetDirectoryTableOffset() {
    RtlGetVersion(&Version);
    switch (Version.dwBuildNumber) {
    case 17763: return 0x0278;
    case 18363: return 0x0280;
    case 19041:
    case 19569:
    case 20180: return 0x0388;
    default:    return 0x0388;
    }
}

ULONG64 GetProcessCr3(PEPROCESS pProcess) {
    if (!pProcess) return 0;
    return *(ULONG64*)((PUCHAR)pProcess + DIRECTORY_TABLE_BASE_OFFSET);
}

namespace ReadPageMemory {

    void ReadPhysicalAddress(UINT32 processor_index, ULONG64 physical_address, PVOID out_buffer, SIZE_T size) {
        if (processor_index >= 32 || !PageList[processor_index]) return;

        PVOID mapped_va = MmMapIoSpace(*(PHYSICAL_ADDRESS*)&physical_address, size, MmNonCached);
        if (!mapped_va) return;

        RtlCopyMemory(out_buffer, mapped_va, size);
        MmUnmapIoSpace(mapped_va, size);
    }

    ULONG64 TransformationCR3(UINT32 processor_index, ULONG64 dirbase, ULONG64 address) {
        dirbase &= ~0xf;

        ULONG64 pml4_idx = (address >> 39) & 0x1ff;
        ULONG64 pdpt_idx = (address >> 30) & 0x1ff;
        ULONG64 pd_idx   = (address >> 21) & 0x1ff;
        ULONG64 pt_idx   = (address >> 12) & 0x1ff;

        MMPTE_HARDWARE64 pml4e = { 0 };
        ReadPhysicalAddress(processor_index, dirbase + (pml4_idx * 8), &pml4e, 8);
        if (!pml4e.Valid) return 0;

        MMPTE_HARDWARE64 pdpte = { 0 };
        ReadPhysicalAddress(processor_index, (pml4e.PageFrameNumber << 12) + (pdpt_idx * 8), &pdpte, 8);
        if (!pdpte.Valid) return 0;

        if (pdpte.LargePage)
            return (pdpte.PageFrameNumber << 12) + (address & 0x3FFFFFFF);

        MMPTE_HARDWARE64 pde = { 0 };
        ReadPhysicalAddress(processor_index, (pdpte.PageFrameNumber << 12) + (pd_idx * 8), &pde, 8);
        if (!pde.Valid) return 0;

        if (pde.LargePage)
            return (pde.PageFrameNumber << 12) + (address & 0x1FFFFF);

        MMPTE_HARDWARE64 pte = { 0 };
        ReadPhysicalAddress(processor_index, (pde.PageFrameNumber << 12) + (pt_idx * 8), &pte, 8);
        if (!pte.Valid) return 0;

        return (pte.PageFrameNumber << 12) + (address & 0xFFF);
    }
}
