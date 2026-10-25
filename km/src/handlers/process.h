#pragma once
#include "../types.h"

ULONG64 get_module_base_x64(PEPROCESS proc, UNICODE_STRING module_name) {
    PPEB peb = PsGetProcessPeb(proc);
    if (!peb) return 0;

    PVOID ldr_ptr = nullptr;
    SIZE_T bytes = 0;

    if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)((char*)peb + 0x18), PsGetCurrentProcess(), &ldr_ptr, sizeof(ldr_ptr), KernelMode, &bytes)))
        return 0;
    if (!ldr_ptr) return 0;

    LIST_ENTRY head_local;
    if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)((char*)ldr_ptr + 0x10), PsGetCurrentProcess(), &head_local, sizeof(head_local), KernelMode, &bytes)))
        return 0;

    PVOID current_remote_node = head_local.Flink;
    PVOID head_remote_node = (PVOID)((char*)ldr_ptr + 0x10);

    int safety = 0;
    while (current_remote_node != head_remote_node && safety < 150) {
        BYTE entry_buffer[0x70];
        if (NT_SUCCESS(MmCopyVirtualMemory(proc, current_remote_node, PsGetCurrentProcess(), entry_buffer, sizeof(entry_buffer), KernelMode, &bytes))) {
            PUNICODE_STRING name_ptr = (PUNICODE_STRING)(entry_buffer + 0x58);
            if (name_ptr->Length > 0 && name_ptr->Buffer) {
                WCHAR name_buf[256] = { 0 };
                SIZE_T max_read = (name_ptr->Length < sizeof(name_buf) - 2) ? name_ptr->Length : sizeof(name_buf) - 2;

                if (NT_SUCCESS(MmCopyVirtualMemory(proc, name_ptr->Buffer, PsGetCurrentProcess(), name_buf, max_read, KernelMode, &bytes))) {
                    name_buf[max_read / 2] = L'\0';

                    UNICODE_STRING current_name;
                    RtlInitUnicodeString(&current_name, name_buf);

                    if (RtlCompareUnicodeString(&current_name, &module_name, TRUE) == 0)
                        return *(ULONG64*)(entry_buffer + 0x30);
                }
            }
            current_remote_node = *(PVOID*)entry_buffer;
        }
        else {
            break;
        }
        safety++;
    }
    return 0;
}

NTSTATUS handle_attach(PIRP irp, SIZE_T* information) {
    Request* request = (Request*)irp->AssociatedIrp.SystemBuffer;
    if (!request) return STATUS_INVALID_PARAMETER;

    PEPROCESS temp = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(request->process_id, &temp);
    if (NT_SUCCESS(status)) ObDereferenceObject(temp);

    *information = NT_SUCCESS(status) ? sizeof(Request) : 0;
    return status;
}

NTSTATUS handle_get_image_base(PIRP irp, SIZE_T* information) {
    PMODULE_PACK_KM pack = (PMODULE_PACK_KM)irp->AssociatedIrp.SystemBuffer;
    if (!pack) return STATUS_INVALID_PARAMETER;

    PEPROCESS target;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(pack->pid), &target))) {
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
