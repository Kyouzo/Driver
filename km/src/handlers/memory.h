#pragma once
#include "../types.h"
#include "../paging.h"

NTSTATUS handle_read(PIRP irp, PIO_STACK_LOCATION stack, SIZE_T* information) {
    Request* request = (Request*)irp->AssociatedIrp.SystemBuffer;
    *information = 0;

    if (!request || !request->process_id) return STATUS_INVALID_PARAMETER;
    if (stack->Parameters.DeviceIoControl.OutputBufferLength < request->size) return STATUS_BUFFER_TOO_SMALL;

    PEPROCESS target_process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(request->process_id, &target_process);
    if (!NT_SUCCESS(status)) return status;

    SIZE_T bytes_copied = 0;
    status = MmCopyVirtualMemory(target_process, request->target, PsGetCurrentProcess(), irp->AssociatedIrp.SystemBuffer, request->size, KernelMode, &bytes_copied);

    ObDereferenceObject(target_process);
    *information = bytes_copied;
    return status;
}

NTSTATUS handle_page_walk_read(PIRP irp, PIO_STACK_LOCATION stack, SIZE_T* information) {
    UNREFERENCED_PARAMETER(stack);

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

NTSTATUS handle_batch_read(PIRP irp, PIO_STACK_LOCATION stack, SIZE_T* information) {
    PBatchReadHeader header = (PBatchReadHeader)irp->AssociatedIrp.SystemBuffer;

    if (!header || !header->process_id) return STATUS_INVALID_PARAMETER;
    if (header->total_buffer_size > 1024 * 1024 * 10) return STATUS_BUFFER_TOO_SMALL;
    if (stack->Parameters.DeviceIoControl.OutputBufferLength < header->total_buffer_size) return STATUS_BUFFER_TOO_SMALL;

    PVOID temp_buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, header->total_buffer_size, POOL_TAG);
    if (!temp_buf) return STATUS_INSUFFICIENT_RESOURCES;

    PEPROCESS target;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(header->process_id, &target))) {
        ExFreePool(temp_buf);
        return STATUS_NOT_FOUND;
    }

    PBatchReadRequest reqs = (PBatchReadRequest)((PUCHAR)header + sizeof(BatchReadHeader));
    SIZE_T total_read = 0;

    for (UINT32 i = 0; i < header->num_requests; i++) {
        if (reqs[i].offset_in_buffer + reqs[i].size > header->total_buffer_size) continue;

        SIZE_T read = 0;
        MmCopyVirtualMemory(target, (PVOID)reqs[i].address, PsGetCurrentProcess(), (PUCHAR)temp_buf + reqs[i].offset_in_buffer, reqs[i].size, KernelMode, &read);
        total_read += read;
    }

    RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, temp_buf, total_read);

    ExFreePool(temp_buf);
    ObDereferenceObject(target);
    *information = total_read;
    return STATUS_SUCCESS;
}
