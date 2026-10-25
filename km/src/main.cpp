#pragma comment(lib, "ntoskrnl.lib")
#include "helpers.h"

// Global to hold OS version info so we don't have to fetch it every time.
RTL_OSVERSIONINFOW Version = { 0 };

namespace driver {
    namespace codes {
        // Defining our IOCTL control codes. 
        // These are the magic numbers the user-mode app will send to tell the driver what to do.
        // using FILE_DEVICE_UNKNOWN and METHOD_BUFFERED is standard for this kind of "communication" driver.
        constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x850, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x851, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG get_pid = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x852, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG get_module_by_peb = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x853, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG get_image_base = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x854, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG get_peb = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x855, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG batch_read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x860, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG get_logs = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x865, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG nt_read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x980, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG page_walk_read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x981, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG page_walk_write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x982, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG kernel_inject = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x990, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG free_virtual_memory = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x995, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    }

    // Basic create handler. Just says "Success" when someone grabs a handle to the driver.
    NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    // Close handler. Clean up when they let go of the handle.
    NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    // The meat and potatoes. This handles the actual commands sent from user mode.
    NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);

        // Sanity check: If we're running at a high IRQL (interrupt level), we can't safely access paged memory.
        // If we try, we'll likely BSOD the system, so bail out.
        if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_UNSUCCESSFUL;

        // Get the current stack location to figure out what the hell the caller wants.
        PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);

        // If the stack is garbage or the system buffer is missing, we can't do anything.
        if (!stack_irp || !irp->AssociatedIrp.SystemBuffer) {
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }

        // Grab the specific IOCTL code from the stack parameters.
        ULONG ioctl = stack_irp->Parameters.DeviceIoControl.IoControlCode;
        NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
        SIZE_T information = 0;

        // Route the request to the correct handler based on the IOCTL code.
        switch (ioctl) {
            // Read operations - routing to specific safe handlers in helpers.h
        case codes::read: status = handle_read(irp, stack_irp, &information); break;
        case codes::page_walk_read: status = handle_page_walk_read(irp, stack_irp, &information); break;
        case codes::batch_read: status = handle_batch_read(irp, stack_irp, &information); break;

            // Metadata and Info gathering ops
        case codes::attach: status = handle_attach(irp, &information); break;
        case codes::get_module_by_peb: status = handle_get_module_by_peb(irp, &information); break;
        case codes::get_image_base: status = handle_get_image_base(irp, &information); break;
        case codes::get_peb: status = handle_get_peb(irp, &information); break;
            // Kernel manual-map injection
        case codes::kernel_inject: status = handle_kernel_inject(irp, stack_irp, &information); break;
            // Unknown command? Tell 'em to kick rocks.
        default: status = STATUS_INVALID_DEVICE_REQUEST; break;
        }

        // Finish up the IRP and send the status back to the caller.
        irp->IoStatus.Status = status;
        irp->IoStatus.Information = information;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
    }
}

// The actual setup function called by IoCreateDriver.
NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);

    // First thing to go tits up, change this to whatever to bypass some weak checks ricochet does
    UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\slimegetem");
    UNICODE_STRING sym_link = RTL_CONSTANT_STRING(L"\\DosDevices\\slimegetem");
    PDEVICE_OBJECT device_object = nullptr;

    // Create the device object so the OS knows we exist.
    NTSTATUS status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);
    if (!NT_SUCCESS(status)) return status;

    // Create a symbolic link so user mode apps can actually find us (usually via CreateFile).
    status = IoCreateSymbolicLink(&sym_link, &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device_object); // Clean up if the link fails.
        return status;
    }

    // Set up Buffered IO - safer because the I/O manager handles the buffers for us.
    SetFlag(device_object->Flags, DO_BUFFERED_IO);

    // Hook up our function pointers.
    driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

    // We're done initializing, clear the flag so we can start taking requests.
    ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);
    return STATUS_SUCCESS;
}

// Entry point.
// Looks like we're using the IoCreateDriver trick, which is common for manually mapped drivers 
// or when you don't have a standard service registry key setup.
NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(driver_object);
    UNREFERENCED_PARAMETER(registry_path);

    // Resolve IoCreateDriver dynamically.
    UNICODE_STRING s_IoCreateDriver = RTL_CONSTANT_STRING(L"IoCreateDriver");
    PIO_CREATE_DRIVER IoCreateDriverPtr = (PIO_CREATE_DRIVER)MmGetSystemRoutineAddress(&s_IoCreateDriver);

    if (IoCreateDriverPtr) {
        UNICODE_STRING driver_name;
        // The driver name here needs to match what we expect internally, though it might be hidden later.
        RtlInitUnicodeString(&driver_name, L"\\Driver\\slimegetem");
        return IoCreateDriverPtr(&driver_name, &driver_main);
    }

    // If we can't find IoCreateDriver, we're screwed.
    return STATUS_FAILED_DRIVER_ENTRY;
}