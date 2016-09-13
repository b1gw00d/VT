#include<intrin.h>
#include <ntddk.h>
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevice_object, PIRP pIrp);
NTSTATUS DispatchClose(PDEVICE_OBJECT pDevice_object, PIRP pIrp);
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevice_object, PIRP pIrp);
VOID DriverUnload(PDRIVER_OBJECT pDriver_object);
NTSTATUS OpenVT();

extern"C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver_object, PUNICODE_STRING reg_part)
{

	pDriver_object->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriver_object->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriver_object->DriverUnload = DriverUnload;
	OpenVT();
	return STATUS_SUCCESS;
}



NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevice_object, PIRP pIrp)
{

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevice_object, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevice_object, PIRP pIrp)
{
	PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(pIrp);
	ULONGLONG ulonglongbuffer = 0;
	PVOID buffer;
	ULONG inlen;
	ULONG outlen;
	ULONGLONG bufferaddress;
	switch (irpsp->MajorFunction)
	{
	case IRP_MJ_DEVICE_CONTROL:

		buffer = pIrp->AssociatedIrp.SystemBuffer;
		inlen = irpsp->Parameters.DeviceIoControl.InputBufferLength;
		outlen = irpsp->Parameters.DeviceIoControl.OutputBufferLength;
		switch (irpsp->Parameters.DeviceIoControl.IoControlCode)
		{
		default:
			pIrp->IoStatus.Status = STATUS_SUCCESS;
			pIrp->IoStatus.Information = 0;
			break;
		}
		break;

	default:
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = 0;
		break;
	}
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT pDriver_object)
{

}
