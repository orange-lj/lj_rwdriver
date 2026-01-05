#include <ntifs.h>
#include "VMXTools.h"

VOID KeGenericCallDpc(PKDEFERRED_ROUTINE Routine,PVOID Context);

VOID KeSignalCallDpcDone(PVOID Context);

LOGICAL KeSignalCallDpcSynchronize(PVOID Context);

VOID VmxStartVT(_In_ struct _KDPC* Dpc,_In_opt_ PVOID DeferredContext,_In_opt_ PVOID SystemArgument1,_In_opt_ PVOID SystemArgument2)
{
	if (VmxIsCheckBIOSSupport()) 
	{
		DbgPrintEx(77, 0, "VmxIsCheckBIOSSupport number = %d\r\n", KeGetCurrentProcessorNumber());

		if (VmxIsCheckCPUIDSupport())
		{
			DbgPrintEx(77, 0, "VmxIsCheckCPUIDSupport number = %d\r\n", KeGetCurrentProcessorNumber());

			if (VmxIsCheckCR4Support())
			{
				DbgPrintEx(77, 0, "VmxIsCheckCR4Support number = %d\r\n", KeGetCurrentProcessorNumber());
			}
		}
	}

	KeSignalCallDpcDone(SystemArgument1);

	KeSignalCallDpcSynchronize(SystemArgument2);
}

VOID VmxStopVT(_In_ struct _KDPC* Dpc, _In_opt_ PVOID DeferredContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
	KeSignalCallDpcDone(SystemArgument1);

	KeSignalCallDpcSynchronize(SystemArgument2);
}

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	KeGenericCallDpc(VmxStopVT, NULL);
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg) 
{
	KeGenericCallDpc(VmxStartVT, NULL);

	pDriver->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}