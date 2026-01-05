#include"driverhexin.h"
PDYNDATA DynamicData = NULL;





VOID DriverUnload(PDRIVER_OBJECT pDriver)
{

}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pReg)
{
	DbgBreakPoint();
	DynamicData = (PDYNDATA)(RtlAllocateMemory(sizeof(DYNDATA)));

	if (MmIsAddressValid(DynamicData)) {

		DynamicData->UserVerify = TRUE;


	}
	pDriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}