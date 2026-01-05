#include "Module.h"

ULONG_PTR GetModuleR3(HANDLE pid, char* moduleName)
{
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
	if (!NT_SUCCESS(status))
	{
		return 0;
	}
	STRING aModuleName = { 0 };
	RtlInitAnsiString(&aModuleName, moduleName);
	UNICODE_STRING uModuleName = { 0 };
	status = RtlAnsiStringToUnicodeString(&uModuleName, &aModuleName, TRUE);
	if (!NT_SUCCESS(status))
	{
		return 0;
	}
	_wcsupr(uModuleName.Buffer);
	KAPC_STATE kApcState = {0};
	KeStackAttachProcess(process, &kApcState);


	KeUnstackDetachProcess(&kApcState);
}
