#include "driverhexin.h"

PHOOK_NOTIFY_BUFFER pRegisterNotifyHookBuffer = NULL;

auto RegisterNotifyInit(BOOLEAN Enable) -> NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (pRegisterNotifyHookBuffer->Enable != Enable) {

		if (pRegisterNotifyHookBuffer->HookPoint == NULL) {

			UNICODE_STRING funcName;

			RtlInitUnicodeString(&funcName, L"CmRegisterCallback");

			PVOID realCmRegisterCallback = MmGetSystemRoutineAddress(&funcName);

			DbgPrint("[DEBUG] Real CmRegisterCallback at: 0x%p\n", realCmRegisterCallback);

			pRegisterNotifyHookBuffer->HookPoint = SearchSignForImage2(DynamicData->KernelBase, "\xFF\xE1", "xx", 2);

			DbgPrint("[DEBUG] Found FF E1 at: 0x%p\n",pRegisterNotifyHookBuffer->HookPoint);
		}

		if (pRegisterNotifyHookBuffer->HookPoint != NULL) {

			if (Enable == TRUE) {

				Status = CmRegisterCallback((PEX_CALLBACK_FUNCTION)(pRegisterNotifyHookBuffer->HookPoint), RegisterNotify, &pRegisterNotifyHookBuffer->Cookie);

				if (NT_SUCCESS(Status)) {

					pRegisterNotifyHookBuffer->Enable = TRUE;
				}
			}

			if (Enable != TRUE) {

				if (pRegisterNotifyHookBuffer->HookPoint != NULL) {

					Status = CmUnRegisterCallback(pRegisterNotifyHookBuffer->Cookie);

					if (NT_SUCCESS(Status)) {

						pRegisterNotifyHookBuffer->Enable = FALSE;
					}
				}
			}
		}
	}

	if (pRegisterNotifyHookBuffer->Enable == Enable) {

		Status = STATUS_SUCCESS;
	}

	return Status;
}


auto RegisterNotify(LPVOID, REG_NOTIFY_CLASS OperationType, PREG_SET_VALUE_KEY_INFORMATION PreSetValueInfo) -> NTSTATUS {

	NTSTATUS Status = STATUS_SUCCESS;

	if (OperationType == RegNtPreSetValueKey && PreSetValueInfo->Type >= '0000') {
		DbgBreakPoint();
	}

	return Status;
}
