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

	if (OperationType == RegNtPreSetValueKey && PreSetValueInfo->Type >= '0002') {

		//DbgBreakPoint();

		if (PreSetValueInfo->DataSize == NULL) {

			RtlFreeMemoryEx(InjectData.InjectData);

			RtlZeroMemoryEx(&InjectData, sizeof(InjectData));

			Status = NT_SUCCESS(InjectNotifyInit(FALSE)) ? ERROR_成功 : ERROR_失败;
		}

		if (PreSetValueInfo->DataSize == sizeof(INJECT_DATA)) {

			PINJECT_DATA pBuffer = (PINJECT_DATA)PreSetValueInfo->Data;

			if (InjectData.InjectData == NULL) {

				RtlCopyMemoryEx(&InjectData, pBuffer, PreSetValueInfo->DataSize);

				InjectData.InjectData = RtlAllocateMemory(pBuffer->InjectSize);

				if (InjectData.InjectData == NULL) {

					Status = ERROR_失败;
				}

				if (InjectData.InjectData != NULL) {

					RtlCopyMemoryEx(InjectData.InjectData, pBuffer->InjectData, pBuffer->InjectSize);

					Status = NT_SUCCESS(InjectNotifyInit(TRUE) + ProcessNotifyInit(InjectData.InjectHide == 1 ? TRUE : FALSE)) ? ERROR_成功 : ERROR_失败;
				}
			}
		}
	}
	if (OperationType == RegNtPreSetValueKey && PreSetValueInfo->Type == '0006'/*GS_内存读写*/) {

		//DbgBreakPoint();

		typedef struct _READ_WRITE_MEMORY_BUFFER {
			ULONG64 hProcessId;
			PVOID64 TargetAddress;
			PVOID64 SourceAddress;
			ULONG64 NumberOfBytes;
			ULONG32 ReadWriteType;
		} READ_WRITE_MEMORY_BUFFER, * PREAD_WRITE_MEMORY_BUFFER;

		if (PreSetValueInfo->DataSize == sizeof(READ_WRITE_MEMORY_BUFFER)) {

			PREAD_WRITE_MEMORY_BUFFER pBuffer = (PREAD_WRITE_MEMORY_BUFFER)PreSetValueInfo->Data;

			PEPROCESS pProcess = NULL;;

			HANDLE hProcess = NULL;

			Status = OpenProcessEx((HANDLE)(pBuffer->hProcessId), &pProcess, pBuffer->ReadWriteType == 2 ? &hProcess : NULL);

			if (NT_SUCCESS(Status) != TRUE) {

				Status = ERROR_无法打开进程;
			}

			if (NT_SUCCESS(Status) == TRUE) {

				if (pBuffer->TargetAddress == NULL || pBuffer->SourceAddress == NULL) {

					Status = ERROR_读写地址错误;
				}

				if (pBuffer->TargetAddress != NULL && pBuffer->SourceAddress != NULL) {
					//如果是读内存
					if (pBuffer->ReadWriteType == 0) {

						Status = NT_SUCCESS(ZwCopyVirtualMemory(pProcess, pBuffer->TargetAddress, PsGetCurrentProcess(), pBuffer->SourceAddress, pBuffer->NumberOfBytes, UserMode)) ? ERROR_成功 : ERROR_失败;
					}
					//如果是写内存
					if (pBuffer->ReadWriteType == 1) {

						Status = NT_SUCCESS(ZwCopyVirtualMemory(PsGetCurrentProcess(), pBuffer->SourceAddress, pProcess, pBuffer->TargetAddress, pBuffer->NumberOfBytes, UserMode)) ? ERROR_成功 : ERROR_失败;
					}
					//如果是强写内存
					if (pBuffer->ReadWriteType == 2) {

						if (pBuffer->NumberOfBytes > PAGE_SIZE) {

							Status = ERROR_超出读写字节;
						}

						if (pBuffer->NumberOfBytes <= PAGE_SIZE) {

							if (hProcess == NULL) {

								Status = ERROR_无法打开进程;
							}

							if (hProcess != NULL) {

								MEMORY_BASIC_INFORMATION Mbi;

								Status = ZwQueryVirtualMemory(hProcess, pBuffer->TargetAddress, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);

								if (NT_SUCCESS(Status) != TRUE) {

									Status = ERROR_查询内存失败;
								}

								if (NT_SUCCESS(Status) == TRUE) {

									if (Mbi.Protect != PAGE_READONLY && Mbi.Protect != PAGE_EXECUTE_READ) {

										Status = NT_SUCCESS(ZwCopyVirtualMemory(PsGetCurrentProcess(), pBuffer->SourceAddress, pProcess, pBuffer->TargetAddress, pBuffer->NumberOfBytes, UserMode)) ? ERROR_成功 : ERROR_失败;
									}

									if (Mbi.Protect == PAGE_READONLY || Mbi.Protect == PAGE_EXECUTE_READ) {

										LPVOID WriteData = RtlAllocateMemory(PAGE_SIZE);

										if (WriteData == NULL) {

											Status = ERROR_分配内存失败;
										}

										if (WriteData != NULL) {

											struct {
												ULONG64 hProcessId;
												PVOID64 TargetAddress;
												PVOID64 SourceAddress;
												ULONG64 NumberOfBytes;
												ULONG32 ReadWriteType;
											} Cache;

											RtlCopyMemoryEx(&Cache, pBuffer, sizeof(Cache));

											RtlCopyMemoryEx(WriteData, pBuffer->SourceAddress, pBuffer->NumberOfBytes);

											KPROCESSOR_MODE OldPevMode = SetPreviousMode(KernelMode);

											KAPC_STATE ApcState;

											KeStackAttachProcess(pProcess, &ApcState);

											PMDL lpMemoryDescriptorList = MmCreateMdl(NULL, Cache.TargetAddress, Cache.NumberOfBytes);

											if (lpMemoryDescriptorList != NULL) {
												//锁定物理页到 MDL
												MmProbeAndLockPages(lpMemoryDescriptorList, KernelMode, IoReadAccess);
												//将 MDL 映射到系统地址空间
												LPVOID lpMappedAddress = MmMapLockedPagesSpecifyCache(lpMemoryDescriptorList, KernelMode, MmCached, NULL, 0, NormalPagePriority);

												if (lpMappedAddress != NULL) {

													RtlCopyMemoryEx(lpMappedAddress, WriteData, Cache.NumberOfBytes);

													MmUnmapLockedPages(lpMappedAddress, lpMemoryDescriptorList);

													Status = ERROR_成功;
												}

												MmUnlockPages(lpMemoryDescriptorList);

												IoFreeMdl(lpMemoryDescriptorList);
											}

											KeUnstackDetachProcess(&ApcState);

											SetPreviousMode(OldPevMode);

											RtlFreeMemoryEx(WriteData);

											Status = Status == ERROR_成功 ? ERROR_成功 : ERROR_失败;
										}
									}
								}
								ObCloseHandle(hProcess, KernelMode);
							}
						}
					}
				}
			}
		}
	}
	return Status;
}


auto OpenProcessEx(HANDLE hProcessId, PEPROCESS* pProcess, HANDLE* hProcess) -> NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	Status = PsLookupProcessByProcessId(hProcessId, pProcess);

	if (NT_SUCCESS(Status)) {

		if (hProcess != NULL) {
			//把 PEPROCESS 转换成一个“合法的进程 HANDLE”，以便走 Zw / Nt / Mm 等“句柄型 API”
			Status = ObOpenObjectByPointer(*pProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, hProcess);
		}
		ObfDereferenceObject(*pProcess);
	}
	return Status;
}