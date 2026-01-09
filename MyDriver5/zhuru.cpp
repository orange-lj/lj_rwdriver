#include "driverhexin.h"

INJECT_DATA InjectData;

INJECT_CACHE InjectCache;

PHOOK_NOTIFY_BUFFER pInjectNotifyHookBuffer = NULL;

auto InjectNotifyInit(ULONG Enable) -> NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (pInjectNotifyHookBuffer->Enable != Enable) {

		if (pInjectNotifyHookBuffer->HookPoint == NULL) {

			pInjectNotifyHookBuffer->HookPoint = GetSystemDrvJumpHook(InjectNotify, pInjectNotifyHookBuffer);
		}

		if (pInjectNotifyHookBuffer->HookPoint != NULL) {

			if (Enable == TRUE) {

				DbgBreakPoint();

				RtlSuperCopyMemory(pInjectNotifyHookBuffer->HookPoint, pInjectNotifyHookBuffer->NewBytes, sizeof(pInjectNotifyHookBuffer->NewBytes));

				Status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)(pInjectNotifyHookBuffer->HookPoint));

				if (NT_SUCCESS(Status)) {

					pInjectNotifyHookBuffer->Enable = TRUE;
				}
			}

			if (Enable != TRUE) {

				if (pInjectNotifyHookBuffer->HookPoint != NULL) {

					Status = PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)(pInjectNotifyHookBuffer->HookPoint));

					if (NT_SUCCESS(Status)) {

						RtlSuperCopyMemory(pInjectNotifyHookBuffer->HookPoint, pInjectNotifyHookBuffer->OldBytes, sizeof(pInjectNotifyHookBuffer->OldBytes));

						pInjectNotifyHookBuffer->Enable = FALSE;
					}
				}
			}
		}
	}
	if (pInjectNotifyHookBuffer->Enable == Enable) {

		Status = STATUS_SUCCESS;
	}

	return Status;
}



auto InjectNotify(PUNICODE_STRING pFullImageName, HANDLE hProcessId, PIMAGE_INFO pImageInfo) -> VOID {

	//打印进程名字和pid
	//DbgPrint("[DEBUG] InjectNotify: Process Name: %wZ, PID: %d, ImageBase: 0x%p\n", pFullImageName, (ULONG)(UINT64)hProcessId, pImageInfo->ImageBase);

	if (pFullImageName != NULL && pImageInfo != NULL) {

		if (pImageInfo->SystemModeImage) {

		}
		else {
			if (InjectData.InjectBits == 64) { 

				StartInject_x64(pFullImageName, hProcessId, pImageInfo);
			}
		}
	}
}


auto StartInject_x64(PUNICODE_STRING pFullImageName, HANDLE hProcessId, PIMAGE_INFO pImageInfo) -> NTSTATUS {

	NTSTATUS Status = STATUS_SUCCESS;

	if (InjectData.InjectMode <= 0) {

		if (InjectCache.hProcessId != hProcessId) {

			if (ValidInjectEx(pFullImageName, InjectData.InjectHash, L"\\System32\\ntdll.dll")) {

				DbgBreakPoint();

				SIZE_T ImageSize = (SIZE_T)(GetMapSize_x64(InjectData.InjectData));
				
				SIZE_T AllocSize = (SIZE_T)(ImageSize + InjectData.InjectSize + sizeof(ShellCodeX64_0) + sizeof(ShellCodeX64_3));

				UINT64 AllocAdds = (UINT64)(AllocMemory_x64(&AllocSize, InjectData.InjectHide <= 1 ? PAGE_EXECUTE_READWRITE : (InjectData.InjectHide == 2 ? PAGE_READWRITE : PAGE_NOACCESS)));

				if (AllocAdds != 0 && NT_SUCCESS(InjectData.InjectHide == 1 ? AddMemoryItem(IoGetCurrentProcess(), AllocAdds, AllocSize) : /*(InjectData.InjectHide == 2 ? SetPhysicalPage(AllocAdds, AllocSize, TRUE, TRUE) :*/ STATUS_SUCCESS)) {

					InjectCache.AllocCache[0] = reinterpret_cast<LPBYTE>(AllocAdds);

					InjectCache.AllocCache[1] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize);

					InjectCache.AllocCache[2] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize + InjectData.InjectSize + sizeof(ShellCodeX64_0));

					XorByte(InjectCache.AllocCache[1], ShellCodeX64_0, sizeof(ShellCodeX64_0));

					XorByte(InjectCache.AllocCache[2], ShellCodeX64_3, sizeof(ShellCodeX64_3));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0006) = (UINT64)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_0));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x000F) = (UINT32)((UINT64)(InjectCache.AllocCache[2]) - (UINT64)(InjectCache.AllocCache[1]) - 0x000E - 0x0005);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0015) = (UINT64)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_0));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0021) = (UINT64)(InjectData.InjectSize + sizeof(ShellCodeX64_0));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[2]) + 0x04FD) = (UINT64)(InjectCache.AllocCache[0]);

					RtlCopyMemoryEx(reinterpret_cast<LPBYTE>((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_0)), InjectData.InjectData, InjectData.InjectSize);

					if (NT_SUCCESS(ZwCreateThreadEx(ZwCurrentProcess(), InjectCache.AllocCache[1]))) {

						RtlZeroMemoryEx(&InjectCache, sizeof(InjectCache));

						RtlCopyMemoryEx(&InjectCache.hProcessId, &hProcessId, sizeof(hProcessId));
					}
				}
			}
		}
	}
	return Status;
}


auto ValidInjectEx(PUNICODE_STRING pFullImageName, UINT32 InjectNameHash, LPWSTR DelayModule) -> BOOLEAN {

	BOOLEAN bResult = NULL;

	UNICODE_STRING SearchImageName;

	RtlInitUnicodeString(&SearchImageName, DelayModule);

	if (NT_SUCCESS(SearchStr(pFullImageName, &SearchImageName, TRUE))) {

		PUNICODE_STRING UnicodeBuffer = NULL;

		if (NT_SUCCESS(ZwGetProcessFullName(NtCurrentProcess(), &UnicodeBuffer)) && UnicodeBuffer != NULL) {
		
			UNICODE_STRING InjectNamesHash;

			if (NT_SUCCESS(StripPath(UnicodeBuffer, &InjectNamesHash))) {

				if (GetTextHashW(InjectNamesHash.Buffer) == InjectNameHash) {

					bResult = TRUE;
				}
			}

			RtlFreeMemoryEx(UnicodeBuffer);
		}
	}
	return bResult;
}



auto GetMapSize_x64(PBYTE pInjectData) -> ULONG {

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(pInjectData);

	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(pInjectData + pDosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNtHeaders + sizeof(IMAGE_NT_HEADERS64));

	ULONG nAlign = pNtHeaders->OptionalHeader.SectionAlignment;

	ULONG ImageSize = (ULONG)((ULONG)(pNtHeaders->OptionalHeader.SizeOfHeaders + nAlign - 1) / nAlign * nAlign);

	for (ULONG i = NULL; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {

		ULONG CodeSize = pSectionHeader[i].Misc.VirtualSize;

		ULONG LoadSize = pSectionHeader[i].SizeOfRawData;

		ULONG MaxSize = (ULONG)(LoadSize > CodeSize ? LoadSize : CodeSize);

		ULONG SectionSize = (pSectionHeader[i].VirtualAddress + MaxSize + nAlign - 1) / nAlign * nAlign;

		if (ImageSize < SectionSize) {

			ImageSize = SectionSize;
		}
	}
	return ImageSize;
}


auto AllocMemory_x64(PSIZE_T pDesiredSize, ULONG Protect) -> PBYTE {

	PBYTE Result = NULL;

	if (Protect != PAGE_NOACCESS) {

		PBYTE AllocateAddress = DynamicData->WinVersion < WINVER_8X ? (PBYTE)(0x70000000) : (PBYTE)(0x700000000000);

		if (NT_SUCCESS(ZwAllocateVirtualMemory(ZwCurrentProcess(), reinterpret_cast<LPVOID*>(&AllocateAddress), 0, pDesiredSize, MEM_RESERVE | MEM_COMMIT, Protect))) {

			RtlZeroMemoryEx(AllocateAddress, *pDesiredSize);

			Result = AllocateAddress;
		}
	}
	else {
		
	}
	return Result;
}


auto SetPhysicalPage(UINT64 VirtualAddress, SIZE_T Size, BOOL Write, BOOL Execute) -> BOOLEAN {

	//获取页起始地址（页边界）
	UINT64 Begin = (UINT64)(VirtualAddress & (~0xFFF));
	//获取结束页的起始地址
	UINT64 End = (UINT64)((VirtualAddress + Size) & (~0xFFF));

	for (UINT64 Local = Begin; Local < End; Local += PAGE_SIZE) {

		PMMPTE PTE = MiGetPteAddress(DynamicData->PageTables[0], Local); {

			if (PTE->u.Hard.Valid == 1) {

				PTE->u.Hard.Write = Write;

				PTE->u.Hard.NoExecute = !Execute;
			}
		}

		PMMPTE PDE = MiGetPdeAddress(DynamicData->PageTables[1], Local); {

			if (PDE->u.Hard.Valid == 1) {

				PDE->u.Hard.Write = Write;

				PDE->u.Hard.NoExecute = !Execute;
			}
		}

		PMMPTE PPE = MiGetPpeAddress(DynamicData->PageTables[2], Local); {

			if (PPE->u.Hard.Valid == 1) {

				PPE->u.Hard.Write = Write;

				PPE->u.Hard.NoExecute = !Execute;
			}
		}

		PMMPTE PXE = MiGetPxeAddress(DynamicData->PageTables[3], Local); {

			if (PXE->u.Hard.Valid == 1) {

				PXE->u.Hard.Write = Write;

				PXE->u.Hard.NoExecute = !Execute;
			}
		}

		__invlpg((PVOID)(Local));
	}

	return STATUS_SUCCESS;
}