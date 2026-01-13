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

				//DbgBreakPoint();

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
			//反反作弊BE，从最小的代价来使BE驱动失效(hook ExAllocatePool,ExAllocatePoolWithTag,MmGetSystemRoutineAddress)

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

				SIZE_T ImageSize = (SIZE_T)(GetMapSize_x64(InjectData.InjectData));
				
				SIZE_T AllocSize = (SIZE_T)(ImageSize + InjectData.InjectSize + sizeof(ShellCodeX64_0) + sizeof(ShellCodeX64_3));

				UINT64 AllocAdds = (UINT64)(AllocMemory_x64(&AllocSize, InjectData.InjectHide <= 1 ? PAGE_EXECUTE_READWRITE : (InjectData.InjectHide == 2 ? PAGE_READWRITE : PAGE_NOACCESS)));

				if (AllocAdds != 0 && NT_SUCCESS(InjectData.InjectHide == 1 ? AddMemoryItem(IoGetCurrentProcess(), AllocAdds, AllocSize) : (InjectData.InjectHide == 2 ? SetPhysicalPage(AllocAdds, AllocSize, TRUE, TRUE) : STATUS_SUCCESS))) {

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
	if (InjectData.InjectMode == 1) {

		//DbgBreakPoint();

		if (InjectCache.hProcessId != hProcessId) {

			if (ValidInjectEx(pFullImageName, InjectData.InjectHash, L"\\System32\\ntdll.dll")) {

				SIZE_T ImageSize = (SIZE_T)(GetMapSize_x64(InjectData.InjectData));

				SIZE_T AllocSize = (SIZE_T)(ImageSize + InjectData.InjectSize + sizeof(ShellCodeX64_1) + sizeof(ShellCodeX64_3));

				UINT64 AllocAdds = (UINT64)(AllocMemory_x64(&AllocSize, InjectData.InjectHide <= 1 ? PAGE_EXECUTE_READWRITE : (InjectData.InjectHide == 2 ? PAGE_READWRITE : PAGE_NOACCESS)));

				UINT64 HijackFun = (UINT64)(GetProcFun_x64(reinterpret_cast<LPBYTE>(pImageInfo->ImageBase), "ZwContinue"));

				if (AllocAdds != 0 && HijackFun != 0 && NT_SUCCESS(InjectData.InjectHide == 1 ? AddMemoryItem(IoGetCurrentProcess(), AllocAdds, AllocSize) : (InjectData.InjectHide == 2 ? SetPhysicalPage(AllocAdds, AllocSize, TRUE, TRUE) : STATUS_SUCCESS))) {

					InjectCache.AllocCache[0] = reinterpret_cast<LPBYTE>(AllocAdds);

					InjectCache.AllocCache[1] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize);

					InjectCache.AllocCache[2] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize + InjectData.InjectSize + sizeof(ShellCodeX64_1));

					XorByte(InjectCache.AllocCache[1], ShellCodeX64_1, sizeof(ShellCodeX64_1));

					XorByte(InjectCache.AllocCache[2], ShellCodeX64_3, sizeof(ShellCodeX64_3));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x001E) = (UINT64)(0x000E);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0028) = (UINT64)(HijackFun);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0032) = (UINT64)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_1) - 0x000E);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x003E) = (UINT64)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_1));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0047) = (UINT32)((UINT64)(InjectCache.AllocCache[2]) - (UINT64)(InjectCache.AllocCache[1]) - 0x0046 - 0x0005);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x004D) = (UINT64)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_1));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0059) = (UINT64)(InjectData.InjectSize + sizeof(ShellCodeX64_1));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0085) = (UINT64)(HijackFun);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[2]) + 0x04FD) = (UINT64)(InjectCache.AllocCache[0]);

					RtlCopyMemoryEx(reinterpret_cast<LPBYTE>((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_1)), InjectData.InjectData, InjectData.InjectSize);

					struct {
						UINT64 BaseAddress;
						UINT64 RegionSize;
						UINT32 NewProtect;
					} Context;

					Context.BaseAddress = HijackFun;

					Context.RegionSize = 14;

					Context.NewProtect = PAGE_EXECUTE_READWRITE;

					if (NT_SUCCESS(ZwProtectVirtualMemory(ZwCurrentProcess(), &Context))) {

						BYTE ShellCodeX64_HookJmp[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

						*(UINT64*)(ShellCodeX64_HookJmp + 0x0006) = (UINT64)(InjectCache.AllocCache[1]);

						RtlCopyMemoryEx(reinterpret_cast<LPBYTE>((UINT64)(InjectCache.AllocCache[1]) + 141), reinterpret_cast<LPBYTE>(HijackFun), 14);

						RtlCopyMemoryEx(reinterpret_cast<LPBYTE>(HijackFun), ShellCodeX64_HookJmp, sizeof(ShellCodeX64_HookJmp));

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
		
		LARGE_INTEGER LowAddress;

		LARGE_INTEGER HighAddress;

		LowAddress.QuadPart = 0;

		HighAddress.QuadPart = 0xFFFF'FFFF'FFFF'FFFFULL;
		//向内核的物理内存管理器申请一批连续物理页，并用一个MDL描述它们
		PMDL pMdl = MmAllocatePagesForMdlEx(LowAddress, HighAddress, LowAddress, *pDesiredSize, MmCached, MM_DONT_ZERO_ALLOCATION);

		if (pMdl != NULL) {
			//判断 MmMapLockedPagesSpecifyCache 返回的映射地址是否和 MDL 里记录的 MappedSystemVa 是同一个地址
			if (MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, NULL, NormalPagePriority) == pMdl->MappedSystemVa) {
				//修改“MDL 已映射到系统地址空间的那段 VA”的页保护属性
				if (NT_SUCCESS(MmProtectMdlSystemAddress(pMdl, PAGE_EXECUTE_READWRITE))) {

					PPFN_NUMBER MdlPfnArray = MmGetMdlPfnArray(pMdl);

					if (MdlPfnArray != NULL) {

						SIZE_T PageSize = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(pMdl), MmGetMdlByteCount(pMdl));

						for (SIZE_T i = 0; i < PageSize; i++) {

							MdlPfnArray[i] = 0;
						}
					}

					Result = ShareMemoryEx((LPBYTE)(pMdl->MappedSystemVa), *pDesiredSize);

					RtlZeroMemoryEx(pMdl->MappedSystemVa, *pDesiredSize);
				}
			}
		}
	}
	return Result;
}

auto ShareMemoryEx(LPBYTE MappedSystemVa, SIZE_T Size) -> LPBYTE {

	UINT64 Begin = (UINT64)((UINT64)MappedSystemVa & (~0xFFF));

	UINT64 End = (UINT64)(((UINT64)MappedSystemVa + Size) & (~0xFFF));

	for (UINT64 Local = Begin; Local < End; Local += PAGE_SIZE) {

		PMMPTE PTE = MiGetPteAddress(DynamicData->PageTables[0], Local); {

			if (MmIsAddressValid(PTE)) {

				PTE->u.Hard.Valid = 1;

				PTE->u.Hard.Write = 1;

				PTE->u.Hard.Owner = 1;

				PTE->u.Hard.NoExecute = 0;
			}
		}

		PMMPTE PDE = MiGetPdeAddress(DynamicData->PageTables[1], Local); {

			if (MmIsAddressValid(PDE)) {

				PDE->u.Hard.Valid = 1;

				PDE->u.Hard.Write = 1;

				PDE->u.Hard.Owner = 1;

				PDE->u.Hard.NoExecute = 0;
			}
		}

		PMMPTE PPE = MiGetPpeAddress(DynamicData->PageTables[2], Local); {

			if (MmIsAddressValid(PPE)) {

				PPE->u.Hard.Valid = 1;

				PPE->u.Hard.Write = 1;

				PPE->u.Hard.Owner = 1;

				PPE->u.Hard.NoExecute = 0;
			}
		}

		PMMPTE PXE = MiGetPxeAddress(DynamicData->PageTables[3], Local); {

			if (MmIsAddressValid(PXE)) {

				PXE->u.Hard.Valid = 1;

				PXE->u.Hard.Write = 1;

				PXE->u.Hard.Owner = 1;

				PXE->u.Hard.NoExecute = 0;
			}
		}

		__invlpg((PVOID)(Local));
	}

	return MappedSystemVa;
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


auto GetProcFun_x64(PBYTE hModule, LPCTSTR lpProcName) -> UINT64 {

	UINT_PTR uiLibraryAddress = (UINT_PTR)hModule;

	ULONG_PTR fpResult = NULL;

	UINT_PTR uiAddressArray = NULL;

	UINT_PTR uiNameArray = NULL;

	UINT_PTR uiNameOrdinals = NULL;

	PIMAGE_NT_HEADERS64 pNtHeaders64 = NULL;

	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	pNtHeaders64 = (PIMAGE_NT_HEADERS64)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

	pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

	uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

	uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

	uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

	if ((PtrToUlong(lpProcName) & 0xFFFF0000) == 0x00000000) {

		uiAddressArray += ((IMAGE_ORDINAL(PtrToUlong(lpProcName)) - pExportDirectory->Base) * sizeof(unsigned long));

		fpResult = (ULONG_PTR)(uiLibraryAddress + *(unsigned long*)(uiAddressArray));
	}
	else {

		unsigned long dwCounter = pExportDirectory->NumberOfNames;

		while (dwCounter--) {

			char* cpExportedFunctionName = (char*)(uiLibraryAddress + *(unsigned long*)(uiNameArray));

			if (strcmp(cpExportedFunctionName, lpProcName) == 0) {

				uiAddressArray += (*(unsigned short*)(uiNameOrdinals) * sizeof(unsigned long));

				fpResult = (ULONG_PTR)(uiLibraryAddress + *(unsigned long*)(uiAddressArray));

				break;
			}

			uiNameArray += sizeof(unsigned long);

			uiNameOrdinals += sizeof(unsigned short);
		}
	}
	return (UINT64)fpResult;
}