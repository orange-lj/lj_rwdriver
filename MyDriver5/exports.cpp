#include "driverhexin.h"

auto RtlAllocateMemory(SIZE_T Size) -> LPBYTE {

	LPBYTE Result = (LPBYTE)(ExAllocatePoolWithTag(NonPagedPool, Size, 'SG'));

	if (Result != NULL) {

		RtlZeroMemoryEx(Result, Size);
	}

	return Result;
}


auto RtlZeroMemoryEx(PVOID pDst, SIZE_T Size) -> VOID {

	for (SIZE_T i = 0; i < Size; i++) {

		((BYTE*)pDst)[i] = (BYTE)0;
	}
}

auto RtlCopyMemoryEx(PVOID pDst, PVOID pSrc, SIZE_T Size) -> VOID {

	for (SIZE_T i = 0; i < Size; i++) {

		((BYTE*)pDst)[i] = ((BYTE*)pSrc)[i];
	}
}

auto RtlGetSystemFun(LPWSTR Name) -> LPBYTE {

	UNICODE_STRING RoutineName;

	RtlInitUnicodeString(&RoutineName, Name);

	return (LPBYTE)(MmGetSystemRoutineAddress(&RoutineName));

}

auto ZwQuerySystemInformation(ULONG SystemInformationClass, LPVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) -> NTSTATUS {

	typedef NTSTATUS(NTAPI* fn_ZwQuerySystemInformation)(ULONG, LPVOID, ULONG, PULONG);

	static fn_ZwQuerySystemInformation _ZwQuerySystemInformation = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_ZwQuerySystemInformation == NULL) {

		_ZwQuerySystemInformation = (fn_ZwQuerySystemInformation)(RtlGetSystemFun(L"ZwQuerySystemInformation"));
	}

	if (_ZwQuerySystemInformation != NULL) {

		Status = _ZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	}

	return Status;
}

auto RtlFreeMemoryEx(LPVOID pDst) -> VOID {

	if (pDst != NULL) {

		ExFreePoolWithTag(pDst, 'SG');

		pDst = NULL;
	}
}

auto GetServiceTableBase(LPBYTE pKernelBase) -> LPBYTE {

	LPBYTE Result = NULL;

	if (pKernelBase != NULL) {

		LPBYTE pFound = SearchSignForImage(pKernelBase, "\x4C\x8D\x15\x00\x00\x00\x00\x4C\x8D\x1D\x00\x00\x00\x00\xF7", "xxx????xxx????x");

		if (pFound != NULL) {

			Result = ResolveRelativeAddress(pFound, 3);

		}
	}

	return Result;
}


auto SearchSignForImage(LPBYTE ImageBase, PCHAR Pattern, PCHAR Mask) -> LPBYTE {

	LPBYTE Result = NULL;

	if (ImageBase != NULL) {

		PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);;

		PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);

		for (DWORD Index = 0; Index < Headers->FileHeader.NumberOfSections; ++Index) {

			PIMAGE_SECTION_HEADER pSection = &Sections[Index];

			if (RtlEqualMemory(pSection->Name, ".text", 5) || RtlEqualMemory(pSection->Name, "PAGE", 4)) {

				Result = SearchSignForMemory(ImageBase + pSection->VirtualAddress, pSection->Misc.VirtualSize, Pattern, Mask);

				if (Result != NULL) {

					break;
				}
			}
		}
	}

	return Result;
}

auto SearchSignForMemory(LPBYTE MemoryBase, DWORD Length, PCHAR Pattern, PCHAR Mask) -> LPBYTE {

	DWORD SignSize = (DWORD)(Length - (DWORD)(strlen(Mask)));

	for (DWORD Index = NULL; Index < SignSize; Index++) {

		PCHAR pTempAddress = (PCHAR)(&MemoryBase[Index]);

		if (Compare(pTempAddress, Pattern, Mask)) {

			return (LPBYTE)(pTempAddress);
		}
	}

	return NULL;
}


auto SearchSignForMemory2(LPBYTE MemoryBase, DWORD Length, PCHAR Pattern, PCHAR Mask, DWORD MaskLen) -> LPBYTE {

	for (DWORD Index = NULL; Index < (DWORD)(Length - MaskLen); Index++) {

		LPBYTE pTempAddress = &MemoryBase[Index];

		if (Compare2(pTempAddress, Pattern, Mask, MaskLen)) {

			return pTempAddress;
		}
	}

	return NULL;
}

auto Compare(PCHAR pAddress, PCHAR Pattern, PCHAR Mask) -> BOOL {

	for (; *Mask; ++pAddress, ++Pattern, ++Mask) {

		if ('x' == *Mask && *pAddress != *Pattern) {

			return FALSE;
		}
	}

	return TRUE;
}


auto Compare2(LPBYTE pAddress, PCHAR Pattern, PCHAR Mask, DWORD MaskLen) -> BOOL {

	for (SIZE_T i = 0; i < MaskLen; i++) {

		if (Mask[i] == 'x' && pAddress[i] != (BYTE)(Pattern[i])) {

			return FALSE;
		}
	}

	return TRUE;
}


auto GetTableFunByName(PSYSTEM_SERVICE_DESCRIPTOR_TABLE pServiceTableBase, LPBYTE FileData, ULONG FileSize, LPCSTR ExportName) -> LPBYTE {

	LPBYTE Result = NULL;

	ULONG ExportOffset = GetExportOffset(FileData, FileSize, ExportName);

	if (ExportOffset != NULL) {

		INT32 SSDTIndex = -1;

		LPBYTE RoutineData = FileData + ExportOffset;

		for (ULONG i = NULL; i < 32 && ExportOffset + i < FileSize; i++) {

			if (RoutineData[i] == 0xB8) {

				SSDTIndex = *(INT32*)(RoutineData + i + 1);

				break;
			}
		}

		if (SSDTIndex > -1 && SSDTIndex < pServiceTableBase->NumberOfServices) {

			Result = (LPBYTE)((LPBYTE)pServiceTableBase->ServiceTableBase + (((PLONG)pServiceTableBase->ServiceTableBase)[SSDTIndex] >> 4));
		}
	}

	return Result;
}

auto GetExportOffset(LPBYTE FileData, ULONG FileSize, LPCSTR ExportName) -> ULONG {

	ULONG Result = NULL;

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)FileData;

	PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(FileData + DosHeader->e_lfanew);

	PIMAGE_DATA_DIRECTORY ImageDataDirectory = NtHeaders->OptionalHeader.DataDirectory;

	ULONG ExportDirectoryRva = ImageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	ULONG ExportDirectorySize = ImageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	ULONG ExportDirectoryOffset = RvaToOffset(NtHeaders, ExportDirectoryRva, FileSize);

	if (ExportDirectoryOffset != NULL) {

		PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(FileData + ExportDirectoryOffset);

		ULONG NumberOfNames = ExportDirectory->NumberOfNames;

		ULONG AddressOfFunctionsOffset = RvaToOffset(NtHeaders, ExportDirectory->AddressOfFunctions, FileSize);

		if (AddressOfFunctionsOffset != NULL) {

			ULONG AddressOfNameOrdinalsOffset = RvaToOffset(NtHeaders, ExportDirectory->AddressOfNameOrdinals, FileSize);

			if (AddressOfNameOrdinalsOffset != NULL) {

				ULONG AddressOfNamesOffset = RvaToOffset(NtHeaders, ExportDirectory->AddressOfNames, FileSize);

				if (AddressOfNamesOffset != NULL) {

					PULONG AddressOfNames = (PULONG)(FileData + AddressOfNamesOffset);

					PULONG AddressOfFunctions = (PULONG)(FileData + AddressOfFunctionsOffset);

					PUSHORT AddressOfNameOrdinals = (PUSHORT)(FileData + AddressOfNameOrdinalsOffset);

					for (ULONG i = NULL; i < NumberOfNames; i++) {

						ULONG CurrentNameOffset = RvaToOffset(NtHeaders, AddressOfNames[i], FileSize);

						if (CurrentNameOffset != NULL) {

							LPCSTR CurrentName = (LPCSTR)(FileData + CurrentNameOffset);

							ULONG CurrentFunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]];

							if (CurrentFunctionRva >= ExportDirectoryRva && CurrentFunctionRva < ExportDirectoryRva + ExportDirectorySize) {

								continue;
							}
							else {

								if (!strcmp(CurrentName, ExportName)) {

									Result = RvaToOffset(NtHeaders, CurrentFunctionRva, FileSize);

									break;
								}
							}
						}
					}
				}
			}
		}
	}

	return Result;
}

auto RvaToOffset(PIMAGE_NT_HEADERS64 ImageHead, ULONG RVA, ULONG FileSize) -> ULONG {

	ULONG Result = NULL;

	PIMAGE_SECTION_HEADER ImageSection = IMAGE_FIRST_SECTION(ImageHead);

	USHORT NumberOfSections = ImageHead->FileHeader.NumberOfSections;

	for (USHORT i = NULL; i < NumberOfSections; i++) {

		if (ImageSection->VirtualAddress <= RVA && (ImageSection->VirtualAddress + ImageSection->Misc.VirtualSize) > RVA) {

			RVA -= ImageSection->VirtualAddress;

			RVA += ImageSection->PointerToRawData;

			Result = RVA < FileSize ? RVA : 0;

			break;
		}
		else
			ImageSection++;
	}

	return Result;
}


auto ResolveRelativeAddress(LPBYTE pAddress, ULONG Index) -> LPBYTE {

	LPBYTE Result = NULL;

	if (pAddress != NULL) {

		Result = (LPBYTE)(pAddress + *(INT*)(pAddress + Index) + Index + 4);
	}

	return Result;
}

auto VariateInit() -> NTSTATUS {

	///*内核发包*/ {

	//	RtlZeroMemoryEx(&WSKProviderNpi, sizeof(WSKProviderNpi));

	//	RtlZeroMemoryEx(&WSKSocketsState, sizeof(WSKSocketsState));

	//	RtlZeroMemoryEx(&WSKRegistration, sizeof(WSKRegistration));

	//	RtlZeroMemoryEx(&WSKClientDispatch, sizeof(WSKClientDispatch));
	//}

	///*键鼠模拟*/ {

	//	RtlZeroMemoryEx(&MouseDeviceObject, sizeof(MouseDeviceObject));

	//	RtlZeroMemoryEx(&MouseClassServiceCallback, sizeof(MouseClassServiceCallback));

	//	RtlZeroMemoryEx(&KeyboardDeviceObject, sizeof(KeyboardDeviceObject));

	//	RtlZeroMemoryEx(&KeyboardClassServiceCallback, sizeof(KeyboardClassServiceCallback));
	//}

	return STATUS_SUCCESS;
}


auto SearchSignForImage2(LPBYTE ImageBase, PCHAR Pattern, PCHAR Mask, DWORD MaskLen) -> LPBYTE {

	LPBYTE Result = NULL;

	if (ImageBase != NULL) {

		PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);;

		PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);

		for (DWORD Index = NULL; Index < Headers->FileHeader.NumberOfSections; ++Index) {

			PIMAGE_SECTION_HEADER pSection = &Sections[Index];

			if (RtlEqualMemory(pSection->Name, ".text", 5)) {

				Result = SearchSignForMemory2(ImageBase + pSection->VirtualAddress, pSection->Misc.VirtualSize, Pattern, Mask, MaskLen);

				if (Result != NULL) {

					break;
				}
			}
		}
	}

	return Result;
}


auto GetSystemDrvJumpHook(PVOID Notify, PHOOK_NOTIFY_BUFFER NotifyBuffer) -> LPBYTE {

	LPBYTE pJumpDrvBase = NULL;

	for (PLIST_ENTRY pListEntry = ((PLIST_ENTRY)(DynamicData->ModuleList))->Flink; pListEntry != (PLIST_ENTRY)(DynamicData->ModuleList) && !pJumpDrvBase; pListEntry = pListEntry->Flink) {

		//从链表节点获取完整的模块信息结构
		PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		static UINT32 SystemModuleHash[] = { 0x19C74195/*tcpipreg.sys*/, 0x480CCDFA/*null.sys*/, 0xAF41C973/*beep.sys*/, 0xBC69A139/*http.sys*/, 0x71254340/*hidusb.sys*/, 0x7AB2FACC/*hidclass.sys*/, 0x5255C6CB/*kbdhid.sys*/, 0x848A4E96/*kbdclass.sys*/, 0x25A4DD11/*mouhid.sys*/, 0x9826A1DC/*mouclass.sys*/ };

		for (ULONG i = 0; i < ARRAYSIZE(SystemModuleHash); i++) {

			if (pEntry->BaseDllName.Buffer && GetTextHashW(pEntry->BaseDllName.Buffer) == SystemModuleHash[i]) {

				pJumpDrvBase = SearchHookForImage(pEntry->DllBase, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC", "xxxxxxxxxxxxx", 13);

				if (pJumpDrvBase != NULL) {

					unsigned char JmpCode[] = {
						0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x90,
						0xFF, 0xE0
					};

					RtlCopyMemoryEx(&JmpCode[2], &Notify, sizeof(Notify));

					RtlCopyMemoryEx(&NotifyBuffer->NewBytes, JmpCode, sizeof(NotifyBuffer->NewBytes));

					// 某些安全软件会检查驱动是否被修改
					pEntry->Flags |= 0x20;

					break;
				}
			}
		}
	}
	return pJumpDrvBase;
}


auto GetTextHashW(PCWSTR Str) -> UINT32 {
	UINT32 Hash = NULL;

	while (Str != NULL && *Str) {

		Hash = (UINT32)(65599 * (Hash + (*Str++) + (*Str > 64 && *Str < 91 ? 32 : 0)));
	}

	return Hash;
}

auto SearchHookForImage(LPBYTE ImageBase, PCHAR Pattern, PCHAR Mask, DWORD MaskLen) -> LPBYTE {

	LPBYTE Result = NULL;

	if (ImageBase != NULL) {

		PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);

		PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);

		for (DWORD Index = 0; Index < Headers->FileHeader.NumberOfSections; ++Index) {

			PIMAGE_SECTION_HEADER pSection = &Sections[Index];

			if ((pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) && RtlEqualMemory(pSection->Name, ".text", 5)) {

				Result = SearchSignForMemory2(ImageBase + pSection->VirtualAddress, pSection->Misc.VirtualSize, Pattern, Mask, MaskLen);

				if (Result != NULL) {

					break;
				}
			}
		}
	}

	return Result;
}

auto RtlSuperCopyMemory(LPVOID pDst, LPVOID pSrc, ULONG Length) -> NTSTATUS {

	NTSTATUS Result = STATUS_UNSUCCESSFUL;
	//创建MDL结构，不分配物理页
	PMDL pMdl = IoAllocateMdl(pDst, Length, FALSE, FALSE, NULL);

	if (pMdl != NULL) {
		//直接构建MDL
		MmBuildMdlForNonPagedPool(pMdl);
		//表示这个 MDL 已经映射到系统地址空间
		pMdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
		//锁定物理页为非缓存
		LPVOID pMapped = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, NULL, NULL, LowPagePriority);

		if (pMapped != NULL) {

			KIRQL kirql = KeRaiseIrqlToDpcLevel();

			RtlCopyMemory(pMapped, pSrc, Length);

			KeLowerIrql(kirql);

			MmUnmapLockedPages(pMapped, pMdl);

			Result = STATUS_SUCCESS;
		}
		IoFreeMdl(pMdl);
	}
	return Result;
}


auto SearchStr(PUNICODE_STRING Dst, PUNICODE_STRING Src, BOOLEAN CaseInSensitive) -> NTSTATUS {

	INT32 Result = STATUS_UNSUCCESSFUL;

	if (Dst->Length >= Src->Length) {

		USHORT Diff = Dst->Length - Src->Length;

		for (USHORT i = 0; i <= (Diff / sizeof(WCHAR)); i++) {

			if (RtlCompareUnicodeStrings(Dst->Buffer + i, Src->Length / sizeof(WCHAR), Src->Buffer, Src->Length / sizeof(WCHAR), CaseInSensitive) == 0) {

				Result = STATUS_SUCCESS;

				break;
			}
		}
	}

	return Result;
}


auto ZwGetProcessFullName(HANDLE ProcessHandle, PUNICODE_STRING* pNameBuffer) -> NTSTATUS {

	NTSTATUS Status = STATUS_SUCCESS;

	ULONG NameBufferLen = 0;

	Status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, 0, &NameBufferLen);

	if (!NT_SUCCESS(Status) && NameBufferLen != NULL) {

		PUNICODE_STRING pBuffer = (PUNICODE_STRING)(RtlAllocateMemory(NameBufferLen));

		if (pBuffer != NULL) {

			Status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, pBuffer, NameBufferLen, &NameBufferLen);

			if (NT_SUCCESS(Status)) {

				*pNameBuffer = pBuffer;
			}
		}
	}

	return Status;
}


auto StripPath(PUNICODE_STRING FilePath, PUNICODE_STRING FileName) -> NTSTATUS {

	INT32 Result = STATUS_UNSUCCESSFUL;

	for (USHORT i = (FilePath->Length / sizeof(WCHAR)) - 1; i != 0; i--) {

		if (FilePath->Buffer[i] == L'\\' || FilePath->Buffer[i] == L'/') {

			FileName->Buffer = &FilePath->Buffer[i + 1];

			FileName->Length = FileName->MaximumLength = FilePath->Length - (i + 1) * sizeof(WCHAR);

			Result = STATUS_SUCCESS;

			break;
		}
	}

	return Result;
}


auto ZwQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, LPVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) -> NTSTATUS {

	typedef NTSTATUS(NTAPI* fn_ZwQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, LPVOID, ULONG, PULONG);

	static fn_ZwQueryInformationProcess _ZwQueryInformationProcess = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_ZwQueryInformationProcess == NULL) {

		_ZwQueryInformationProcess = (fn_ZwQueryInformationProcess)(RtlGetSystemFun(L"ZwQueryInformationProcess"));
	}

	if (_ZwQueryInformationProcess != NULL) {

		Status = _ZwQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	}

	return Status;
}


auto XorByte(LPBYTE Dst, LPBYTE Src, SIZE_T Size) -> LPBYTE {

	for (ULONG i = NULL; i < Size; i++) {

		Dst[i] = (BOOLEAN)(Src[i] != 0x00 && Src[i] != 0xFF) ? Src[i] ^ 0xFF : Src[i];
	}

	return Dst;
}

auto ZwCreateThreadEx(HANDLE ProcessHandle, LPVOID StratAddress) -> NTSTATUS {

	typedef NTSTATUS(NTAPI* fn_ZwCreateThreadEx)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPVOID, LPVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);

	static fn_ZwCreateThreadEx _ZwCreateThreadEx = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_ZwCreateThreadEx == NULL) {

		_ZwCreateThreadEx = (fn_ZwCreateThreadEx)DynamicData->NtCreateThreadEx;
	}

	if (_ZwCreateThreadEx != NULL) {

		HANDLE hThread = NULL;

		OBJECT_ATTRIBUTES Object = { 0 };

		InitializeObjectAttributes(&Object, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

		CHAR pOldMode = SetPreviousMode(KernelMode);

		Status = _ZwCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &Object, ProcessHandle, StratAddress, NULL, DynamicData->WinVersion <= WINVER_7 ? 0 : 2, 0, 0, 0, NULL);

		if (NT_SUCCESS(Status)) {

			ObCloseHandle(hThread, KernelMode);
		}

		SetPreviousMode(pOldMode);
	}

	return Status;
}

auto SetPreviousMode(BYTE Mode) -> BYTE {

	return _InterlockedExchange8((PCHAR)((UINT64)(PsGetCurrentThread()) + (UINT64)(DynamicData->WinVersion <= WINVER_7 ? 0x1F6 : 0x232)), Mode);
}

auto ZwProtectVirtualMemory(HANDLE ProcessHandle, LPVOID pContext) -> NTSTATUS {

	typedef NTSTATUS(NTAPI* fn_ZwProtectVirtualMemory)(HANDLE, PULONG64, PULONG64, ULONG, PULONG);

	static fn_ZwProtectVirtualMemory _ZwProtectVirtualMemory = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_ZwProtectVirtualMemory == NULL) {

		_ZwProtectVirtualMemory = (fn_ZwProtectVirtualMemory)DynamicData->NtProtectVirtualMemory;
	}

	if (_ZwProtectVirtualMemory != NULL) {

		struct {
			ULONG64 BaseAddress;
			ULONG64 RegionSize;
			ULONG32 NewProtect;
		} Context;

		RtlCopyMemoryEx(&Context, pContext, sizeof(Context));

		ULONG OldProtect;

		KPROCESSOR_MODE OldPreviousMode = SetPreviousMode(KernelMode);

		Status = _ZwProtectVirtualMemory(ProcessHandle, &Context.BaseAddress, &Context.RegionSize, Context.NewProtect, &OldProtect);

		SetPreviousMode(OldPreviousMode);
	}
	return Status;
}

auto ZwCopyVirtualMemory(PEPROCESS FromProcess, LPVOID FromAddress, PEPROCESS ToProcess, LPVOID ToAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode) -> NTSTATUS {

	typedef NTSTATUS(NTAPI* fn_MmCopyVirtualMemory)(PEPROCESS, LPVOID, PEPROCESS, LPVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);

	static fn_MmCopyVirtualMemory _MmCopyVirtualMemory = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_MmCopyVirtualMemory == NULL) {

		_MmCopyVirtualMemory = (fn_MmCopyVirtualMemory)(RtlGetSystemFun(L"MmCopyVirtualMemory"));
	}

	if (_MmCopyVirtualMemory != NULL) {

		SIZE_T NumberOfBytesCopied;

		Status = _MmCopyVirtualMemory(FromProcess, FromAddress, ToProcess, ToAddress, BufferSize, PreviousMode, &NumberOfBytesCopied);

	}
	return Status;
}