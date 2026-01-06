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
