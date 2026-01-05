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