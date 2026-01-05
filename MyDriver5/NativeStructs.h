#pragma once

typedef struct _DYNDATA {
	ULONG UserVerify;
	ULONG WinVersion;
	ULONG BuildNumber;
	ULONG VadRoot;
	ULONG PrcessId;
	ULONG Protection;
	ULONG PspCidTable;
	ULONG ProcessLinks;
	ULONG PrcessIdOffset;
	ULONG ParentPrcessIdOffset;
	PBYTE KernelBase;
	PBYTE DriverBase;
	PBYTE ModuleList;
	PBYTE PageTables[4];
	PBYTE NtCreateThreadEx;
	PBYTE NtProtectVirtualMemory;
} DYNDATA, * PDYNDATA;

