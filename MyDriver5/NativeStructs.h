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


typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
	PBYTE DllBase;
	PBYTE EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	PBYTE Section;
	PBYTE MappedBase;
	PBYTE ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	SHORT LoadOrderIndex;
	SHORT InitOrderIndex;
	SHORT LoadCount;
	SHORT PathLength;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE {

	PULONG_PTR ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG_PTR NumberOfServices;
	LPBYTE ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

typedef struct _HOOK_NOTIFY_BUFFER {
	ULONG Enable;
	PVOID HookPoint;
	UCHAR NewBytes[13];
	UCHAR OldBytes[13];
	PVOID NotifyHandle;
	LARGE_INTEGER Cookie;
} HOOK_NOTIFY_BUFFER, * PHOOK_NOTIFY_BUFFER;

typedef struct _MMPTE_HARDWARE {

	UINT64 Valid : 1;
	UINT64 Dirty1 : 1;
	UINT64 Owner : 1;
	UINT64 WriteThrough : 1;
	UINT64 CacheDisable : 1;
	UINT64 Accessed : 1;
	UINT64 Dirty : 1;
	UINT64 LargePage : 1;
	UINT64 Global : 1;
	UINT64 CopyOnWrite : 1;
	UINT64 Unused : 1;
	UINT64 Write : 1;
	UINT64 PageFrameNumber : 36;
	UINT64 ReservedForHardware : 4;
	UINT64 ReservedForSoftware : 4;
	UINT64 WsleAge : 4;
	UINT64 WsleProtection : 3;
	UINT64 NoExecute : 1;
} MMPTE_HARDWARE, * PMMPTE_HARDWARE;

typedef struct _MMPTE {

	union {

		UINT64 Long;
		UINT64 VolatileLong;
		struct _MMPTE_HARDWARE Hard;
	} u;
} MMPTE, * PMMPTE;

typedef struct _HIDE_MEMORY_BUFFER {
	PEPROCESS pProcess;
	UINT64 Address;
	SIZE_T Size;
} HIDE_MEMORY_BUFFER, * PHIDE_MEMORY_BUFFER;

typedef struct _INJECT_DATA {
	INT32 InjectHash;
	INT32 InjectBits;
	INT32 InjectMode;
	INT32 InjectHide;
	PBYTE InjectData;
	INT64 InjectSize;
} INJECT_DATA, * PINJECT_DATA;

typedef struct _INJECT_CACHE {
	LPVOID hProcessId;
	PBYTE AllocCache[3];
	PBYTE SteamCache[6];
} INJECT_CACHE, * PINJECT_CACHE;