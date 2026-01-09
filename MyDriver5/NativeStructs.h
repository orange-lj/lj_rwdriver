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


typedef struct _WIN1X_MM_AVL_NODE {
	/*+0x000*/    union
	{
		struct _WIN1X_MM_AVL_NODE* Children[2];
		struct
		{
			struct _WIN1X_MM_AVL_NODE* LeftChild;
			struct _WIN1X_MM_AVL_NODE* RightChild;
		};
	};
	/*+0x010*/    union
	{
		UCHAR Red : 1;
		UCHAR Balance : 2;
		ULONG_PTR ParentValue;
	};
} WIN1X_MM_AVL_NODE, * WIN1X_PMM_AVL_NODE;

typedef struct _WIN1X_MM_AVL_TABLE {
	/*+0x000*/    union
	{
		/*+0x000*/    struct _WIN1X_MM_AVL_NODE* BalancedRoot;
		/*+0x000*/    void* NodeHint;
		/*+0x000*/    unsigned __int64 NumberGenericTableElements;
	};
} WIN1X_MM_AVL_TABLE, * WIN1X_PMM_AVL_TABLE;


typedef struct _WIN1X_MMVAD_SHORT {
	/*+0x000*/    union
	{
		/*+0x000*/    struct _WIN1X_MM_AVL_NODE VadNode;
		/*+0x000*/    struct _WIN1X_MMVAD_SHORT* NextVad;
	};
	/*+0x018*/    ULONG StartingVpn;
	/*+0x01C*/    ULONG EndingVpn;
	/*+0x020*/    UCHAR StartingVpnHigh;
	/*+0x021*/    UCHAR EndingVpnHigh;
	/*+0x022*/    UCHAR CommitChargeHigh;
	/*+0x023*/    UCHAR SpareNT64VadUChar;
	/*+0x024*/    ULONG ReferenceCount;
	/*+0x028*/    LPVOID PushLock;
	/*+0x030*/    ULONG VadFlags;
	/*+0x034*/    ULONG LongFlags;
	/*+0x038*/    struct _MI_VAD_EVENT_BLOCK* EventList;
} WIN1X_MMVAD_SHORT, * WIN1X_PMMVAD_SHORT;


typedef struct _MMPTE_HARDWARE {
	UINT64 Valid : 1;// [0] 页是否有效（1=有效，0=不存在或交换到磁盘）
	UINT64 Dirty1 : 1;// [1] 写时脏位（软件使用）
	UINT64 Owner : 1; // [2] 所有者（0=系统，1=用户）
	UINT64 WriteThrough : 1;// [3] 写直达缓存策略
	UINT64 CacheDisable : 1;// [4] 禁用缓存
	UINT64 Accessed : 1;// [5] 页是否被访问过（读/写）
	UINT64 Dirty : 1;// [6] 页是否被修改过（写操作）
	UINT64 LargePage : 1;// [7] 是否为大页（2MB或1GB）
	UINT64 Global : 1;// [8] 全局页（TLB刷新时不清除）
	UINT64 CopyOnWrite : 1;// [9] 写时复制标志
	UINT64 Unused : 1;
	UINT64 Write : 1;// [11] 是否可写（1=可写，0=只读）
	UINT64 PageFrameNumber : 36;// [12:47] 物理页帧号（PFN）最重要的部分！
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
		MMPTE_HARDWARE Hard;
	} u;
} MMPTE, * PMMPTE;