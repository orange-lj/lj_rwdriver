#pragma once
extern PHIDE_MEMORY_BUFFER pHideMemoryList;

extern PHOOK_NOTIFY_BUFFER pProcessNotifyHookBuffer;

auto AddMemoryItem(PEPROCESS, UINT64, SIZE_T) -> NTSTATUS;

auto VadHideMemory(PEPROCESS pProcess, UINT64 Address, SIZE_T Size, PHIDE_MEMORY_BUFFER pBuffer) -> NTSTATUS;

auto WIN1X_MiFindNodeOrParent(WIN1X_PMM_AVL_TABLE, ULONG_PTR, WIN1X_PMM_AVL_NODE*) -> ULONG;

auto RtlAvlRemoveNode(LPVOID Table, LPVOID Node) -> NTSTATUS;

auto ProcessNotifyInit(ULONG) -> NTSTATUS;

auto ProcessNotify(HANDLE ParentId, HANDLE hProcessId, BOOLEAN Create) -> VOID;

auto DelMemoryItem(PEPROCESS) -> NTSTATUS;

auto VadShowMemory(PHIDE_MEMORY_BUFFER Buffer) -> NTSTATUS;