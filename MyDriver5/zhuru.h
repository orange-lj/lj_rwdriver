#pragma once

extern INJECT_DATA InjectData;

extern INJECT_CACHE InjectCache;

extern PHOOK_NOTIFY_BUFFER pInjectNotifyHookBuffer;

auto InjectNotifyInit(ULONG) -> NTSTATUS;

auto InjectNotify(PUNICODE_STRING pFullImageName, HANDLE hProcessId, PIMAGE_INFO pImageInfo) -> VOID;

auto StartInject_x64(PUNICODE_STRING, HANDLE, PIMAGE_INFO) -> NTSTATUS;

auto ValidInjectEx(PUNICODE_STRING, UINT32, LPWSTR) -> BOOLEAN;

auto GetMapSize_x64(PBYTE) -> ULONG;

auto AllocMemory_x64(PSIZE_T, ULONG) -> PBYTE;

auto SetPhysicalPage(UINT64, SIZE_T, BOOL, BOOL) -> BOOLEAN;

auto ShareMemoryEx(LPBYTE MappedSystemVa, SIZE_T Size) -> LPBYTE;

auto GetProcFun_x64(PBYTE, LPCTSTR) -> UINT64;