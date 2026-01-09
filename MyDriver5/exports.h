#pragma once

auto RtlAllocateMemory(SIZE_T) -> LPBYTE;

auto RtlZeroMemoryEx(PVOID, SIZE_T) -> VOID;

auto RtlCopyMemoryEx(PVOID, PVOID, SIZE_T) -> VOID;

auto RtlGetSystemFun(LPWSTR) -> LPBYTE;

auto ZwQuerySystemInformation(ULONG, LPVOID, ULONG, PULONG) -> NTSTATUS;

auto RtlFreeMemoryEx(LPVOID) -> VOID;

auto GetServiceTableBase(LPBYTE) -> LPBYTE;

auto SearchSignForImage(LPBYTE, PCHAR, PCHAR) -> LPBYTE;

auto SearchSignForMemory(LPBYTE, DWORD, PCHAR, PCHAR) -> LPBYTE;

auto Compare(PCHAR, PCHAR, PCHAR) -> BOOL;

auto GetTableFunByName(PSYSTEM_SERVICE_DESCRIPTOR_TABLE, LPBYTE, ULONG, LPCSTR) -> LPBYTE;

auto GetExportOffset(LPBYTE, ULONG, LPCSTR) -> ULONG;

auto RvaToOffset(PIMAGE_NT_HEADERS64, ULONG, ULONG) -> ULONG;

auto ResolveRelativeAddress(LPBYTE, ULONG) -> LPBYTE;

auto VariateInit() -> NTSTATUS;

auto SearchSignForImage2(LPBYTE, PCHAR, PCHAR, DWORD) -> LPBYTE;

auto SearchSignForMemory2(LPBYTE, DWORD, PCHAR, PCHAR, DWORD) -> LPBYTE;

auto Compare2(LPBYTE, PCHAR, PCHAR, DWORD) -> BOOL;

auto GetSystemDrvJumpHook(PVOID, PHOOK_NOTIFY_BUFFER) -> LPBYTE;

auto GetTextHashW(PCWSTR) -> UINT32;

auto SearchHookForImage(LPBYTE, PCHAR, PCHAR,DWORD) -> LPBYTE;

auto RtlSuperCopyMemory(LPVOID, LPVOID, ULONG) -> NTSTATUS;

auto SearchStr(PUNICODE_STRING, PUNICODE_STRING, BOOLEAN) -> NTSTATUS;

auto ZwGetProcessFullName(HANDLE, PUNICODE_STRING*) -> NTSTATUS;

auto ZwQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, LPVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) -> NTSTATUS;

auto StripPath(PUNICODE_STRING, PUNICODE_STRING) -> NTSTATUS;

auto XorByte(LPBYTE, LPBYTE, SIZE_T) -> LPBYTE;

auto ZwCreateThreadEx(HANDLE, LPVOID) -> NTSTATUS;

auto SetPreviousMode(BYTE) -> BYTE;