#pragma once

auto RtlAllocateMemory(SIZE_T) -> LPBYTE;

auto RtlZeroMemoryEx(PVOID, SIZE_T) -> VOID;

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