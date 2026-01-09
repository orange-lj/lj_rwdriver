#pragma once
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <iostream>

namespace Fun {

	typedef VOID(__cdecl* fn_memset)(PVOID, ULONG, SIZE_T); fn_memset memset = NULL;

	typedef VOID(__cdecl* fn_memcpy_s)(PVOID, SIZE_T, PVOID, SIZE_T); fn_memcpy_s memcpy_s = NULL;

	typedef VOID(__cdecl* fn_strcpy_s)(LPSTR, SIZE_T, LPCSTR); fn_strcpy_s strcpy_s = NULL;

	typedef VOID(__cdecl* fn_wcscpy_s)(LPWSTR, SIZE_T, LPCWSTR); fn_wcscpy_s wcscpy_s = NULL;

	typedef VOID(__cdecl* fn_sprintf_s)(LPSTR, SIZE_T, LPCSTR, ...); fn_sprintf_s sprintf_s = NULL;

	typedef VOID(__cdecl* fn_vsprintf_s)(LPSTR, SIZE_T, LPCSTR, va_list); fn_vsprintf_s vsprintf_s = NULL;

	typedef LONG(__stdcall* fn_NtLoadDriver)(PVOID); fn_NtLoadDriver NtLoadDriver = NULL;

	typedef LONG(__stdcall* fn_NtSetValueKey)(HANDLE, PVOID, DWORD, DWORD, PVOID, DWORD); fn_NtSetValueKey NtSetValueKey = NULL;

	typedef LONG(__stdcall* fn_RtlOpenCurrentUser)(ACCESS_MASK, PHANDLE); fn_RtlOpenCurrentUser RtlOpenCurrentUser = NULL;

	typedef LONG(__stdcall* fn_URLDownloadToFileA)(PVOID, LPCSTR, LPCSTR, DWORD, PVOID); fn_URLDownloadToFileA URLDownloadToFileA = NULL;

	typedef LONG(__stdcall* fn_NtUnmapViewOfSection)(HANDLE, PVOID); fn_NtUnmapViewOfSection NtUnmapViewOfSection = NULL;

	typedef LONG(__stdcall* fn_RtlFreeUnicodeString)(PVOID); fn_RtlFreeUnicodeString RtlFreeUnicodeString = NULL;

	typedef LONG(__stdcall* fn_RtlAnsiStringToUnicodeString)(PVOID, PVOID, DWORD); fn_RtlAnsiStringToUnicodeString RtlAnsiStringToUnicodeString = NULL;
}

SHSTDAPI_(BOOL) IsUserAnAdmin(VOID);

BOOL WINAPI GSDrv_初始函数();

LONG WINAPI GSDrv_驱动消息(DWORD Msg, PVOID Data, DWORD DataSize);

BOOL WINAPI GSDrv_进程提权();

BOOL WINAPI GSDrv_安装驱动();

/*
函数: 离线注入
参数: 进程名进程位数,注入类型(32,64),注入模式(0,1,2),保护内存(0,1,2,3),DLL数据,DLL数据长度
返回: 0xE0000000 = 注入成功
返回: 0xE0000001 = 注入失败
返回: 0xE0000002 = 进程ID无效
返回: 0x00000000 = 驱动未激活
*/ LONG WINAPI GSDrv_2(LPCTSTR, ULONG32, ULONG32, BOOL, PVOID, ULONG32);