#include "demo.h"

HANDLE DriverHandle = NULL;

BOOL WINAPI GSDrv_初始函数() 
{
	Fun::memset = (Fun::fn_memset)(GetProcAddress(LoadLibraryA("ntdll.dll"), "memset"));

	Fun::memcpy_s = (Fun::fn_memcpy_s)(GetProcAddress(LoadLibraryA("ntdll.dll"), "memcpy_s"));

	Fun::strcpy_s = (Fun::fn_strcpy_s)(GetProcAddress(LoadLibraryA("ntdll.dll"), "strcpy_s"));

	Fun::wcscpy_s = (Fun::fn_wcscpy_s)(GetProcAddress(LoadLibraryA("ntdll.dll"), "wcscpy_s"));

	Fun::sprintf_s = (Fun::fn_sprintf_s)(GetProcAddress(LoadLibraryA("ntdll.dll"), "sprintf_s"));

	Fun::vsprintf_s = (Fun::fn_vsprintf_s)(GetProcAddress(LoadLibraryA("ntdll.dll"), "vsprintf_s"));

	Fun::NtLoadDriver = (Fun::fn_NtLoadDriver)(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtLoadDriver"));

	Fun::NtSetValueKey = (Fun::fn_NtSetValueKey)(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtSetValueKey"));

	Fun::RtlOpenCurrentUser = (Fun::fn_RtlOpenCurrentUser)(GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlOpenCurrentUser"));

	Fun::URLDownloadToFileA = (Fun::fn_URLDownloadToFileA)(GetProcAddress(LoadLibraryA("urlmon.dll"), "URLDownloadToFileA"));

	Fun::NtUnmapViewOfSection = (Fun::fn_NtUnmapViewOfSection)(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtUnmapViewOfSection"));

	Fun::RtlFreeUnicodeString = (Fun::fn_RtlFreeUnicodeString)(GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlFreeUnicodeString"));

	Fun::RtlAnsiStringToUnicodeString = (Fun::fn_RtlAnsiStringToUnicodeString)(GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAnsiStringToUnicodeString"));

	return TRUE;
}


LONG WINAPI GSDrv_驱动消息(DWORD Msg, PVOID Data, DWORD DataSize) 
{
	if (DriverHandle == NULL) {

		Fun::RtlOpenCurrentUser(GENERIC_WRITE, &DriverHandle);
	}

	if (DriverHandle != NULL) {

		struct {
			USHORT Length;
			USHORT MaximumLength;
			LPVOID Buffer;
		} NullData;

		NullData.Buffer = &NullData;

		NullData.Length = 0;

		NullData.MaximumLength = 0;

		return Fun::NtSetValueKey(DriverHandle, &NullData, NULL, Msg, Data, DataSize);
	}

	return 0xFFFFFFFF;
}

BOOL WINAPI GSDrv_进程提权() 
{
	BOOL Results = FALSE;

	HANDLE TokenHandle;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &TokenHandle)) {

		TOKEN_PRIVILEGES TokenPrivileges;

		TokenPrivileges.PrivilegeCount = 1;

		if (LookupPrivilegeValueA(NULL, SE_LOAD_DRIVER_NAME, &TokenPrivileges.Privileges[0].Luid) == TRUE) {

			TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			Results = AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TokenPrivileges), NULL, NULL);
		}

		CloseHandle(TokenHandle);
	}

	return Results;
}


BOOL WINAPI GSDrv_安装驱动()
{
	LONG Result = 0;

	CHAR DriverName[MAX_PATH]; {

		Fun::memset(DriverName, NULL, sizeof(DriverName));

		Fun::sprintf_s(DriverName, sizeof(DriverName), "liujundemo");
	}

	CHAR DriverPath[MAX_PATH]; {

		Fun::memset(DriverPath, NULL, sizeof(DriverPath));

		GetTempPathA(sizeof(DriverPath), DriverPath);

		Fun::sprintf_s(DriverPath, sizeof(DriverPath), "%s%s.sys", DriverPath, DriverName);
	}

	HKEY hKey = NULL;

	CHAR SubKey[MAX_PATH]; {

		Fun::memset(SubKey, NULL, sizeof(SubKey));

		Fun::sprintf_s(SubKey, sizeof(SubKey), "System\\CurrentControlSet\\Services\\%s", DriverName);
	}

	if (RegCreateKeyA(HKEY_LOCAL_MACHINE, SubKey, &hKey) == S_OK) {

		CONST BYTE TypeData[] = { 0x01, 0x00, 0x00, 0x00 };

		if (RegSetValueExA(hKey, "Type", 0, REG_DWORD, (CONST BYTE*)TypeData, sizeof(TypeData)) == S_OK) {

			CONST BYTE StartData[] = { 0x03, 0x00, 0x00, 0x00 };

			if (RegSetValueExA(hKey, "Start", 0, 4, (CONST BYTE*)StartData, sizeof(StartData)) == S_OK) {

				CONST BYTE ErrorControlData[] = { 0x01, 0x00, 0x00, 0x00 };

				if (RegSetValueExA(hKey, "ErrorControl", 0, 4, (CONST BYTE*)ErrorControlData, sizeof(ErrorControlData)) == S_OK) {

					CHAR DrvFullKernelPath[MAX_PATH]; {

						Fun::memset(DrvFullKernelPath, NULL, sizeof(DrvFullKernelPath));

						Fun::sprintf_s(DrvFullKernelPath, sizeof(DrvFullKernelPath), "\\??\\%s", DriverPath);
					}

					if (RegSetValueExA(hKey, "ImagePath", 0, 1, (CONST BYTE*)DrvFullKernelPath, strlen(DrvFullKernelPath)) == S_OK) {

						struct {
							USHORT MinLength;
							USHORT MaxLength;
							LPVOID Buffer;
						} Buffer[2]; {

							Fun::memset(&Buffer, NULL, sizeof(Buffer));
						}

						CHAR ServicesPath[MAX_PATH]; {

							Fun::memset(ServicesPath, NULL, sizeof(ServicesPath));

							Fun::sprintf_s(ServicesPath, sizeof(ServicesPath), "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", DriverName);
						}

						Buffer[0].Buffer = ServicesPath;

						Buffer[0].MinLength = strlen(ServicesPath);

						Buffer[0].MaxLength = Buffer[0].MinLength + sizeof(CHAR);

						Fun::RtlAnsiStringToUnicodeString(&Buffer[1], &Buffer[0], TRUE);

						Result = Fun::NtLoadDriver(&Buffer[1]);

						Fun::RtlFreeUnicodeString(&Buffer[1]);

						RegDeleteKeyA(HKEY_LOCAL_MACHINE, SubKey);

						DeleteFileA(DriverPath);

						RegCloseKey(hKey);

					}
				}
			}
		}
	}
	return Result;
}

int main() {
	if (IsUserAnAdmin()) { 

		if (GSDrv_初始函数()) {
		
			if (GSDrv_驱动消息('0000', 0, 0) != 0xE0000000) {
				
				if (GSDrv_进程提权()) { /*提升进程权限, 安装签名著署*/

					if (GSDrv_安装驱动()) 
					{
						printf("驱动安装成功!\n");
					}
					else
					{
						printf("驱动安装失败!\n");
					}
				}
			}
		}
	}
}