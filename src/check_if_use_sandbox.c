#include <windows.h>

// this function check if use virtual machine by check DLL
// reference: https://msdn.microsoft.com/en-us/library/windows/desktop/ms683199%28v=vs.85%29.aspx
bool Check_if_use_VM()
{
	HKEY hKey;

	char ProductKey[MAX_PATH] = {0};
	DWORD dwSize = sizeof(ProductKey);

	bool ret_key = FALSE;

	DWORD dwVersion = GetVersion();
	DWORD dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));

	if(GetModuleHandleA("SbieDll.dll")) //SANDBOXIE
		return TRUE;
	else if(GetModuleHandleA("snxhk.dll")) //AVAST Sandbox
		return TRUE;
	else if(GetModuleHandleA("dbghelp.dll")) // VMware
		return TRUE;
	else if(GetModuleHandleA("api_log.dll")) // SunBelt SandBox
		return TRUE;
	else if(GetModuleHandleA("dir_watch.dll")) // SunBelt SandBox
		return TRUE;
	else if(GetModuleHandleA("pstorec.dll")) // SunBelt SandBox
		return TRUE;
	else if(GetModuleHandleA("vmcheck.dll")) // Virtual PC
		return TRUE;
	else if(GetModuleHandleA("wpespy.dll")) // WPE Pro
		return TRUE;
	else if(GetModuleHandleA("dbghelp.dll")) //THREATEXPERT
		return TRUE;
	else if(dwMajorVersion == 5) 
	{
		if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
		{
			if(RegQueryValueExA(hKey, "ProductId", 0, 0, (BYTE*)ProductKey, &dwSize) == ERROR_SUCCESS)
			{
				if(strcmp(ProductKey, "76487-640-1457236-23837") == 0) // Anubis
					ret_key = TRUE;
				else if(strcmp(ProductKey, "76487-644-3177037-23510") == 0) // CWSandbox old
					ret_key = TRUE;
				else if(strcmp(ProductKey, "55274-640-2673064-23950") == 0) // JoeBox
					ret_key = TRUE;
				else if (strcmp(ProductKey, "76497-640-6308873-23835") == 0) // CWSandbox 2.1.22
					ret_key = TRUE;
			}
		}

		RegCloseKey(hKey);
	}

	return ret_key;
}
