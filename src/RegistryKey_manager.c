#include <windows.h>
#include <winreg.h>

// Registry key functions to control
// reference https://msdn.microsoft.com/en-us/library/windows/desktop/ms724897%28v=vs.85%29.aspx
bool Create_RegistryKey(HKEY hkey_var, char *SubKey, char *KeyName, char *cKeyValue)
{
	bool bReturn = FALSE;

    	char cValue[DEFAULT];
    	sprintf(cValue, "\"%s\"", cKeyValue);

    	HKEY hKey = NULL;
    	DWORD dwSizeOfValue = strlen(cValue);

    	if(RegCreateKeyExA(hkey_var, SubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_QUERY_VALUE | KEY_READ | KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    	{
        	if(RegSetValueExA(hKey, KeyName, 0, REG_SZ, (BYTE*)cValue, dwSizeOfValue) == ERROR_SUCCESS)
            		bReturn = TRUE;

        	RegFlushKey(hKey);
        	RegCloseKey(hKey);
    	}

    	return bReturn;
}

bool Check_RegistryKeyExists(HKEY hkey_var, char *SubKey, char *KeyName)
{
    	HKEY hKey = NULL;
    	bool bReturn = FALSE;

    	if(RegOpenKeyExA(hkey_var, SubKey, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    	{
        	if(RegQueryValueExA(hKey, KeyName, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
           		bReturn = TRUE;

        	RegCloseKey(hKey);
    	}

    	return bReturn;
}

bool Delete_RegistryKey(HKEY hkey_var, char *SubKey, char *KeyName)
{
    	HKEY hKey = NULL;
    	bool bReturn = FALSE;

    	if(RegOpenKeyExA(hkey_var, SubKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
    	{
        	if(RegDeleteValueA(hKey, KeyName) == ERROR_SUCCESS)
           		bReturn = TRUE;

        	RegFlushKey(hKey);
        	RegCloseKey(hKey);
    	}

    	return bReturn;
}

char *Read_RegistryKey(HKEY hkey_var, char *SubKey, char *KeyName)
{
	HKEY hKey;
	DWORD lpType = REG_SZ;
	DWORD lpcbData = MAX_PATH;

	static char cReadKeyBuffer[DEFAULT];

	if(RegOpenKeyEx(hkey_var, SubKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		DWORD dwQueryReturn = 0;

		dwQueryReturn = RegQueryValueEx(hKey, KeyName, 0, &lpType, (unsigned char*)cReadKeyBuffer, &lpcbData);

        	if(dwQueryReturn == ERROR_FILE_NOT_FOUND)
			strcpy(cReadKeyBuffer, "EFNF");
        	else if(dwQueryReturn != ERROR_SUCCESS)
            		strcpy(cReadKeyBuffer, "NOERRSUC");

		RegCloseKey(hKey);

		return (char*)cReadKeyBuffer;
	}
	else
        	return (char*)"ERROPFA";
}
