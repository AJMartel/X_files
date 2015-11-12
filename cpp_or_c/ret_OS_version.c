#include <windows.h>

// i improve this func https://msdn.microsoft.com/en-us/library/windows/desktop/ms724834%28v=vs.85%29.aspx
char * SetOperatingSystem() 
{
    OSVERSIONINFOEX VersionOS;
    VersionOS.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if(GetVersionEx((OSVERSIONINFO*)&VersionOS))
    {
        if((VersionOS.dwMajorVersion == 5) && (VersionOS.dwMinorVersion == 0))
            return "WINDOWS 2000";
        else if((VersionOS.dwMajorVersion ==5) && (VersionOS.dwMinorVersion == 1))
            return " WINDOWS XP";
        else if((VersionOS.dwMajorVersion == 5) && (VersionOS.dwMinorVersion == 2))
        {
            if(VersionOS.wProductType == VER_NT_WORKSTATION && Is64Bits(GetCurrentProcess()))
                return "WINDOWS XP";
            else
                return "WINDOWS 2003";
        }
        else if((VersionOS.dwMajorVersion == 6) && (VersionOS.dwMinorVersion == 0))
            return  "WINDOWS VISTA";
        else if((VersionOS.dwMajorVersion == 6) && (VersionOS.dwMinorVersion == 1))
            return  "WINDOWS 7";
        else if((VersionOS.dwMajorVersion == 6) && (VersionOS.dwMinorVersion == 2))
            return  "WINDOWS 8";
        else if((VersionOS.dwMajorVersion == 6) && (VersionOS.dwMinorVersion == 3))
            return "WINDOWS 8";
    	  else if((VersionOS.dwMajorVersion == 10)
	          return "WINDOWS 10";
        else
            return  "WINDOWS UNKNOWN";
    }
    else
        return  "error";
}
