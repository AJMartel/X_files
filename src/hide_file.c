#include <windows.h>
#include <WinBase.h>

// this function hide a file
// reference https://msdn.microsoft.com/en-us/library/windows/desktop/aa365535%28v=vs.85%29.aspx
bool Hide_File(char *FileName)
{
    if(SetFileAttributes(FileName, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY) > 0)
        return TRUE;
    else
        return FALSE;
}
