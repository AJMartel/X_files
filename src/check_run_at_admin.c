#include <stdio.h>
// This fuction determine if the executable is running as user or admin
bool Check_run_Admin() 
{
    FILE * pOpenAdminFile;
    char AdminFile_test[45];

    sprintf(AdminFile_test, "%s\\System32\\drivers\\etc\\protocol", cWindowsDirectory);

    pOpenAdminFile = fopen(AdminFile_test, "a");

    if(pOpenAdminFile != NULL)
    {
        fclose(pOpenAdminFile);
	      return TRUE;
    }

    return FALSE;
}
