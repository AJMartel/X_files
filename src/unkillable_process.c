/*
Example to making the current process at unkillable

Tested at windows 7 and windows XP
*/
#include <aclapi.h>

DWORD unkillable_this_Process(void)
{
	HANDLE hProcess = GetCurrentProcess();
	PACL pEmptyDacl;
	DWORD var_proc;

	pEmptyDacl = (PACL)malloc(sizeof(ACL));

	if (!InitializeAcl(pEmptyDacl, sizeof(ACL), ACL_REVISION))
	{
		var_proc = GetLastError();
	} else {
		var_proc = SetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pEmptyDacl, NULL);
	}

	free(pEmptyDacl);	
	pEmptyDacl=NULL;

	return var_proc;
}
