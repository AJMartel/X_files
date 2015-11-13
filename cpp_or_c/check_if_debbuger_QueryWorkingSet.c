#include "stdafx.h"
#include "windows.h"
#include "stdio.h"
 // check if have debbuger, using QueryWorkingSet
// reference https://msdn.microsoft.com/en-us/library/windows/desktop/ms684946%28v=vs.85%29.aspx
 
typedef union _PSAPI_WORKING_SET_BLOCK {
  unsigned long Flags;
  struct {
    unsigned long Protection  :5;
    unsigned long ShareCount  :3;
    unsigned long Shared  :1;
    unsigned long Reserved  :3;
    unsigned long VirtualPage  :20;
  };
}PSAPI_WORKING_SET_BLOCK, *PPSAPI_WORKING_SET_BLOCK;
 
 
typedef struct _PSAPI_WORKING_SET_INFORMATION {
  unsigned long               NumberOfEntries;
  PSAPI_WORKING_SET_BLOCK WorkingSetInfo[1];
} PSAPI_WORKING_SET_INFORMATION, *PPSAPI_WORKING_SET_INFORMATION;
 
typedef BOOL(__stdcall *QWS)(HANDLE hProcess,void* pv,unsigned long cb);
 
unsigned long GetCurrentEIP()
{
    unsigned long x_eip=0;
    __asm
    {
        call x
x:
        pop eax
        mov x_eip,eax
    }
    return x_eip;
}
 
 
bool check_debbuger_by_query()
{
	QWS QueryWorkingSet = (QWS)GetProcAddress(GetModuleHandle("kernel32.dll"),"K32QueryWorkingSet");
 	unsigned long i=0;
	bool debugger_present = false;


	if(!QueryWorkingSet)
    	{
        	printf("Can't resolve address\r\n");
        	return 0;
    	}
 
 
    	PSAPI_WORKING_SET_INFORMATION* API_INFORMATION = (PSAPI_WORKING_SET_INFORMATION*)VirtualAlloc(0,0x10000,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
 
	    if(!API_INFORMATION) 
		    return 0;
 
    	BOOL ret = QueryWorkingSet(GetCurrentProcess(),API_INFORMATION,0x10000);

    	if(!ret)
    	{
        	VirtualFree(API_INFORMATION,0,MEM_RELEASE);
        	return 0;
    	}
 
    	unsigned long Num = API_INFORMATION->NumberOfEntries;

    	if(!Num)
    	{
        	VirtualFree(API_INFORMATION,0,MEM_RELEASE);
        	return 0;
    	}
 
 

 
    	while(i<Num)
	{
        	unsigned long Addr= ((API_INFORMATION->WorkingSetInfo[i].VirtualPage))<<0x0C;

        	if(Addr==(GetCurrentEIP()&0xFFFFF000))
        	{

        
            		if( (API_INFORMATION->WorkingSetInfo[i].Shared==0) || (API_INFORMATION->WorkingSetInfo[i].ShareCount==0) )
            		{
                		debugger_present = true;
                		break;
            		}
        	}
		      i++;
    	}
 
    	return debugger_present;

 
    exit(0);
}
