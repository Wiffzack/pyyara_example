# pyyara_example
A small Python Script Example for Anti Debug and VM awareness analyse with [yara-python](https://github.com/VirusTotal/yara-python) .

- Usage :
> python.exe D:\all\tools\antidebugscan.py -i C:\Windows\explorer.exe

> [IsPE64, IsWindowsGUI, HasOverlay, HasDebugData, HasRichSignature, DebuggerCheck__QueryInfo, anti_dbg, disable_dep, screenshot, keylogger, migrate_apc, win_mutex, win_files_operation, win_hook, Advapi_Hash_API, detect_msvcrt_randomization, detect_msvcrt_call, detect_bullshit, IP, hook_check]

- Virus Example (from [dasmalwerk](http://dasmalwerk.eu/)):

>python.exe D:\all\tools\antidebugscan.py -i C:\Users\Wiffzack\Desktop\1e84ff45-414b-11e8-b837-80e65024849a.file

>[IsPE32, IsWindowsGUI, IsPacked, HasDebugData, HasRichSignature, anti_dbg, inject_thread, network_http, escalate_priv, screenshot, keylogger, win_registry, win_token, win_files_operation, detect_msvcrt_call, detect_bullshit, IP, _ASPack_v2xx_]

Interesting flags are :  
- IsPacked 
- _ASPack_v2xx_
- inject_thread
