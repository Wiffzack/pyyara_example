# pyyara_example
A small Python Script Example for Anti Debug and VM awareness analyse with [yara-python](https://github.com/VirusTotal/yara-python) .

- Usage :
> python.exe D:\all\tools\antidebugscan.py -i C:\Windows\explorer.exe

> [IsPE64, IsWindowsGUI, HasOverlay, HasDebugData, HasRichSignature, DebuggerCheck__QueryInfo, anti_dbg, disable_dep, screenshot, keylogger, migrate_apc, win_mutex, win_files_operation, win_hook, Advapi_Hash_API, detect_msvcrt_randomization, detect_msvcrt_call, detect_bullshit, IP, hook_check]
