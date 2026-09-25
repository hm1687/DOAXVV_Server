' DOAXVV one-click stop (VBS, no CMD window flash) - kill tray+server+probe+hosts+offset
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)  ' this VBS dir = DOAXVV_Server
target = fso.BuildPath(dir, "stop_all.py")
sh.Run "pythonw """ & target & """", 0, False  ' 0=hidden window, False=do not wait
