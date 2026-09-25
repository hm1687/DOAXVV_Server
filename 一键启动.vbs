' DOAXVV one-click start (VBS, no CMD window flash) - double-click to launch tray
'   tray app runs server+probe(hidden)+hosts in background, hides to system tray
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)  ' this VBS dir = DOAXVV_Server
target = fso.BuildPath(dir, "tray_app.py")
sh.Run "pythonw """ & target & """", 0, False  ' 0=hidden window, False=do not wait
