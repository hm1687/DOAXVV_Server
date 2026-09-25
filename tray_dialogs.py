# -*- coding: utf-8 -*-
"""
tray_dialogs.py — 托盘右键菜单弹出的对话框 (独立进程)
用法: pythonw tray_dialogs.py {status|log}
  status : 服务器/hosts 状态 (自动刷新)
  log    : full_server.log 实时滚动
(2026-09-18: 时刻控制编辑器移除, 只剩 status/log)
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tkinter as tk
from tkinter import scrolledtext
import tray_app

def show_status():
    root = tk.Tk(); root.title("DOAXVV 状态"); root.geometry("400x120")
    root.configure(bg="#222")
    t = tk.Text(root, font=("Consolas", 10), bg="#222", fg="#ddd", relief="flat")
    t.pack(fill="both", expand=True, padx=6, pady=6)
    def refresh():
        try:
            t.delete("1.0", "end"); t.insert("1.0", tray_app.status_text())
        except Exception as e:
            t.delete("1.0", "end"); t.insert("1.0", "状态查询失败: " + str(e))
        root.after(2000, refresh)
    refresh()
    tk.Button(root, text="关闭", command=root.destroy).pack(pady=4)
    root.mainloop()

def show_log():
    root = tk.Tk(); root.title("DOAXVV 服务器日志 (实时)"); root.geometry("800x500")
    t = scrolledtext.ScrolledText(root, font=("Consolas", 9), bg="#1a1a1a", fg="#ddd", insertbackground="#ddd")
    t.pack(fill="both", expand=True)
    def refresh():
        try:
            with open(tray_app.SERVER_LOG, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-800:]
            t.delete("1.0", "end"); t.insert("1.0", "".join(lines))
            t.see("end")
        except Exception:
            t.delete("1.0", "end"); t.insert("1.0", "（暂无日志：服务器刚启动或无请求流量。启动游戏产生请求后此处会实时显示。\n路径: %s）" % tray_app.SERVER_LOG)
        root.after(1500, refresh)
    refresh()
    root.mainloop()

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "status"
    if mode == "log":
        show_log()
    else:
        show_status()

if __name__ == "__main__":
    main()
