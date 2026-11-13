# -*- coding: utf-8 -*-
"""
tray_dialogs.py — 托盘右键菜单弹出的对话框 (独立进程)
用法: pythonw tray_dialogs.py {status|log|gmlink}
  status : 服务器/hosts 状态 (自动刷新)
  log    : full_server.log 实时滚动
  gmlink : 未安装 Chrome 时, 提示 GM 面板链接 (可复制 / 用默认浏览器打开)
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tkinter as tk
from tkinter import scrolledtext
import webbrowser
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

def show_gmlink():
    """未检测到 Chrome 时的提示: 展示 GM 链接, 可复制或用默认浏览器打开"""
    url = tray_app.GM_URL
    root = tk.Tk()
    root.title("DOAXVV GM 面板")
    root.geometry("560x200")
    root.configure(bg="#222")
    root.resizable(False, False)

    tk.Label(root, text="未检测到 Chrome 浏览器", bg="#222", fg="#ffcc66",
             font=("Microsoft YaHei", 12, "bold")).pack(pady=(16, 4))
    tk.Label(root, text="请复制下面的链接, 用任意浏览器打开 GM 面板：",
             bg="#222", fg="#ccc", font=("Microsoft YaHei", 10)).pack()

    var = tk.StringVar(value=url)
    ent = tk.Entry(root, textvariable=var, font=("Consolas", 11), justify="center",
                   bg="#111", fg="#7fd1ff", insertbackground="#7fd1ff", relief="flat")
    ent.pack(fill="x", padx=18, pady=10, ipady=5)
    ent.select_range(0, "end")
    ent.focus_set()

    status = tk.Label(root, text="", bg="#222", fg="#7CFC98", font=("Microsoft YaHei", 9))
    status.pack()

    def copy_link():
        root.clipboard_clear()
        root.clipboard_append(url)
        root.update()
        status.config(text="已复制到剪贴板")

    def open_default():
        webbrowser.open(url)

    bar = tk.Frame(root, bg="#222")
    bar.pack(pady=8)
    for text, cmd in (("复制链接", copy_link), ("用默认浏览器打开", open_default), ("关闭", root.destroy)):
        tk.Button(bar, text=text, command=cmd, width=16, relief="flat",
                  bg="#2f3640", fg="#eee", activebackground="#3d4655",
                  activeforeground="#fff", cursor="hand2").pack(side="left", padx=6)

    root.mainloop()

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "status"
    if mode == "log":
        show_log()
    elif mode == "gmlink":
        show_gmlink()
    else:
        show_status()

if __name__ == "__main__":
    main()
