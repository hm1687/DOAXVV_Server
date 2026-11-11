# -*- coding: utf-8 -*-
r"""
tray_app.py — DOAXVV 系统托盘应用
职责只有两件: 改 hosts 劫持 + 后台跑服务器(隐藏)。
托盘图标 + 右键菜单: 状态/查看日志/打开控制台(实时)/重启服务器/启动游戏/一键关闭。
路径全部 __file__ 锚定 → 任意工作目录、任意安装位置都能跑。
被 一键启动.vbs/.bat 用 pythonw 启动(无控制台窗口), 启动后只剩托盘图标。
2026-11-07: 时间钳制(clamp_offset.py)+frida 探针(attach_wait_forever.py/probe_smart_clamp.js)
已整体停用并移出仓库, 本文件不再有相关开关/分支。
"""
import os, sys, subprocess, json, threading, time
from PIL import Image, ImageDraw, ImageFont
import pystray

DIR = os.path.dirname(os.path.abspath(__file__))   # DOAXVV_Server (本文件所在目录)
BASE = os.path.dirname(DIR)                          # 上级目录 (游戏根目录)
SERVER = os.path.join(DIR, "local_server", "local_server_v2.py")
HOSTS_SWITCH = os.path.join(DIR, "hosts_switch.ps1")
SERVER_LOG = os.path.join(DIR, "local_server", "full_server.log")
LAUNCHER = os.path.join(BASE, "DOAX_VV_Launcher.exe")
GAME = os.path.join(BASE, "DOAX_VV.exe")
DIALOGS = os.path.join(DIR, "tray_dialogs.py")
# 2026-11-07: 时间钳制机制(clamp_offset.py / probe_smart_clamp.js / attach_wait_forever.py)
# 已整体停用并移出仓库 —— 19点白屏的根因是服务端日切时区错误,
# 已按客户端 19:00 UTC 修正, 不需要再把时钟钉死(钉死会让日切永不发生, 签到/每日任务不刷新)。
# 仅保留 offset 文件用于"清理历史残留偏移", 服务器 local_server_v2.py 仍会读该文件。
OFFSET_FILE = os.path.join(DIR, "local_server", "time_offset_config.json")
SERVER_CFG = os.path.join(DIR, "server_config.json")
PY = sys.executable
PYW = os.path.join(os.path.dirname(PY), "pythonw.exe")
if not os.path.exists(PYW): PYW = PY
CREATE_NO_WINDOW = 0x08000000

icon = None

def run_ps(cmd, timeout=30):
    try:
        return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                              capture_output=True, text=True, timeout=timeout,
                              creationflags=CREATE_NO_WINDOW).stdout.strip()
    except Exception:
        return ""

def server_pid():
    return run_ps("Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty OwningProcess")

def hosts_hijacked():
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", HOSTS_SWITCH, "status"],
                           capture_output=True, text=True, timeout=20, creationflags=CREATE_NO_WINDOW)
        return "[HIJACKED]" in r.stdout
    except Exception:
        return False

def status_text():
    svr = server_pid()
    return ("服务器(443): %s\nhosts劫持: %s" % (
        ("运行 PID %s" % svr) if svr else "未运行",
        "是" if hosts_hijacked() else "否"))

def start_server_bg():
    subprocess.Popen([PY, "-u", SERVER], cwd=DIR,
                     creationflags=CREATE_NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def ensure_hosts():
    if not hosts_hijacked():
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", HOSTS_SWITCH, "on"],
                       creationflags=CREATE_NO_WINDOW)

def ensure_log():
    try:
        if not os.path.exists(SERVER_LOG):
            open(SERVER_LOG, "a", encoding="utf-8").close()
    except Exception:
        pass

def reset_time_offset():
    """把服务器时间偏移清零. 钳制机制已移除, 这里只负责清理历史残留:
    若 offset 不是 0, 服务器时间会偏离真实时间 -> 日切/时间戳再次错乱."""
    try:
        if not os.path.exists(OFFSET_FILE):
            return
        cfg = json.load(open(OFFSET_FILE, encoding="utf-8"))
        keys = ("offset_days", "offset_hours", "offset_minutes", "offset_seconds")
        if not any(int(cfg.get(k, 0) or 0) != 0 for k in keys):
            return
        for k in keys:
            cfg[k] = 0
        json.dump(cfg, open(OFFSET_FILE, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        log_write("reset_time_offset: 检测到残留时间偏移, 已清零")
    except Exception as e:
        log_write("reset_time_offset 异常: " + str(e))

def game_running():
    return bool(run_ps("Get-Process DOAX_VV -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Id"))

def launcher_running():
    return bool(run_ps("Get-Process DOAX_VV_Launcher -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Id"))

def launch_game():
    if game_running() or launcher_running():
        return
    if os.path.exists(LAUNCHER):
        subprocess.Popen([LAUNCHER])
    elif os.path.exists(GAME):
        subprocess.Popen([GAME])

def startup():
    try:
        # 钳制机制已移除: 只做一次残留偏移清理, 不再拉起探针/定时刷新
        reset_time_offset()
        ensure_hosts()
        if not server_pid():
            start_server_bg()
            for _ in range(40):
                if server_pid():
                    break
                time.sleep(0.5)
        if server_pid():
            launch_game()
        else:
            log_write("startup: 服务器20s内未就绪, 跳过自动拉起启动器")
    except Exception as e:
        log_write("startup 异常: " + str(e))

def kill_pids(out):
    n = 0
    for ln in out.splitlines():
        pid = ln.strip()
        if pid.isdigit():
            subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True, creationflags=CREATE_NO_WINDOW)
            n += 1
    return n

def kill_all_servers():
    """只关服务器: 443 的监听进程 + local_server_v2 进程.
    不再杀 probe/frida —— 钳制机制已移除, 且 'frida*' 会误杀用户自己开的逆向会话.
    也不再找 start_all.py —— 该文件早已不存在."""
    kill_pids(run_ps("Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique"))
    kill_pids(run_ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'python' -and $_.CommandLine -match 'local_server_v2' } | Select-Object -ExpandProperty ProcessId"))

def shutdown():
    kill_all_servers()
    time.sleep(1)
    if hosts_hijacked():
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", HOSTS_SWITCH, "off"],
                       creationflags=CREATE_NO_WINDOW)
    reset_time_offset()
    if icon:
        icon.stop()

def restart_server():
    kill_pids(run_ps("Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique"))
    kill_pids(run_ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'python' -and $_.CommandLine -match 'local_server_v2' } | Select-Object -ExpandProperty ProcessId"))
    time.sleep(1)
    if not server_pid():
        start_server_bg()

def log_write(msg):
    try:
        with open(os.path.join(DIR, "tray_app.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%H:%M:%S ") + msg + "\n")
    except Exception:
        pass

def _thread(fn):
    threading.Thread(target=fn, daemon=True).start()

def on_status(ic, item):
    def _s():
        if not run_ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'python' -and $_.CommandLine -match 'tray_dialogs' } | Select-Object -First 1 -ExpandProperty ProcessId"):
            subprocess.Popen([PYW, DIALOGS, "status"])
    _thread(_s)
def on_view_log(ic, item):
    def _v():
        ensure_log()
        subprocess.Popen(["notepad", SERVER_LOG])
    _thread(_v)
def on_console(ic, item):
    def _c():
        if not run_ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'python' -and $_.CommandLine -match 'tray_dialogs' } | Select-Object -First 1 -ExpandProperty ProcessId"):
            ensure_log()
            subprocess.Popen([PYW, DIALOGS, "log"])
    _thread(_c)
def on_restart(ic, item): _thread(restart_server)
def on_game(ic, item): _thread(launch_game)
def on_close(ic, item): _thread(shutdown)

def make_icon():
    img = Image.new('RGBA', (64, 64), (28, 30, 40, 255))
    d = ImageDraw.Draw(img)
    try: f = ImageFont.truetype("arial.ttf", 30)
    except Exception: f = ImageFont.load_default()
    d.text((11, 15), "VV", fill=(120, 210, 255, 255), font=f)
    return img

def main():
    global icon
    _existing = run_ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'python' -and $_.CommandLine -match 'tray_app.py' } | Select-Object -ExpandProperty ProcessId")
    for _p in _existing.splitlines():
        _p = _p.strip()
        if _p.isdigit() and int(_p) != os.getpid():
            try:
                import ctypes
                ctypes.windll.user32.MessageBoxW(0, "DOAXVV 托盘已在运行 (PID %s)。" % _p, "DOAXVV 托盘", 0x40)
            except Exception: pass
            return
    menu = pystray.Menu(
        pystray.MenuItem("DOAXVV 单机服", None, enabled=False),
        pystray.MenuItem("当前状态", on_status, default=True),
        pystray.MenuItem("查看日志", on_view_log),
        pystray.MenuItem("打开控制台", on_console),
        pystray.MenuItem("重启服务器", on_restart),
        pystray.MenuItem("启动游戏", on_game),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("一键关闭", on_close),
    )
    icon = pystray.Icon("DOAXVV", make_icon(), "DOAXVV 单机服", menu)
    threading.Thread(target=startup, daemon=True).start()
    icon.run()

if __name__ == "__main__":
    main()
