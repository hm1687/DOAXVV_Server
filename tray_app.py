# -*- coding: utf-8 -*-
r"""
tray_app.py — DOAXVV 系统托盘应用
职责只有两件: 改 hosts 劫持 + 后台跑服务器(隐藏)。
托盘图标 + 右键菜单: 状态/查看日志/打开控制台(实时)/重启服务器/启动游戏/一键关闭。
路径全部 __file__ 锚定 → 任意工作目录、任意安装位置都能跑。
被 一键启动.bat 用 pythonw 启动(无控制台窗口), 启动后只剩托盘图标。
2026-11-07: 时间钳制(clamp_offset.py)+frida 探针(attach_wait_forever.py/probe_smart_clamp.js)
已整体停用并移出仓库, 本文件不再有相关开关/分支。
"""
import os, sys, subprocess, json, threading, time
from PIL import Image, ImageDraw, ImageFont
import pystray

DIR = os.path.dirname(os.path.abspath(__file__))   # DOAXVV_Server (本文件所在目录)
BASE = os.path.dirname(DIR)                          # 游戏根目录 (DOAXVV_Server 的上级)
SERVER = os.path.join(DIR, "local_server", "local_server_v2.py")
HOSTS_SWITCH = os.path.join(DIR, "hosts_switch.ps1")
SERVER_LOG = os.path.join(DIR, "local_server", "full_server.log")
LAUNCHER = os.path.join(BASE, "DOAX_VV_Launcher.exe")
GAME = os.path.join(BASE, "DOAX_VV.exe")
DIALOGS = os.path.join(DIR, "tray_dialogs.py")
# 2026-11-12: GM 面板无感开/关 —— 固定用 Chrome --new-window 开独立 Chrome 窗口
# (完整 Chrome 界面); 检测/关闭按窗口标题「DOAXVV 玩家服务」精确识别, 只碰 GM 页,
# 不影响用户自己的浏览器窗口; 关闭发 WM_CLOSE 等同手点 X, 无任何确认弹窗。
GM_URL = "https://127.0.0.1/gm/"
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

def _find_chrome():
    """GM 面板固定用 Chrome 打开。系统级/用户级安装位置都找;
    找不到返回 None → 由调用方弹出链接提示。"""
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    la = os.environ.get("LocalAppData", "")
    cands = [os.path.join(pf, r"Google\Chrome\Application\chrome.exe"),
             os.path.join(pf86, r"Google\Chrome\Application\chrome.exe")]
    if la:
        cands.append(os.path.join(la, r"Google\Chrome\Application\chrome.exe"))
    for c in cands:
        if os.path.exists(c):
            return c
    return None

GM_TITLE_TAGS = ("DOAXVV 玩家服务", "DOAXVV Player Service", "DOAXVV プレイヤーサービス")
# ↑ gm_panel.html 三种界面语言下的页面标题 (zh/en/ja), 任一匹配即认定为 GM 窗口

def _gm_windows():
    """枚举所有标题含 GM 页面标题的顶层窗口 (ctypes, 毫秒级)。
    2026-11-12: 改为普通 Chrome 窗口打开后, 无法再用 profile 匹配进程,
    改按窗口标题识别 GM 窗口 —— 只命中 GM 页, 不会碰到用户自己的标签页。"""
    import ctypes
    hits = []
    user32 = ctypes.windll.user32
    proto = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def _cb(hwnd, lparam):
        n = user32.GetWindowTextLengthW(hwnd)
        if n > 0:
            buf = ctypes.create_unicode_buffer(n + 1)
            user32.GetWindowTextW(hwnd, buf, n + 1)
            t = buf.value
            if any(tag in t for tag in GM_TITLE_TAGS):
                hits.append(hwnd)
        return True
    user32.EnumWindows(proto(_cb), 0)
    return hits

def gm_running():
    """GM 窗口是否已打开 (按窗口标题检测)"""
    return bool(_gm_windows())

def _gm_api(path, payload=None, timeout=5):
    """调用本地 GM 接口。自签证书: 不校验证书 (仅本机 127.0.0.1)。"""
    import ssl, urllib.request
    url = GM_URL.rstrip("/") + "/" + path.lstrip("/")
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data,
                                 method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))

def _set_gm_session(active):
    """开关服务器端 GM 会话 (服务器没跑返回 None)。"""
    if not server_pid():
        return None
    try:
        r = _gm_api("api/gm_session", {"active": bool(active)})
        return bool(r.get("active", active))
    except Exception as e:
        log_write("GM 会话切换失败 (active=%s): %s" % (active, e))
        return None

def _focus_gm_windows():
    """把已打开的 GM 窗口提到前台 (重连时无需再开新窗口)"""
    import ctypes
    user32 = ctypes.windll.user32
    for hwnd in _gm_windows():
        try:
            user32.ShowWindow(hwnd, 9)          # SW_RESTORE
            user32.SetForegroundWindow(hwnd)
        except Exception:
            pass

def start_gm():
    """启动GM: 先恢复服务器端 GM 会话; 已有窗口就提到前台, 没有才用 Chrome 打开。"""
    # 服务器没跑就先拉起 (GM 面板依赖本地 443)
    if not server_pid():
        start_server_bg()
        for _ in range(20):
            if server_pid():
                break
            time.sleep(0.5)
    _set_gm_session(True)   # 之前在托盘关过 GM 也能直接恢复, 页面 2.5s 内自动复活
    if _gm_windows():
        _focus_gm_windows()
        return              # 已有 GM 窗口, 不重复开
    chrome = _find_chrome()
    if not chrome:
        # 没有 Chrome: 不擅自用其它浏览器, 弹出链接让用户自己打开
        log_write("start_gm: 未找到 Chrome, 弹出 GM 链接提示")
        subprocess.Popen([PYW, DIALOGS, "gmlink"])
        return
    # 普通 Chrome 独立窗口 (带完整 Chrome 界面)。证书已含 127.0.0.1 SAN
    # 并导入受信根, 不再需要 --ignore-certificate-errors。
    subprocess.Popen([chrome, "--new-window", GM_URL, "--no-first-run",
                      "--no-default-browser-check"],
                     creationflags=CREATE_NO_WINDOW,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def close_gm():
    """关闭GM = 断开服务器端 GM 会话: 页面显示「GM 已关闭」并停止交互,
    其余 GM 接口一律 403 (真正断开), 托盘点「启动GM」立即恢复。
    不碰浏览器: Chrome 单进程多标签, 关窗口会连带用户自己的标签页一起关掉。"""
    r = _set_gm_session(False)
    if r is None:
        log_write("close_gm: 无法断开 GM (服务器未运行, 或服务器仍是旧版本 —— 重启托盘即可)")
    else:
        log_write("close_gm: GM 会话已断开 (active=%s)" % r)

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
    # 2026-11-12 用户要求: 一键关闭要连 GM 系统一起关。
    # 顺序必须在 kill_all_servers() 之前 —— 断开会话的接口需要服务器还活着;
    # 关窗口只关"纯 GM 窗口"(标题完全等于 GM 页面标题), 不碰用户自己的标签页。
    # 2026-11-13: 若该 GM 窗口是 Chrome 的最后一个窗口则跳过 (关掉会整个退出 Chrome,
    # 用户曾反馈"一键关闭把我的 Chrome 也一起关闭了")。
    try:
        import gm_shutdown
        gm_shutdown.shutdown_gm(log=log_write)
        time.sleep(0.5)   # 给 Chrome 一点时间处理 WM_CLOSE
    except Exception as e:
        log_write("一键关闭: GM 清理失败 %s" % e)
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
def on_gm_open(ic, item): _thread(start_gm)
def on_gm_close(ic, item): _thread(close_gm)
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
        # GM 面板: 两个菜单项常驻显示, 不做状态智能判断 (用户要求: 一直摆在那)
        pystray.MenuItem("启动GM", on_gm_open),
        pystray.MenuItem("关闭GM", on_gm_close),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("一键关闭", on_close),
    )
    icon = pystray.Icon("DOAXVV", make_icon(), "DOAXVV 单机服", menu)
    threading.Thread(target=startup, daemon=True).start()
    icon.run()

if __name__ == "__main__":
    main()
