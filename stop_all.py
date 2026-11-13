# -*- coding: utf-8 -*-
"""
stop_all.py — 一键关闭: 关服务器+托盘+hosts (start_all 的逆操作)
被 一键关闭.bat 调用; 托盘右键「一键关闭」走 tray_app.shutdown()。
2026-11-07: 时间钳制机制(clamp_offset.py 等)已整体移除并归档, 本脚本不再调用它,
            只把服务器的 time_offset_config.json 归零, 清掉可能的历史残留偏移。
"""
import os, sys, json, subprocess, time
try: sys.stdout.reconfigure(line_buffering=True)
except Exception: pass

DIR = os.path.dirname(os.path.abspath(__file__))  # DOAXVV_Server
HOSTS_SWITCH = os.path.join(DIR, "hosts_switch.ps1")
OFFSET_FILE = os.path.join(DIR, "local_server", "time_offset_config.json")
PY = sys.executable
CREATE_NO_WINDOW = 0x08000000

def run_ps(cmd, timeout=30):
    try:
        return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                              capture_output=True, text=True, timeout=timeout,
                              creationflags=CREATE_NO_WINDOW).stdout.strip()
    except Exception:
        return ""

def kill_pids(out):
    n = 0
    for line in out.splitlines():
        pid = line.strip()
        if pid.isdigit():
            subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True, creationflags=CREATE_NO_WINDOW)
            n += 1
    return n

def hosts_hijacked():
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", HOSTS_SWITCH, "status"],
                           capture_output=True, text=True, timeout=20, creationflags=CREATE_NO_WINDOW)
        return "[HIJACKED]" in r.stdout
    except Exception:
        return False

def reset_time_offset():
    """时间偏移归零 (服务器 local_server_v2.py 仍读该文件, 非 0 会让服务器时间偏离真实时间)"""
    try:
        if not os.path.exists(OFFSET_FILE):
            return True
        cfg = json.load(open(OFFSET_FILE, encoding="utf-8"))
        keys = ("offset_days", "offset_hours", "offset_minutes", "offset_seconds")
        if not any(int(cfg.get(k, 0) or 0) != 0 for k in keys):
            return True
        for k in keys:
            cfg[k] = 0
        with open(OFFSET_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False

def main():
    print("=" * 60)
    print(" DOAXVV 一键关闭: 服务器 + 托盘 + hosts")
    print("=" * 60)

    # 2026-11-12 用户要求: 一键关闭连带关闭 GM 系统 (断开会话 + 尝试关 GM 窗口)。
    # 必须在杀服务器之前做 —— /gm/api/gm_session 需要服务器还活着。
    # 2026-11-13: gm_shutdown 增加"最后一窗口"保护 —— GM 是 Chrome 唯一窗口时跳过,
    # 否则关掉窗口会让整个 Chrome 退出 (用户曾反馈浏览器被一起关掉)。
    try:
        import gm_shutdown
        sess, nwin, nskip = gm_shutdown.shutdown_gm()
        state = "会话已断开" if sess is False else ("服务器未运行" if sess is None else "会话仍开启")
        extra = ""
        if nwin:
            extra += ", 关闭 GM 窗口 %d 个" % nwin
        if nskip:
            extra += ", 保留 %d 个 GM 窗口 (Chrome 最后一个窗口, 关掉会退出浏览器)" % nskip
        print("  GM: " + state + extra)
        if nwin:
            time.sleep(0.5)   # 给 Chrome 一点时间处理 WM_CLOSE
    except Exception as e:
        print("  GM: [WARN] 清理失败 " + str(e))

    n443 = kill_pids(run_ps("Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique"))
    nls = kill_pids(run_ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'python' -and $_.CommandLine -match 'local_server_v2' } | Select-Object -ExpandProperty ProcessId"))
    print("  服务器: " + ("已关闭" if (n443 or nls) else "未运行, 跳过"))

    ntray = kill_pids(run_ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'python' -and $_.CommandLine -match 'tray_app.py' } | Select-Object -ExpandProperty ProcessId"))
    print("  托盘: " + ("已关闭" if ntray else "未运行, 跳过"))

    time.sleep(1)

    if hosts_hijacked():
        print("  hosts: 关闭劫持 (会弹 UAC, 点是)...")
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", HOSTS_SWITCH, "off"],
                       creationflags=CREATE_NO_WINDOW)
        print("  -> " + ("已解除" if not hosts_hijacked() else "解除失败"))
    else:
        print("  hosts: 未劫持, 跳过")

    print("  时间偏移: " + ("已归零" if reset_time_offset() else "[WARN] 归零失败, 请检查 time_offset_config.json"))
    time.sleep(1)
    still = run_ps("Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty OwningProcess")
    print("\n" + ("[OK] 全部已关闭" if not still else "[WARN] 443 仍被占用, 请手动检查"))

if __name__ == "__main__":
    main()
