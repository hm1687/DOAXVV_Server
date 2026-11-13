# -*- coding: utf-8 -*-
"""
gm_shutdown.py — 一键关闭时连带关闭 GM 系统

背景 (2026-11-12 用户要求):
  托盘「一键关闭」/ 一键关闭.bat 原本只杀服务器与托盘, GM 面板的 Chrome 窗口
  会留在桌面上, 看着像"GM 还开着"。这里把 GM 系统一起收掉:
    1) 先调服务器 /gm/api/gm_session {"active": false} 断开 GM 会话
       (服务器还活着时才通, 让面板立刻显示「GM 已关闭」);
    2) 再尝试关掉 GM 的 Chrome 窗口。

2026-11-13 事故与修复 (用户反馈「一键关闭把我的 Chrome 也一起关闭了」):
  Chrome 是单进程多窗口, 关掉某个窗口本身不会影响别的窗口 —— 但**关掉最后一个
  窗口会让整个 Chrome 退出**。当时 GM 窗口恰好是唯一的 Chrome 窗口, 于是一键关闭
  把浏览器一起收掉了。实测对照: 同进程两个窗口关掉其一, 另一个存活; 只剩一个时
  关掉即整个进程结束。
  修复: 关闭前先统计该 Chrome 进程还有几个窗口, 只有 **>1** 才发 WM_CLOSE;
  若 GM 窗口就是最后一个, 直接跳过并在日志里说明, 绝不连带退出用户的 Chrome。

与托盘菜单「关闭GM」的区别:
  「关闭GM」= 只断会话、不碰浏览器 (日常开关, 用户可能还要看面板)。
  「一键关闭」= 整机停服, 会话断开 + 尽可能关掉 GM 窗口 (不牺牲用户的浏览器)。

安全边界:
  只关闭"纯 GM 窗口" —— 窗口标题去掉 " - Google Chrome" 后必须**完全等于**某个
  GM 页面标题; 且该窗口不能是所属 Chrome 进程的最后一个窗口。
"""
import ctypes
import json
import ssl
import urllib.request
from collections import Counter

GM_URL = "https://127.0.0.1/gm/"

# gm_panel.html 三种界面语言下的页面标题 (zh / en / ja)
GM_TITLE_TAGS = ("DOAXVV 玩家服务", "DOAXVV Player Service", "DOAXVV プレイヤーサービス")

# Windows 浏览器窗口标题统一是 "<页面标题> - <浏览器名>"
_BROWSER_SUFFIXES = (
    " - Google Chrome",
    " - Microsoft​ Edge",   # 含 U+200B, Edge 实际标题里有零宽字符
    " - Microsoft Edge",
    " - Chromium",
    " - Brave",
    " - Vivaldi",
)

WM_CLOSE = 0x0010

_WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)


def _title_of(hwnd, user32):
    n = user32.GetWindowTextLengthW(hwnd)
    if n <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(n + 1)
    user32.GetWindowTextW(hwnd, buf, n + 1)
    return buf.value


def _strip_browser(title):
    t = (title or "").strip()
    for suf in _BROWSER_SUFFIXES:
        if t.endswith(suf):
            return t[: -len(suf)].strip()
    return t


def _visible_titled_windows():
    """枚举所有"可见且有标题"的顶层窗口 → [{hwnd, pid, title}]"""
    user32 = ctypes.windll.user32
    out = []

    def _cb(hwnd, lparam):
        if user32.IsWindowVisible(hwnd):
            t = _title_of(hwnd, user32)
            if t:
                pid = ctypes.c_ulong()
                user32.GetWindowThreadProcessId(ctypes.c_void_p(hwnd), ctypes.byref(pid))
                out.append({"hwnd": hwnd, "pid": pid.value, "title": t})
        return True

    user32.EnumWindows(_WNDENUMPROC(_cb), 0)
    return out


def gm_windows(exact=True):
    """枚举 GM 窗口句柄。
    exact=True  → 只返回"纯 GM 窗口"(标题去掉浏览器后缀后完全等于 GM 页面标题);
    exact=False → 标题包含 GM 页面标题即算。"""
    wins = _visible_titled_windows()
    if exact:
        return [w["hwnd"] for w in wins if _strip_browser(w["title"]) in GM_TITLE_TAGS]
    return [w["hwnd"] for w in wins if any(tag in w["title"] for tag in GM_TITLE_TAGS)]


def close_session(timeout=3):
    """让服务器把 GM 会话置为关闭 (服务器没跑/旧版本时返回 None)"""
    url = GM_URL.rstrip("/") + "/api/gm_session"
    data = json.dumps({"active": False}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            return bool(json.loads(r.read().decode("utf-8", "replace")).get("active", False))
    except Exception:
        return None


def close_windows():
    """向纯 GM 窗口发 WM_CLOSE。

    返回 (已关闭数量, 为保住 Chrome 而跳过的数量)。
    关键保护: 若该窗口是所属 Chrome 进程的**最后一个可见窗口**, 关掉它会让整个
    Chrome 退出 —— 这种情况一律跳过, 宁可留一个已断连的页面, 也不动用户的浏览器。
    """
    user32 = ctypes.windll.user32
    wins = _visible_titled_windows()
    targets = [w for w in wins if _strip_browser(w["title"]) in GM_TITLE_TAGS]
    if not targets:
        return 0, 0
    per_pid = Counter(w["pid"] for w in wins)   # 每个进程当前的可见窗口数
    closed = skipped = 0
    for w in targets:
        # 关掉后该进程还剩几个窗口; <=0 说明这是最后一个 → 会连带退出 Chrome
        if per_pid[w["pid"]] - 1 <= 0:
            skipped += 1
            continue
        try:
            user32.PostMessageW(ctypes.c_void_p(w["hwnd"]), WM_CLOSE, 0, 0)
            per_pid[w["pid"]] -= 1
            closed += 1
        except Exception:
            pass
    return closed, skipped


def shutdown_gm(log=None):
    """一键关闭用: 断开会话 → 尝试关 GM 窗口。返回 (会话结果, 关闭窗口数, 跳过数)"""
    sess = close_session()
    n, skipped = close_windows()
    if log:
        msg = "shutdown_gm: GM 会话=%s, 关闭 GM 窗口 %d 个" % (
            "已断开" if sess is False else ("服务器未运行" if sess is None else "仍为开启"), n)
        if skipped:
            msg += ", 跳过 %d 个(Chrome 最后一个窗口, 保留以免浏览器退出)" % skipped
        log(msg)
    return sess, n, skipped
