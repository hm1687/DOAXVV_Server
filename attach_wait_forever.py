"""
attach_wait_forever2.py — 等待游戏进程并挂载探针 (改进版: 实时flush + 详细诊断)
用法: python -u attach_wait_forever2.py <js文件名> [--proc <进程名>] [--poll <秒>]
改进: 所有 print 立即 flush; attach/注入失败打印堆栈; 检测到进程后持续输出状态
"""
import os, sys, time, datetime, traceback
import frida

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
JS_NAME = sys.argv[1] if len(sys.argv) > 1 else "probe_mg_fullresp.js"
HOOK_JS = os.path.join(TOOL_DIR, JS_NAME)
PROC_NAME = "DOAX_VV.exe"
POLL_SEC = 0.2
if "--proc" in sys.argv:
    i = sys.argv.index("--proc")
    PROC_NAME = sys.argv[i+1]
if "--poll" in sys.argv:
    i = sys.argv.index("--poll")
    POLL_SEC = float(sys.argv[i+1])
LOG_DIR = os.path.join(TOOL_DIR, "frida_logs")

log_file = None

def log(msg):
    line = msg + "\n"
    print(line, end="", flush=True)
    if log_file:
        log_file.write(line); log_file.flush()

def on_message(message, data):
    try:
        if message["type"] == "send":
            text = str(message["payload"])
        elif message["type"] == "log":
            text = str(message.get("payload", ""))
        elif message["type"] == "error":
            text = "[JS_ERROR] " + str(message.get("stack", message.get("description", "")))
        else:
            text = str(message)
        log(text)
    except Exception as e:
        log("[on_message异常] " + str(e))

def find_pid(name):
    try:
        dev = frida.get_local_device()
        for p in dev.enumerate_processes():
            if p.name.lower() == name.lower():
                return p.pid
    except Exception as e:
        log("[!] 枚举进程失败: " + str(e))
    return None

def main():
    global log_file
    os.makedirs(LOG_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    js_base = os.path.splitext(JS_NAME)[0]
    log_path = os.path.join(LOG_DIR, f"attach2_{ts}_{js_base}.log")
    log_file = open(log_path, "w", encoding="utf-8")
    log(f"[*] 日志: {log_path}")
    log(f"[*] 探针: {JS_NAME} -> {HOOK_JS} (存在={os.path.exists(HOOK_JS)})")
    log(f"[*] 等待进程: {PROC_NAME}, 轮询 {POLL_SEC}s")

    dev = frida.get_local_device()
    pid = None
    t0 = time.time()
    while pid is None:
        pid = find_pid(PROC_NAME)
        if pid is None:
            time.sleep(POLL_SEC)
        # 每30秒报一次仍在等待
        if pid is None and int(time.time() - t0) % 30 < 1 and int(time.time() - t0) > 0:
            log(f"[*] {int(time.time()-t0)}s 仍在等待 {PROC_NAME}...")
    log(f"[*] 检测到 {PROC_NAME} pid={pid}, 立即 attach...")
    try:
        session = dev.attach(pid)
        log("[*] attach OK")
    except Exception as e:
        log("[!] attach 失败: " + str(e))
        log(traceback.format_exc())
        return 3
    js_code = open(HOOK_JS, encoding="utf-8").read()
    _offset_path = os.path.join(TOOL_DIR, "local_server", "time_offset_config.json").replace("\\", "\\\\")
    js_code = js_code.replace("__TIME_OFFSET_FILE__", _offset_path)
    script = session.create_script(js_code)
    script.on("message", on_message)
    try:
        script.set_log_handler(lambda level, text: on_message({"type": "log", "payload": text}, None))
    except Exception as e:
        log("[!] set_log_handler 不可用: " + str(e))
    try:
        script.load()
        log("[*] 探针已注入: " + JS_NAME)
    except Exception as e:
        log("[!] 注入失败: " + str(e))
        log(traceback.format_exc())
        try: session.detach()
        except Exception: pass
        return 4
    log("[*] 开始持续监听 (Ctrl+C 结束)...")
    try:
        while True:
            time.sleep(1)
            # 检测游戏是否退出
            if find_pid(PROC_NAME) is None:
                log("[!] 游戏进程已退出, 结束挂载")
                break
    except KeyboardInterrupt:
        pass
    finally:
        try: script.unload()
        except Exception: pass
        try: session.detach()
        except Exception: pass
        log_file.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())