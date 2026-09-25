# logutil.py — 日志缓冲写入 (从 local_server_v2.py 提取, 行为不变)
# 合并多次 open/close 为批量刷盘, 保留 full_server.log 排查能力
import os, datetime
from paths import LOG

_LOG_BUF = []
_LOG_BUF_SIZE = 0
_LOG_BUF_MAX = 16384   # 2026-09-15: IO优化 恢复16KB, 减少 open/close 频率(原512几乎每条log都flush)

def _flush_log():
    global _LOG_BUF, _LOG_BUF_SIZE
    if not _LOG_BUF:
        return
    data = "".join(_LOG_BUF)
    _LOG_BUF = []
    _LOG_BUF_SIZE = 0
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(data)
    except Exception:
        pass

def log_write(text):
    global _LOG_BUF, _LOG_BUF_SIZE
    _LOG_BUF.append(text)
    _LOG_BUF_SIZE += len(text.encode("utf-8", "replace"))
    if _LOG_BUF_SIZE >= _LOG_BUF_MAX:
        _flush_log()

try:
    import atexit
    atexit.register(_flush_log)
except Exception:
    pass

def now_ts():
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
