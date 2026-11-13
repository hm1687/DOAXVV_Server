"""
local_server_v2.py — 完整本地单机服务器 (CSV版)
实现:
  1. 完整协议 + RSA握手 + AES-256-CBC加密 (B2)
  2. /v1/csv/list 返回真实 csv_file_list (zlib压缩)
  3. /production/csv/<ver>/<hash> 返回 gzip 压缩的 CSV 明文
"""
import os, json, ssl, datetime, uuid, base64, zlib, gzip, re, time, threading, socket as _sockmod, csv
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509

from paths import OUT, CERT, KEY, LOG, GM_HTML, RSA_PUB, RSA_PRIV, TOOL, CSV_LIST_JSON, CSV_MASTER

# 鉴权凭据 (2026-11-12: 默认值改为无意义占位, 可用环境变量覆盖; 见 README)
TOKEN = os.environ.get("DOAXVV_TOKEN", "deadbeefdeadbeefdeadbeefdeadbeef")
OWNER_ID = int(os.environ.get("DOAXVV_OWNER_ID", "114514") or "114514")
SESSION_KEY = None

# 2026-11-08: 泳装形态列表回放开关.
#   False = GET /v1/swimsuit_arrange_flag 返回空列表 (安全默认; 重启后形态回默认但不会崩溃)
#   True  = 回放 STATE.swimsuit_arrange_flags (需先确认 variation 语义, 否则客户端越界崩溃)
#   2026-11-08 22:52 关闭(第二次崩): 回放 {item_mid:59983, variation:1} 仍导致启动闪退(先卡后崩)
#     → 该列表不是"形态记忆"的载体, 或条目还需其它字段; 在拿到正版可用的真实样本前保持空列表.
#   【最终结论 2026-11-08 · 勿再尝试】两种变体值(74 / 1)回放均崩, 详见 GET 分支内的详细备注销.
#     要修必须有"正版非空样本", 靠推测无解; 用户已同意暂时搁置, 功能在游戏内可正常切换.
_ARRANGE_REPLAY_ENABLED = False
# 回放时 variation 的安全上限: 客户端把它当"变体下标"用, 大值(实测 74)会越界崩进程.
#   → 只回放 0..CAP 的条目; 超出的按"默认形态不放"处理 (不崩优先)
_ARRANGE_VARIATION_CAP = 3
# 形态诊断: 客户端到底有没有在点箭头时发 PUT、发的什么值 —— 写独立小文件, 即时 flush,
#   不受 logutil 16KB 缓冲影响 (full_server.log 会滞后/丢失, 之前据此误判"0 请求")
_ARRANGE_TRACE = True

def _arrange_trace(kind, **kw):
    if not _ARRANGE_TRACE:
        return
    try:
        import time as _t
        _p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arrange_trace.log")
        with open(_p, "a", encoding="utf-8") as _f:
            _f.write(_t.strftime("%Y-%m-%d %H:%M:%S") + " " + kind + " " +
                     " ".join("%s=%s" % (_k, _v) for _k, _v in kw.items()) + "\n")
    except Exception:
        pass

from logutil import _flush_log, log_write, now_ts

# ============================================================================
# 函数索引 (按域分组; 不带行号——改动会漂移, 靠 grep 函数名定位)
# ----------------------------------------------------------------------------
# 路径/常量:  paths.py(OUT,CERT,KEY,LOG,GM_HTML,RSA_PUB/PRIV,TOOL,CSV_LIST_JSON,CSV_MASTER)
#             本文件: TOKEN, OWNER_ID, SESSION_KEY(运行时鉴权占位)
# 日志/抓取:  logutil.py(_flush_log, log_write, now_ts)  _cap(回归基线,DOAXVV_CAPTURE开关)
# 资源代理:   _res_begin_download/_res_end_download(in-flight去重) _res_read_cache/_res_write_cache_atomic
#             _load_vpn_ips/_record_vpn_ip/_is_public_ipv4/_vpn_probe/_get_akamai_fallback_ips
# 时间:       server_now/server_now_str (UTC, 与客户端GetSystemTime一致)  game_today_str/game_now (19点日切, boundary=10)
# 加密/CSV:   load_rsa  load_csv_list/_patch_venus_shop  rsa_decrypt_session_key
#             aes_cbc_decrypt/aes_cbc_encrypt  normalize_dates(日期归一化)
# 扭蛋:       _resolve_rt/_invalidate_gacha_pool_cache  _gacha_info/_gacha_type/_gacha_is_active/_gacha_paired
#             _get_gacha_pool/_get_gacha_config/_random_gacha_items
# 状态/装备:  _load_state/_save_state(原子写+STATE_LOCK) STATE(唯一数据源) _inject_state_wallet
#             state_girl_equipment/apply_girl_state/_equipment_owner_map/_validate_equipment_owner/girl_obj_from_db
# 挑战赛:     _pick_rotate  _quest_start_idx/_quest_end_idx/_set_quest_start_idx/_set_quest_end_idx
#             _init_match/_gen_round/_build_volley_dynamic  _load_quest_tables
# 邮箱/商店:  _mark_claimed/_is_claimed  _build_giftbox(三分类)  _process_shop_exchange
# 响应构建:   _apply_state_overlay(STATE叠加)  _build_dynamic(动态引擎,14端点)
#             _decode_chunked/_fetch_real_resource_list/_build_resource_list
# HTTP入口:   Handler._handle(路由+加密信封) _serve_csv _proxy_api01/_proxy_real_page/_proxy_fetch
#             _res_download_dedup/_serve_resource  _handle_gm/_handle_gm_impl(GM面板,粗粒度锁)
#             _build_response(优先级链) do_GET/POST/PUT/DELETE run
# ----------------------------------------------------------------------------
# 响应优先级链 (_build_response 自上而下首个命中即返回):
#   特殊硬编码 → information → login_bonus → giftbox → wallet → item/consume →
#   mission → friendship → _apply_state_overlay → _build_dynamic → REAL_RESPONSES → 兜底{status:success}
# ============================================================================

# ===== 回归基线抓取 (DOAXVV_CAPTURE 环境变量开启, 默认关闭, 不影响行为) =====
# 抓 (method, path, 解密请求, 明文响应dict) 到 baseline_capture.jsonl; 重构后回放比对, 保证协议字节不变
_CAPTURE_ON = bool(os.environ.get("DOAXVV_CAPTURE"))
_CAPTURE_FILE = os.path.join(OUT, "baseline_capture.jsonl")
_cap_lock = threading.Lock()
if _CAPTURE_ON:
    try:
        open(_CAPTURE_FILE, "w", encoding="utf-8").close()  # 每次启动清空, 新基线
    except Exception:
        pass
def _cap(method, path, req, resp):
    """抓取 (method, path, 解密请求, 明文响应dict); 默认关闭(DOAXVV_CAPTURE 未设)"""
    if not _CAPTURE_ON:
        return
    try:
        rec = json.dumps({"ts": now_ts(), "method": method, "path": path,
                          "req": req, "resp": resp}, ensure_ascii=False, default=str)
        with _cap_lock:
            with open(_CAPTURE_FILE, "a", encoding="utf-8") as f:
                f.write(rec + "\n")
    except Exception:
        pass

# ===== 2026-09-14 资源下载并发修复 (A1/A3/A4/B2/C3) =====
# 问题背景: ThreadingHTTPServer 每请求一线程 + HTTP/1.0, 同一 hash 的并发 Range 请求
#   各自判 os.path.exists(cache)==False 后各跑一遍 _proxy_fetch (200+ 次并发 IP 探测)。
# 修复: (A1) in-flight 去重, 同 hash 只一个线程回源; (A3) VPN IP 列表化+成功率排序;
#       (A4) Akamai 真实 IP 直连兜底; (B2) 指数退避重试; (C3) 缓存原子写。

# --- A1: in-flight 去重 ---
_RES_INFLIGHT = {}            # {hash: threading.Event} 正在回源下载的 hash
_RES_LOCK = threading.Lock()  # 保护 _RES_INFLIGHT
_RES_OWNER_WAIT = 180         # 秒: 等待者最长等待时间(约 3 次重试的回源耗时)

def _res_begin_download(hash_val):
    """尝试成为 hash_val 的回源下载所有者。
    返回 (is_owner, event):
      is_owner=True  → 本线程负责下载, 结束后必须调 _res_end_download
      is_owner=False → 已有其他线程在回源, 调用者应 ev.wait() 后重读缓存
    """
    with _RES_LOCK:
        ev = _RES_INFLIGHT.get(hash_val)
        if ev is None or ev.is_set():
            ev = threading.Event()          # 不存在或上次异常残留 → 本线程接管
            _RES_INFLIGHT[hash_val] = ev
            return True, ev
        return False, ev

def _res_end_download(hash_val, ev):
    """回源结束(成功或失败): 通知等待者并移除 in-flight 条目。"""
    try:
        ev.set()
    except Exception:
        pass
    with _RES_LOCK:
        if _RES_INFLIGHT.get(hash_val) is ev:
            del _RES_INFLIGHT[hash_val]

def _res_read_cache(cache_file):
    try:
        with open(cache_file, "rb") as f:
            return f.read()
    except Exception:
        return None

def _res_write_cache_atomic(cache_file, data):
    """原子写缓存: 先写 .tmp 再 os.replace, 避免并发读到半截文件 (C3)。
    只有 in-flight 所有者会调用, 同一 hash 同时只有一个写者, .tmp 无竞争。"""
    tmp = cache_file + ".tmp"
    try:
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, cache_file)
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

# --- A3: VPN IP 列表化 (替代单值覆盖) ---
VPN_IP_FILE = os.path.join(TOOL, "vpn_ip.txt")
VPN_KNOWN_DEFAULT = ["198.18.0.35", "198.18.0.20", "198.18.0.65", "198.18.0.64", "198.18.0.44"]
VPN_SCAN_RANGE = range(3, 65)        # 198.18.0.3 - 198.18.0.64
VPN_IP_MAX_ENTRIES = 20              # 列表上限, 防止膨胀
VPN_KNOWN_TRY_MAX = 8                # 单次回源最多尝试的已知 IP 数 (防列表膨胀后逐个 5s 超时阻塞过久)
_VPN_IP_LOCK = threading.Lock()      # 保护 vpn_ip.txt 并发读写

# --- A4: Akamai 真实 IP 直连兜底 (来自 _proxy_real_page 的实测 IP) ---
AKAMAI_FALLBACK_IPS = ("104.109.143.26", "104.109.143.30")

def _load_vpn_ips():
    """读取 VPN IP 列表, 返回按(成功次数, 最近成功时间)降序排列的纯 IP 列表。
    兼容旧格式: 纯文本每行一个 IP; 新格式: {"ips": [{ip,last_success,successes,failures}]}"""
    raw = ""
    try:
        with open(VPN_IP_FILE, "r", encoding="utf-8") as f:
            raw = f.read().strip()
    except Exception:
        raw = ""
    entries = []
    seen = set()
    if raw:
        try:
            obj = json.loads(raw)
            for e in obj.get("ips", []):
                ip = str(e.get("ip", "")).strip()
                if ip and ip not in seen:
                    seen.add(ip)
                    entries.append(e)
        except Exception:
            for line in raw.splitlines():      # 旧纯文本格式
                line = line.strip()
                if line and not line.startswith("#") and line not in seen:
                    seen.add(line)
                    entries.append({"ip": line, "last_success": 0, "successes": 1, "failures": 0})
    for ip in VPN_KNOWN_DEFAULT:               # 兜底列表始终参与
        if ip not in seen:
            seen.add(ip)
            entries.append({"ip": ip, "last_success": 0, "successes": 0, "failures": 0})
    entries.sort(key=lambda e: (int(e.get("successes", 0)), int(e.get("last_success", 0))), reverse=True)
    return [e["ip"] for e in entries]

def _record_vpn_ip(ip, success):
    """记录 IP 成功/失败并回写 vpn_ip.txt (JSON 格式)。失败数过高会被淘汰。"""
    with _VPN_IP_LOCK:
        try:
            entries = []
            try:
                with open(VPN_IP_FILE, "r", encoding="utf-8") as f:
                    obj = json.load(f)
                entries = [e for e in obj.get("ips", []) if str(e.get("ip", "")).strip()]
            except Exception:
                entries = []
            entry = None
            for e in entries:
                if str(e.get("ip", "")).strip() == ip:
                    entry = e
                    break
            now = int(time.time())
            if entry is None:
                entry = {"ip": ip, "last_success": 0, "successes": 0, "failures": 0}
                entries.append(entry)
            if success:
                entry["successes"] = int(entry.get("successes", 0)) + 1
                entry["last_success"] = now
                entry["failures"] = max(0, int(entry.get("failures", 0)) - 1)
            else:
                entry["failures"] = int(entry.get("failures", 0)) + 1
            # 淘汰连续失败过多且从未成功的条目
            entries = [e for e in entries
                       if int(e.get("successes", 0)) > 0 or int(e.get("failures", 0)) <= 5]
            # 超上限时按成功率+最近成功时间淘汰
            entries.sort(key=lambda e: (int(e.get("successes", 0)), int(e.get("last_success", 0))), reverse=True)
            entries = entries[:VPN_IP_MAX_ENTRIES]
            with open(VPN_IP_FILE, "w", encoding="utf-8") as f:
                json.dump({"ips": entries}, f, ensure_ascii=False, indent=1)
        except Exception:
            pass

def _is_public_ipv4(ip):
    """判断是否为公网 IPv4 (排除回环/私网/保留/VPN 段)。
    ★关键: hosts 劫持后 getaddrinfo("game.doaxvv.com") 返回 127.0.0.1,
      若不排除回环地址, 回源会连到本机自己的 443 → 同 hash 的 in-flight 事件
      被外层占用 → 内层等外层、外层等内层 → 互锁, 且每次 socket 超时派生新一层
      自请求, 递归爆炸打爆线程池。必须在这里拦死。"""
    try:
        octets = [int(x) for x in ip.split(".")]
    except Exception:
        return False
    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        return False
    a, b = octets[0], octets[1]
    if a == 0 or a == 127:             # 0.0.0.0/8, 127.0.0.0/8 回环
        return False
    if a == 10:                        # 10.0.0.0/8 私网
        return False
    if a == 172 and 16 <= b <= 31:     # 172.16.0.0/12 私网
        return False
    if a == 192 and b == 168:          # 192.168.0.0/16 私网
        return False
    if a == 198 and b == 18:           # 198.18.0.0/15 VPN 段
        return False
    if a == 224:                       # 224.0.0.0/4 组播
        return False
    if a >= 240:                       # 240.0.0.0/4 保留
        return False
    return True

def _vpn_probe(timeout=1.5):
    """快速探测 VPN 段可达性 (纯 TCP connect, 不下数据)。
    无 VPN 时 198.18.0.x 的包被丢弃 → connect 超时; 有 VPN 时 VPN 客户端路由 → connect 成功。
    返回 True 表示 VPN 段可达, 值得尝试 VPN 回源; False 则跳过 VPN 段直连 Akamai,
    避免无 VPN 时在 8 个已知 IP × 5s 超时上空耗 ~40s/次重试。"""
    for ip in _load_vpn_ips()[:3]:
        try:
            s = _sockmod.create_connection((ip, 80), timeout=timeout)
            s.close()
            return True
        except Exception:
            continue
    return False

def _get_akamai_fallback_ips():
    """Akamai 直连候选 IP: 实测硬编码 IP + DNS 解析结果。
    DNS 结果必须过 _is_public_ipv4 —— hosts 劫持场景下会解析出 127.0.0.1, 见上方说明。"""
    ips = [ip for ip in AKAMAI_FALLBACK_IPS if _is_public_ipv4(ip)]
    try:
        for _fam, _typ, _proto, _name, sockaddr in _sockmod.getaddrinfo("game.doaxvv.com", 443, _sockmod.AF_INET):
            ip = sockaddr[0]
            if _is_public_ipv4(ip) and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips

# ===== 服务器时间 (本地时间 + 时间偏移) =====
# 时间偏移从 time_offset_config.json 读取。该机制原本用于"钳制"(clamp_offset.py 写入 + frida 探针同步改客户端),
# 2026-11-07 钳制整体移除(已整体停用并移出仓库), 19点白屏根因已按客户端 19:00 UTC 日切修正。
# 现在该文件只作为"可选的手工偏移", 正常情况必须全 0: 一旦非 0, 服务器时间就偏离真实时间,
# 而客户端已无探针跟随 → 时间戳/日切再次错位 → 必定白屏。托盘/一键关闭都会把它归零。
TIME_OFFSET_FILE = os.path.join(OUT, "time_offset_config.json")

def _load_time_offset():
    try:
        with open(TIME_OFFSET_FILE, "r", encoding="utf-8") as _f:
            _cfg = json.load(_f)
            return (int(_cfg.get("offset_days", 0)), int(_cfg.get("offset_hours", 0)),
                    int(_cfg.get("offset_minutes", 0)), int(_cfg.get("offset_seconds", 0)))
    except Exception:
        return (0, 0, 0, 0)

TIME_OFFSET_D, TIME_OFFSET_H, TIME_OFFSET_M, TIME_OFFSET_S = _load_time_offset()

def time_offset_delta():
    # 每次调用都重读, 便于手工改动后立即生效(不再有后台定时写入方: clamp_offset.py 已移除)
    _d, _h, _m, _s = _load_time_offset()
    return datetime.timedelta(days=_d, hours=_h, minutes=_m, seconds=_s)

def server_now():
    """服务器当前时间 (= 本地时间 + time_offset_delta, 正常情况偏移恒为 0).
    注: .timestamp() 已自动转 UTC epoch, 故 X-DOAXVV-ServerTime = str(int(game_now().timestamp()))
    本就是正确 UTC epoch (2026-09-25 实测: now().timestamp()==time.time(), utcnow().timestamp() 反而偏 -8h)."""
    return datetime.datetime.now() + time_offset_delta()

def server_now_str(fmt="%Y-%m-%d %H:%M:%S"):
    """响应体时间串 -> 必须输出 UTC。
    官方服务器响应里的所有时间都是 UTC (实证: 档期结束 18:59:59 / last_logged_at 11:17 对应北京 19:17),
    客户端也按 UTC 解析(_mkgmtime64)。用本地时间会让所有时间整体快 8 小时, 客户端看到"未来时间"。"""
    return datetime.datetime.fromtimestamp(
        server_now().timestamp(), datetime.timezone.utc).strftime(fmt)

# ===== 游戏日 (19:00 UTC 日切) — 2026-11-07 REA 实证修正 =====
# 客户端真实日界 (IDA Pro 反编译 DOAX_VV.exe sub_14236BC20 / sub_1424BBE80, 镜像基址 0x140000000):
#     v20[0] = now_epoch - 68400;                        // 68400 = 19*3600
#     gmtime(v20) -> snprintf("%04d-%02d-%02d 19:00:00") // 再 _mkgmtime64 转回 epoch 比较
#   => 游戏日 D 覆盖 [D 19:00 UTC, D+1 19:00 UTC) = 北京 [D+1 03:00, D+2 03:00) = 日本 [D+1 04:00, D+2 04:00)
# 官方服务器响应体里的时间串同样是 UTC (实证: 档期结束大量 18:59:59; last_logged_at=11:17:49 对应北京 19:17)
#
# 【旧实现的 bug】把 19 当成"本地小时"用 (now.hour >= 19 + 1day):
#   服务器在北京 19:00 就翻页, 而客户端要等到北京 03:00 才翻 -> 每天 19:00~次日 03:00 服务器整整超前一天
#   -> 客户端收到"明天/未来"的日期 -> 判定为未来日期并拒绝 -> 大厅初始化反复重试 -> 19点白屏
#   旧注释里"客户端以 19:00 北京时间分界"是误判: 那个 19 是 UTC 19 点, 不是本地 19 点。
#
# 开关: server_config.json "game_day_boundary_hour" 现表示【UTC 日切小时】, 默认 19 (=官方 04:00 JST)
# 注: CONFIG 在本函数定义之后才初始化(L391), Python 在调用时解析全局名, 请求处理阶段 CONFIG 已存在
GAME_DAY_BOUNDARY_UTC_HOUR = 19

def _game_day_boundary_utc_hour():
    try:
        h = int(CONFIG.get("game_day_boundary_hour", GAME_DAY_BOUNDARY_UTC_HOUR))
    except (TypeError, ValueError):
        h = GAME_DAY_BOUNDARY_UTC_HOUR
    return GAME_DAY_BOUNDARY_UTC_HOUR if h < 0 else (h % 24)

def utc_now():
    """服务器当前时间的 UTC 视图 (naive, 已含时间偏移). 响应体时间串必须用它, 不能用本地时间"""
    return datetime.datetime.fromtimestamp(server_now().timestamp(), datetime.timezone.utc).replace(tzinfo=None)

def game_now_str(fmt="%Y-%m-%d %H:%M:%S"):
    """响应体里的时间串: UTC 格式化 (官方服务器如此, 否则客户端看到 +8h 的"未来时间")"""
    return utc_now().strftime(fmt)

def game_today_str():
    """游戏日"标签" (%Y-%m-%d) — 注意是【标签】, 比客户端算出的窗口起点晚一天。

    客户端 sub_14236BC20 算的是【窗口起点】: gmtime(now-19h) 那天的 19:00:00 UTC,
    用来做阈值比较 (项目日期 < 阈值 => 已过期)。它算出的日期是 D-1, 而这一天真正
    叫法(官方日标签)是 D —— 因为游戏日 D 覆盖 [D-1 19:00 UTC, D 19:00 UTC),
    即日本 [D 04:00, D+1 04:00)。实证: CSV 里"档期结束"统一写 18:59:59 UTC
    (= 次日 03:59:59 JST), 两者是同一时刻的两种写法, 都指向 D 19:00 UTC 这个边界。

    所以: 标签 = gmtime(now - B + 24h) 的日期 = gmtime(now + (24-B)h)。B=19 => now+5h。
    (B=19 时 at 北京 03:00 = 19:00Z 前一秒 => 标签 D-1; 一到 03:00 => 标签 D。)
    """
    shift = _game_day_boundary_utc_hour() * 3600 - 86400   # 等价于 +24h 后再减边界
    ts = server_now().timestamp() - shift
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d")

def game_now():
    """raw 当前时间 (不 shift). 09-25 真修复: 之前 game_now 在 boundary 后 +1天 → X-DOAXVV-ServerTime=明天
    → 客户端 srvOff=+86400 → 19点后死循环(探针实证). 改回 raw server_now → ServerTime=今天 → srvOff=0.
    游戏日 shift 只保留在 game_today_str (签到/月度/last_logged_at), 此处不 shift."""
    return server_now()

def load_rsa():
    with open(RSA_PUB, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    with open(RSA_PRIV, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    pub_pem = open(RSA_PUB, "r").read()
    return pub, priv, pub_pem

PUB, PRIV, PUB_PEM = load_rsa()

def load_csv_list():
    with open(CSV_LIST_JSON, encoding="utf-8") as f:
        data = json.load(f)
    csv_map = data["csv_file_list"]
    # file_encrypt_key 在 csv_file_list dict 内部末尾
    fek = csv_map.get("file_encrypt_key", "") or data.get("file_encrypt_key", "")
    return csv_map, fek

CSV_MAP, FILE_ENCRYPT_KEY = load_csv_list()
HASH_TO_NAME = {v: k for k, v in CSV_MAP.items()}
CSV_DATA = {}
if os.path.isdir(CSV_MASTER):
    for fn in os.listdir(CSV_MASTER):
        if fn.endswith(".csv"):
            with open(os.path.join(CSV_MASTER, fn), "rb") as f:
                CSV_DATA[fn] = f.read()
    print(f"[*] 已加载 {len(CSV_DATA)} 个CSV文件")

# 2026-09-14: 维纳斯商店动态修复 (Shop end_time置空永久开放 + ShopItemList维纳斯货币价格0白嫖)
def _patch_venus_shop():
    import csv as _vscsv, io as _vsio
    _venus_currency = {8,9,12,13,14,15,16,17,18,19,20,21,22,26,27,46,47}
    _raw = CSV_DATA.get("Shop.csv")
    if _raw:
        try:
            _rows = list(_vscsv.reader(_vsio.StringIO(_raw.decode("utf-8-sig","replace"))))
            for _r in _rows:
                if len(_r) > 4:
                    try:
                        if 6 <= int(_r[1]) <= 25:
                            _r[4] = ""
                    except (ValueError, IndexError):
                        pass
            _out = _vsio.StringIO(); _vscsv.writer(_out).writerows(_rows)
            CSV_DATA["Shop.csv"] = _out.getvalue().encode("utf-8")
            print("[*] 维纳斯商店 Shop.csv end_time 已置空(永久开放)")
        except Exception as _e:
            print(f"[!] Shop.csv patch fail: {_e}")
    _raw2 = CSV_DATA.get("ShopItemList.csv")
    if _raw2:
        try:
            _rows2 = list(_vscsv.reader(_vsio.StringIO(_raw2.decode("utf-8-sig","replace"))))
            _cnt = 0
            for _r in _rows2:
                if len(_r) > 5:
                    try:
                        if int(_r[4]) in _venus_currency:
                            _r[5] = "0"; _cnt += 1
                    except (ValueError, IndexError):
                        pass
            _out2 = _vsio.StringIO(); _vscsv.writer(_out2).writerows(_rows2)
            CSV_DATA["ShopItemList.csv"] = _out2.getvalue().encode("utf-8")
            print(f"[*] 维纳斯商店 ShopItemList.csv 价格置0: {_cnt} 个商品")
        except Exception as _e:
            print(f"[!] ShopItemList.csv patch fail: {_e}")
# _patch_venus_shop()  # 2026-09-14 回退: 改CSV_DATA内容导致客户端9003校验(hash不匹配); exchange购买不扣货币已实现白嫖

# 物品类型映射: item_mid -> type (从 Consume_Parameter.csv 第一列)
# 用于 giftbox accept 的 item_consume_list type 字段 (替代错误的 message_type)
ITEM_TYPE_MAP = {}
_cp_path = os.path.join(CSV_MASTER, "Consume_Parameter.csv")
if os.path.exists(_cp_path):
    import csv as _csv
    with open(_cp_path, "r", encoding="utf-8") as _f:
        for _row in _csv.reader(_f):
            if len(_row) >= 2 and _row[0]:
                try:
                    ITEM_TYPE_MAP[int(_row[0])] = int(_row[1])
                except ValueError:
                    pass
    print(f"[*] 已加载物品类型映射: {len(ITEM_TYPE_MAP)} 条 (Consume_Parameter)")

# 装备类型映射: item_mid -> type (从 Equipment_Parameter.csv col1)
# 2026-09-13 故障2: 扭蛋抽到的装备 type 不全是1 (头饰22/脸饰23/臂饰24等), 需从主数据查
# 2026-11-11c: 会让客户端"任务"面板闪退的 mission_mid 黑名单 (现已清空, 见下)
#   现象: 主界面点"任务"按钮 → 界面卡住 → 闪退 (0xc0000005)
#   定位: 崩溃转储 201905 / 203849 / 205103 / 205600 / 210846 五份,
#     崩溃点全是 DOAX_VV.exe+0x274e73b, Rax=0 且 Rdx 恒为 0x3486(13446)。
#     指令 cmp dword ptr [rax+8], 3 — 前一条 call 0x24cece0 是
#     std::map<int, MissionState>::find(内联, 未命中返回 0, 命中返回 node+0x28),
#     客户端用 mission_mid 查内部任务状态表, 返回 NULL 后未判空直接 [rax+8] → 空指针。
#   真正的根因 (2026-11-11c 修正, 之前判错了):
#     崩溃时被遍历的 int 数组长度 = (R14-R15)/4 = 27 项 —— 这正好是
#     MissionData.csv 里 category=9 的任务总数(27 个), 且第一个就是 13446。
#     客户端任务面板遍历的是【本地 csv 的 category=9 任务 mid 列表】,
#     逐个去 mission 状态 map 查状态; 而服务端 /v1/mission/9 的抓包快照是 [],
#     multiple 里含 13446 的那份样本又被旧黑名单剔掉 → map 里一条都没有
#     → 第一个元素就空指针。所以"剔除 13446"不但无效, 反而让它必崩。
#   正确做法: 见 _gen_mission_list_by_category — 按类别把任务补齐下发, 让 map 有键。
#   仅保留集合本身作为应急开关, 正常为空。
MISSION_MID_BLOCKLIST = frozenset()

# 2026-11-11b: 任务主数据集合 (MissionData.csv col0)。
#   抓包池里 /v1/mission/7 的 50 份样本**每一份最后一条都是** {"mission_mid": 0, ...},
#   而 0 不在任何任务表里 → 客户端任务面板查表返回 NULL 后解引用 → 与 13446 同款
#   0xc0000005 空指针。因为本服把全部任务 progress 强设为 3(可领取), 这条脏数据会被
#   当成"可领取任务"去渲染, 属于必然触发的下一颗雷, 故在响应侧统一剔除。
MISSION_MASTER_IDS = set()
# 2026-11-11c: 任务类别索引 category -> [(mission_mid, start, end), ...]
#   用途见 _gen_mission_list_by_category()
MISSION_BY_CAT = {}
_md_path = os.path.join(CSV_MASTER, "MissionData.csv")
if os.path.exists(_md_path):
    import csv as _mdcsv
    with open(_md_path, "r", encoding="utf-8-sig") as _md_f:
        for _row in _mdcsv.reader(_md_f):
            if _row and _row[0].strip().isdigit():
                _mid = int(_row[0])
                MISSION_MASTER_IDS.add(_mid)
                if len(_row) > 4:
                    MISSION_BY_CAT.setdefault(_row[2].strip(), []).append(
                        (_mid, _row[3].strip(), _row[4].strip()))
    print(f"[*] 已加载任务主数据: {len(MISSION_MASTER_IDS)} 条 (MissionData), "
          f"类别索引: " + ", ".join(f"{k}={len(v)}" for k, v in sorted(MISSION_BY_CAT.items())))


def _gen_mission_list_by_category(_cat):
    """按 MissionData 的 category 生成 mission_list (progress=3 已完成)。
    2026-11-11c: 客户端任务面板会遍历【本地 csv 的 category=8/9 任务 mid】,
      逐个查内部 mission 状态 map; 服务端若一条都不下发就整段缺失 → 空指针闪退。
      category=9 的第一个任务就是 13446 (见 MISSION_MID_BLOCKLIST 注释)。"""
    _out = []
    for _mid, _st, _en in MISSION_BY_CAT.get(str(_cat), []):
        _out.append({
            "mission_mid": _mid,
            "progress": 3,
            "started_at": _st or "2019-03-28 11:10:39",
            # end 为空时跟 start 保持一致 (normalize_dates 会把两者同样改写, 不会出现 end<start)
            "end_at": _en or (_st or "2019-03-28 11:10:39"),
            "param1": 0,
        })
    return _out


def _mission_mid_ok(_m):
    """mission_mid 是否可安全下发给客户端。
    拒绝: 非整数 / <=0 / 黑名单 / 不在 MissionData 主数据里。
    2026-11-11b: 客户端对查不到的任务 id 没有判空, 直接 [rax+8] → 闪退。"""
    try:
        _i = int(_m)
    except (TypeError, ValueError):
        return False
    if _i <= 0 or _i in MISSION_MID_BLOCKLIST:
        return False
    if MISSION_MASTER_IDS and _i not in MISSION_MASTER_IDS:
        return False
    return True


def _mission_panel_list(_tokens):
    """按请求里的 mission_ids(面板号) 合并出完整 mission_list。
    2026-11-11e: 客户端的 mission_ids 是【面板号】而不是类别号, 一次要一批面板:
        "1,2" → /mission/1(27) + /mission/2(42) = 69 条, "3,4" → 162, "5,6" → 82,
        "7"   → 1011 条(唯一含 category=8/9 的那份: 8×9 + 9×27)。
      单个面板的完整列表 == 对应 /v1/mission/<号> 抓包 pool[0] 的 mission_list。
      面板 8/9 真实服务器对该账号返回空, 用主数据按类别补全(见 _gen_mission_list_by_category)。
    返回去重后的原始条目(已 deepcopy), progress / 合法性由调用方处理。"""
    import copy as _cp_pl
    _ep = (SERVER_DB.get("endpoints", {}) or {})
    _out, _seen = [], set()
    for _tk in _tokens:
        if _tk in ("8", "9"):
            _part = _gen_mission_list_by_category(_tk)
        else:
            _pool = _ep.get("/v1/mission/" + _tk) or []
            _head = _pool[0] if _pool and isinstance(_pool[0], dict) else None
            _part = (_head or {}).get("mission_list") or []
        for _t in _part:
            if not isinstance(_t, dict):
                continue
            _m = _t.get("mission_mid")
            if _m in _seen:
                continue
            _seen.add(_m)
            _out.append(_cp_pl.deepcopy(_t))
    return _out


def _mission_selfcheck():
    """启动后首次访问任务接口时自检: 统计"客户端会枚举的类别"是否被状态表覆盖。
    客户端任务面板(岛主应援)按本地 csv 的 category=9 列表逐个查状态 map, 缺一条就空指针
    (2026-11-11 闪退根因)。这里把 1-9 全部面板合并后按类别统计覆盖度写日志, 方便复发时定位。"""
    try:
        _toks = ["1", "2", "3", "4", "5", "6", "7", "8", "9"]
        _merged = _mission_panel_list(_toks)
        _mid2cat = {}
        for _c, _lst in MISSION_BY_CAT.items():
            for _mid, _st, _en in _lst:
                _mid2cat[_mid] = _c
        _have = {}
        for _t in _merged:
            _c = _mid2cat.get(_t.get("mission_mid"))
            _have[_c] = _have.get(_c, 0) + 1
        _lines = []
        for _c in sorted(MISSION_BY_CAT, key=lambda x: (len(x), x)):
            _need = len(MISSION_BY_CAT[_c])
            _got = _have.get(_c, 0)
            _lines.append(f"cat{_c} {_got}/{_need}")
        log_write("  [MISSION] 自检(全面板合并 %d 条): %s\n"
                  % (len(_merged), " ".join(_lines)))
        # category=9(岛主应援 27 条)是已证实的闪退源: 缺一条客户端就空指针
        _miss9 = [m for m, _s, _e in MISSION_BY_CAT.get("9", []) if m not in
                  {t.get("mission_mid") for t in _merged}]
        if _miss9:
            log_write(f"  [MISSION][WARN] category=9 缺 {len(_miss9)} 条 "
                      f"(前5 {_miss9[:5]}) — 客户端枚举到必闪退\n")
    except Exception as _ex:
        log_write(f"  [MISSION] 自检异常: {_ex}\n")


EQUIP_TYPE_MAP = {}
_ep_path = os.path.join(CSV_MASTER, "Equipment_Parameter.csv")
if os.path.exists(_ep_path):
    import csv as _epcsv
    with open(_ep_path, "r", encoding="utf-8") as _epf:
        for _row in _epcsv.reader(_epf):
            if len(_row) >= 2 and _row[0]:
                try:
                    EQUIP_TYPE_MAP[int(_row[0])] = int(_row[1])
                except ValueError:
                    pass
    print(f"[*] 已加载装备类型映射: {len(EQUIP_TYPE_MAP)} 条 (Equipment_Parameter)")

# 2026-09-16: 女孩主数据 (girl_master.csv) — 解锁女孩28/33时构造 girl_list 条目用
GIRL_MASTER_MAP = {}
_gm_path = os.path.join(CSV_MASTER, "girl_master.csv")
if os.path.exists(_gm_path):
    import csv as _gmcsv
    with open(_gm_path, "r", encoding="utf-8") as _gm_f:
        for _row in _gmcsv.reader(_gm_f):
            if len(_row) >= 15 and _row[0]:
                try:
                    GIRL_MASTER_MAP[int(_row[0])] = {
                        "power": int(_row[2]), "stamina": int(_row[4]),
                        "technic": int(_row[6]), "appeal": int(_row[8]),
                        "swimsuit": int(_row[12]), "hair": int(_row[14]),
                    }
                except (ValueError, IndexError):
                    pass
    print(f"[*] 已加载女孩主数据: {len(GIRL_MASTER_MAP)} 个 (girl_master)")

# 2026-11-13: /v1/girl 实际返回的 girl_list 顺序 (affection_level_reward_list 必须同序)
GIRL_RESP_ORDER = []

def affection_girl_order():
    _o = [g for g in GIRL_RESP_ORDER if g in GIRL_MASTER_MAP]
    for _g in sorted(GIRL_MASTER_MAP):
        if _g not in _o:
            _o.append(_g)
    return _o

# ===== 2026-11-13: 维纳斯图板 (Venus Board / 维纳斯面板) 主数据 =====
# 表结构(无表头, 来自 csv_master):
#   VenusBoard_Panel.csv       : panel_id, content_mid, girl_mid(-1=全女孩), panel_type,
#                                ?, ?, cost_item_mid, cost_count, ?, ?, gain, reward_group
#   VenusBoard_PanelReward.csv : reward_group, girl_mid(-1=全女孩), item_mid, count
#   VenusBoard_ReleaseGirls.csv: idx, girl_mid, flag
# 说明(抓包实证):
#   - open 响应 {"venus_board_reward_list":[{"item_mid":35008,"count":1003217}], ...}
#     里 35008 的 count 是剧情 episode_mid(EpisodeList 可查到 1003217), 不是数量;
#     25001(扭蛋券) 的 count 是 gacha_mid(1451~1460 正好对应 Gacha.csv 的扭蛋 id), 也不是数量。
#     这两类只回填 reward_list, 不写进背包数量, 否则会凭空多出百万件道具。
#   - 其余 item_mid 按常规处理: 消耗品→item_counts, 装备→equipment_inventory。
VENUS_PANEL_ROWS = []
VENUS_REWARD_MAP = {}
VENUS_RELEASE_GIRLS = set()
_VENUS_ID_LIKE_ITEMS = {35008, 25001}

def _venus_int(s, default=0):
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return default

_vb_panel_path = os.path.join(CSV_MASTER, "VenusBoard_Panel.csv")
if os.path.exists(_vb_panel_path):
    import csv as _vbcsv
    try:
        with open(_vb_panel_path, "r", encoding="utf-8-sig") as _vb_f:
            for _row in _vbcsv.reader(_vb_f):
                if len(_row) < 12 or not _row[0].strip().isdigit():
                    continue
                VENUS_PANEL_ROWS.append({
                    "panel_id": _venus_int(_row[0]),
                    "content_mid": _venus_int(_row[1]),
                    "girl_mid": _venus_int(_row[2], -1) if _row[2].strip() else -1,
                    "panel_type": _venus_int(_row[3]),
                    "cost_item": _venus_int(_row[6]),
                    "cost": _venus_int(_row[7]),
                    "gain": _venus_int(_row[10]),
                    "reward_group": _venus_int(_row[11]),
                })
        print(f"[*] 已加载维纳斯图板: {len(VENUS_PANEL_ROWS)} 条面板 (VenusBoard_Panel)")
    except Exception as _vb_ex:
        print(f"[!] 维纳斯面板加载失败: {_vb_ex}")

_vb_reward_path = os.path.join(CSV_MASTER, "VenusBoard_PanelReward.csv")
if os.path.exists(_vb_reward_path):
    import csv as _vbrcsv
    try:
        with open(_vb_reward_path, "r", encoding="utf-8-sig") as _vbr_f:
            for _row in _vbrcsv.reader(_vbr_f):
                if len(_row) < 4 or not _row[0].strip().isdigit():
                    continue
                _grp = _venus_int(_row[0])
                _gm = _venus_int(_row[1], -1) if _row[1].strip() else -1
                VENUS_REWARD_MAP.setdefault(_grp, []).append(
                    (_gm, _venus_int(_row[2]), _venus_int(_row[3])))
        print(f"[*] 已加载维纳斯图板: {len(VENUS_REWARD_MAP)} 组奖励 (VenusBoard_PanelReward)")
    except Exception as _vbr_ex:
        print(f"[!] 维纳斯奖励加载失败: {_vbr_ex}")

_vb_rel_path = os.path.join(CSV_MASTER, "VenusBoard_ReleaseGirls.csv")
if os.path.exists(_vb_rel_path):
    import csv as _vbrlcsv
    try:
        with open(_vb_rel_path, "r", encoding="utf-8-sig") as _vbrl_f:
            for _row in _vbrlcsv.reader(_vbrl_f):
                if len(_row) >= 3 and _row[1].strip().isdigit():
                    VENUS_RELEASE_GIRLS.add(_venus_int(_row[1]))
    except Exception:
        pass

# 2026-11-13: 亲爱度报酬表 (Girl_Affectionup_Reward.csv, 339 级全女孩共用)。
#   列: 1级号 2等级 3道具1 4数量1 5道具2序号 6数量2 7潜力 8剧情序号 9称号序号 10姿势 11语音
#   真服 POST /v1/affection_reward 响应 4 个字段(抓包 server_response_db 第2份):
#     affection_levelup_reward_list[]  每级一条, 弹窗"获得奖励"就渲染这个 ← 之前完全没返回 → 空白
#     girl_status_progress             四维 before/gain/after
#     affection_level_reward_list      accepted_level 推进
#     girl_list                        该女孩最新数据(只有 1 条)
#   序号列(5/8/9/10)不是道具ID, 要按女孩从 Girl_Affectionup_{Item,Cmu,Deg,Pose}_Table 里查真ID。
AFFECTION_REWARD_TABLE = {}      # 兼容旧调用: lv -> [(item_mid, count), ...]
AFFECTION_LEVEL_ROWS = {}        # lv -> {"item1","count1","item2","count2","pot","ep","deg","pose","voice"}
AFFECTION_EXTRA = {}             # girl_mid -> {"item":[..], "cmu":[..], "deg":[..], "pose":[..]}

def _aff_int(s):
    s = (s or "").strip()
    return int(s) if s.lstrip("-").isdigit() else 0

_ar_path = os.path.join(CSV_MASTER, "Girl_Affectionup_Reward.csv")
import csv as _arcsv
if os.path.exists(_ar_path):
    try:
        with open(_ar_path, "r", encoding="utf-8-sig") as _ar_f:
            for _row in _arcsv.reader(_ar_f):
                if len(_row) < 4 or not _row[1].strip().isdigit():
                    continue
                _row = _row + [""] * (11 - len(_row))
                _ar_lv = int(_row[1])
                _rw = {
                    "item1": _aff_int(_row[2]), "count1": _aff_int(_row[3]),
                    "item2": _aff_int(_row[4]), "count2": _aff_int(_row[5]),
                    "pot": _aff_int(_row[6]), "ep": _aff_int(_row[7]),
                    "deg": _aff_int(_row[8]), "pose": _aff_int(_row[9]),
                    "voice": _aff_int(_row[10]),
                }
                if not any(_rw.values()):
                    continue
                AFFECTION_LEVEL_ROWS[_ar_lv] = _rw
                _ar_prs = []
                if _rw["item1"] and _rw["count1"]:
                    _ar_prs.append((_rw["item1"], _rw["count1"]))
                if _rw["voice"]:
                    _ar_prs.append((_rw["voice"], 1))
                if _ar_prs:
                    AFFECTION_REWARD_TABLE[_ar_lv] = _ar_prs
    except Exception as _ar_ex:
        print(f"[!] Girl_Affectionup_Reward.csv 读取失败: {_ar_ex}")

# 女孩专属的序号→真ID 映射表 (首列均为 girl_mid, 其余列为该索引对应的真实ID)
for _tbl_key, _tbl_name in (("cmu", "Girl_Affectionup_Cmu_Table.csv"),
                            ("deg", "Girl_Affectionup_Deg_Table.csv"),
                            ("item", "Girl_Affectionup_Item_Table.csv"),
                            ("pose", "Girl_Affectionup_Pose_Table.csv")):
    _tbl_path = os.path.join(CSV_MASTER, _tbl_name)
    if not os.path.exists(_tbl_path):
        continue
    try:
        with open(_tbl_path, "r", encoding="utf-8-sig") as _tf:
            for _row in _arcsv.reader(_tf):
                if not _row or not _row[0].strip().isdigit():
                    continue
                _gm = int(_row[0])
                AFFECTION_EXTRA.setdefault(_gm, {})[_tbl_key] = [
                    _aff_int(x) for x in _row[1:]
                ]
    except Exception as _ar_ex2:
        print(f"[!] {_tbl_name} 读取失败: {_ar_ex2}")

def _aff_pick(girl_mid, kind, idx):
    """按序号取该女孩的真实ID (idx 从 1 开始, 0 表示无)"""
    if not idx:
        return 0
    arr = (AFFECTION_EXTRA.get(int(girl_mid)) or {}).get(kind) or []
    return arr[idx - 1] if 0 < idx <= len(arr) else 0

def affection_entry(girl_mid, level, rw=None):
    """构造 affection_levelup_reward_list 的一条 (字段名与真服抓包完全一致)

    说明: 剧情序号按 Girl_Affectionup_Cmu_Table 查真ID(已核对 EpisodeList 存在);
    称号序号(Deg_Table 的 984/1002…)在 Honor.csv(0~747) 里查不到对应记录,
    为避免客户端解析到不存在的称号而整条渲染失败, 这里置 0 不发放。
    没有任何可解析奖励的等级直接返回 None (不产生空行)。
    """
    rw = rw or AFFECTION_LEVEL_ROWS.get(level)
    if not rw:
        return None
    _ep = _aff_pick(girl_mid, "cmu", rw["ep"])
    _im2 = _aff_pick(girl_mid, "item", rw["item2"])
    _pose = _aff_pick(girl_mid, "pose", rw["pose"])
    if not any((rw["item1"], _im2, _ep, _pose, rw["voice"])):
        return None
    return {
        "content_mid": 1,
        "level": level,
        "girl_mid": int(girl_mid),
        "item_mid1": rw["item1"],
        "item_count1": rw["count1"] if rw["item1"] else 0,
        "item_mid2": _im2,
        "item_count2": rw["count2"] if _im2 else 0,
        "potential_mid": 0,
        "episode_mid": _ep,
        "honor_mid": 0,
        "pose_mid": _pose,
        "voice_mid": rw["voice"],
    }

def affection_entry_blank(girl_mid, level):
    """无奖励等级也占一行 (保证 levelup 最后一行 level == accepted_level)"""
    return {
        "content_mid": 1,
        "level": level,
        "girl_mid": int(girl_mid),
        "item_mid1": 0, "item_count1": 0,
        "item_mid2": 0, "item_count2": 0,
        "potential_mid": 0, "episode_mid": 0, "honor_mid": 0,
        "pose_mid": 0, "voice_mid": 0,
    }

# 2026-09-17: 回忆菜单 episode 全集 (EpisodeList.csv col1=episode_mid)
# 客户端 GET /v1/owner/episode 用 episode_list 判"解锁"(在列表=已解锁), count>=1 判"已读"(count=0亮"新").
# 原走静态快照只178条(私服抓的部分), 其余2530个在回忆菜单看不到. 改为动态返回全集 count=1(全已读).
EPISODE_MIDS = []
_ep_path = os.path.join(CSV_MASTER, "EpisodeList.csv")
if os.path.exists(_ep_path):
    import csv as _epcsv
    try:
        with open(_ep_path, "r", encoding="utf-8-sig") as _ep_f:
            for _row in _epcsv.reader(_ep_f):
                if len(_row) > 1:
                    try:
                        _em = int(_row[1])
                        if _em >= 1000000:
                            EPISODE_MIDS.append(_em)
                    except (ValueError, IndexError):
                        pass
        print(f"[*] 已加载 episode 全集: {len(EPISODE_MIDS)} 个 (EpisodeList.csv)")
    except Exception as _e:
        print(f"[!] EpisodeList.csv 加载失败: {_e}")

# ===== 2026-11-08: 场景解锁 + 姿势/表情解锁 的数据源 =====
# ① 场景: Item_Photospot_Table.csv = [item_mid, scene_no], 447 条, item 全部是 Consume_Parameter
#    type=7 的"场景解锁道具"。持有/使用这些道具即可解锁对应岛主房间场景。
#    本存档 type7 道具持有 0 件 → 场景全灰。
PHOTOSPOT_SCENE_MAP = {}      # item_mid -> scene_no
PHOTOSPOT_SCENE_IDS = set()   # 全部合法场景号 (取自 CSV, 都是游戏里真实存在的场景)
FRIENDLY_PHOTOSPOT_MAP = {}   # photo_spot_mid -> 解锁所需 friendly 等级 (CR_Friendly3Photospot)
_ps_path = os.path.join(CSV_MASTER, "Item_Photospot_Table.csv")
if os.path.exists(_ps_path):
    import csv as _pscsv
    try:
        with open(_ps_path, "r", encoding="utf-8-sig") as _ps_f:
            for _row in _pscsv.reader(_ps_f):
                if len(_row) >= 2 and _row[0]:
                    try:
                        _mid_ps, _sc_ps = int(_row[0]), int(_row[1])
                    except ValueError:
                        continue
                    PHOTOSPOT_SCENE_MAP[_mid_ps] = _sc_ps
                    PHOTOSPOT_SCENE_IDS.add(_sc_ps)
        print(f"[*] 已加载场景道具表: {len(PHOTOSPOT_SCENE_MAP)} 件道具 / "
              f"{len(PHOTOSPOT_SCENE_IDS)} 个场景 (Item_Photospot_Table)")
    except Exception as _e:
        print(f"[!] Item_Photospot_Table.csv 加载失败: {_e}")

# CR_Friendly3Photospot.csv = [所需 friendly 等级, photo_spot_mid]
#   实证: 外出(约会)界面的"地点"解锁判定 = 两个女孩组合的 friendly 等级 (用户截图: 上面写
#   "亲密等级达到后解锁")。真服样本 friendly value=11185 → level=21; 本表最高需要 level 120。
_fp_path = os.path.join(CSV_MASTER, "CR_Friendly3Photospot.csv")
if os.path.exists(_fp_path):
    import csv as _fpcsv
    try:
        with open(_fp_path, "r", encoding="utf-8-sig") as _fp_f:
            for _row in _fpcsv.reader(_fp_f):
                if len(_row) >= 2 and _row[0]:
                    try:
                        FRIENDLY_PHOTOSPOT_MAP[int(_row[1])] = int(_row[0])
                    except ValueError:
                        continue
        print(f"[*] 已加载外出地点解锁表: {len(FRIENDLY_PHOTOSPOT_MAP)} 个地点 "
              f"(最高需 friendly Lv{max(FRIENDLY_PHOTOSPOT_MAP.values())}) (CR_Friendly3Photospot)")
    except Exception as _e:
        print(f"[!] CR_Friendly3Photospot.csv 加载失败: {_e}")

# ② 姿势/表情: Equipment_Parameter type=37(姿势卡 1325 件) / type=81(表情卡 2416 件)。
#    实证: 真服 /v1/girl/private 的 private_item_list 里, 每个女孩只有基础 6 张
#    (50057/50066/50099/50100/50101/50102) + 活动送的零散几张 → 其余姿势/表情在菜单里是锁的。
POSE_ITEM_MIDS = []      # type37 姿势卡全集
EXPR_ITEM_MIDS = []      # type81 表情卡全集
for _mid_pe, _t_pe in EQUIP_TYPE_MAP.items():
    if _t_pe == 37:
        POSE_ITEM_MIDS.append(_mid_pe)
    elif _t_pe == 81:
        EXPR_ITEM_MIDS.append(_mid_pe)
POSE_ITEM_MIDS.sort()
EXPR_ITEM_MIDS.sort()
print(f"[*] 已加载姿势/表情卡: 姿势 {len(POSE_ITEM_MIDS)} 件, 表情 {len(EXPR_ITEM_MIDS)} 件")

# 2026-11-08 14:10 版(favorite 全量)已被用户实测否决:
#   ① 姿势/表情没解锁; ② 反而让所有卡显示"已星标", 取消后重启又复原。
#   → favorite 只负责星标(现走 STATE["pose_expr_favorite"], 真正的持久化在 POST 分支里)。
_FAV_POSE_EXPR_ENABLED = False   # 已废弃: 37/81 的 GET 现在只回真正标星的, 不再全量返回
_FAV_POSE_EXPR_GLOBAL = False
# 2026-11-08 14:20: 尝试过 GET /v1/special_order/37 → pose_card_item_list (客户端启动时逐类拉已购列表:
#   29=订单券, 37=姿势卡, 19=时间停止, 52=扇子, 86=SP订单)。返回 3741 条后用户实测仍未解锁。
#   怀疑: 混入 type81 让客户端整批丢弃, 或该列表只服务商店兑换界面。
#   现改为只发 type37(1325 条), 作为区分实验的一条支路。
_POSE_CARD_ORDER_ENABLED = True
_POSE_CARD_INCLUDE_EXPR = False
_POSE_CARD_TS = "2019-03-28 11:13:59"   # 固定时间戳: 在 normalize_dates 的 2700 天窗口外, 不会被改成"今天"
_POSE_TRACE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pose_trace.log")


def _pose_trace(girl_mid, fav_type, n):
    """即时落盘记录姿势/表情请求 (logutil 有 16KB 缓冲, print 在 bat 窗口里看不到)。"""
    try:
        with open(_POSE_TRACE_PATH, "a", encoding="utf-8") as _f:
            _f.write(f"{server_now_str()} girl={girl_mid or 'ALL'} type={fav_type} "
                     f"returned={n} enabled={_FAV_POSE_EXPR_ENABLED} global={_FAV_POSE_EXPR_GLOBAL}\n")
    except Exception:
        pass

# 扭卡消费映射: gacha_mid -> {"consume_item_mid": int, "price": int} (从 GachaStepup.csv, step=1 行)
# consume_item_mid=0 表示用 vstone 抽; 非0 表示用对应抽卡券(item_mid)抽
# 2026-09-13 阶段2: gacha/draw 扣费持久化的数据源
GACHA_STEPUP_MAP = {}     # gacha_mid -> {consume_item_mid, price, reward_table_id} (step=1 行, 扣费用)
GACHA_STEPUP_FULL = {}    # gacha_mid -> {step: {reward_table_id, consume_item_mid, price}} (全量 step 1-8, 阶梯天井)
_gsu_path = os.path.join(CSV_MASTER, "GachaStepup.csv")
if os.path.exists(_gsu_path):
    import csv as _gcsv
    with open(_gsu_path, "r", encoding="utf-8") as _gf:
        for _row in _gcsv.reader(_gf):
            if len(_row) < 12:
                continue
            try:
                _gm = int(_row[1]) if _row[1] else None
            except ValueError:
                _gm = None
            if _gm is None:
                continue
            try:
                _step = int(_row[2]) if _row[2] else 1
            except ValueError:
                _step = 1
            try:
                _consume = int(_row[8]) if _row[8] else 0
            except ValueError:
                _consume = 0
            try:
                _price = int(_row[11]) if _row[11] else 0
            except ValueError:
                _price = 0
            _rt_id = _row[3] if len(_row) > 3 else ""
            # 全量 step 数据 (阶梯天井: 不同 step 用不同 reward_table)
            _sf = GACHA_STEPUP_FULL.setdefault(_gm, {})
            _sf[_step] = {"reward_table_id": _rt_id, "consume_item_mid": _consume, "price": _price}
            # step=1 行存入 GACHA_STEPUP_MAP (扣费逻辑向后兼容)
            if _step == 1 and _gm not in GACHA_STEPUP_MAP:
                GACHA_STEPUP_MAP[_gm] = {"consume_item_mid": _consume, "price": _price,
                                         "reward_table_id": _rt_id}
    print(f"[*] 已加载扭卡消费映射: {len(GACHA_STEPUP_MAP)} 条 (step=1, GachaStepup)")
    _stepup_pools = sum(1 for v in GACHA_STEPUP_FULL.values() if len(v) > 1)
    print(f"[*] 已加载阶梯天井数据: {len(GACHA_STEPUP_FULL)} 卡池, 其中 {_stepup_pools} 个有多 step")

# 2026-09-14: 加载 Gacha.csv 卡池元数据 (type/currency/时间/配对)
# col0=gacha_mid, col1=type(1=基础/2=常驻/3=限定/4=VIP), col2=currency_group,
# col3=price(显示序号), col4=start_time, col5=end_time, col6=flag,
# col7=paired_mid_forward, col8=pairing_flag(3=单抽配对/6=十连配对/8=特殊), col9=paired_mid_backward
GACHA_INFO_MAP = {}  # gacha_mid -> {type, currency_group, start_time, end_time, pairing_flag, paired_gacha_mid}
_gacha_csv_path = os.path.join(CSV_MASTER, "Gacha.csv")
if os.path.exists(_gacha_csv_path):
    import csv as _gacha_csv
    with open(_gacha_csv_path, "r", encoding="utf-8") as _gf2:
        for _row in _gacha_csv.reader(_gf2):
            if len(_row) < 7:
                continue
            try:
                _gm = int(_row[0])
            except ValueError:
                continue
            _pair_flag = _row[8] if len(_row) > 8 else ""
            _paired = _row[7] if len(_row) > 7 and _row[7] else (_row[9] if len(_row) > 9 and _row[9] else "")
            try:
                _paired = int(_paired) if _paired else None
            except ValueError:
                _paired = None
            GACHA_INFO_MAP[_gm] = {
                "type": int(_row[1]) if _row[1] else 3,
                "currency_group": _row[2],
                "start_time": _row[4] if len(_row) > 4 else "",
                "end_time": _row[5] if len(_row) > 5 else "",
                "pairing_flag": _pair_flag,
                "paired_gacha_mid": _paired,
            }
    _type_dist = {}
    for _v in GACHA_INFO_MAP.values():
        _type_dist[_v["type"]] = _type_dist.get(_v["type"], 0) + 1
    print(f"[*] 已加载卡池元数据: {len(GACHA_INFO_MAP)} 卡池 (Gacha.csv), type分布: {_type_dist}")
else:
    print(f"[!] Gacha.csv 不存在, 卡池元数据未加载")

# 真随机奖池: reward_table=14 (常驻泳装, 从 GachaRewardItem.csv)
# 2026-09-13: draw 从此池按权重随机选 item_mid, 替代固定模板轮换
_GACHA_RANDOM_POOL = {"items": [], "weights": []}
_gri_path = os.path.join(CSV_MASTER, "GachaRewardItem.csv")
if os.path.exists(_gri_path):
    import csv as _gricsv
    with open(_gri_path, "r", encoding="utf-8") as _grif:
        for _row in _gricsv.reader(_grif):
            if len(_row) < 5 or _row[1] != "14" or not _row[2]:
                continue
            try:
                _im = int(_row[2])
            except ValueError:
                continue
            try:
                _w = int(_row[4])
            except ValueError:
                _w = 1
            _GACHA_RANDOM_POOL["items"].append(_im)
            _GACHA_RANDOM_POOL["weights"].append(max(_w, 1))
    print(f"[*] 已加载真随机奖池: {len(_GACHA_RANDOM_POOL['items'])} 个泳装 (reward_table=14)")

# 2026-09-13: 按卡池解析奖池 (不同 gacha_mid 用不同 reward_table, 含 SSR/SR/R 分类)
# GachaRewardItem: col0=id, col1=reward_table_id, col2=item_mid, col3=稀有度(9=SSR/1=R/10=SR), col5=引用
_GACHA_RI_MAP = {}  # reward_table_id -> [rows]
_gri2_path = os.path.join(CSV_MASTER, "GachaRewardItem.csv")
if os.path.exists(_gri2_path):
    import csv as _ri2csv
    with open(_gri2_path, "r", encoding="utf-8") as _ri2f:
        for _row in _ri2csv.reader(_ri2f):
            if len(_row) >= 5 and _row[1]:
                _GACHA_RI_MAP.setdefault(_row[1], []).append(_row)
    print(f"[*] 已加载扭蛋奖池数据: {len(_GACHA_RI_MAP)} 个 reward_table (GachaRewardItem)")

# ---- 扭蛋奖池缓存与解析 (方案C: 全权重控制 + 阶梯天井 + 保底) ----
_GACHA_POOL_CACHE = {}  # (gacha_mid, step) -> {"SSR": [(item_mid, weight)], "SR": [...], "R": [...]}
_RARITY_MAP = {"9": "SSR", "10": "SR", "1": "R"}
_RARITY_DEFAULT = {"SSR": 5, "SR": 15, "R": 80}  # 默认爆率 (gacha_config.json 可覆盖)

def _resolve_rt(rt_id, seen=None, parent_c3="", parent_weight=1):
    """递归解析 reward_table_id, 返回 [(item_mid, 稀有度, 有效权重)].
    有效权重 = 父级 tier 权重 × ... × 叶节点 col4 权重 (沿引用链累乘).
    parent_c3: 父级稀有度(9=SSR/1=R/10=SR), 子表item继承父级稀有度.
    parent_weight: 父级累计权重, 叶节点权重 = parent_weight × 本行col4."""
    if seen is None:
        seen = set()
    if rt_id in seen or len(seen) > 12:
        return []
    seen.add(rt_id)
    result = []
    for _r in _GACHA_RI_MAP.get(rt_id, []):
        _im = _r[2] if len(_r) > 2 else ""
        _c3 = _r[3] if len(_r) > 3 else ""
        _c4 = _r[4] if len(_r) > 4 else ""
        _c5 = _r[5] if len(_r) > 5 else ""
        # 稀有度继承: 父级有 SSR/SR 标记(9/10)时, 子表继承; 否则用本行 col3
        _eff_c3 = parent_c3 if parent_c3 in ("9", "10") else (_c3 if _c3 in ("9", "10", "1") else "1")
        # 解析本行权重 col4 (默认1)
        try:
            _w = int(_c4) if _c4 else 1
        except ValueError:
            _w = 1
        _w = max(_w, 1)
        _eff_w = parent_weight * _w
        if _im:
            try:
                result.append((int(_im), _eff_c3, _eff_w))
            except ValueError:
                pass
        elif _c5:
            result.extend(_resolve_rt(_c5, seen.copy(), _eff_c3, _eff_w))
    return result

# 2026-09-15: 全局稀有度物品池 — 从所有 reward_table 收集 SSR/SR/R 物品(去重)
# 用途: 卡池某稀有度池空时补充(如 reward_table 只有R物品), 让用户设的爆率(SSR=50等)能生效
# 否则 _random_gacha_items line 714 的 if pool[r] 会过滤空池 → SSR/SR权重被丢弃 → 全出R
_GACHA_GLOBAL_RARITY = {"SSR": [], "SR": [], "R": []}
_GGR_SEEN = {"SSR": set(), "SR": set(), "R": set()}  # 去重集合(O(1)查重, 替代原 any()线性扫 → O(n²)→O(n), 消除启动卡顿)
for _rt_id_g in list(_GACHA_RI_MAP.keys()):
    for _im_g, _c3_g, _w_g in _resolve_rt(_rt_id_g):
        _rar_g = _RARITY_MAP.get(_c3_g, "R")
        if _im_g not in _GGR_SEEN[_rar_g]:
            _GGR_SEEN[_rar_g].add(_im_g)
            _GACHA_GLOBAL_RARITY[_rar_g].append((_im_g, max(_w_g, 1)))
del _GGR_SEEN  # 建完即弃, 不占常驻内存
print(f"[*] 全局稀有度池: SSR={len(_GACHA_GLOBAL_RARITY['SSR'])} SR={len(_GACHA_GLOBAL_RARITY['SR'])} R={len(_GACHA_GLOBAL_RARITY['R'])}")

def _invalidate_gacha_pool_cache(gm=None):
    """GM 修改配置后清除奖池缓存 (gm=None 清除全部)"""
    if gm is None:
        _GACHA_POOL_CACHE.clear()
    else:
        _keys_to_del = [k for k in _GACHA_POOL_CACHE if k[0] == gm]
        for k in _keys_to_del:
            del _GACHA_POOL_CACHE[k]

def _gacha_info(gm):
    """获取卡池元数据 (type/currency/time/pairing), 来自 Gacha.csv"""
    return GACHA_INFO_MAP.get(gm, {})

def _gacha_type(gm):
    """获取卡池 type (1=基础/2=常驻/3=限定/4=VIP)"""
    return GACHA_INFO_MAP.get(gm, {}).get("type", 3)

def _gacha_is_active(gm):
    """检查卡池是否在有效时间范围内 — 单机版放宽: 服务器时间未必与档期数据对齐, 限定池(type=3)容易被判定过期, 故不限制卡池时间"""
    return True

def _gacha_paired(gm):
    """获取配对卡池 mid (十连配对), 无配对返回 None"""
    _info = GACHA_INFO_MAP.get(gm)
    if not _info:
        return None
    _pf = _info.get("pairing_flag", "")
    # pairing_flag=6 → 十连配对, =3 → 单抽配对
    if _pf in ("6", "3", "8"):
        return _info.get("paired_gacha_mid")
    return None

def _get_gacha_pool(gm, step=1):
    """获取 (gacha_mid, step) 卡池奖池(按稀有度分类+权重), lazy 解析+缓存.
    返回 {"SSR": [(item_mid, weight)], "SR": [...], "R": [...]}"""
    _ck = (gm, step)
    if _ck in _GACHA_POOL_CACHE:
        return _GACHA_POOL_CACHE[_ck]
    # 阶梯天井: 按 step 取对应 reward_table_id; 无该 step 则取 step=1
    _full = GACHA_STEPUP_FULL.get(gm)
    if _full:
        _step_cfg = _full.get(step) or _full.get(1) or {}
    else:
        _step_cfg = GACHA_STEPUP_MAP.get(gm, {})
    _rt_id = _step_cfg.get("reward_table_id", "") if _step_cfg else ""
    pool = {"SSR": [], "SR": [], "R": []}
    if _rt_id:
        for _im, _c3, _w in _resolve_rt(_rt_id):
            _rarity = _RARITY_MAP.get(_c3, "R")
            # 同稀有度内同 item 取最大权重 (多条路径引用同一 item)
            _found = False
            for _i, (_eim, _ew) in enumerate(pool[_rarity]):
                if _eim == _im:
                    if _w > _ew:
                        pool[_rarity][_i] = (_im, _w)
                    _found = True
                    break
            if not _found:
                pool[_rarity].append((_im, _w))
            # 2026-09-15: R池不污染 — SSR/SR不加入R池, R池只含R专属物品(抽R出R物品, 稀有度标签与物品一致)
    if sum(len(v) for v in pool.values()) == 0:
        pool["R"] = [(im, 1) for im in _GACHA_RANDOM_POOL["items"]]
    _GACHA_POOL_CACHE[_ck] = pool
    return pool

# ===== 2026-11-12 卡池分组：客户端按 banner 把多个 gacha_mid 叠成一个卡池 =====
# Gacha.csv 的 col3 是 UI banner 资源 ID(GachaPopAndTexture.csv 首列 pop_id)。
# 同一 pop_id 下的 mid 是同一卡池的不同抽法(单抽/十连/用券)，必须共用一份爆率与保底。
GACHA_GROUPS = {"groups": [], "mid_to_group": {}}
_GROUPS_PATH = os.path.join(TOOL, "gacha_groups.json")
try:
    if os.path.exists(_GROUPS_PATH):
        with open(_GROUPS_PATH, encoding="utf-8") as _ggf:
            GACHA_GROUPS = json.load(_ggf)
        print(f"[*] 卡池分组加载: {len(GACHA_GROUPS.get('groups', []))} 组, "
              f"可见 {GACHA_GROUPS.get('visible_group_count', 0)} 组")
except Exception as _gge:
    print(f"[gacha_groups] 加载失败: {_gge}")

# 组表缺失时从 Gacha.csv 现场兜底生成，保证任何部署都能按组工作
if not GACHA_GROUPS.get("mid_to_group"):
    import csv as _ggcsv
    _gg_path = os.path.join(CSV_MASTER, "Gacha.csv")
    _gg_pop = {}
    if os.path.exists(_gg_path):
        with open(_gg_path, "r", encoding="utf-8-sig") as _ggf2:
            for _gg_r in _ggcsv.reader(_ggf2):
                if len(_gg_r) > 3 and _gg_r[0].isdigit():
                    try:
                        _gg_pop[int(_gg_r[0])] = int(_gg_r[3])
                    except ValueError:
                        pass
    _gg_buckets = {}
    for _gg_m in sorted(_gg_pop):
        _gg_p = _gg_pop[_gg_m]
        _gg_id = ("p" + str(_gg_p)) if 0 < _gg_p <= 541 else ("m" + str(_gg_m))
        _gg_buckets.setdefault(_gg_id, []).append(_gg_m)
    GACHA_GROUPS = {
        "groups": [{"group_id": k, "mids": v, "has_banner": k.startswith("p"),
                    "tabs": ["limited"]} for k, v in _gg_buckets.items()],
        "mid_to_group": {str(m): k for k, v in _gg_buckets.items() for m in v},
    }
    print(f"[*] 卡池分组兜底生成: {len(GACHA_GROUPS['groups'])} 组")

GACHA_GROUP_OF = {int(k): v for k, v in GACHA_GROUPS.get("mid_to_group", {}).items()}
GACHA_GROUP_BY_ID = {g.get("group_id"): g for g in GACHA_GROUPS.get("groups", [])}


def _gacha_group_of(gm):
    """gacha_mid -> 卡池组 id；未分组返回 None。"""
    if gm is None:
        return None
    try:
        return GACHA_GROUP_OF.get(int(gm))
    except (TypeError, ValueError):
        return None


def _gacha_pity_key(gm):
    """保底计数按组累计：同一 banner 的不同抽法共享一份保底。"""
    gid = _gacha_group_of(gm)
    return ("g:" + gid) if gid else str(gm)


def _gacha_effective_pool(gm, step, pool):
    """补齐缺失稀有度：组内其它抽法 -> 全局稀有度池。
    纯 R 抽法原本会把 GM 设的 SSR/SR 权重整段丢掉，爆率控制看起来完全失效。"""
    out = {r: list(v) for r, v in pool.items()}
    gid = _gacha_group_of(gm)
    for rar in ("SSR", "SR", "R"):
        if out.get(rar):
            continue
        fill = []
        if gid:
            for m in GACHA_GROUP_BY_ID.get(gid, {}).get("mids", []):
                if m == gm:
                    continue
                other = _get_gacha_pool(m, step)
                if other.get(rar):
                    fill = list(other[rar])
                    break
        if not fill:
            fill = list(_GACHA_GLOBAL_RARITY.get(rar, []))
        if fill:
            out[rar] = fill
    return out


def _get_gacha_config(gm=None):
    """解析扭蛋配置. 优先级(低→高): 文件默认 → STATE全局 → 文件按卡池
    → STATE按卡池 → STATE按卡池组(最高，GM 按 banner 设的爆率要覆盖所有抽法)."""
    # 1. 全局: 文件默认 + STATE 全局 (STATE 覆盖文件)
    _cfg = dict(_GACHA_CONFIG_FILE.get("defaults", {}))
    _sc = STATE.get("gacha_config", {})
    _cfg.update(_sc.get("defaults", {}))
    # 2. 按卡池: 文件覆盖 + STATE 覆盖 (per-pool 始终优先于 global)
    if gm is not None:
        _cfg.update(_GACHA_CONFIG_FILE.get("pool_overrides", {}).get(str(gm), {}))
        _cfg.update(_sc.get("pool_overrides", {}).get(str(gm), {}))
        _gid = _gacha_group_of(gm)
        if _gid:
            _cfg.update(STATE.get("gacha_group_config", {}).get(_gid, {}))
    # 填充默认值
    _cfg.setdefault("rarity_weights", dict(_RARITY_DEFAULT))
    _cfg.setdefault("use_csv_rarity", False)
    _cfg.setdefault("hard_pity", 0)
    _cfg.setdefault("soft_pity_start", 0)
    _cfg.setdefault("soft_pity_increment", 6)
    _cfg.setdefault("enable_stepup", True)
    _cfg.setdefault("step_increment", 1)
    _cfg.setdefault("step_cap_behavior", "reset")
    _cfg.setdefault("max_step_bonus", "none")
    _cfg.setdefault("ssr_auto_lock", False)
    _cfg.setdefault("item_weights", {})
    _cfg.setdefault("use_group_fill", True)  # 纯 R 抽法是否补齐 SSR/SR（GM 爆率生效的前提）
    return _cfg

def _random_gacha_items(gm, count, step=1):
    """从 (gacha_mid, step) 卡池按配置爆率+保底逻辑随机选 count 个 item_mid.
    保底: 硬保底(N抽必出SSR) + 软保底(接近N抽SSR权重递增). per-pool 计数持久化到 STATE."""
    cfg = _get_gacha_config(gm)
    _raw_pool = _get_gacha_pool(gm, step)
    # GM 可关闭补齐，保留卡池原本的纯 R 行为
    pool = _gacha_effective_pool(gm, step, _raw_pool) if cfg.get("use_group_fill", True) else _raw_pool
    import random as _grand

    # 无奖池数据 → 回退常驻池
    if not any(pool[r] for r in ("SSR", "SR", "R")):
        _items = _GACHA_RANDOM_POOL["items"]
        _weights = _GACHA_RANDOM_POOL["weights"]
        return _grand.choices(_items, weights=_weights, k=count)

    # 保底状态 (per-pool)
    _pity = STATE.setdefault("gacha_pity", {})
    _pk = _gacha_pity_key(gm)
    # 兼容旧存档：按 mid 记的保底存在而组记录尚未建立时，平移到组 key
    if _pk not in _pity and str(gm) in _pity:
        _pity[_pk] = dict(_pity[str(gm)])
    _ps = _pity.get(_pk, {})
    _dss = _ps.get("draws_since_ssr", 0)

    # 稀有度权重
    _rw = cfg.get("rarity_weights", {})
    _use_csv = cfg.get("use_csv_rarity", False)

    result = []
    _drawn = set()  # 无放回: 同一次十连内已抽到的物品不重复
    for _ in range(count):
        # 1. 硬保底: 连续 N 抽未出 SSR, 强制 SSR
        _hp = cfg.get("hard_pity", 0)
        _force_ssr = _hp and _dss >= _hp

        if _force_ssr and pool["SSR"]:
            _rarity = "SSR"
        else:
            # 2. 计算稀有度权重
            if _use_csv:
                # 用 CSV 派生权重 (各稀有度权重之和)
                _rw_eff = {r: sum(w for _, w in pool[r]) for r in ("SSR", "SR", "R") if pool[r]}
            else:
                _rw_eff = {r: _rw.get(r, _RARITY_DEFAULT.get(r, 0)) for r in ("SSR", "SR", "R") if pool[r]}

            # 3. 软保底: 超过起点后 SSR 权重递增
            _sp_start = cfg.get("soft_pity_start", 0)
            _sp_incr = cfg.get("soft_pity_increment", 6)
            if _sp_start and _dss >= _sp_start and "SSR" in _rw_eff:
                _rw_eff["SSR"] += (_dss - _sp_start + 1) * _sp_incr

            _v_rar = [r for r in ("SSR", "SR", "R") if r in _rw_eff and _rw_eff[r] > 0]
            _v_w = [_rw_eff[r] for r in _v_rar]
            if not _v_rar:
                _rarity = "R"
            else:
                _rarity = _grand.choices(_v_rar, weights=_v_w, k=1)[0]

        # 4. 更新保底计数
        if _rarity == "SSR":
            _dss = 0
        else:
            _dss += 1

        # 5. 在稀有度内按物品权重选 (config 覆盖 > CSV 默认), 无放回避免重复
        _items_r = pool.get(_rarity, [])
        if not _items_r:
            # 该稀有度无物品 → 降级: R → SR → SSR → 常驻池
            for _fb in ("R", "SR", "SSR"):
                if pool.get(_fb):
                    _items_r = pool[_fb]
                    break
        if not _items_r:
            _items_r = [(im, 1) for im in _GACHA_RANDOM_POOL["items"]]
        if _items_r:
            _iw = cfg.get("item_weights", {})
            # 无放回: 排除本次十连已抽到的物品
            _avail = [(im, w) for im, w in _items_r if im not in _drawn]
            if not _avail:
                # 该稀有度物品已抽完 → 降级到 R 池(通常最大)找未抽过的
                for _fb_pool in ("R", "SR", "SSR"):
                    _fb = pool.get(_fb_pool, [])
                    _avail = [(im, w) for im, w in _fb if im not in _drawn]
                    if _avail:
                        _items_r = _avail
                        break
            if not _avail:
                _avail = _items_r  # 全部耗尽 → 允许重复
            _ws = [max(int(_iw.get(str(im), w)), 1) for im, w in _avail]
            _ims = [im for im, _ in _avail]
            _picked = _grand.choices(_ims, weights=_ws, k=1)[0]
            _drawn.add(_picked)
            result.append(_picked)

    # 持久化保底状态
    _ps["draws_since_ssr"] = _dss
    _ps["total_draws"] = _ps.get("total_draws", 0) + count
    # 阶梯步进
    _si = cfg.get("step_increment", 1)
    _cur_step = _ps.get("current_step", 1)
    _cur_step += _si
    _full = GACHA_STEPUP_FULL.get(gm, {})
    _max_step = max(_full.keys()) if _full else 1
    if _cur_step > _max_step:
        _cur_step = 1 if cfg.get("step_cap_behavior", "reset") == "reset" else _max_step
    _ps["current_step"] = _cur_step
    _pity[_pk] = _ps

    return result

# 货币类型 -> 钱包字段映射 (从真实 accept 响应还原)
# type=25 item 35023 -> zack_money; type=26 item 35013 -> guest_point; type=27 item 35021 -> free_vstone
# type=35 item 35008 为活动货币(TrendEventFes), 不在标准钱包, 仅标记为货币不入背包
WALLET_CURRENCY_TYPES = {25, 26, 27, 35}
WALLET_CURRENCY_MAP = {25: "zack_money", 26: "guest_point", 27: "free_vstone"}

# 真实 csv/list 的压缩体(6688B, zlib level1) — 用于完全复刻真实响应
REAL_CSVLIST_BIN = None
_real_path = os.path.join(TOOL, "real_csvlist.bin")
if os.path.exists(_real_path):
    with open(_real_path, "rb") as f:
        REAL_CSVLIST_BIN = f.read()
    print(f"[*] 已加载真实csv/list压缩体: {len(REAL_CSVLIST_BIN)}B")

# 真实业务响应映射
REAL_RESPONSES = {}
_resp_path = os.path.join(TOOL, "real_responses.json")
if os.path.exists(_resp_path):
    with open(_resp_path, encoding="utf-8") as f:
        REAL_RESPONSES = json.load(f)
    print(f"[*] 已加载真实业务响应: {len(REAL_RESPONSES)} 条")

# 关键: login_bonus 第1次请求必须返回 login_bonus_list (签到列表), 从私服版日志提取
LOGIN_BONUS_FIRST = {"login_bonus_list": []}
_lb_path = os.path.join(TOOL, "login_bonus_first.json")
if os.path.exists(_lb_path):
    with open(_lb_path, encoding="utf-8") as f:
        LOGIN_BONUS_FIRST = json.load(f)
    print(f"[*] 已加载 login_bonus 第1次响应: {len(LOGIN_BONUS_FIRST.get('login_bonus_list', []))} 条签到记录")

# 关键: login_bonus 第2次及之后返回空奖励结构 (私服版序列: 第1次=签到列表, 之后=空奖励)
# 否则游戏以为还有签到奖励要领 -> 反复请求 -> 白屏循环
LOGIN_BONUS_AFTER = {"login_bonus_reward_list": [], "shared_login_bonus_reward_list": [],
                     "expired_item_list": [], "compensation_create_girl_item_set": {"posecard_list": [], "photo_spot_list": []}}
_lba_path = os.path.join(TOOL, "login_bonus_after.json")
if os.path.exists(_lba_path):
    with open(_lba_path, encoding="utf-8") as f:
        LOGIN_BONUS_AFTER = json.load(f)
    print("[*] 已加载 login_bonus 第2次响应(空奖励结构)")
# 2026-09-05 尝试: 私服版9/5 POST login_bonus 返回真实发奖(5条奖励), 用于解决白屏
# v2: 用私服版完整响应(含item_consume_list背包+wallet_list钱包), 客户端才能认可奖励已发放
LOGIN_BONUS_REWARD = {}
for _rp in [os.path.join(TOOL, "login_bonus_reward_full.json"), os.path.join(TOOL, "login_bonus_reward.json")]:
    if os.path.exists(_rp):
        with open(_rp, encoding="utf-8") as f:
            LOGIN_BONUS_REWARD = json.load(f)
        break
if LOGIN_BONUS_REWARD:
    print(f"[*] 已加载 login_bonus 发奖响应: {len(LOGIN_BONUS_REWARD.get('login_bonus_reward_list', []))} 条奖励, "
          f"{len(LOGIN_BONUS_REWARD.get('item_consume_list', []))} 条背包物品, "
          f"{len(LOGIN_BONUS_REWARD.get('wallet_list', []))} 条钱包")

# 2026-09-05: 私服版 POST login_bonus/monthly 真实月度发奖 (login_monthly_reward + 物品进背包)
LOGIN_BONUS_MONTHLY_REWARD = {}
_monthly_path = os.path.join(TOOL, "login_bonus_monthly_reward.json")
if os.path.exists(_monthly_path):
    with open(_monthly_path, encoding="utf-8") as f:
        LOGIN_BONUS_MONTHLY_REWARD = json.load(f)
    print(f"[*] 已加载 login_bonus/monthly 发奖响应: {len(LOGIN_BONUS_MONTHLY_REWARD.get('login_monthly_reward', {}).get('login_bonus_list', []))} 条月度奖励")
LOGIN_BONUS_COUNT = 0  # 第几次 login_bonus 请求 (会话内)

# 2026-09-05 尝试: 私服版9/5 information/global 真实公告(140条), 用于解决公告卡住
INFORMATION_GLOBAL = {}
_info_path = os.path.join(TOOL, "information_global.json")
if os.path.exists(_info_path):
    with open(_info_path, encoding="utf-8") as f:
        INFORMATION_GLOBAL = json.load(f)
    print(f"[*] 已加载 information/global 公告: {len(INFORMATION_GLOBAL.get('information_list', []))} 条")

# ============ 动态响应数据库 (私服版全量抓取) ============
SERVER_DB = {"endpoints": {}, "quest_start_by_mid": {}, "main_girl_by_mid": {}, "gacha_draw_1": [], "gacha_draw_10": []}
_db_path2 = os.path.join(TOOL, "server_response_db.json")
if os.path.exists(_db_path2):
    with open(_db_path2, encoding="utf-8") as f:
        SERVER_DB = json.load(f)
    print(f"[*] 已加载动态响应数据库: {len(SERVER_DB.get('endpoints', {}))} 端点, "
          f"quest关卡 {len(SERVER_DB.get('quest_start_by_mid', {}))} 个, "
          f"女孩 {len(SERVER_DB.get('main_girl_by_mid', {}))} 个")

# 状态机游标
DYN_CURSOR = {}      # path -> 轮换游标
QUEST_START_IDX = {} # quest_mid -> quest/start 序列游标
QUEST_ROUND_IDX = {} # quest_mid -> volley/round 游标
QUEST_END_IDX = {}   # quest_mid -> quest/end 游标

# ---- 2026-09-10: 启动器资源清单 (api01 /v1/resource/list) ----
LOCAL_VERSION = 82300  # 单机版游戏/启动器当前版本 (启动器二进制含 82300, 服务器会话头亦为 82300)
RESOURCE_LIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resource_list_real.json")
RESOURCE_LIST_CACHE = None

def _decode_chunked(raw):
    """解码 HTTP/1.1 chunked 传输编码 (真实后端用 Transfer-Encoding: chunked)"""
    body = b""
    pos = 0
    while True:
        eol = raw.find(b"\r\n", pos)
        if eol < 0:
            break
        try:
            size = int(raw[pos:eol].split(b";")[0].strip(), 16)
        except Exception:
            break
        if size <= 0:
            break
        body += raw[eol + 2:eol + 2 + size]
        pos = eol + 2 + size + 2
    return body

def _fetch_real_resource_list():
    """从真实后端抓取 /v1/resource/list (绕过 hosts 直连), 缓存到本地文件"""
    import socket as _sock, ssl as _ssl
    for ip in ("54.178.128.246", "52.193.93.101"):
        try:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            raw = _sock.create_connection((ip, 443), timeout=10)
            ss = ctx.wrap_socket(raw, server_hostname="api01.doaxvv.com")
            ss.sendall(b"GET /v1/resource/list HTTP/1.1\r\nHost: api01.doaxvv.com\r\n"
                       b"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
            buf = b""
            while True:
                ch = ss.recv(65536)
                if not ch:
                    break
                buf += ch
            try:
                ss.close()
            except Exception:
                pass
            _, _, body = buf.partition(b"\r\n\r\n")
            head = buf.split(b"\r\n\r\n", 1)[0]
            if b"transfer-encoding: chunked" in head.lower():
                body = _decode_chunked(body)
            obj = json.loads(body)
            if "resource_list" in obj:
                with open(RESOURCE_LIST_FILE, "w", encoding="utf-8") as f:
                    json.dump(obj, f, ensure_ascii=False)
                log_write("[*] 已抓取真实资源清单 -> " + RESOURCE_LIST_FILE + "\n")
                return obj
        except Exception:
            continue
    return None

def _build_resource_list():
    """给启动器的资源清单: 真实清单过滤到 ≤LOCAL_VERSION (启动器判定已最新),
    exe 组版本改写为 LOCAL_VERSION (避免启动器自更新下载新 exe 破坏劫持环境)"""
    global RESOURCE_LIST_CACHE
    if RESOURCE_LIST_CACHE is None:
        obj = None
        if os.path.exists(RESOURCE_LIST_FILE):
            try:
                with open(RESOURCE_LIST_FILE, encoding="utf-8") as f:
                    obj = json.load(f)
            except Exception:
                obj = None
        if obj is None:
            obj = _fetch_real_resource_list()
        if obj is None:
            return None
        RESOURCE_LIST_CACHE = obj
    src = RESOURCE_LIST_CACHE.get("resource_list", {})
    out = {"resource_list": {}}
    for g in ("common", "high", "low"):
        out["resource_list"][g] = [e for e in src.get(g, [])
                                   if e.get("version", 0) <= LOCAL_VERSION]
    exe_src = src.get("exe", [])
    if exe_src:
        e = dict(exe_src[0])
        e["version"] = LOCAL_VERSION
        e["file_name"] = "APP00" + str(LOCAL_VERSION) + "000000_" + str(e.get("hash", "00000000"))[:8] + ".exe"
        out["resource_list"]["exe"] = [e]
    else:
        out["resource_list"]["exe"] = [{"version": LOCAL_VERSION, "directory": "",
                                        "file_name": "APP00" + str(LOCAL_VERSION) + "000000_00000000.exe",
                                        "file_size": 0, "hash": ""}]
    return out
LAST_DRAW_RESP = None

# ============ 服务器状态 (存档) ============
STATE_FILE = os.path.join(TOOL, "server_state.json")
STATE_LOCK = threading.RLock()  # P0: 请求级串行, 防 GM+游戏并发改 STATE (粗粒度, 单机低RPS下无性能代价; RLock可重入, _save_state 在持锁请求内调用不死锁)

def _load_state():
    st = {"main_girl_mid": 3, "girl_equipment": {},
          # 2026-09-05 扩展: 持久化 quest 进度 / 轮换游标 / 领取记录
          "quest_cursors": {},      # quest_mid -> {"start": idx, "end": idx}
          "dyn_cursors": {},        # path -> 轮换游标
          "claimed": {},            # 领取记录: "giftbox:<id>" -> ts 等
          "giftbox_claimed": [],    # 2026-09-07 复活版: 邮箱已领取邮件id
          "read_information": [],   # 2026-09-07 复活版: 公告已读
          "wallet": {},             # 2026-09-12: 钱包状态 (货币领取后追踪)
          "item_counts": {},        # 2026-09-12: 消耗品库存 (item_mid -> 总量, 领取后追踪)
          "custom_mails": [],       # 2026-09-13: GM 自定义邮件 (自定义发放物品)
          "equipment_inventory": [],  # 2026-09-13 阶段3: 抽卡获得的装备实例库 (动态, 叠加到 /v1/item/equipment/type/*)
          "gacha_draw_counts": {},  # 2026-09-13 阶段4: 抽卡进度 (gacha_mid -> 累计抽卡次数, 叠加到 gacha/list)
          "gacha_pity": {},        # 2026-09-14 方案C: 保底计数 (gacha_mid -> {draws_since_ssr, total_draws, current_step})
          "gacha_config": {},      # 2026-09-14 方案C: 运行时配置覆盖 (GM 修改, 优先级高于文件)
          "gacha_group_config": {},  # 2026-11-12: 按卡池组(banner)的爆率覆盖, 优先级最高
          "private_items": [],    # 2026-09-14: 私人套装物品列表 (girl_mid+item_mid, 抽卡获得)
          "checked_at": {            # 2026-09-14: 红点已读时间戳 (像私服版, 各功能查看时更新; 初始=私服版真实值)
              "owner_id": OWNER_ID, "news_checked_at": "2019-03-28 11:10:39",
              "quest_checked_at": "2019-03-28 11:10:39", "event_checked_at": "2019-03-28 11:10:39",
              "reward_notification_checked_at": "2019-03-28 11:10:39", "notification_checked_at": "2019-03-28 11:10:39",
              "giftbox_checked_at": "2019-03-28 11:10:39", "shared_giftbox_checked_at": "2026-09-12 14:25:24",
              "friendship_checked_at": "2026-09-03 11:09:57", "honor_checked_at": "2026-09-12 14:25:22",
              "mission_checked_at": "2026-09-09 14:27:19", "shared_login_bonus_checked_at": "2026-09-12 02:28:23",
              "subscription_checked_at": "2026-09-03 11:12:02", "lesson2onsen_exchanged_item_at": "2023-05-24 05:36:57",
              "comeback_login_bonus_expire_at": None, "compensation_create_girl_append_item_at": "2026-01-09 10:12:01",
              "created_at": "2019-03-28 11:10:39", "updated_at": "2026-09-12 14:25:24"},
          "casino_chip": {          # 2026-09-14: 赌场筹码 (像私服版, 初始私服版真实值7220/148; 赌场play时更新)
              "owner_id": OWNER_ID, "chip_normal": 7220, "chip_gold": 148,
              "limit_chip_gold": 148, "gold_chip_mid": 73, "dealer_chip_count": 0,
              "created_at": "2021-04-04 03:07:30", "updated_at": "2026-09-13 11:17:53"},
          "casino_game": [   # 2026-09-14: 赌场统计 (像私服版, 初始真实值; 赌场play时play_count++/win_count++)
              {"game": 2, "play_count": 176, "win_count_total": 73, "win_count_series": 0, "win_count_series_max": 7},
              {"game": 1, "play_count": 3, "win_count_total": 1, "win_count_series": 1, "win_count_series_max": 1}],
          # 2026-09-15: 温泉/送礼/岛主房间工作 动态持久化 (抓包私服版确认的端点+请求体)
          "onsen": {                       # 温泉: 槽位女孩/领奖计数/gauge/品质/女孩经验
              "slots": [{"slot_id": 0, "girl_mid": 15}, {"slot_id": 1, "girl_mid": 16},
                        {"slot_id": 2, "girl_mid": 4}, {"slot_id": 3, "girl_mid": 3}],
              "reward_count": 91, "gauge": 0, "quality_mid": 1, "girl_exp": {}},
          "room_request": {"current": None, "log": [], "girls": None},  # 岛主房间工作: 当前/历史/选中对象
          "friendly_value": [],             # 女孩间好感度 [{girl_mid,friendly_girl_mid,value,level,unlock_count}]
          "girl_exp": {},                  # 送礼/温泉累计的女孩经验 (girl_mid -> experience)
          "owner_room": {"owner_id": OWNER_ID, "main_girl_mid": 3, "sub_girl_mid": 15, "set_no": 0},
          "gacha_visible_pools": None}  # GM 控制可见卡池: None=全部显示, [gacha_mid,...]=只显示这些
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, encoding="utf-8") as f:
                loaded = json.load(f)
            # 兼容旧存档: 缺少的新字段用默认值
            for k, v in st.items():
                loaded.setdefault(k, v)
            st = loaded
    except Exception as e:
        print(f"[state] 加载失败: {e}")
    # 2026-11-11: 启动自愈 — 旧版本切换看板娘只改了 main_girl_mid、没同步 owner_room,
    # 且没有 ID 合法性校验, 坏存档会在加载后立刻把客户端带进白屏。这里对齐两者并拒绝非法 ID。
    if GIRL_MASTER_MAP and st.get("main_girl_mid") not in GIRL_MASTER_MAP:
        st["main_girl_mid"] = 3
    _or0 = st.get("owner_room")
    if isinstance(_or0, dict):
        _or0["main_girl_mid"] = st.get("main_girl_mid", 3)
        # 2026-11-11b: 副女孩同样校验, 并补齐缺失键 (历史脏存档可能残留非法 sub_girl_mid)
        if GIRL_MASTER_MAP and _or0.get("sub_girl_mid") not in GIRL_MASTER_MAP:
            _or0["sub_girl_mid"] = 15
        _or0.setdefault("owner_id", OWNER_ID)
        _or0.setdefault("sub_girl_mid", 15)
        _or0.setdefault("set_no", 0)
    return st

_STATE_DIRTY = False  # IO优化: 去抖标记, _save_state 只设dirty, 后台线程定时写盘

def _save_state():
    """标记 dirty, 后台线程定时写盘 (去抖: 44个调用点不再每次fsync 500KB, 大幅减少IO卡顿)"""
    global _STATE_DIRTY
    _STATE_DIRTY = True


# ===== 2026-11-07 背包修复④: 库存键类型统一 =====
# 内存里 item_counts 的键规范是 int (见 STATE 加载后的归一化);
# 但历史代码有几处直接把请求里的值写进去, 一旦是字符串
#   → 同一件东西出现 35066 和 "35066" 两条, 各记一半数量。
#   表现: 抽卡券/道具数量忽多忽少, 用完了还剩、或者明明有却判定不足。
# 统一: 一律 int 键, 并顺手清掉同 mid 的历史字符串键。
def ic_key(mid):
    try:
        return int(mid)
    except (TypeError, ValueError):
        return mid


def ic_get(mid, default=0):
    ic = STATE.get("item_counts") or {}
    k = ic_key(mid)
    for _k in (k, str(k)):
        if _k in ic:
            try:
                return int(ic[_k] or 0)
            except (TypeError, ValueError):
                return default
    return default


def ic_set(mid, val):
    ic = STATE.setdefault("item_counts", {})
    k = ic_key(mid)
    ic[k] = int(val)
    _dup = str(k)
    if _dup != k and _dup in ic:
        ic.pop(_dup, None)   # 清掉历史字符串键, 避免同一物品两份
    return ic[k]


def ic_add(mid, delta):
    return ic_set(mid, ic_get(mid) + int(delta))


def ic_take(mid, n, floor=0):
    """扣减库存并返回 (扣前, 扣后)。floor=0 时不会扣成负数。"""
    cur = ic_get(mid)
    new = max(floor, cur - int(n))
    ic_set(mid, new)
    return cur, new


def _flush_state():
    """实际写盘: 原子写(tmp+replace). 2026-09-18 IO优化: 持锁只做浅拷贝快照(微秒), 释放锁再写盘,
    避免8.7MB写盘期间阻塞请求线程(此前持锁写导致每2秒卡顿). 紧凑JSON(无indent)减小体积."""
    global _STATE_DIRTY
    if not _STATE_DIRTY:
        return
    tmp = STATE_FILE + ".tmp"
    try:
        # 持锁做浅拷贝(顶层dict引用复制,~微秒级), 立即释放锁. 顶层值多为不可变(int/str)或整体替换的
        # dict/list, 浅拷贝足够保证一致性; 写盘期间请求线程不被阻塞.
        with STATE_LOCK:
            _snap = dict(STATE)
            _STATE_DIRTY = False  # 快照时刻的dirty已处理; 期间新变更置dirty, 下次flush再写
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_snap, f, ensure_ascii=False, separators=(",", ":"))  # 紧凑(8.7MB→~5.4MB)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE_FILE)
    except Exception as e:
        print(f"[state] 保存失败: {e}")
        _STATE_DIRTY = True  # 写失败重置dirty, 下次flush重试(防丢数据)
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def _state_flush_loop():
    """后台守护线程: 每2秒检查dirty写盘 (daemon, 随主进程退出)"""
    while True:
        time.sleep(2)
        if _STATE_DIRTY:
            _flush_state()

import atexit as _atexit_state
_atexit_state.register(_flush_state)  # 正常退出最终写(防丢最后2秒)
threading.Thread(target=_state_flush_loop, daemon=True).start()

STATE = _load_state()

# 2026-11-12: GM 会话开关 (托盘「启动GM / 关闭GM」用)。
# 关闭 = 断开 GM 面板: 页面保留, 显示「GM 已关闭」并停止交互; 不关闭浏览器窗口
# (Chrome 单进程多标签, 关窗会连带用户自己的标签页一起关掉)。
# 仅内存态, 不写盘 —— 服务器重启后自动回到开启。
GM_SESSION = {"active": True}

# 2026-11-12: GM 专属「名称修正表」。
# 背景: 官方 item_mid / 卡池 banner 的真实名称映射表缺失或难找, 改为人工修正。
# 原则: 只写这张 GM 自己的 CSV, **绝不改动 csv_master 原始主数据**;
#       删掉该文件即完全还原, 对游戏内数据零影响 (纯展示层)。
# 文件: GM/gm_names.csv   列: kind,key,name,original,updated_at
#   kind=item  → key = item_mid
#   kind=group → key = 卡池组 id (如 p6)
GM_NAMES_FILE = os.path.join(TOOL, "GM", "gm_names.csv")
GM_NAMES_HEADER = ["kind", "key", "name", "original", "updated_at"]
_GM_NAMES_LOCK = threading.RLock()

def _gm_names_read():
    """读取名称修正表 → {"items": {mid: 名称}, "groups": {组id: 名称}, "types": {分类id: 名称}}。
    文件很小, 每次现读, 用户在 Excel 里手改后刷新页面即生效。"""
    items, groups, types = {}, {}, {}
    if not os.path.exists(GM_NAMES_FILE):
        return {"items": items, "groups": groups, "types": types}
    with _GM_NAMES_LOCK:
        try:
            with open(GM_NAMES_FILE, encoding="utf-8-sig", newline="") as f:
                for row in csv.DictReader(f):
                    kind = (row.get("kind") or "").strip().lower()
                    key = (row.get("key") or "").strip()
                    name = (row.get("name") or "").strip()
                    if not key or not name:
                        continue
                    if kind == "item":
                        items[key] = name
                    elif kind == "group":
                        groups[key] = name
                    elif kind == "type":
                        types[key] = name
        except Exception as e:
            print("[!] 读取 GM 名称修正表失败:", e)
    return {"items": items, "groups": groups, "types": types}

def _gm_names_write(kind, key, name, original=""):
    """写入/更新/删除一条修正 (name 为空 = 删除该条), 原子替换, 保留其它行。"""
    kind = (kind or "").strip().lower()
    key = (key or "").strip()
    if kind not in ("item", "group", "type") or not key:
        raise ValueError("kind 必须是 item/group/type, key 不能为空")
    name = (name or "").strip()
    with _GM_NAMES_LOCK:
        rows = []
        if os.path.exists(GM_NAMES_FILE):
            try:
                with open(GM_NAMES_FILE, encoding="utf-8-sig", newline="") as f:
                    rows = [r for r in csv.DictReader(f)]
            except Exception:
                rows = []
        rows = [r for r in rows
                if not ((r.get("kind") or "").strip().lower() == kind
                        and (r.get("key") or "").strip() == key)]
        if name:
            rows.append({"kind": kind, "key": key, "name": name[:60],
                         "original": (original or "").strip()[:60],
                         "updated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        rows.sort(key=lambda r: ((r.get("kind") or ""), (r.get("key") or "")))
        os.makedirs(os.path.dirname(GM_NAMES_FILE), exist_ok=True)
        tmp = GM_NAMES_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=GM_NAMES_HEADER, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow({k: r.get(k, "") for k in GM_NAMES_HEADER})
        os.replace(tmp, GM_NAMES_FILE)
    return _gm_names_read()

# 2026-11-08: 启动时清洗历史存档里的非法替补女孩 ID。
# 客户端用 65535/0xffff 表示"无替补", 旧版曾把它原样存进 quest_team 并回显,
# 客户端按该 ID 查女孩对象返回 null → DOAX_VV.exe+0x240dd1b 空指针崩溃。
# 合法女孩 ID 是 2..33, 真服"无替补"用 -1。
_qt_boot = STATE.get("quest_team")
if isinstance(_qt_boot, dict):
    try:
        _sub_boot = int(_qt_boot.get("girl_mid_substitute", -1))
    except (TypeError, ValueError):
        _sub_boot = -1
    if not (2 <= _sub_boot <= 33) and _sub_boot != -1:
        _qt_boot["girl_mid_substitute"] = -1

# 2026-09-13: 归一化 item_counts key 为整数 (JSON 加载后 key 变字符串, 导致 int 查找失败)
_ic_raw = STATE.get("item_counts", {})
if _ic_raw:
    STATE["item_counts"] = {int(k): v for k, v in _ic_raw.items()}

# 2026-11-12: 邮箱自愈 —— 未领取的自定义邮件若被错误标记为已领取, 启动时解除。
# 根因(GM 邮件发出后游戏邮箱看不到): 旧版 id 用 900000001+len(custom_mails) 分配,
# 领取过的旧 id 残留在 giftbox_claimed 里, 新邮件复用同一 id -> 一发出就被当"已领"过滤。
# 新分配逻辑已改成永不复用, 这里再兜底修掉历史脏数据。
try:
    _cm_boot = STATE.get("custom_mails") or []
    _cl_boot = STATE.get("giftbox_claimed")
    if _cm_boot and isinstance(_cl_boot, list):
        _pending_ids = {int(m.get("id")) for m in _cm_boot
                        if isinstance(m, dict) and isinstance(m.get("id"), int)
                        and not m.get("accepted_at")}
        if _pending_ids:
            _before_n = len(_cl_boot)
            STATE["giftbox_claimed"] = [c for c in _cl_boot if c not in _pending_ids]
            _healed_n = _before_n - len(STATE["giftbox_claimed"])
            if _healed_n:
                _save_state()
                print(f"[*] 邮箱自愈: 解除 {_healed_n} 条未领自定义邮件的错误已领取标记")
except Exception as _e_heal:
    print("[!] 邮箱自愈跳过:", _e_heal)

# 2026-09-12: 从 SERVER_DB 初始化 wallet 和 item_counts (首次启动时)
_eps_init = SERVER_DB.get("endpoints", {})
if not STATE.get("wallet"):
    _wl_init = _eps_init.get("/v1/wallet", [])
    if _wl_init:
        _w = _wl_init[0].get("wallet", {})
        STATE["wallet"] = dict(_w) if isinstance(_w, dict) else {}
    else:
        STATE["wallet"] = {}
    _save_state()
    print(f"[*] 钱包初始化: {STATE['wallet']}")
if not STATE.get("item_counts"):
    _ic_init = _eps_init.get("/v1/item/consume", [])
    if _ic_init:
        _icl = _ic_init[0].get("item_consume_list", [])
        STATE["item_counts"] = {
            item.get("item_mid"): item.get("count", 0)
            for item in _icl if item.get("item_mid") is not None
        }
    else:
        STATE["item_counts"] = {}
    _save_state()
    print(f"[*] 消耗品库存初始化: {len(STATE['item_counts'])} 条")

# 2026-09-14: 装备库存播种 — 从 REAL_RESPONSES 一次性导入为初始库存, 之后 STATE 是唯一数据源
_ALL_GIRL_MIDS = [2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,26,27,28,29,30,31,32,33]
_inv_seed = STATE.setdefault("equipment_inventory", [])
_seed_added = 0
# 从 REAL_RESPONSES 的所有 equipment/type/* 端点导入装备实例
for _p_seed, _r_seed in REAL_RESPONSES.items():
    if "/item/equipment/type/" not in _p_seed or not isinstance(_r_seed, dict):
        continue
    for _e_seed in _r_seed.get("item_equipment_list", []):
        if isinstance(_e_seed, dict) and _e_seed.get("item_mid"):
            # 去重: 同 item_mid 的实例只保留一份 (避免重复播种)
            _already = any(_e2.get("item_mid") == _e_seed.get("item_mid") for _e2 in _inv_seed)
            if not _already:
                _inv_seed.append(dict(_e_seed))
                _seed_added += 1
# 从 REAL_RESPONSES 的 private_item_list 播种私人套装
_spi_seed = STATE.setdefault("private_items", [])
# 清除旧的 girl_mid=0 记录
_spi_seed[:] = [p for p in _spi_seed if p.get("girl_mid", 0) != 0]
_spi_keys_seed = {(p.get("girl_mid", 0), p.get("item_mid", 0)) for p in _spi_seed}
# 导入 REAL_RESPONSES 的 private_item_list
_ge_seed = REAL_RESPONSES.get("/v1/girl/private", {})
if isinstance(_ge_seed, dict):
    for _pi_seed in _ge_seed.get("private_item_list", []):
        _k_seed = (_pi_seed.get("girl_mid", 0), _pi_seed.get("item_mid", 0))
        if _k_seed not in _spi_keys_seed:
            _spi_seed.append(dict(_pi_seed))
            _spi_keys_seed.add(_k_seed)
            _seed_added += 1
# 同时把 equipment_inventory 中的物品也加入 private_items (为所有女孩)
# 2026-09-14 修复: type 11 (发型) 是女孩专属, 不能加给全部女孩!
#   铁证 real_responses /v1/girl/private: girl3 只有 366/367, 370 属于 girl4, 388 属于 girl8, 554 属于 girl13
#   旧逻辑把 type/11 库存的发型加给全部女孩 → 穗香"拥有"其他女孩发型 → 装备时模型不匹配 → 闪退
for _e_bf in _inv_seed:
    if isinstance(_e_bf, dict):
        _im_bf = _e_bf.get("item_mid", 0)
        if _im_bf:
            _et_bf = EQUIP_TYPE_MAP.get(_im_bf, 1)
            continue  # 09-25: 全部跳过 cross-扩充 — inventory 是拥有源(/type/{N} serve + equip 一律放行不校验归属), 不再灌 private_items; 否则全量装备(22891)×28≈64万条撑爆 /v1/girl/private. private_items 保留旧 151519 条不动.
            for _agm_bf in _ALL_GIRL_MIDS:
                _k_bf = (_agm_bf, _im_bf)
                if _k_bf not in _spi_keys_seed:
                    _spi_seed.append({"girl_mid": _agm_bf, "item_mid": _im_bf})
                    _spi_keys_seed.add(_k_bf)
                    _seed_added += 1
if _seed_added:
    _save_state()
    print(f"[*] 装备库存播种: +{_seed_added} (总计装备 {len(_inv_seed)} 件, 私人套装 {len(_spi_seed)} 条)")


# ===== 2026-11-07 商店/背包修复 ①a: 装备被误记进消耗品库存 → 衣橱里永远看不到 =====
# 实证: STATE.item_counts 里躺着 58 条装备类物品 (泳装22/姿势卡24/其它12),
#       而 /v1/item/equipment/type/* 只读 equipment_inventory → 客户端查不到 → "买了不进背包/衣橱"。
# 处理: 装备类 (0/1/11/22/23/24/56/82, 与商店 exchange 的判定保持一致) 迁出 item_counts,
#       按缺少的份数补进 equipment_inventory; 其余类型(姿势卡37/封69等)保留为消耗品。
# 幂等: 迁移后 item_counts 不再有这些 key, 下次启动自然跳过。
def _migrate_equip_from_item_counts():
    _ic = STATE.get("item_counts", {})
    _inv = STATE.setdefault("equipment_inventory", [])
    # 2026-11-07 修复②: 原白名单只有 (0,1,11,22,23,24,56,82), 漏了 19/37/52/69
    #   → 姿势卡(37)/饰品(52)/封印(69)/19 类物品同时留在 item_counts 和 equipment_inventory,
    #     客户端背包里数量翻倍、衣橱里也有一份 → "背包物品数量不对"。
    #   依据: Consume_Parameter 与 Equipment_Parameter 的 item_mid 完全不相交(实测 0 重叠),
    #         所以只要在装备表里, 就一定属于衣橱实例, 不进消耗品库存。
    # 2026-11-08 追加 67(家具): 商店里 690 个家具商品(type67), 旧白名单漏掉它 →
    #   买家具只写 item_counts, 永远进不了 equipment_inventory → /v1/furniture/ 看不到 →
    #   岛主房间"道具没解锁"。这条同时把历史误记在 item_counts 的家具迁回衣橱。
    _epts = (0, 1, 11, 19, 22, 23, 24, 37, 52, 56, 67, 69, 82)
    _moved = _kinds = 0
    _base = (int(datetime.datetime.now().timestamp() * 1000) % 1000000000) + 4510000000
    for _k in list(_ic.keys()):
        try:
            _mid = int(_k)
        except (TypeError, ValueError):
            continue
        _et = EQUIP_TYPE_MAP.get(_mid)
        if _et is None or _et not in _epts:
            continue
        _cnt = int(_ic.get(_k, 0) or 0)
        _have = sum(1 for _e in _inv if isinstance(_e, dict) and _e.get("item_mid") == _mid)
        _add = min(max(_cnt - _have, 0), max(0, 3 - _have))   # 每件最多补到 3 个实例, 防止无限膨胀
        for _i in range(_add):
            _inv.append({"id": _base + _moved, "item_mid": _mid, "type": _et, "level": 1,
                         "experience": 0, "girl_mid": 0, "favorite": 0, "in_lock": 1,
                         "unlock_count": 0, "upgrade_count": 0, "combine_count": 0})
            _moved += 1
        _ic.pop(_k, None)   # 装备不属于消耗品库存, 无论补没补都要移出
        _kinds += 1
    if _kinds:
        _save_state()
        print(f"[*] 修复①a: {_kinds} 种装备从消耗品库存迁出, 补入衣橱 {_moved} 件"
              f" (衣橱现有 {len(_inv)} 件)")
_migrate_equip_from_item_counts()


# ===== 2026-11-07 背包修复②: 衣橱实例 id 去重 =====
# 背景: GM 批量播种装备时写入了重复的实例 id —— 实测 22898 件里有 38 件共用 7 个 id。
#   客户端用 id 作装备主键, 同 id 的多件会被当成同一件 → 换装换错、强化加到别件、
#   分解/锁定互相串台。表现为"物品点了没反应/效果不对"。
# 做法: 每个撞号组保留一件(优先保留"被女孩穿着"的那件)的原 id, 其余重新编号。
# 幂等: 只有检测到撞号才写盘。
def _dedupe_equipment_ids():
    _inv = [e for e in STATE.get("equipment_inventory", []) if isinstance(e, dict)]
    if not _inv:
        return
    _worn = set()
    for _g in (STATE.get("girl_equipment") or {}).values():
        if isinstance(_g, dict):
            for _v in _g.values():
                if isinstance(_v, int) and _v > 1000:
                    _worn.add(_v)
    _groups = {}
    for _e in _inv:
        _groups.setdefault(_e.get("id"), []).append(_e)
    _used = {e.get("id") for e in _inv}
    _maxid = max((e.get("id") or 0) for e in _inv)
    _renum = 0
    _dupgrp = 0
    for _iid, _g in _groups.items():
        if len(_g) < 2:
            continue
        _dupgrp += 1
        _keep = next((c for c in _g if c.get("item_mid") in _worn), _g[0])
        for _c in _g:
            if _c is _keep:
                continue
            _maxid += 1
            while _maxid in _used:
                _maxid += 1
            _c["id"] = _maxid
            _used.add(_maxid)
            _renum += 1
    if _renum:
        _save_state()
        print(f"[*] 修复②: 衣橱实例 id 去重 — {_dupgrp} 个撞号组, 重新编号 {_renum} 件")


_dedupe_equipment_ids()


# ===== 2026-11-08: 清除非装备类"幽灵装备" (姿势卡误标成泳装) =====
# 现象: 衣橱 22902 件里有 25 件 item_mid 在 Equipment_Parameter 中根本不存在
#       (35012/35201/35222/35226/35266/35290/35294/35557/37275/37277/38342/38344/
#        38526/38528/39063/39065/39495/39878/39880/39909/39911/40056/40592/40594/35290)
#       它们只出现在 Consume_Parameter / Item_Photospot_Table / PosecardShop* → 是姿势卡(消耗品),
#       被历史迁移误标 type=1 当泳装塞进衣橱。客户端按泳装加载模型必然失败 → 佩戴后闪退.
# 做法: 一次性剔除 item_mid 不在 Equipment_Parameter (EQUIP_TYPE_MAP) 里的实例.
# 幂等: STATE.phantom_equip_pruned_v1.
def _prune_phantom_equipment():
    if STATE.get("phantom_equip_pruned_v1"):
        return
    _inv = STATE.get("equipment_inventory") or []
    _keep, _drop = [], []
    for _e in _inv:
        if not isinstance(_e, dict):
            _keep.append(_e)
            continue
        if _e.get("item_mid") in EQUIP_TYPE_MAP:
            _keep.append(_e)
        else:
            _drop.append(_e)
    if _drop:
        STATE["equipment_inventory"] = _keep
        print(f"[*] 清理幽灵装备: 剔除 {len(_drop)} 件非装备类条目 "
              f"(mid={[d.get('item_mid') for d in _drop][:30]})")
        _save_state()
    STATE["phantom_equip_pruned_v1"] = True
    _save_state()


_prune_phantom_equipment()


# ===== 2026-11-08: 衣橱库存归一 (同款超量截断 + 家具主数据补齐) =====
# 现象①: 泳装 5873 件里有 94 个 item_mid 重复, 同款最多 13 件 —— 历史 GM 全量播种重复 append 的产物。
#   购买逻辑(_process_shop_exchange)本身就限"同款最多 3 件", 库存里的超量只会让衣橱出现成排同款,
#   既拖慢衣柜列表渲染, 又让"是否已拥有"的判定混乱。截断到 3 件, 优先保留被锁定/收藏的那件。
# 现象②: 家具(type 67)主数据 656 种, 库存只有 655 → 缺 45220(播种漏项), 家具图鉴/摆放里少一件。
#   按主数据补齐, 保持"该有的都有"。
# 幂等: STATE.equip_inventory_normalized_v1
KEEP_PER_ITEM = 3


def _normalize_equipment_inventory():
    if STATE.get("equip_inventory_normalized_v1"):
        return
    _inv = [e for e in (STATE.get("equipment_inventory") or []) if isinstance(e, dict)]
    if not _inv:
        STATE["equip_inventory_normalized_v1"] = True
        _save_state()
        return

    # ① 同 (type, item_mid) 超过 KEEP_PER_ITEM 件 → 截断
    _groups = {}
    for _e in _inv:
        _groups.setdefault((_e.get("type"), _e.get("item_mid")), []).append(_e)
    _keep, _drop_n = [], 0
    for _k, _g in _groups.items():
        if len(_g) <= KEEP_PER_ITEM:
            _keep.extend(_g)
            continue
        # 排序: 锁定/收藏优先保留, 其次 id 小的
        _g2 = sorted(_g, key=lambda x: (0 if (x.get("in_lock") or x.get("favorite")) else 1,
                                        x.get("id") or 0))
        _keep.extend(_g2[:KEEP_PER_ITEM])
        _drop_n += len(_g2) - KEEP_PER_ITEM

    # ② 家具(type 67)按主数据补齐缺失 item_mid
    _have67 = {e.get("item_mid") for e in _keep if e.get("type") == 67}
    _miss67 = sorted(m for m, t in EQUIP_TYPE_MAP.items() if t == 67 and m not in _have67)
    _maxid = max((e.get("id") or 0) for e in _keep) if _keep else 0
    _used = {e.get("id") for e in _keep}
    for _mid in _miss67:
        _maxid += 1
        while _maxid in _used:
            _maxid += 1
        _used.add(_maxid)
        _keep.append({"id": _maxid, "item_mid": _mid, "type": 67, "level": 1, "experience": 0,
                      "girl_mid": 0, "favorite": 0, "in_lock": 0, "unlock_count": 0,
                      "upgrade_count": 0, "combine_count": 0})

    if _drop_n or _miss67:
        STATE["equipment_inventory"] = _keep
        print(f"[*] 库存归一: 截断同款超量 {_drop_n} 件, 补家具 {_miss67}, 现 {len(_keep)} 件")
        _save_state()
    STATE["equip_inventory_normalized_v1"] = True
    _save_state()


_normalize_equipment_inventory()


# ===== 2026-11-08: 场景全解锁 + 所有女孩姿势/表情全解锁 =====
# 用户诉求: 岛主房间的"场景"全部解锁; 每个女孩都拥有全部"姿势"和"表情"。
#
# 【场景】
#   数据源 Item_Photospot_Table.csv (447 条 = item_mid → scene_no), item 全部是 Consume_Parameter
#   type=7 的"场景解锁道具"。本存档 type7 持有 0 件 → 岛主房间的场景列表几乎全灰。
#   做法: 把这 447 件道具一次性放进 item_counts(count=1, 只补缺失的), 客户端道具列表里就有;
#         同时 /v1/photospot 动态返回"全女孩 × 全场景"(见 _apply_state_overlay 顶部), 双保险。
#   场景号全集 = CSV 里的 16 个 scene_no ∪ 抓包快照里出现过的 photo_spot_mid(1,2,3,4,5,7,9,13)。
#   ⚠ 只使用"数据里真实出现过的 id": 客户端会拿 photo_spot_mid 去索引场景资源,
#     凭空造的 id 会像 variation=74 那样越界崩进程(2026-11-08 已验证过一次)。
#     若某天客户端更新后列表对不上, 只需要改 PHOTOSPOT_EXTRA_IDS 这一个常量。
#
# 【姿势 / 表情】
#   Equipment_Parameter 里 type=37 = 姿势卡 1325 件, type=81 = 表情卡 2416 件。
#   实证: 真服 /v1/girl/private 的 private_item_list 中, 每个女孩只有基础 6 张
#   (50057 / 50066 / 50099 / 50100 / 50101 / 50102) + 活动零散几张, 且**不同女孩的额外卡不同**
#   (girl4 有 50065/50093, girl11 有 50055/50165, girl13 有 50045/50051) → 姿势卡是"每女孩独立解锁"的。
#   客户端拍照(岛主房间)的姿势/表情菜单读的就是 private_item_list 里 type37/81 的条目。
#   做法: 给 32 个女孩补齐全部 type37 + type81 (32 × 3741 = 119576 条)。
#   体积影响: private_items 150934 → 270510 条; /v1/girl/private 响应 ~6MB → ~9.4MB。
#     与现有"全泳装发放"(144338 条 type1)同一量级, 客户端已能处理。
#   幂等: STATE.scene_pose_unlocked_v1 (要重跑就删掉这个键)。
#
# 【回退方法 (若姿势/表情导致卡顿或闪退)】
#   把下面的 _POSE_EXPR_UNLOCK_ENABLED 改成 False, 再执行一次:
#     python -c "import json;d=json.load(open('server_state.json',encoding='utf-8'));\
#       n=d['scene_pose_unlocked_v1']['base_private_items'];d['private_items']=d['private_items'][:n];\
#       d.pop('scene_pose_unlocked_v1',None);json.dump(d,open('server_state.json','w',encoding='utf-8'),ensure_ascii=False)"
#   (新增条目全部 append 在尾部, 截断到 base_private_items 即可完全还原; 场景解锁不受影响)
SCENE_POSE_FLAG = "scene_pose_unlocked_v1"
_POSE_EXPR_UNLOCK_ENABLED = False  # 姿势/表情全解锁开关 (场景解锁与之独立)
#   【2026-11-08 13:40 关闭 — 实证客户端内存崩溃】开启后 private_items 150934→270510 条,
#   /v1/girl/private 响应 9.38MB, 游戏启动直接弹 "Memory allocation (new) failed" 进不去。
#   客户端对 private_item_list 的解析内存是按条目数线性涨的, 27 万条直接 OOM。
#   除非找到"客户端能消化"的瘦身格式(比如只发 type37/81 而不发泳装), 否则别再开。
# 抓包快照(real_responses /v1/photospot)里出现过的 photo_spot_mid, 属于"回忆景点"编号体系。
PHOTOSPOT_EXTRA_IDS = (1, 2, 3, 4, 5, 7, 9, 13)


def _photospot_all_ids():
    """所有合法的 photo_spot_mid (外出地点), 升序。
    来源: CR_Friendly3Photospot 的地点 id (客户端真实地点) ∪ 抓包快照里出现过的 id。
    ⚠ Item_Photospot_Table 的 scene_no 是"场景道具"的归属编号, 与外出地点不是同一体系,
      2026-11-08 13:35 版曾把两者混进 photo_spot_list (22 个 id), 用户实测地点判定仍全锁
      且属"凭空造 id"风险源 —— 已改为只用本函数的 9 个有据可查的地点。"""
    return sorted(set(FRIENDLY_PHOTOSPOT_MAP) | set(PHOTOSPOT_EXTRA_IDS))


def _unlock_all_scenes_and_poses():
    if STATE.get(SCENE_POSE_FLAG):
        return
    # ---- ① 场景解锁道具: 447 件 type7 全部按 count=1 进背包 ----
    _ic = STATE.setdefault("item_counts", {})
    _add_item = 0
    for _mid in PHOTOSPOT_SCENE_MAP:
        try:
            _cur = int(_ic.get(str(_mid), _ic.get(_mid, 0)) or 0)
        except (TypeError, ValueError):
            _cur = 0
        if _cur <= 0:
            _ic[str(_mid)] = 1
            _add_item += 1
    # ---- ② 姿势/表情: 每个女孩补齐 type37 + type81 全集 ----
    _pi = STATE.setdefault("private_items", [])
    _base_len = len(_pi)          # 原有条目数: 回退时截断到此处即可 (新增条目一律 append 在尾部)
    _add_pi = 0
    _all_mids = POSE_ITEM_MIDS + EXPR_ITEM_MIDS   # 提到 if 外: 下方 print 无条件引用(避免 NameError)
    if _POSE_EXPR_UNLOCK_ENABLED:
        _have = set()
        for _p in _pi:
            if isinstance(_p, dict):
                try:
                    _have.add((int(_p.get("girl_mid")), int(_p.get("item_mid"))))
                except (TypeError, ValueError):
                    continue
        _all_mids = POSE_ITEM_MIDS + EXPR_ITEM_MIDS
        for _g in sorted(GIRL_MASTER_MAP):
            for _mid in _all_mids:
                if (_g, _mid) in _have:
                    continue
                _pi.append({"girl_mid": _g, "item_mid": _mid})
                _have.add((_g, _mid))
                _add_pi += 1
    STATE[SCENE_POSE_FLAG] = {"base_private_items": _base_len,
                              "added_items": _add_item, "added_private": _add_pi}
    _save_state()
    print(f"[*] 场景/姿势解锁: 补场景道具 {_add_item} 件 (共 {len(PHOTOSPOT_SCENE_MAP)}), "
          f"补姿势/表情 {_add_pi} 条 (每女孩 {len(_all_mids)} 张 × {len(GIRL_MASTER_MAP)} 人), "
          f"private_items 现 {len(_pi)} 条")


_unlock_all_scenes_and_poses()


# ===== 2026-11-08 14:48: 姿势卡/表情卡 —— 按"归属女孩"分类发放 =====
# 【用户实测推翻的做法】上一版把 type37/81 的全部 3741 张都塞给 girl 3 → 客户端显示成功(证明
#   private_item_list 就是解锁源), 但 girl 3 的菜单里出现了别的角色的姿势。用户原话:
#   "这些姿势都是属于不同的女孩的, 你把所有女孩的姿势都加给了这一个女孩"。
# 【归属从哪来 —— 硬证据】
#   ① 日志(full_server.log 14:37:21 起): 客户端兑换姿势卡时发
#        {"girl_mid":18,..,24, "item_mid_list":[56401,..,56407], "order_item_type":37}
#      → 同一款卡的各女孩版本在 item_mid 上连续: girl 18→56401 … girl 24→56407。
#   ② 表情侧交叉验证: girl 5 的 56073 与 girl 23 的 56091 相差 18, 正好等于女孩差 18;
#      girl 5 的 56105 与 girl 23 的 56123 同样差 18 → 同一规律。
#   ③ 真服抓包 /v1/girl/private: 883 对归属, 其中 type37/81 共 136 对 (pose_real_private.json)。
#   ★ v4 (2026-11-08 16:10) 推翻两条旧结论:
#     - Item_PoseGrowth_table 第 0 列是"成长组 id"(2~59), 不是 girl! 旧版当锚点用是错的;
#     - 归属是多对多: 50093 同属 girl4+13, 50057/50066/50099~50102 是全女孩通用卡。
#   ★ v5 (2026-11-08 16:35) 修正 v4 的过度保守 —— v4 把没有锚点的段全砍了, 表情从 88 张掉到 2 张:
#     - 游戏编号规则是 (item - girl) % N == (段起点 - 2) % N, 不是"绝对斜率 m-g 恒定";
#       type37 段 50812..51021 的 208 个真实兑换锚点 (m-g)%26 全等于 6 → 老款 N=26;
#       真服表情两段 56070..56100 / 56102..56132 起点差 32、段长 31 → 新款 N=32(含 girl28~33)。
#     - 所以表情按"段周期"铺满(短段<10 跳过), 姿势仍用 v4 的锚点链严格算法(用户已确认不乱)。
#     - 另: 旧算法时期用户取消星标留下的 :81 黑名单会误伤新表情列表 → 启动时一次性清掉。
#   (另已穷举确认: Equipment_Parameter 109 列 / PosecardShop 三表串联 / 193 张 CSV 反查 /
#    Shop.csv+ShopItemList 商店分组 / 反向"每女孩一行"表 / 客户端 exe, 都不存在直接的
#    item→girl 全量映射表 —— 游戏的归属表在客户端哈希资源包里, 服务器侧只能靠真实锚点 +
#    从真实锚点统计出的编号规则。用户质疑"算法是不是自己想的"是对的, 现已改为只用有实证的规则。)
_POSE_ASSIGN_MODE = "segment"   # "off"=不补 / "anchor"=只发锚点(100%准但每女孩只有 7~10 张) / "segment"=段内顺延(覆盖全)
POSE_UNLOCK_FLAG = "pose_private_unlock_v5"
POSE_OWNER_OVERRIDE = {}        # 手工修正表: {item_mid: girl_mid} —— 发现哪个 item 分错就直接钉死
POSE_OWNER_OVERRIDE_SETS = {k: {v} for k, v in POSE_OWNER_OVERRIDE.items()}
POSE_BASE_ITEMS = (50057, 50066, 50099, 50100, 50101, 50102)   # 通用基础卡: 32 个女孩都有(真实数据实证)
# ★ v5: 表情(type81)按段铺满的最短段长。规则 (item - girl) % N == (段起点 - 2) % N,
#   N=26(老款, 段长<27) 或 N=32(新款, 段长>=27, 覆盖 girl28~33)。短段不铺 —— 每段首张
#   都会落到 girl2, 实测会让 girl2 虚增到 261 张。真服 4 条表情锚点 4/4 命中。
POSE_EXPR_SEGMENT_MINLEN = 10
_POSE_UNIVERSAL_CACHE = None
_POSE_REAL_PAIRS_CACHE = None


def _pose_universal_items():
    """真服 /v1/girl/private 实证的"通用姿势/表情": 几乎每个女孩都拥有的 type37/81 道具。
    这些卡不属于任何单一女孩, 应该发给所有女孩。"""
    global _POSE_UNIVERSAL_CACHE
    if _POSE_UNIVERSAL_CACHE is not None:
        return _POSE_UNIVERSAL_CACHE
    _rp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pose_real_private.json")
    _cnt = {}
    _n = 0
    try:
        import json as _json
        with open(_rp, "r", encoding="utf-8") as _rf:
            _data = _json.load(_rf)
        _n = len(_data)
        from collections import Counter as _C
        _cc = _C()
        for _g, _items in _data.items():
            for _it in _items:
                if EQUIP_TYPE_MAP.get(int(_it)) in (37, 81):
                    _cc[int(_it)] += 1
        _uni = {_m for _m, _c in _cc.items() if _c >= max(1, _n - 1)}
    except Exception:
        _uni = set(POSE_BASE_ITEMS)
    _POSE_UNIVERSAL_CACHE = _uni
    return _uni


def _pose_real_pairs():
    """真服 /v1/girl/private 的 (type37/81) 归属, item -> set(girl)。
    这是硬证据(真服务器亲手写进每个女孩 private 列表的), 一条都不许丢, 也允许多女孩共用。"""
    global _POSE_REAL_PAIRS_CACHE
    if _POSE_REAL_PAIRS_CACHE is not None:
        return _POSE_REAL_PAIRS_CACHE
    _rp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pose_real_private.json")
    _pairs = {}
    try:
        import json as _json
        with open(_rp, "r", encoding="utf-8") as _rf:
            for _g, _items in _json.load(_rf).items():
                for _it in _items:
                    if EQUIP_TYPE_MAP.get(int(_it)) in (37, 81):
                        _pairs.setdefault(int(_it), set()).add(int(_g))
    except Exception as _e:
        print(f"[!] pose_real_private.json 读取失败: {_e}")
    _POSE_REAL_PAIRS_CACHE = _pairs
    return _pairs


def _pose_segments_of(type_code):
    """把某类型的 item_mid 切成"连续段"(相邻 id 相差 1 视为同段)。"""
    _mids = sorted(_m for _m, _t in EQUIP_TYPE_MAP.items() if _t == type_code)
    _segs = []
    if not _mids:
        return _segs
    _s = _prev = _mids[0]
    for _m in _mids[1:]:
        if _m == _prev + 1:
            _prev = _m
            continue
        _segs.append((_s, _prev))
        _s = _prev = _m
    _segs.append((_s, _prev))
    return _segs


POSE_ANCHOR_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pose_anchors.json")
# 2026-11-08 15:05 —— 锚点从哪来(这是本功能的命根子, 别再猜):
#   用户客户端在"维纳斯商店/活动商店"里逐张兑换姿势卡时, 每个请求都自带归属:
#     POST /v1/special_order/exchange {"girl_mid":33,"item_mid_list":[25060],"order_item_type":37}
#   一次会话攒下 555 条 (girl 2~33 全覆盖), 已固化到 pose_anchors.json —— 这是硬证据, 100% 可信。
#   回测: 用这 555 条当锚点, 分类结果 555/555 全对。
#   ★ 以后想让某张卡的归属"确定", 最省事的办法就是让客户端去商店兑一次, 日志里就有了。


def _load_pose_anchors():
    """item_mid -> girl_mid 的硬锚点。三个来源叠加, 后者覆盖前者。
    ★ 2026-11-08 16:10 v4 重大修正: Item_PoseGrowth_table.csv 第 0 列是"成长组 id"(2~59 连续
      编号, 出现 34~38 这些不存在的女孩), 不是 girl! 上一版把组 id 当 girl 注入了大量脏锚点
      (如 51660→19, 其实 19 是组号), 这是"姿势分类乱"的重要来源之一。已彻底移除该来源。
    """
    _a = {}
    # ① 从客户端兑换请求里攒下的锚点(固化文件) —— 用户真实购买记录, 100% 可信
    if os.path.exists(POSE_ANCHOR_FILE):
        try:
            import json as _json
            with open(POSE_ANCHOR_FILE, "r", encoding="utf-8") as _af:
                for _k, _v in _json.load(_af).items():
                    _a[int(_k)] = int(_v)
        except Exception as _e:
            print(f"[!] pose_anchors.json 读取失败: {_e}")
    # ② 现场扫一遍日志(有新的兑换就自动吸收, 不用改代码)
    _lg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "full_server.log")
    if os.path.exists(_lg):
        try:
            import re as _re
            _pat = _re.compile(r'\{"girl_mid":(\d+),"is_present":\w+,"item_mid_list":\[([0-9,]*)\],"order_item_type":(\d+)\}')
            with open(_lg, "r", encoding="utf-8", errors="ignore") as _lf:
                for _g, _its, _t in _pat.findall(_lf.read()):
                    if int(_t) != 37:
                        continue
                    for _it in _its.split(","):
                        if _it:
                            _a[int(_it)] = int(_g)
        except Exception:
            pass
    # ③ 真服抓包 /v1/girl/private 的 (girl, item) 归属(883 对里 type37/81 的 136 对)
    _rp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pose_real_private.json")
    if os.path.exists(_rp):
        try:
            import json as _json
            with open(_rp, "r", encoding="utf-8") as _rf:
                for _g, _items in _json.load(_rf).items():
                    for _it in _items:
                        _a[int(_it)] = int(_g)
        except Exception as _e:
            print(f"[!] pose_real_private.json 读取失败: {_e}")
    # ④ 历史实证: girl 18~24 → 56401~56407
    for _it, _ag in zip(range(56401, 56408), range(18, 25)):
        _a[_it] = _ag
    return {_m: _g for _m, _g in _a.items() if _g in GIRL_MASTER_MAP}


def _load_pose_owner_map_file():
    """v5 固化映射基准(pose_owner_map.json)。
    full_server.log 会被启动脚本清掉(2026-11-08 实测: 重启后 224 条兑换锚点全部消失),
    如果每次都纯靠日志重算, 姿势/表情数量会随日志存废忽多忽少。
    这里把「已经实际落库、经过实证的归属」固化成 JSON 作为重建基准, 新兑换的锚点仍会叠加。
    """
    _p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pose_owner_map.json")
    _out = {}
    if os.path.exists(_p):
        try:
            import json as _json
            with open(_p, "r", encoding="utf-8") as _f:
                for _k, _v in _json.load(_f).items():
                    _gs = {int(_x) for _x in _v} & set(GIRL_MASTER_MAP)
                    if _gs:
                        _out[int(_k)] = _gs
            print(f"[*] 已加载固化姿势/表情映射 {len(_out)} 张")
        except Exception as _e:
            print(f"[!] pose_owner_map.json 读取失败: {_e}")
    return _out


def _build_pose_owner_map(_anchors=None):
    """item_mid -> set(girl_mid) (type37 姿势卡 / type81 表情卡)。
    ★ 2026-11-08 16:10 v4 重写 —— 依据三个实证结论:
      ① 真服 /v1/girl/private 实证: 50057/50066/50099/50100/50101/50102 被**所有**女孩共同
         拥有 → 它们是"通用姿势", 不属于任何单一女孩, 必须发给每个女孩。
      ② 真服实证 50093 同时属于 girl4 和 girl13 → 归属是**多对多**, 所以返回 set。
      ③ 兑换锚点实证: 段内"item_mid +1 ↔ girl +1"的线性关系只在同一款内成立;
         54603..54631 这类"乱序段"是通用姿势被不同女孩购买留下的锚点, 绝不能按 26 循环外推。
    【算法】姿势严格靠锚点(用户实测已确认不乱), 表情按游戏编号规则铺段:
      a) 相邻锚点 Δitem == Δgirl 且距离 ≤64 → 区间内线性填充(同款姿势, 实测全部成立);
      b) 连续 ≥5 个锚点同女孩且 id 连号 → 整块填该女孩(新角色专属块, 如 25060..25071=girl33);
      c) 【v5 新增】type81 每个长度>=10 的段按 (item-girl)%N == (段起点-2)%N 铺满,
         N=26/32 按段长自适应。这条规则来自 208 个真实兑换锚点 + 真服 4 条表情归属,
         不是凭空假设; v4 因为用错判定方式把表情砍到每女孩 2 张。
      硬锚点本身无条件收录。
    """
    _anchors = _anchors if _anchors is not None else _load_pose_anchors()
    # ---- 通用姿势: 真服数据里几乎所有女孩都有 → 从单属锚点里摘出来 ----
    _uni = _pose_universal_items()
    # ---- 真服 (girl, item) 对直接按多对多注入(50093 同时属于 girl4+13 这类共用卡) ----
    # ---- 固化映射作基准(防止 full_server.log 被清后数量缩水), 再叠加真服归属 ----
    _real_pairs = _pose_real_pairs()
    _out = _load_pose_owner_map_file()
    for _m, _gs in _real_pairs.items():
        _out.setdefault(_m, set()).update(_gs)
    for _t in (37, 81):
        for _s, _e in _pose_segments_of(_t):
            # ★ v5 (2026-11-08): type81 表情按【游戏自己的编号规则】铺段, 不是凭空猜的。
            #   实证 A(真服 /v1/girl/private): 56073→girl5、56091→girl23 属于段 56070..56100,
            #       56105→girl5、56123→girl23 属于段 56102..56132;
            #       两段各自 (item-girl)%26 == (段起点-2)%26, 4/4 全中。
            #   实证 B(客户端兑换请求): type37 段 50812..51021 的 182 个锚点 (item-girl)%26 全=6,
            #       100% 吻合 —— 姿势/表情共用同一套"一款 26 连号 = girl2~27 循环"的编号体系。
            #   v4 误用"绝对斜率 m-g 恒定"判定, 把这类段当成乱序砍掉 → 表情从 88 张掉到 2 张。
            #   短段(< POSE_EXPR_SEGMENT_MINLEN)不铺: 每段首张都归 girl2, 实测会让 girl2 虚增。
            #   ★ 循环周期自适应: 老款(段长<=26)是 26 循环(当时只有 girl2~27);
            #     新增 6 名角色后的新款(段长>=27)是 32 循环(覆盖 girl2~33)。
            #     实证: 真服两段表情 56070..56100(31张) 与 56102..56132(31张) 起点正好差 32,
            #     按 32 算两段的 C 都是 4, 4/4 锚点全中; 按 26 算则 girl28~33 一张表情都没有。
            if _t == 81 and _e - _s + 1 >= POSE_EXPR_SEGMENT_MINLEN:
                _N81 = 32 if _e - _s + 1 >= 27 else 26
                _C81 = (_s - 2) % _N81
                for _m in range(_s, _e + 1):
                    _g81 = ((_m - _C81 - 2) % _N81) + 2
                    if _g81 in GIRL_MASTER_MAP:
                        _out.setdefault(_m, set()).add(_g81)
            _pts = sorted((_m, _g) for _m, _g in _anchors.items()
                          if _s <= _m <= _e and _m not in _uni
                          and EQUIP_TYPE_MAP.get(_m) == _t)
            if not _pts:
                continue
            # a) 线性区间填充
            for (_m1, _g1), (_m2, _g2) in zip(_pts, _pts[1:]):
                if 0 < _m2 - _m1 <= 64 and _g2 - _g1 == _m2 - _m1:
                    for _m in range(_m1, _m2 + 1):
                        _out.setdefault(_m, set()).add(_g1 + (_m - _m1))
            # b) 同女孩连号块 (≥5 个连续锚点同女孩)
            _run_start = 0
            for _i in range(1, len(_pts) + 1):
                _same = (_i < len(_pts) and _pts[_i][1] == _pts[_i - 1][1]
                         and _pts[_i][0] == _pts[_i - 1][0] + 1)
                if _same:
                    continue
                if _i - _run_start >= 5:
                    for _m in range(_pts[_run_start][0], _pts[_i - 1][0] + 1):
                        _out.setdefault(_m, set()).add(_pts[_run_start][1])
                _run_start = _i
            # 锚点无条件收录
            for _m, _g in _pts:
                _out.setdefault(_m, set()).add(_g)
            # c) 仅表情(type81): "整款补全" —— 表情是全女孩通用的脸, 不存在姿势那种
            #    10 人子集款; 实测锚点链斜率恒为 1(56073→girl5 / 56091→girl23, Δm=Δg=18;
            #    56401..56407→girl18..24 同款)。所以只要有 ≥2 个锚点构成斜率 1 的链,
            #    就把整款补全到 girl2~33(限定在本连续段内)。
            #    姿势(type37)绝不做这种外推 —— 实测姿势有 10 人子集款(51640..51659)和
            #    通用款乱序锚点(54603..54631), 外推必错。
            if _t == 81:
                _runs = []
                _r = [_pts[0]]
                for _pr in zip(_pts, _pts[1:]):
                    if _pr[1][0] - _pr[0][0] == _pr[1][1] - _pr[0][1] and _pr[1][0] - _pr[0][0] <= 64:
                        _r.append(_pr[1])
                    else:
                        _runs.append(_r)
                        _r = [_pr[1]]
                _runs.append(_r)
                for _run in _runs:
                    if len(_run) < 2:
                        continue
                    _m0, _g0 = _run[0]
                    _off = _m0 - _g0
                    for _gg in range(2, 34):
                        _mm = _gg + _off
                        if _s <= _mm <= _e and _gg in GIRL_MASTER_MAP:
                            _out.setdefault(_mm, set()).add(_gg)
    _out.update(POSE_OWNER_OVERRIDE_SETS)
    return {_m: _gs for _m, _gs in _out.items() if _gs & set(GIRL_MASTER_MAP)}


_POSE_OWNER_CACHE = None


def _pose_owner_map_cached():
    """_build_pose_owner_map() 要遍历 3741 个 mid + 切段, 每次请求都算太慢 → 算一次缓存住。
    (映射只依赖静态 CSV 和日志锚点, 进程内不会变, 缓存安全。)"""
    global _POSE_OWNER_CACHE
    if _POSE_OWNER_CACHE is None:
        _POSE_OWNER_CACHE = _build_pose_owner_map()
    return _POSE_OWNER_CACHE


def _unlock_poses_in_private():
    if STATE.get(POSE_UNLOCK_FLAG):
        return
    _owner = _build_pose_owner_map()
    _pi = STATE.setdefault("private_items", [])
    _removed = 0
    # ---- 回滚上一版的分类结果(v2~v4 都是纯 append, 按记录的 base_private_items 截断即可复原) ----
    for _prev in ("pose_private_unlock_v4", "pose_private_unlock_v3", "pose_private_unlock_v2"):
        _v = STATE.get(_prev)
        if isinstance(_v, dict) and _v.get("base_private_items"):
            _cut = int(_v["base_private_items"])
            if 0 < _cut < len(_pi):
                _removed += len(_pi) - _cut
                STATE["private_items"] = _pi = _pi[:_cut]
                print(f"[*] 已回滚 {_prev}: private_items → {_cut} 条")
            break
    _base = len(_pi)
    _have = set()
    for _p in _pi:
        if isinstance(_p, dict):
            try:
                _have.add((int(_p.get("girl_mid")), int(_p.get("item_mid"))))
            except (TypeError, ValueError):
                continue
    _added = 0
    # ① 通用姿势: 每个女孩都要有(真服实证)
    _uni = _pose_universal_items()
    for _g in sorted(GIRL_MASTER_MAP):
        for _m in sorted(_uni):
            if (_g, _m) in _have:
                continue
            _pi.append({"girl_mid": _g, "item_mid": _m})
            _have.add((_g, _m))
            _added += 1
    # ② 映射表: item → {girls}(v4 起多对多)
    for _g in sorted(GIRL_MASTER_MAP):
        for _m, _gs in _owner.items():
            if _g not in _gs or (_g, _m) in _have:
                continue
            _pi.append({"girl_mid": _g, "item_mid": _m})
            _have.add((_g, _m))
            _added += 1
    _t37 = sum(1 for _m in _owner if EQUIP_TYPE_MAP.get(_m) == 37)
    _t81 = sum(1 for _m in _owner if EQUIP_TYPE_MAP.get(_m) == 81)
    STATE[POSE_UNLOCK_FLAG] = {"base_private_items": _base, "mode": "v5",
                               "removed": _removed, "mapped": len(_owner), "added": _added,
                               "universal": sorted(_uni)}
    _save_state()
    from collections import Counter as _C
    _per = _C()
    for _m, _gs in _owner.items():
        for _g in _gs:
            _per[_g] += 1
    _mn = min(_per.values()) if _per else 0
    _mx = max(_per.values()) if _per else 0
    print(f"[*] 姿势/表情分类 v5: 映射 {len(_owner)} 张 (姿势{_t37}/表情{_t81}), "
          f"通用卡 {len(_uni)} 张×全女孩, 回滚旧数据 {_removed} 条, 新增 {_added} 条, "
          f"每女孩映射 {_mn}~{_mx} 张, private_items {_base} → {len(_pi)} 条")


def _migrate_v5_favorite():
    """v5 一次性迁移: 清掉 v3/v4 乱分类时期用户在表情页取消星标留下的黑名单。
    那批 item 是旧算法算出来的, v5 的表情列表已按游戏编号规则重建; 旧黑名单会误伤新列表
    (实测 STATE 里 girl3:81 有 27 条黑名单, 会把新铺出来的表情挡掉 —— 用户说的"表情全没了")。
    姿势(:37)黑名单保留, 用户主动取消的姿势星标依然有效。"""
    if STATE.get("pose_expr_migrated_v5"):
        return
    _del = STATE.get("pose_expr_removed", {})
    _n = 0
    for _k in list(_del):
        if _k.endswith(":81") and _del[_k]:
            _n += len(_del[_k])
            _del[_k] = []
    STATE["pose_expr_migrated_v5"] = {"cleared_expr_blacklist": _n}
    _save_state()
    if _n:
        print(f"[*] v5: 清除旧表情黑名单 {_n} 条")


_migrate_v5_favorite()
_unlock_poses_in_private()


# ===== 2026-11-08 13:50: 所有女孩两两组合的 friendly(亲密)等级拉满 → 外出地点全解锁 =====
# 【判定实证】用户截图: 外出界面"地点"上写"亲密等级达到后才能解锁";
#   CR_Friendly3Photospot.csv = [所需 friendly 等级, 地点id] (0→2, 40→1, 60→3, 70→10, 80→7, 100→4, 120→5);
#   真服 /v1/room/girl/friendly 样本: value=45→level 3, value=11185→level 21 (level 随 value 累计).
# 【病根】STATE.friendly_value 是空的 → /v1/room/girl/friendly 返回 [] → 所有组合 level=0 → 地点全锁.
# 【做法】32 个女孩的全部有序对 (32×31=992 条) 一次性补齐: value=9999999, level=120 (CR 表最高需求 120).
#   客户端判定是 "level >= 地点需求", 120 覆盖全部; unlock_count 沿用真服结构。
#   幂等: STATE.friendly_maxed_v1; 回退: STATE["friendly_value"]=[] 后删该键。
FRIENDLY_MAX_LEVEL = 120
FRIENDLY_MAX_VALUE = 9999999


def _max_all_friendly():
    if STATE.get("friendly_maxed_v1"):
        return
    _fv = STATE.setdefault("friendly_value", [])
    _have = set()
    for _f in _fv:
        if isinstance(_f, dict):
            try:
                _have.add((int(_f.get("girl_mid")), int(_f.get("friendly_girl_mid"))))
            except (TypeError, ValueError):
                continue
    _girls = sorted(GIRL_MASTER_MAP)
    _add_fv = 0
    for _g1 in _girls:
        for _g2 in _girls:
            if _g1 == _g2 or (_g1, _g2) in _have:
                continue
            _fv.append({"girl_mid": _g1, "friendly_girl_mid": _g2,
                        "value": FRIENDLY_MAX_VALUE, "level": FRIENDLY_MAX_LEVEL,
                        "unlock_count": 0})
            _have.add((_g1, _g2))
            _add_fv += 1
    STATE["friendly_maxed_v1"] = True
    _save_state()
    print(f"[*] 亲密等级拉满: 补 {len(_girls)} 女孩 × 组合 friendly {_add_fv} 条 "
          f"(level={FRIENDLY_MAX_LEVEL}, value={FRIENDLY_MAX_VALUE}), 共 {len(_fv)} 条")


_max_all_friendly()


# ===== 2026-11-08: 岛主房间家具摆放自愈 + 家具屏蔽名单 (修"装家具→卡住→闪退") =====
# 【崩溃实证】dump/doaxvv-20261108-124312-13668.dmp
#   exception 0xc0000005, ExceptionInformation = [0x0(读), 0x10(地址)] → 读 *(0 + 0x10)
#   崩溃指令在 sub_142DA2F40+0x52: `v11 = *(DWORD *)(v10 + 16)`, 其中 v10 来自
#   `sub_142DA2D40(a2)` 这个 id→对象 的哈希表查找; a2 == 0 时代码直接令 v10 = 0,
#   紧接着无条件解引用 → 进程 abort。也就是说: **客户端收到了一个 id 为 0 / 查不到的家具条目**。
# 【数据实证】STATE.furniture_myset_home 的 7 条摆放, 实例 id 全部不在 equipment_inventory 里:
#   158143/158144/158145(参考样本里的旧 id) 与 4528388208/210/211、4593476321(旧版"毫秒时间戳"
#   分配器产出的脏 id, 已在今日 _alloc_equip_ids 修复)。其中 45430 的 layout_mid=0,
#   而真私服参考样本(myset/home 8 条)里 0 号位从未出现 → 0 号位是非法摆位。
# 【做法】
#   ① 启动自愈: 逐条校验 → item_mid 必须 type67 且本人持有、layout_mid 必须 0<=slot<32 且不与他人
#      撞位; 实例 id 一律换成本人该家具的**真实实例 id**(客户端才能解析); 校验不过的移出布局,
#      记入 STATE.furniture_quarantine(保留原始数据, 可人工还原)。
#   ⚠ 2026-11-08 13:03 修正: layout_mid=0 是**合法摆位**! 实测客户端把 45805 摆在 0 号位
#      (POST update_furniture_list 实录), 之前把 0 当非法导致"摆放后无法保存"。已改回 0<=slot<32。
#   ② 屏蔽名单: STATE.furniture_blocklist = [item_mid, ...] → 该家具不出现在 /v1/furniture/,
#      也不会被摆放(已摆放的会被移出)。怀疑某件家具导致闪退时, 把它的 item_mid 加进来即可。
#   ③ 响应侧二次兜底: /v1/furniture/myset* 返回前再过滤一遍, 防止运行期又写进脏数据。
#   幂等: STATE.furniture_layout_sanitized_v1
MAX_LAYOUT_SLOT = 32          # 房间摆位上限 (实测样本用到的位: 3,7,8,9,10,24,28,29)

# 默认屏蔽的家具 (item_mid)。45430 = 本次闪退的首要嫌疑: layout_mid=0 + 脏实例 id。
# 想解除屏蔽时把这个 mid 从列表删掉、并删掉 STATE.furniture_layout_sanitized_v1 即可重新校验。
DEFAULT_FURNITURE_BLOCKLIST = (45430,)


def _furniture_blocklist():
    _bl = STATE.get("furniture_blocklist")
    if _bl is None:
        _bl = list(DEFAULT_FURNITURE_BLOCKLIST)
    _out = set()
    for _x in _bl:
        try:
            _out.add(int(_x))
        except (TypeError, ValueError):
            pass
    return _out


def _furniture_instances():
    """item_mid -> [真实实例 id, ...] (仅 type67), 按 id 升序"""
    _inst = {}
    for _e in (STATE.get("equipment_inventory") or []):
        if isinstance(_e, dict) and _e.get("type") == 67:
            _inst.setdefault(_e.get("item_mid"), []).append(_e.get("id"))
    for _v in _inst.values():
        _v.sort(key=lambda x: (x is None, x))
    return _inst


def _sanitize_furniture_layout(force=False):
    if STATE.get("furniture_layout_sanitized_v1") and not force:
        return
    _layout = STATE.get("furniture_myset_home")
    if not isinstance(_layout, list):
        STATE["furniture_layout_sanitized_v1"] = True
        _save_state()
        return
    _inst = _furniture_instances()
    _bl = _furniture_blocklist()
    _slots, _ids = set(), set()
    _keep, _quar = [], []
    for _it in _layout:
        if not isinstance(_it, dict):
            continue
        try:
            _mid = int(_it.get("item_mid") or 0)
            _lm = int(_it.get("layout_mid") or 0)
            _ry = int(_it.get("rot_y") or 0)
            _oid = int(_it.get("id") or 0)
        except (TypeError, ValueError):
            _quar.append({"id": _it.get("id"), "item_mid": _it.get("item_mid"),
                          "layout_mid": _it.get("layout_mid"), "reason": "parse_error"})
            continue
        _why = None
        if _mid in _bl:
            _why = "blocked"
        elif EQUIP_TYPE_MAP.get(_mid) != 67:
            _why = "not_furniture"
        elif _mid not in _inst or not _inst[_mid]:
            _why = "not_owned"
        elif not (0 <= _lm < MAX_LAYOUT_SLOT):
            _why = "layout_out_of_range"
        elif _lm in _slots:
            _why = "duplicate_slot"
        if _why:
            _quar.append({"id": _oid, "item_mid": _mid, "layout_mid": _lm, "reason": _why})
            continue
        # 实例 id 必须是本人真实持有的那件 (旧的脏 id 一律替换)
        if _oid in _inst[_mid] and _oid not in _ids:
            _nid = _oid
        else:
            _cands = [i for i in _inst[_mid] if i not in _ids]
            _nid = _cands[0] if _cands else _inst[_mid][0]
        _ids.add(_nid)
        _slots.add(_lm)
        _keep.append({"id": _nid, "item_mid": _mid, "layout_mid": _lm, "rot_y": _ry})
    _changed = (_keep != _layout) or bool(_quar)
    if _changed:
        STATE["furniture_myset_home"] = _keep
        _qlog = list(STATE.get("furniture_quarantine") or []) + _quar
        STATE["furniture_quarantine"] = _qlog[-100:]
        print(f"[*] 家具布局自愈: 保留 {len(_keep)} 条, 移出 {len(_quar)} 条 -> {_quar}")
        for _q in _quar:
            print(f"    移出 layout_mid={_q.get('layout_mid')} item_mid={_q.get('item_mid')} "
                  f"id={_q.get('id')} 原因={_q.get('reason')}")
        _save_state()
    STATE["furniture_layout_sanitized_v1"] = True
    _save_state()


def _valid_furniture_layout(layout):
    """响应侧兜底: 只放出客户端能解析的布局条目。
    脏 id / 未持有 / 非法摆位 / 撞位 / 被屏蔽 的条目一律不返回 —— 这类条目会让客户端
    查表得到 0 并在 sub_142DA2F40 里解引用空指针 (0xc0000005) 直接闪退。"""
    _inst = _furniture_instances()
    _bl = _furniture_blocklist()
    _slots, _out = set(), []
    for _it in layout or []:
        if not isinstance(_it, dict):
            continue
        try:
            _mid = int(_it.get("item_mid") or 0)
            _lm = int(_it.get("layout_mid") or 0)
            _ry = int(_it.get("rot_y") or 0)
            _oid = int(_it.get("id") or 0)
        except (TypeError, ValueError):
            continue
        if _mid <= 0 or _mid in _bl:
            continue
        if _mid not in _inst or not _inst[_mid]:
            continue
        if not (0 <= _lm < MAX_LAYOUT_SLOT) or _lm in _slots:
            continue
        _ids = _inst[_mid]
        if _oid not in _ids:
            _oid = _ids[0]
        _slots.add(_lm)
        _out.append({"id": _oid, "item_mid": _mid, "layout_mid": _lm, "rot_y": _ry})
    return _out


_sanitize_furniture_layout()


# ===== 2026-11-07 商店/背包修复 ③: 给"当前开放商店"用到的货币补足余额 =====
# 背景: 商品能不能点, 由客户端按本地持有的货币数量判定。缺货币 → 按钮灰/点了没反应。
# 实证: 商店用的 point_type 有 6/7/8/9/10/12/44/45/46/47/543/544… 一大半背包里根本没有
#       (point_type→item_mid 映射见 ShopPointTypeLink.csv), 而 35103~35178 恰好有 → 只有部分商店能用。
# 做法: 启动时按 CSV 解析"当前开放商店"实际用到的 point_type, 一次性把对应货币补到 999999。
# 幂等: STATE.shop_currency_seeded_v1 标记, 只做一次(不覆盖玩家后续消耗)。
def _seed_shop_currencies():
    if STATE.get("shop_currency_seeded_v1"):
        return
    import csv as _csv3
    _now = game_now_str()
    try:
        _need_ids = set()          # 当前开放商店里出现的 ShopItemList 行 id
        with open(os.path.join(CSV_MASTER, "Shop.csv"), encoding="utf-8-sig") as _f:
            for _r in _csv3.reader(_f):
                if len(_r) < 5:
                    continue
                if _r[4] and _r[4] <= _now:     # end_time 已过 → 该切片失效
                    continue
                if _r[3] and _r[3] > _now:      # start_time 还没到
                    continue
                _need_ids.update(x for x in _r[5:] if x)
        _pts = set()               # 用到的 point_type
        with open(os.path.join(CSV_MASTER, "ShopItemList.csv"), encoding="utf-8-sig") as _f:
            for _r in _csv3.reader(_f):
                if len(_r) > 5 and _r[0] in _need_ids:
                    _pts.add(_r[4])
        _link = {}
        with open(os.path.join(CSV_MASTER, "ShopPointTypeLink.csv"), encoding="utf-8-sig") as _f:
            for _r in _csv3.reader(_f):
                if len(_r) >= 2 and _r[0]:
                    _link[_r[0]] = _r[1]
    except Exception as _e:
        print(f"[!] 商店货币铺底失败(跳过): {_e}")
        return
    _ic = STATE.setdefault("item_counts", {})
    _granted = 0
    for _pt in _pts:
        _im = _link.get(_pt)
        if not _im:
            continue
        try:
            _mid = int(_im)
        except ValueError:
            continue
        if int(_ic.get(_mid, 0) or 0) >= 999999:
            continue
        _ic[_mid] = 999999
        _granted += 1
    STATE["shop_currency_seeded_v1"] = True
    _save_state()
    print(f"[*] 修复③ 商店货币铺底: {_granted} 种货币补到 999999 "
          f"(当前开放商店涉及 {len(_pts)} 类 point_type / {len(_need_ids)} 个商品行)")
_seed_shop_currencies()
if not _seed_added:
    print(f"[*] 装备库存: {len(_inv_seed)} 件, 私人套装 {len(_spi_seed)} 条 (已播种)")
# 2026-09-14: 发型崩溃自动回退 — 重启时检查未确认的发型变更(=上次崩溃), 回退到旧值
_hair_revert = STATE.pop("_hair_revert", None)
if _hair_revert:
    _ge = STATE.get("girl_equipment", {})
    for _gm_r, _old_h in _hair_revert.items():
        if _old_h:
            _ge.setdefault(_gm_r, {})["hair_item_mid"] = _old_h
        else:
            _ge.setdefault(_gm_r, {}).pop("hair_item_mid", None)
        print(f"[*] 发型自动回退: girl{_gm_r} -> {_old_h} (上次发型变更导致崩溃)")
    _save_state()
# 2026-09-08: 跳过签到的服务器侧开关。改完需重启服务器生效。
_CONFIG_FILE = os.path.join(TOOL, "server_config.json")
def _load_config():
    cfg = {"skip_daily_login_bonus": False}   # 默认保留原版每日签到
    try:
        if os.path.exists(_CONFIG_FILE):
            with open(_CONFIG_FILE, encoding="utf-8") as f:
                cfg.update(json.load(f))
    except Exception as e:
        print(f"[config] 加载失败: {e}")
    return cfg
CONFIG = _load_config()
print(f"[*] 功能开关: skip_daily_login_bonus = {CONFIG.get('skip_daily_login_bonus', False)}")

# 2026-09-14 方案C: 扭蛋爆率/保底配置 (文件默认 + STATE 运行时覆盖)
_GACHA_CONFIG_PATH = os.path.join(TOOL, "gacha_config.json")
_GACHA_CONFIG_FILE = {"defaults": {}, "pool_overrides": {}}
try:
    if os.path.exists(_GACHA_CONFIG_PATH):
        with open(_GACHA_CONFIG_PATH, encoding="utf-8") as f:
            _GACHA_CONFIG_FILE = json.load(f)
    print(f"[*] 扭蛋配置加载: defaults={_GACHA_CONFIG_FILE.get('defaults', {})}, "
          f"pool_overrides={len(_GACHA_CONFIG_FILE.get('pool_overrides', {}))} 个卡池")
except Exception as e:
    print(f"[gacha_config] 加载失败: {e}")

def state_girl_equipment(girl_mid):
    """取某女孩当前装备 (来自STATE或默认空)"""
    return STATE.get("girl_equipment", {}).get(str(girl_mid), {})

# 2026-09-11 性能优化: 装备字段映射提为模块常量 (避免每女孩每请求重建)
_GIRL_FIELD_MAP = {
    "swimsuit_equipment_item_id": "swimsuit_item_mid",
    "accessory_head_equipment_item_id": "accessory_head_item_mid",
    "accessory_face_equipment_item_id": "accessory_face_item_mid",
    "accessory_arm_equipment_item_id": "accessory_arm_item_mid",
    "addition_accessory_equipment_item_id": "addition_accessory_item_mid",
    "hair_equipment_item_id": "hair_item_mid",
    "ring_equipment_item_id": "ring_item_mid",
}

# 2026-11-13 六次修复: 亲爱度等级封顶 —— 维纳斯面板「亲爱度报酬」页客户端实测只认
#   LV.300 (Girl_Affection_Level.csv 曲线2 累计到 300 级 = 161,904,000, 逐级实算)。
#   之前发 339 级 + accepted_level=339, 超过客户端可见等级被整包丢弃,
#   表现为「领取」红点常亮、重复领取弹窗空白。
_AFFECTION_LEVEL_CAP = 300
_AFFECTION_POINT_AT_CAP = 161904000

def apply_girl_state(girl_obj):
    """把STATE里该女孩的装备叠加到 girl 对象上 (equipment_id -> item_mid 字段映射).
    2026-09-11 简化: 移除归属校验(_validate_equipment_owner 已改为全放行, 校验为空操作)."""
    if not isinstance(girl_obj, dict):
        return girl_obj
    mid = girl_obj.get("girl_mid")
    eq = state_girl_equipment(mid)
    for eq_field, girl_field in _GIRL_FIELD_MAP.items():
        # 2026-09-13 修复: girl 对象的 *_item_mid 字段只存模板ID(类型ID), 不能塞实例ID
        # 旧逻辑优先读 *_equipment_item_id(实例ID如4276903939) 塞进 *_item_mid 模板字段
        # → 客户端收到非法模板ID → 识别为"没装备" → 切换页面还原默认
        # 修复: 只读 *_item_mid 型 key (girl/{mid}/private 端点写入的模板ID)
        v = eq.get(girl_field)
        if v:   # 跳过 0 值: 0=无配饰, 不覆盖 girl 默认装备
            girl_obj[girl_field] = v
    # 2026-09-14: 叠加 visual_state (sunburn/wet/hip_swing 等, 泳装滑落/护肤状态持久化)
    _vs = STATE.get("girl_visual_state", {}).get(str(mid), {})
    if isinstance(_vs, dict):
        for _f, _v in _vs.items():
            girl_obj[_f] = _v
    # 2026-09-16: 泳装滑落 — 默认开启(visual_state_flag_b=1, 私服抓包可用时=1);
    # 但玩家在打扮里手动关闭过(STATE.girl_visual_state 存了 b)则尊重该值, 实现可开可关(实时切换)
    if not (isinstance(_vs, dict) and "visual_state_flag_b" in _vs):
        girl_obj["visual_state_flag_b"] = 1
    girl_obj["level"] = 100
    girl_obj["experience"] = 999999
    # 2026-11-13 六次修复: 亲爱度成长曲线必须用 Girl_Affection_Level.csv 的第2条曲线
    #   (「40LVまで必要親愛度上昇」, need(1)=300)。真服抓包实证: 女孩 LV.2 时
    #   affection_point=300 = cum(2)。第1条(テスト用=测试用, 100n)算出 cum(2)=100
    #   → 客户端从点数推导的等级与字段值矛盾。
    #   曲线2 累计到 300 级 = 161,904,000 (CSV 逐级累加实算)。
    #   同时维纳斯面板「亲爱度报酬」页客户端实测只显示 LV.300(截图, 全女孩一致),
    #   报酬行只列到这个等级; accepted_level 超过它会被客户端整包丢弃 → 红点常亮、
    #   重复领取空白。因此等级/已领等级统一封顶 300, 与点数三者自洽。
    girl_obj["affection_level"] = _AFFECTION_LEVEL_CAP
    girl_obj["affection_point"] = _AFFECTION_POINT_AT_CAP
    girl_obj["partner_count"] = 999
    # 2026-11-13: 维纳斯图板「开放」要消耗维纳斯记忆, 全解锁约 171 万/人 (VenusBoard_Panel 实算),
    #   写死 999 会被客户端本地判定"记忆不足"拦下, 请求根本不发。
    girl_obj["venus_memory"] = 9999999
    girl_obj["girly"] = 999
    return girl_obj

# 2026-09-11 性能优化: 装备归属映射缓存 (REAL_RESPONSES 启动后不变, 只构建一次, 供所有女孩/请求复用)
_EQUIP_OWNER_CACHE = None


def _item_mid_to_instance():
    """item_mid(模板ID) -> 衣橱里的第一个实例 (同款多件取 id 最小那件)"""
    _m = {}
    for _e in STATE.get("equipment_inventory", []):
        if isinstance(_e, dict) and _e.get("item_mid"):
            _im = _e["item_mid"]
            _old = _m.get(_im)
            if _old is None or int(_e.get("id") or 0) < int(_old.get("id") or 0):
                _m[_im] = _e
    return _m


def _deck_instance_id(inst):
    """卡组端点只接受真服量级的装备实例ID (<= int32 上限).

    本地衣橱 22741 件里绝大多数实例 id 在 20~46 亿段(家具/其他空间共用),
    真服 girl/equipment 的 *_equipment_item_id 最大约 30 亿。把 45 亿段的
    实例塞进 *_equipment_item_id, 客户端按装备实例查表会落空。
    2026-11-08: 客户端进入挑战赛界面时 APPCRASH(0xc0000005) 的防御性修正。
    """
    if not isinstance(inst, dict):
        return 0
    try:
        _id = int(inst.get("id") or 0)
    except (TypeError, ValueError):
        return 0
    return _id if 0 < _id <= 2147483647 else 0


def _build_girl_equipment_one(girl_mid):
    """构造单个女孩的装备响应 (GET /v1/girl/{mid}/equipment)。

    2026-11-07 修复: 原实现不区分 GET/POST, 把 GET 也当成"回显请求参数", 而 GET 没有请求体
    → 永远返回全 0。表现: 女孩身上明明穿着泳装, 点进打扮页显示"未装备"; 此时再点保存,
    客户端按空装备提交 → 装备被真的卸下, 衣服就"消失"了。

    数据源: STATE.girl_equipment 里存的是 *模板ID* (item_mid 型字段), 客户端要的是
    *实例ID* (equipment_item_id 型字段), 必须再过一遍衣橱换取实例。
    真实响应还带 item_equipment_list(穿戴中装备的完整实例数据, 含等级/技能), 一并返回。
    """
    _gm = int(girl_mid)
    _sg = STATE.get("girl_equipment", {}).get(str(_gm), {}) or {}
    _im2e = _item_mid_to_instance()
    _entry = {"owner_id": OWNER_ID, "girl_mid": _gm}
    _items = []
    for _eq_f, _girl_f in _GIRL_FIELD_MAP.items():
        _im = _sg.get(_girl_f)
        _inst = _im2e.get(_im) if _im else None
        _entry[_eq_f] = int(_inst.get("id") or 0) if _inst else 0
        if _inst:
            _items.append(dict(_inst))
    return {"girl_equipment_list": [_entry], "item_equipment_list": _items}


def _equipment_owner_map():
    """构建 item_mid -> {"type": 类型, "owners": 归属girl_mid集合} 的映射 (来自装备实例列表).
    归属规则: girl_mid==0 表示通用装备(任意女孩可装备); 否则该实例专属某女孩.
    数据源: REAL_RESPONSES 的 /v1/item/equipment/type/* 端点 (泳装type1/头22/脸23/臂24/戒56/发11/其它0).
    (2026-09-11 修复: 增加 type 维度; 性能优化: 模块级缓存, 避免每次全量扫描 124 端点)"""
    global _EQUIP_OWNER_CACHE
    if _EQUIP_OWNER_CACHE is not None:
        return _EQUIP_OWNER_CACHE
    mapping = {}   # item_mid -> {"type": int, "owners": set(girl_mid)}
    eps = REAL_RESPONSES
    for _path, _resp in eps.items():
        if "/item/equipment/" not in _path:
            continue
        # 响应可能是列表(轮换池)或单对象
        pool = _resp if isinstance(_resp, list) else [_resp]
        for r in pool:
            if not isinstance(r, dict):
                continue
            lst = r.get("item_equipment_list")
            if not isinstance(lst, list):
                continue
            for it in lst:
                if not isinstance(it, dict):
                    continue
                im = it.get("item_mid")
                if im is None:
                    continue
                gm = it.get("girl_mid", 0)
                itype = it.get("type", 0)
                entry = mapping.setdefault(im, {"type": itype, "owners": set()})
                entry["owners"].add(gm)
    _EQUIP_OWNER_CACHE = mapping
    return mapping

def _validate_equipment_owner(girl_mid, item_mid, owner_map):
    """归属校验: 返回 True 合法 / False 拒绝.
    规则(2026-09-11 三次修复): item_mid==0 无装备(合法); 其余一律放行.
      不校验装备归属、不校验实例是否存在.
      原因: 更衣室从 CSV 主数据展示全部泳装/配饰, 玩家可预览选择;
        部分泳装(如 866/929/112)不在玩家装备实例池(real_responses 的 /item/equipment/type/*),
        但客户端能正常渲染(从主数据找模型). 旧逻辑"查不到实例→拒绝"导致正常换装被置0.
      崩溃风险(09-25 更正): 归属冲突说已被否证(私房版跨女孩 face=10044 不崩; 筑紫崩时穿自己泳装 2980), 见 02/04.1/08/09 号;
        真因疑为筑紫特殊数据(hair=0/泳装2980/唯一 bust_press_lock=1), 未验证. 本函数空操作放开后未再崩(workaround)."""
    if not item_mid:
        return True
    return True

def _build_girl_from_master(mid):
    """无抓包快照的女孩: 用 girl_master 主数据构造一个"自洽"的 girl 对象 (46 字段).

    2026-11-11 修复白屏/闪退: 旧兜底是"拿别的女孩对象改 girl_mid", 会残留原女孩的
    hair_item_mid / ring / accessory / visual_state / *_lock / 好感度等字段。
    于是客户端收到 (girl_mid=28, hair_item_mid=366) 这种不存在的组合,
    按本地模型资源表查不到对应发型模型 -> 白屏卡住 -> APPCRASH。
    抓包池只覆盖 20 个女孩 (2..16/18/21/22/23/26), main_girl 池只有 6 个,
    其余 12 个 (17/19/20/24/25/27/28/29/30/31/32/33) 全走这条兜底,
    正好对应"有些看板娘正常、有些一选就崩"。
    这里只借用字段结构, 身份相关字段一律重置为该女孩自己的主数据值。
    """
    _gmm = GIRL_MASTER_MAP.get(mid)
    if not _gmm:
        return None
    import copy as _copy_gm
    _tmpl = None
    for _resp in SERVER_DB.get("endpoints", {}).get("/v1/girl", []):
        _gl = _resp.get("girl_list") if isinstance(_resp, dict) else None
        if _gl:
            _tmpl = _gl[0]
            break
    if _tmpl is None:
        _pool = SERVER_DB.get("main_girl_by_mid", {})
        if _pool:
            _tmpl = list(_pool.values())[0].get("girl", {})
    if not isinstance(_tmpl, dict) or not _tmpl:
        return None
    g = _copy_gm.deepcopy(_tmpl)
    # --- 身份 ---
    g["owner_id"] = OWNER_ID
    g["girl_mid"] = mid
    # --- 穿戴: 一律用该女孩自己的主数据默认, 不继承模板女孩的任何装备 ---
    g["swimsuit_item_mid"] = _gmm.get("swimsuit", 0)
    g["hair_item_mid"] = _gmm.get("hair", 0)
    for _k in ("ring_item_mid", "addition_accessory_item_mid",
               "accessory_head_item_mid", "accessory_face_item_mid", "accessory_arm_item_mid"):
        g[_k] = 0
    # --- 视觉/身体状态: 全部归零, 客户端不会去查不存在的模型变体 ---
    for _k in ("visual_state_flag_a", "visual_state_flag_b", "visual_state_flag_c",
               "visual_state_flag_d", "sunburn", "wet",
               "hip_swing", "hip_press", "bust_swing", "bust_press",
               "hip_swing_lock", "hip_press_lock", "bust_swing_lock", "bust_press_lock",
               "skin_color", "nail_color", "display_coordinate", "panel_experience"):
        g[_k] = 0
    # --- 能力值: 用 girl_master, 不加成 ---
    g["power"] = _gmm.get("power", 1000)
    g["technic"] = _gmm.get("technic", 800)
    g["stamina"] = _gmm.get("stamina", 1000)
    g["appeal"] = _gmm.get("appeal", 20)
    for _k in ("additional_power", "additional_technic", "additional_stamina",
               "additional_appeal", "appeal_up"):
        g[_k] = 0
    g["mood"] = 0
    g["experience"] = 0
    g["level"] = 1
    g["affection_level"] = 1
    g["affection_point"] = 0
    g["venus_memory"] = 0
    g["girly"] = 0
    g["partner_count"] = 0
    g["created_at"] = "2019-03-28 11:15:12"
    g["updated_at"] = "2019-03-28 11:15:12"
    return g


def girl_obj_from_db(mid):
    """取某女孩的完整对象 (46字段): 抓包快照优先, 缺失则从 girl_master 自洽构造.

    2026-11-11: 不再对缺失女孩返回 None, 否则调用方会退化成"改 mid 的混血对象"。
    非法 mid (不在 GIRL_MASTER_MAP) 仍返回 None。
    """
    eps = SERVER_DB.get("endpoints", {})
    for resp in eps.get("/v1/girl", []):
        for g in resp.get("girl_list", []):
            if g.get("girl_mid") == mid:
                return dict(g)
    # 兜底: main_girl 池
    pool = SERVER_DB.get("main_girl_by_mid", {})
    if str(mid) in pool:
        return dict(pool[str(mid)].get("girl", {}))
    return _build_girl_from_master(mid)

# ===== 2026-11-13: 维纳斯图板 (Venus Board) 状态 / 发奖 =====
# 客户端协议: GET status / GET panel / POST update/status / POST open / GET|POST open/list
# 面板解锁状态按女孩分别保存在 STATE["venus_board"]["opened"][girl] = ["content:panel_id", ...]
_VENUS_ROWS_CACHE = {}

def venus_rows_for(girl_mid):
    """该女孩可用的面板行 (girl_mid=-1 为全女孩共用, 其余为专属)"""
    g = int(girl_mid)
    rows = _VENUS_ROWS_CACHE.get(g)
    if rows is None:
        rows = [r for r in VENUS_PANEL_ROWS if r["girl_mid"] in (-1, g)]
        _VENUS_ROWS_CACHE[g] = rows
    return rows

def venus_panel_key(row):
    return "%d:%d" % (row["content_mid"], row["panel_id"])

def venus_state():
    st = STATE.get("venus_board")
    if not isinstance(st, dict):
        st = {}
        STATE["venus_board"] = st
    if not isinstance(st.get("opened"), dict):
        st["opened"] = {}
    if not isinstance(st.get("seen"), dict):
        st["seen"] = {}
    if not isinstance(st.get("granted"), dict):
        st["granted"] = {}   # 已发过奖励的面板 (重置进度也不清, 防重复领取)
    st.setdefault("current_girl", 0)
    st.setdefault("maxed_at", None)
    st.setdefault("rewards_granted", False)
    return st

def venus_rewards_for(row, girl_mid):
    """某面板对该女孩的奖励 [(item_mid, count)]; 奖励组内 girl=-1 共用, 其余专属"""
    out = []
    for _gm, _im, _cnt in VENUS_REWARD_MAP.get(row.get("reward_group", 0), []):
        if _gm in (-1, int(girl_mid)):
            out.append((_im, _cnt))
    return out

def venus_grant_items(pairs):
    """把奖励写入背包/衣橱。
    - 35008(剧情 episode_mid) / 25001(扭蛋 gacha_mid) 的 count 是 ID 不是数量 → 只回填 reward_list;
    - 货币类型 → wallet; 普通消耗品 → item_counts; 装备 → equipment_inventory。
    返回可直接放进 venus_board_reward_list 的条目。"""
    wallet = STATE.setdefault("wallet", {})
    granted = []
    equip_jobs = []
    for im, cnt in pairs:
        try:
            im = int(im); cnt = int(cnt)
        except (TypeError, ValueError):
            continue
        if cnt <= 0:
            continue
        granted.append({"item_mid": im, "count": cnt})
        if im in _VENUS_ID_LIKE_ITEMS:
            continue
        _t = ITEM_TYPE_MAP.get(im)
        if _t is not None and _t in WALLET_CURRENCY_TYPES:
            _wf = WALLET_CURRENCY_MAP.get(_t)
            if _wf:
                wallet[_wf] = int(wallet.get(_wf, 0) or 0) + cnt
            else:
                ic_add(im, cnt)   # type=35 活动货币无钱包字段 → 进背包
        elif _t is not None:
            ic_add(im, cnt)
        else:
            _et = EQUIP_TYPE_MAP.get(im)
            if _et is None:
                ic_add(im, cnt)
            else:
                equip_jobs.append((im, _et, cnt))
    if equip_jobs:
        _inv = STATE.setdefault("equipment_inventory", [])
        _need = sum(n for _, _, n in equip_jobs)
        _ids = _alloc_equip_ids(_need)
        _k = 0
        for _im, _et, _n in equip_jobs:
            for _ in range(_n):
                _inv.append({
                    "id": _ids[_k], "item_mid": _im, "type": _et,
                    "level": 1, "experience": 0, "girl_mid": 0, "favorite": 0,
                    "in_lock": 0, "unlock_count": 0, "upgrade_count": 0,
                    "combine_count": 0,
                })
                _k += 1
    _save_state()
    return granted

def venus_unlock_all(grant=True):
    """把所有女孩的图板解锁到最大 (可选同时发放全部面板奖励)。返回新增面板数。"""
    if not VENUS_PANEL_ROWS:
        return 0   # 缺 csv_master 时不做任何事, 也不要把 bootstrap_done 置真
    st = venus_state()
    new_rows = 0
    pairs = {}
    for _g in sorted(GIRL_MASTER_MAP):
        _opened = set(st["opened"].get(str(_g)) or [])
        for _r in venus_rows_for(_g):
            _k = venus_panel_key(_r)
            if _k in _opened:
                continue
            _opened.add(_k)
            new_rows += 1
            _gkey = "%d:%s" % (_g, _k)
            if grant and _gkey not in st["granted"]:
                for _im, _c in venus_rewards_for(_r, _g):
                    pairs[_im] = pairs.get(_im, 0) + _c
            st["granted"][_gkey] = 1
        st["opened"][str(_g)] = sorted(_opened)
        st["seen"][str(_g)] = len(_opened)
    if grant and pairs:
        venus_grant_items(sorted(pairs.items()))
    st["maxed_at"] = server_now_str()
    st["rewards_granted"] = bool(grant)
    _save_state()
    print(f"[venus] 图板全解锁: 新增 {new_rows} 块, 奖励 {len(pairs)} 种")
    return new_rows

def venus_open_one(girl_mid, content_mid, panel_id, grant=True):
    """开一块面板; 已开过返回 newly=False 且不重复发奖。找不到返回 None。"""
    _g = int(girl_mid)
    _row = None
    for _r in venus_rows_for(_g):
        if int(panel_id) != _r["panel_id"]:
            continue
        if int(content_mid) not in (0, _r["content_mid"]):
            continue
        _row = _r
        break
    if _row is None:
        return None
    st = venus_state()
    _opened = set(st["opened"].get(str(_g)) or [])
    _k = venus_panel_key(_row)
    _newly = _k not in _opened
    _granted = []
    if _newly:
        _opened.add(_k)
        st["opened"][str(_g)] = sorted(_opened)
        _gkey = "%d:%s" % (_g, _k)
        if grant and _gkey not in st["granted"]:
            _pairs = venus_rewards_for(_row, _g)
            if _pairs:
                _granted = venus_grant_items(_pairs)
        st["granted"][_gkey] = 1
        _save_state()
    return {"row": _row, "newly": _newly, "granted": _granted, "girl_mid": _g}

def venus_panel_list():
    """所有女孩已解锁面板 (给 /v1/venus_board/panel)"""
    st = venus_state()
    out = []
    for _g in sorted(GIRL_MASTER_MAP):
        for _k in st["opened"].get(str(_g), []) or []:
            try:
                _c, _p = str(_k).split(":", 1)
                out.append({"content_mid": int(_c), "girl_mid": _g, "panel_id": int(_p)})
            except (ValueError, TypeError):
                continue
    return out

def venus_stats():
    st = venus_state()
    total = opened = 0
    girls = []
    for _g in sorted(GIRL_MASTER_MAP):
        _rows = venus_rows_for(_g)
        _op = set(st["opened"].get(str(_g)) or [])
        _n = sum(1 for _r in _rows if venus_panel_key(_r) in _op)
        total += len(_rows)
        opened += _n
        girls.append({"girl_mid": _g, "opened": _n, "total": len(_rows)})
    return {
        "total_panels": total,
        "opened_panels": opened,
        "maxed": (total > 0 and opened >= total),
        "rewards_granted": bool(st.get("rewards_granted")),
        "maxed_at": st.get("maxed_at"),
        "girls": girls,
    }

def venus_progress_payload(girl_mid, rows, granted):
    """open / open.list 的响应体 (字段名与真服抓包一致)"""
    _g = int(girl_mid)
    _girl = girl_obj_from_db(_g)
    if _girl:
        apply_girl_state(_girl)
    _aff_before = int(_girl.get("affection_point", 0)) if _girl else 0
    _aff_lv = int(_girl.get("affection_level", 1)) if _girl else 1
    _mem = int(_girl.get("venus_memory", 0)) if _girl else 0
    return {
        "affection_progress": {
            "affection_point_gain": 0,
            "affection_point_before": _aff_before,
            "affection_point_after": _aff_before,
            "affection_level_gain": 0,
            "affection_level_before": _aff_lv,
            "affection_level_after": _aff_lv,
        },
        "venus_memory_progress": {
            "venus_memory_before": _mem,
            "venus_memory_use": 0,
            "venus_memory_after": _mem,
        },
        "venus_board_reward_list": granted,
        "venus_board_girl_panel_list": [
            {"content_mid": _r["content_mid"], "girl_mid": _g, "panel_id": _r["panel_id"]}
            for _r in rows
        ],
        "girl_list": [_girl] if _girl else [],
        **({"episode_list": [
            {"episode_mid": _it["count"], "count": 0, "created_at": server_now_str()}
            for _it in granted if _it.get("item_mid") == 35008
        ]} if any(_it.get("item_mid") == 35008 for _it in granted) else {}),
    }

def _inject_state_wallet(resp):
    """GM 实时生效: 响应中含 wallet/wallet_list 时, 用 STATE 钱包覆盖
    客户端只在登录或交易时读钱包; 此函数让每次带钱包的响应都反映 GM 修改"""
    if not isinstance(resp, dict):
        return resp
    w = STATE.get("wallet")
    if not w:
        return resp
    import copy as _cp
    if "wallet" in resp and isinstance(resp["wallet"], dict):
        resp["wallet"] = _cp.deepcopy(w)
    if "wallet_list" in resp:
        resp["wallet_list"] = [_cp.deepcopy(w)]
    return resp

# ---- 2026-11-08: 查询类端点必须返回稳定快照, 不能每次请求轮换一份抓包 ----
# 病根: _pick_rotate 原本对全部端点一律推进游标, 于是"读当前状态"的接口每请求一次
#   就换一份不同时间点的抓包: mission/multiple 任务数 69/163/1011 来回跳、
#   owner/profile/list 好友 1/10/100 条、guestpoint/accept 领取点数 0/50、
#   honor 称号 179/184 条、gacha/ticket 券 14/15/16 种、quest/guest/list 13 份客串。
#   客户端会看到任务进度/好友/点数/称号乱跳, 有时还会拿到结构不同的响应。
# 做法: 只对这些端点固定取 pool[0] 且不推进游标; 不新增/删除任何字段,
#   各分支在 _pick_rotate 之后的 STATE 叠加(gacha 券库存、抽卡进度、女孩状态等)全部保留。
# 需要轮换的动作类端点(quest/start 阶段机、round/start、gacha/draw、present、
#   casino、giftbox/accept 等)不在表内, 行为完全不变。
# 池元素为 list 的端点(mission/8、option/item_auto_lock、owner/parameter/accept)
#   本身每次内容一致, 不入表以避免改变返回类型。
_STABLE_QUERY_ENDPOINTS = frozenset({
    # 任务
    # 2026-11-11b: 补 /2 /4 /5 —— 原来是"轮换", /5 在 28/29 条之间来回跳(多出一条任务),
    #   /4 的 8 份抓包虽然 id 相同但时间/param1 不同, 每请求一次面板内容就变一次。
    #   查询类端点必须固定快照, 与 /1 /3 /6 /7 /multiple 保持一致。
    "/v1/mission/multiple", "/v1/mission/1", "/v1/mission/2", "/v1/mission/3",
    "/v1/mission/4", "/v1/mission/5", "/v1/mission/6", "/v1/mission/7",
    "/v1/mission/reward_count",
    # 好友 / 客串 / 资料
    "/v1/friendship", "/v1/friendship/received", "/v1/friendship/sent",
    "/v1/owner/profile/list", "/v1/quest/guest/list",
    # 领取 / 检查 / 设置回执
    "/v1/owner/guestpoint/accept", "/v1/owner/checklogin", "/v1/owner/checkedat",
    "/v1/giftbox/count", "/v1/giftbox/fetch", "/v1/affection_reward",
    # 称号 / 抽卡 / 拍照点 / 商店 / 其它只读清单
    "/v1/honor", "/v1/gacha/ticket", "/v1/gacha/list", "/v1/photospot",
    "/v1/ranking/id/active", "/v1/shop/list", "/v1/owner_referral/get",
    "/v1/subscription", "/v1/information/global", "/v1/furniture/myset/home",
    "/v1/matching_pvp/active",
})


def _pick_rotate(pool, key):
    """从响应池轮换取一个, 返回 (resp, 是否成功)"""
    if not pool:
        return None, False
    # 查询类端点: 固定同一份快照, 不推进游标 (见上方注释)
    if key in _STABLE_QUERY_ENDPOINTS and isinstance(pool[0], dict):
        return pool[0], True
    # 2026-09-05: 游标从 STATE 持久化 (跨重启保持轮换进度)
    cursors = STATE.setdefault("dyn_cursors", {})
    i = cursors.get(key, 0) % len(pool)
    cursors[key] = i + 1
    return pool[i], True

def _quest_start_idx(mid):
    """读取 quest/start 游标 (持久化)"""
    return STATE.setdefault("quest_cursors", {}).setdefault(str(mid), {}).get("start", 0)

def _quest_end_idx(mid):
    """读取 quest/end 游标 (持久化)"""
    return STATE.setdefault("quest_cursors", {}).setdefault(str(mid), {}).get("end", 0)

def _set_quest_start_idx(mid, idx):
    STATE.setdefault("quest_cursors", {}).setdefault(str(mid), {})["start"] = idx

def _set_quest_end_idx(mid, idx):
    STATE.setdefault("quest_cursors", {}).setdefault(str(mid), {})["end"] = idx

# ---- 2026-11-08: 挑战赛战斗快照同步 (换女孩/换衣服后技能不再残留抓包旧值) ----
# 病根: quest/start、round/start、skip 的 girl_list 全是抓包账号(女孩11/13)的静态快照。
#   旧代码只改 girl_mid 与泳装 item_mid, equipment_list[*].skill_list / ywrk_skill_list /
#   rally_list[*].active_skill_list 仍是旧账号的技能 → 比赛里释放的还是原先的技能。
# 数据源(真实主数据 + 抓包, 非推测):
#   1) Equipment_Parameter.csv 的 col96/97/98 = 该装备自带的 3 个技能槽 (112 件抓包装备
#      中 71 件完全相等、31 件部分命中); skill.csv col2 = 全部合法 skill_mid(1..898)。
#   2) SERVER_DB 抓包战斗响应里的 equipment_list 完整对象(含 level/数值/skill_list),
#      112 件, 命中时直接复用, 100% 精确。
#   3) STATE.girl_equipment 里玩家当前穿戴的 *_item_mid (POST /v1/girl/{mid}/private 落库)。
_BATTLE_SLOT_FIELDS = {
    1: "swimsuit_item_mid",
    2: "accessory_head_item_mid",
    3: "accessory_face_item_mid",
    4: "accessory_arm_item_mid",
}
# 封印(seal)技能没有佩戴数据源 (fes_deck 的 main/sub seal_id 恒为 0), 抓包里
# team0 的 seal_skill_list 是别的账号的封印。默认把它们转成当前装备的普通技能,
# 避免"换了衣服仍释放旧封印技能"; 若客户端出现异常可置 False 回退。
_BATTLE_SYNC_SEAL = True
_BATTLE_DATA = None


def _battle_data():
    """惰性加载技能主数据 + 抓包战斗装备模板 (只在首次进入挑战赛时构建一次)"""
    global _BATTLE_DATA
    if _BATTLE_DATA is not None:
        return _BATTLE_DATA
    import csv as _csv
    skills, valid, templates = {}, set(), {}
    _dir = os.path.join(TOOL, "csv_master")
    try:
        with open(os.path.join(_dir, "skill.csv"), encoding="utf-8-sig", errors="replace") as f:
            for row in _csv.reader(f):
                if len(row) > 2 and row[2].isdigit():
                    valid.add(int(row[2]))
    except OSError:
        pass
    try:
        with open(os.path.join(_dir, "Equipment_Parameter.csv"), encoding="utf-8-sig", errors="replace") as f:
            for row in _csv.reader(f):
                if len(row) <= 98 or not row[0].isdigit():
                    continue
                s = []
                for i in (96, 97, 98):
                    v = int(row[i]) if row[i].isdigit() else 0
                    if v and v in valid and v not in s:
                        s.append(v)
                if s:
                    skills[int(row[0])] = s
    except OSError:
        pass

    def _collect(o):
        if isinstance(o, dict):
            for _key in ("equipment_list", "item_equipment_list"):
                el = o.get(_key)
                if isinstance(el, list):
                    for e in el:
                        if (isinstance(e, dict) and e.get("item_mid")
                                and isinstance(e.get("skill_list"), list) and e["skill_list"]):
                            templates.setdefault(e["item_mid"], e)
            for v in o.values():
                _collect(v)
        elif isinstance(o, list):
            for v in o:
                _collect(v)

    for _k in ("/v1/quest/start", "/v1/quest/volley/round/start", "/v1/quest/volley/skip"):
        for _obj in SERVER_DB.get("endpoints", {}).get(_k, []):
            _collect(_obj)
    _BATTLE_DATA = {"skills": skills, "templates": templates, "valid": valid}
    print(f"[*] 挑战赛战斗快照: 主数据技能 {len(skills)} 件, 抓包模板 {len(templates)} 件, 合法技能 {len(valid)} 个")
    return _BATTLE_DATA


def _current_quest_team():
    """当前出战队伍: {position: girl_mid}. 由 quest/start 请求写入 STATE, 重启后仍可用.

    没有记录时(玩家还没进过挑战赛)退回抓包的默认队伍, 保证首次进比赛也能同步装备技能。
    """
    t = STATE.get("quest_team") or {}
    if not t:
        t = (REAL_RESPONSES.get("/v1/quest/latest/team", {}) or {}).get("quest_latest_team", {}) or {}
    out = {}
    for pos, key in ((0, "girl_mid_forward"), (1, "girl_mid_back"), (6, "girl_mid_substitute")):
        v = t.get(key)
        try:
            v = int(v)
        except (TypeError, ValueError):
            v = 0
        if v and v > 0 and v in GIRL_MASTER_MAP:
            out[pos] = v
    return out


def _battle_skill_entry(skill_mid, sample=None):
    """按抓包 skill_list 条目结构生成一个技能项 (保留 level/潜力字段)"""
    e = {"skill_mid": skill_mid, "level": 5, "is_potential": False,
         "potential_level": 1, "polishing_count": 0}
    if isinstance(sample, dict):
        for k in ("level", "is_potential", "potential_level", "polishing_count"):
            if k in sample:
                e[k] = sample[k]
    return e


def _battle_equipment(slot_type, item_mid, template):
    """按当前穿戴的 item_mid 重建一件战斗装备(含技能); template 用于补齐客户端要求的字段."""
    import copy as _cp
    bd = _battle_data()
    if item_mid in bd["templates"]:
        obj = _cp.deepcopy(bd["templates"][item_mid])
        obj["type"] = slot_type   # 抓包模板的 type 就是槽位 1/2/3/4
        return obj
    if not isinstance(template, dict):
        for _t in bd["templates"].values():
            if _t.get("type") == slot_type:
                template = _t
                break
    obj = _cp.deepcopy(template) if isinstance(template, dict) else {}
    obj["type"] = slot_type
    obj["item_mid"] = item_mid
    sample = None
    sl = obj.get("skill_list")
    if isinstance(sl, list) and sl and isinstance(sl[0], dict):
        sample = sl[0]
    ids = bd["skills"].get(item_mid, [])
    obj["skill_list"] = [_battle_skill_entry(s, sample) for s in ids]
    return obj


def _sync_battle_girls(girl_list, team_map=None):
    """把 girl_list 里 team0(玩家方) 的女孩/装备/技能同步成当前选择.

    team_map: {position: girl_mid}; 缺省用 STATE.quest_team.
    只改玩家方, 对手(team1)保持抓包数据不动, 避免破坏比赛结算。
    """
    if not isinstance(girl_list, list):
        return 0
    if team_map is None:
        team_map = _current_quest_team()
    if not team_map:
        return 0
    _battle_data()
    changed = 0
    for g in girl_list:
        if not isinstance(g, dict) or g.get("team") != 0:
            continue
        pos = g.get("position")
        nm = team_map.get(pos)
        if not nm or nm not in GIRL_MASTER_MAP:
            continue   # 无选择记录 / 65535 之类的哨兵值: 保持抓包, 避免下发非法 girl_mid
        ge = STATE.get("girl_equipment", {}).get(str(nm), {}) or {}
        g["girl_mid"] = nm
        for dst, src in (("hair_mid", "hair_item_mid"),
                         ("ring_mid", "ring_item_mid"),
                         ("addition_accessory_mid", "addition_accessory_item_mid")):
            if dst in g:
                g[dst] = ge.get(src, 0) or 0
        el = g.get("equipment_list")
        if isinstance(el, list):
            by_type = {}
            for e in el:
                if isinstance(e, dict):
                    by_type.setdefault(e.get("type"), e)
            new_el = []
            for slot, field in _BATTLE_SLOT_FIELDS.items():
                im = ge.get(field) or 0
                if not im:
                    continue
                new_el.append(_battle_equipment(slot, im, by_type.get(slot)))
            for e in el:
                if isinstance(e, dict) and e.get("type") not in _BATTLE_SLOT_FIELDS:
                    new_el.append(e)
            g["equipment_list"] = new_el
            # ywrk_skill_list 是旧账号的套装技能, 只保留当前装备技能池里仍存在的
            pool = set()
            for e in new_el:
                for s in e.get("skill_list", []) if isinstance(e.get("skill_list"), list) else []:
                    if isinstance(s, dict) and s.get("skill_mid"):
                        pool.add(s["skill_mid"])
            yl = g.get("ywrk_skill_list")
            if isinstance(yl, list) and yl:
                g["ywrk_skill_list"] = [s for s in yl
                                        if isinstance(s, dict) and s.get("skill_mid") in pool]
        # 封印技能: 没有佩戴数据, 抓包里是别人账号的封印 → 清空(与卡组 seal_id=0 一致)
        if _BATTLE_SYNC_SEAL and "seal_skill_list" in g:
            g["seal_skill_list"] = []
        changed += 1
    return changed


def _sync_rally_skills(qvr, team_map=None):
    """把回合 rally_list[*].active_skill_list 里玩家方发动的技能换成当前装备技能.

    只替换玩家方条目的 skill_mid, 保留 delta_point/effect 等结算字段不动,
    避免结构变化引起客户端解析异常。封印条目(_BATTLE_SYNC_SEAL)转成普通技能条目。
    """
    if not isinstance(qvr, dict):
        return 0
    if team_map is None:
        team_map = _current_quest_team()
    if not team_map:
        return 0
    pool_by_pos = {}
    gl = qvr.get("girl_list") if isinstance(qvr.get("girl_list"), list) else []
    for g in gl:
        if not isinstance(g, dict) or g.get("team") != 0:
            continue
        ids = []
        for e in g.get("equipment_list", []) if isinstance(g.get("equipment_list"), list) else []:
            if isinstance(e, dict):
                for s in e.get("skill_list", []) if isinstance(e.get("skill_list"), list) else []:
                    if isinstance(s, dict) and s.get("skill_mid") and s["skill_mid"] not in ids:
                        ids.append(s["skill_mid"])
        pool_by_pos[g.get("position")] = ids
    changed = 0
    for rally in qvr.get("rally_list", []) if isinstance(qvr.get("rally_list"), list) else []:
        if not isinstance(rally, dict):
            continue
        for a in rally.get("active_skill_list", []) if isinstance(rally.get("active_skill_list"), list) else []:
            if not isinstance(a, dict) or a.get("team") != 0:
                continue
            ids = pool_by_pos.get(a.get("position")) or []
            if not ids:
                continue
            sk = ids[changed % len(ids)]
            a["skill_mid"] = sk
            if "effect_skill_mid" in a:
                a["effect_skill_mid"] = sk
            if _BATTLE_SYNC_SEAL and a.get("seal_mid"):
                a["seal_mid"] = 0
                if "seal_sub_flag" in a:
                    a["seal_sub_flag"] = 0
                if "seal_rarity" in a:
                    a["seal_rarity"] = 0
            changed += 1
    return changed


# ---- 2026-09-12: 挑战赛动态比赛状态 (替代静态轮换, 解决 round_number 乱序 → -603) ----
_MATCH_STATE = {}   # {quest_mid, match_point, current_round, acc_pp, acc_op, acc_pa, acc_oa, rounds}

def _init_match(quest_mid, match_point):
    """quest/start phase 3 时初始化比赛状态"""
    global _MATCH_STATE
    # 2026-09-12: 优先从 CSV 查正确的 match_point (避免 fallback 响应里的错误值)
    try:
        qm = int(quest_mid) if quest_mid else 0
        if qm in _QUEST_MATCH:
            match_point = _QUEST_MATCH[qm]
    except (ValueError, TypeError):
        pass
    _MATCH_STATE = {
        "quest_mid": quest_mid,
        "match_point": max(match_point or 3, 1),
        "current_round": 1,
        "acc_pp": 0,       # 累积玩家得分
        "acc_op": 0,       # 累积对手得分
        "acc_pa": 0,       # 累积玩家 appeal point
        "acc_oa": 0,       # 累积对手 appeal point
        "rounds": [],      # 已打的回合数据 (用于 skip)
    }

def _gen_round(eps, round_num, acc_pp, acc_op, acc_pa):
    """从模板生成一个一致的 round/start 响应"""
    pool = eps.get("/v1/quest/volley/round/start", [])
    if not pool:
        return None
    import copy as _copy
    resp = _copy.deepcopy(pool[0])
    qvr = resp.get("quest_volley_round", {})
    if not qvr:
        return None
    # 玩家赢这局
    appeal = 700 + round_num * 150   # 递增的 appeal (合理值)
    qvr["round_number"] = round_num
    qvr["timeout_left"] = 3          # 2026-09-12: 和私服一致(模板值1会导致自动跳过)
    qvr["player_point"] = 1
    qvr["opponent_point"] = 0
    qvr["acc_player_point"] = acc_pp
    qvr["acc_opponent_point"] = acc_op
    qvr["player_appeal_point"] = appeal
    qvr["opponent_appeal_point"] = 0
    qvr["acc_player_appeal_point"] = acc_pa
    qvr["acc_opponent_appeal_point"] = 0
    qvr["fever_player_appeal_point"] = 0
    qvr["acc_fever_player_appeal_point"] = 0
    qvr["fever_opponent_appeal_point"] = 0
    qvr["acc_fever_opponent_appeal_point"] = 0
    # 2026-11-08: 每回合都要按当前队伍/装备重建技能快照, 否则客户端释放抓包账号的旧技能
    _sync_battle_girls(qvr.get("girl_list"))
    _sync_rally_skills(qvr)
    return resp

def _build_volley_dynamic(path, eps):
    """动态生成排球回合响应 (替代 _pick_rotate 静态轮换)"""
    global _MATCH_STATE
    if not _MATCH_STATE:
        return None   # 无比赛状态, 回退到上层
    ms = _MATCH_STATE
    mp = ms["match_point"]

    if path == "/v1/quest/volley/round/start":
        rn = ms["current_round"]
        resp = _gen_round(eps, rn, ms["acc_pp"], ms["acc_op"], ms["acc_pa"])
        if resp is None:
            return None
        # 更新状态
        ms["current_round"] = rn + 1
        ms["acc_pp"] = ms["acc_pp"] + 1
        ms["acc_pa"] = ms["acc_pa"] + 700 + rn * 150
        ms["rounds"].append(resp.get("quest_volley_round", {}))
        return resp

    if path == "/v1/quest/volley/round/end":
        # match_point 达到 → 比赛结束
        status = 2 if ms["acc_pp"] >= mp else 1
        return {"quest_volley_round_end": {"status": status}}

    if path == "/v1/quest/volley/skip":
        # 跳过: 补齐剩余回合, 玩家全赢
        import copy as _copy
        pool = eps.get(path, [])
        template = _copy.deepcopy(pool[0]) if pool else {"quest_volley_round_list": {"status": 2, "round_list": []}}
        rl = template.get("quest_volley_round_list", {})
        round_list = list(ms.get("rounds", []))
        # 补齐到 match_point
        while ms["acc_pp"] < mp:
            rn = ms["current_round"]
            rd = _gen_round(eps, rn, ms["acc_pp"], ms["acc_op"], ms["acc_pa"])
            if rd is None:
                break
            qvr = rd.get("quest_volley_round", {})
            ms["current_round"] = rn + 1
            ms["acc_pp"] = ms["acc_pp"] + 1
            ms["acc_pa"] = ms["acc_pa"] + 700 + rn * 150
            round_list.append(qvr)
        rl["status"] = 2
        rl["round_list"] = round_list
        template["quest_volley_round_list"] = rl
        return template

    return None

# ---- 2026-09-12: 从 CSV 加载 quest 配置 (match_point, 评级阈值, 奖励) ----
_QUEST_MATCH = {}     # quest_mid(int) -> match_point(int)
_QUEST_RANK = {}      # quest_mid(int) -> (rank_border_id, S, A, B)
_QUEST_CATEGORY = {}  # quest_mid(int) -> category(int)  (col4: 2=主线, 3=每日/活动)

def _load_quest_tables():
    """从 csv_master 加载 QuestMatchData + QuestData(评级) 查找表"""
    global _QUEST_MATCH, _QUEST_RANK, _QUEST_CATEGORY
    import csv as _csv
    csv_dir = os.path.join(TOOL, "csv_master")
    # QuestMatchData: col0=quest_mid, col6=match_point
    qm_path = os.path.join(csv_dir, "QuestMatchData.csv")
    if os.path.exists(qm_path):
        with open(qm_path, encoding="utf-8-sig", errors="replace") as f:
            for row in _csv.reader(f):
                if row and len(row) > 6:
                    try:
                        _QUEST_MATCH[int(row[0])] = int(row[6])
                    except (ValueError, IndexError):
                        pass
        print(f"[*] 已加载 QuestMatchData: {len(_QUEST_MATCH)} 个 quest 的 match_point")
    # QuestData: col0=quest_mid, col15=rank_border_id
    qd_path = os.path.join(csv_dir, "QuestData.csv")
    if os.path.exists(qd_path):
        with open(qd_path, encoding="utf-8-sig", errors="replace") as f:
            for row in _csv.reader(f):
                if row and len(row) > 15:
                    try:
                        _qid = int(row[0])
                        _QUEST_RANK[_qid] = int(row[15])
                        if len(row) > 4:
                            _QUEST_CATEGORY[_qid] = int(row[4])
                    except (ValueError, IndexError):
                        pass
        print(f"[*] 已加载 QuestData rank_border: {len(_QUEST_RANK)} 个 quest")
    # QuestRankBorderData: col0=rank_border_id, col2=S, col4=A, col6=B
    _RANK_BORDER = {}
    rb_path = os.path.join(csv_dir, "QuestRankBorderData.csv")
    if os.path.exists(rb_path):
        with open(rb_path, encoding="utf-8-sig", errors="replace") as f:
            for row in _csv.reader(f):
                if row and len(row) > 6:
                    try:
                        _RANK_BORDER[int(row[0])] = (int(row[2]), int(row[4]), int(row[6]))
                    except (ValueError, IndexError):
                        pass
        print(f"[*] 已加载 QuestRankBorderData: {len(_RANK_BORDER)} 个评级边界")
    # 合并: quest_mid -> (S, A, B)
    for mid, rbid in _QUEST_RANK.items():
        if rbid in _RANK_BORDER:
            _QUEST_RANK[mid] = _RANK_BORDER[rbid]   # 替换为 (S, A, B) 元组

# 2026-09-14: 维纳斯商店购买映射 (ShopItemDetail: item_id(=exchange的product_mid) -> [(detail_id, count)])
# 实测铁证: 私服版 POST /v1/shop/exchange/43143 → 获得 item 4818, 对应 L45940: "46157","43143","4818","1"
SHOP_DETAIL_MAP = {}
_sd_path = os.path.join(TOOL, "csv_master", "ShopItemDetail.csv")
if os.path.exists(_sd_path):
    import csv as _sd_csv
    with open(_sd_path, encoding="utf-8-sig", errors="replace") as f:
        for row in _sd_csv.reader(f):
            if row and len(row) >= 3:
                try:
                    SHOP_DETAIL_MAP.setdefault(int(row[1]), []).append(
                        (int(row[2]), int(row[3]) if len(row) > 3 and row[3] else 1))
                except (ValueError, IndexError):
                    pass
    print(f"[*] 已加载 ShopItemDetail 购买映射: {len(SHOP_DETAIL_MAP)} 个商品")

def _mark_claimed(kind, key):
    """记录已领取 (用于礼物/任务奖励等)"""
    STATE.setdefault("claimed", {})[f"{kind}:{key}"] = server_now().isoformat()

def _is_claimed(kind, key):
    return f"{kind}:{key}" in STATE.get("claimed", {})

def _build_giftbox(path, req, method="POST"):
    """邮箱完整逻辑: 领取持久化, count/fetch/accept/history 一致
    数据源: server_response_db 的 giftbox 真实邮件 (25封), STATE 记录已领取id
    源码依据: 客户端解析器 sub_1424C3B60 不读 accepted_at 判断已领 → 已领邮件必须从列表移除

    2026-09-12 修复: accept 响应的 item_consume_list / wallet_list 与真实服务器一致
      - type: 从 Consume_Parameter.csv 查物品类别 (不再用 message_type)
      - count: 返回领取后总库存 (不再用邮件里的 count)
      - 货币类物品: 更新钱包, 不入 item_consume_list (与真实抓包一致)
      - wallet_list: 返回 STATE 追踪的钱包 (不再用静态模板)
    """
    import copy as _cp
    db_eps = SERVER_DB.get("endpoints", {})

    # 基础邮件列表 (取响应池第一个变体的 giftbox_list)
    base_mails = []
    pool = db_eps.get("/v1/giftbox", [])
    for p in pool:
        gl = p.get("giftbox_list", [])
        if gl:
            base_mails = gl
            break

    # 2026-11-12: GM 面板「重置邮箱」= 清空邮箱。除了清 custom_mails 与 claimed,
    # 还要把抓包内置的 25 封也隐藏掉, 否则"清空"后邮箱里又会冒出这 25 封。
    # 这是纯显示开关, 删 state 里的 giftbox_hide_builtin 即全部恢复。
    if STATE.get("giftbox_hide_builtin"):
        base_mails = []

    # 2026-09-13: 合并 GM 自定义邮件
    _custom = STATE.get("custom_mails", [])
    if _custom:
        base_mails = list(base_mails) + [_cp.deepcopy(m) for m in _custom]

    # 已领取 id 集合 (STATE 持久化)
    claimed = STATE.setdefault("giftbox_claimed", [])
    claimed_set = set(claimed)

    def unclaimed_mails():
        """只返回未领取的邮件 (已领的从列表移除, 客户端据此显示待领取)"""
        return [_cp.deepcopy(m) for m in base_mails if m.get("id") not in claimed_set]

    # ---- 领取处理 (accept / force_accepted 共用): 标记已领 + 发奖 ----
    def _grant_mails(ids):
        """对每封邮件: 已领/不存在 → not_accept; 否则标记已领 + 按物品类型发奖。
        返回 (not_accept, history, item_consume)。"""
        not_accept = []
        history = []
        item_consume = []
        now_ts = "2026-09-06 09:00:00"
        wallet = STATE.setdefault("wallet", {})
        item_counts = STATE.setdefault("item_counts", {})
        for mid in ids:
            mail = next((m for m in base_mails if m.get("id") == mid), None)
            if mail is None:
                not_accept.append(mid)
                continue
            # 已领取的邮件: 不重复发奖 (防双重领取)
            if mid in claimed_set:
                not_accept.append(mid)
                continue
            # 标记已领取
            claimed.append(mid)
            claimed_set.add(mid)
            # 历史记录
            h = _cp.deepcopy(mail)
            h["accepted_at"] = now_ts
            history.append(h)
            # 物品分类: 货币 / 普通消耗品 / 特殊物品(装备泳装)
            item_mid = mail.get("item_mid")
            mail_count = mail.get("count", 1)
            item_type = ITEM_TYPE_MAP.get(item_mid)
            if item_type is not None and item_type in WALLET_CURRENCY_TYPES:
                # 货币类: 更新钱包, 不入 item_consume_list (与真实抓包一致)
                wfield = WALLET_CURRENCY_MAP.get(item_type)
                if wfield:
                    wallet[wfield] = wallet.get(wfield, 0) + mail_count
                # type=35 (活动货币) 无标准钱包字段, 仅标记已领不更新钱包
            elif item_type is not None:
                # 普通消耗品: 更新库存总量, 入 item_consume_list
                new_count = item_counts.get(item_mid, 0) + mail_count
                item_counts[item_mid] = new_count
                item_consume.append({
                    "item_mid": item_mid,
                    "count": new_count,
                    "type": item_type,
                    "updated_at": now_ts,
                    "created_at": mail.get("created_at"),
                })
            else:
                # 2026-09-28: 装备/泳装等特殊物品 (不在 Consume_Parameter) → 加 equipment_inventory
                _ei = STATE.setdefault("equipment_inventory", [])
                _max_eid = max((e.get("id", 0) for e in _ei if isinstance(e, dict)), default=0)
                _ei.append({
                    "id": _max_eid + 1, "item_mid": item_mid,
                    "type": ITEM_TYPE_MAP.get(item_mid, 0),
                    "level": 1, "experience": 0, "girl_mid": 0, "favorite": 0,
                    "in_lock": 0, "unlock_count": 0, "upgrade_count": 0, "combine_count": 0
                })
        _save_state()
        return not_accept, history, item_consume

    # ---- GET /v1/giftbox: 邮件列表 (只含未领取) ----
    if path == "/v1/giftbox" and method == "GET":
        return {"giftbox_list": unclaimed_mails()}

    # ---- GET /v1/giftbox/count: 未领取邮件数 ----
    if path == "/v1/giftbox/count":
        unclaimed = sum(1 for m in base_mails if m.get("id") not in claimed_set)
        return {"giftbox_received_count": unclaimed}

    # ---- POST /v1/giftbox/fetch: 获取邮件 (游戏打开邮箱时, 只含未领取) ----
    if path == "/v1/giftbox/fetch":
        mails = unclaimed_mails()
        rp = REAL_RESPONSES.get("/v1/giftbox/fetch", {})
        ocal = rp.get("owner_checked_at_list", [])
        return {"giftbox_fetch_list": mails, "owner_checked_at_list": ocal}

    # ---- POST /v1/giftbox/accept: 领取邮件 -> 物品进背包/钱包 + 标记已领 ----
    if path == "/v1/giftbox/accept":
        # 请求体字段名 (实测): {"id_list":[...]} 或 {"giftbox_accept_id_list":[...]}
        accept_ids = req.get("id_list") or req.get("giftbox_accept_id_list") or []
        if isinstance(accept_ids, int):
            accept_ids = [accept_ids]
        accept_ids = list(accept_ids)  # 复制, 避免修改请求体原始列表
        gid = req.get("giftbox_id")
        if gid is not None:
            accept_ids.append(gid)
        accept_ids = [int(i) for i in accept_ids if i]

        not_accept, history, item_consume = _grant_mails(accept_ids)

        # 钱包: 返回当前 STATE 钱包 (而非静态模板)
        wallet = STATE.get("wallet", {})
        wallet_out = [dict(wallet)] if wallet else []
        updated_mails = unclaimed_mails()
        return {
            "giftbox_accept_id_list": accept_ids,
            "giftbox_not_accept_id_list": not_accept,
            "giftbox_history_list": history,
            "giftbox_list": updated_mails,
            "wallet_list": wallet_out,
            "item_consume_list": item_consume,
        }

    # ---- POST /v1/giftbox/force_accepted: 客户端强制领取 (2026-11-12 新增) ----
    # 实测: 客户端认为某封邮件必须强制领取时(如登录后/期限异常)会发本端点,
    # 并期待邮件从列表消失。之前无处理 → 通用兜底 {"status":"success"} 但邮件仍在
    # → 客户端无限重试 fetch/force_accepted (~30次/秒) → 邮箱界面卡死。
    # 处理: 与 accept 相同(标记已领 + 正常发奖, 奖励不丢失), 返回 success。
    if path == "/v1/giftbox/force_accepted":
        fa_ids = req.get("id_list") or req.get("giftbox_accept_id_list") or []
        if isinstance(fa_ids, int):
            fa_ids = [fa_ids]
        fa_ids = [int(i) for i in fa_ids if i]
        _grant_mails(fa_ids)
        return {"status": "success"}

    # ---- GET /v1/giftbox/history: 已领取历史 ----
    if path == "/v1/giftbox/history":
        history = []
        for m in base_mails:
            if m.get("id") in claimed_set:
                h = _cp.deepcopy(m)
                h["accepted_at"] = "2026-09-06 09:00:00"
                history.append(h)
        return {"giftbox_history_list": history}

    return None

# 2026-09-14: 端点→红点checked_at字段映射 (GET查看该端点=查看该红点, 更新对应时间戳使红点灭)
# 注: 仅列确定映射; news/quest/event/notification等不确定的留待反编译确认后再补
_ENDPOINT_CHECKED_MAP = {
    "/v1/giftbox": "giftbox_checked_at",
    "/v1/giftbox/fetch": "giftbox_checked_at",
    "/v1/friendship": "friendship_checked_at",
    "/v1/friendship/received": "friendship_checked_at",
    "/v1/honor": "honor_checked_at",
    "/v1/subscription": "subscription_checked_at",
}

# ---- 2026-11-12: 岛主资料 (岛主名 / 岛名 / 留言) 可编辑 ----
# 背景: /v1/owner 与 /v1/owner/updatelogin 都是抓包静态快照, 客户端改完名字保存后
# 服务端只回放旧值 -> 重进游戏就还原。实测客户端点了确认确实会发 PUT /v1/owner
# (body 如 {"island_name":"x"} / {"name":"y"}), 所以这里两条路都打通:
#   1) PUT /v1/owner 收到的字段写入 STATE["owner_profile"];
#   2) 所有 owner 响应统一套 STATE["owner_profile"] 覆盖层。
# GM 面板「存档状态总览 → 岛主资料」直接写同一份 STATE, 不依赖客户端门槛。
OWNER_PROFILE_FIELDS = ("name", "island_name", "message")


def _owner_profile():
    op = STATE.get("owner_profile")
    return op if isinstance(op, dict) else {}


def _apply_owner_profile(o):
    """把 STATE.owner_profile 的字段覆盖到单个 owner 对象上 (原地修改)"""
    if not isinstance(o, dict):
        return o
    op = _owner_profile()
    for _f in OWNER_PROFILE_FIELDS:
        if _f in op and op[_f] not in (None, ""):
            o[_f] = op[_f]
    return o


def _apply_state_overlay(path, method=None, req=None):
    """状态叠加: /v1/owner /v1/room /v1/girl 注入当前主女孩和装备状态。
    返回响应或 None(不处理)。
    2026-09-13: 增加 method 参数, 让 favorite 等 POST 端点放行给 _build_dynamic 处理
    2026-11-12: 增加 req 参数, /v1/owner 的 PUT 改名需要读请求体"""
    # ---- 2026-11-08: /v1/photospot 场景全解锁 ----
    # 原理: photo_spot_list 里"存在 (photo_spot_mid, girl_mid) 条目"= 该女孩在该场景已解锁(可拍)。
    #   原走 REAL_RESPONSES 静态快照: 只 33 个女孩的部分场景, 且含 girl_mid=34 (客户端 2..33 才有,
    #   34 是抓包账号的脏数据) → 场景列表一半是灰的, 脏 girl 还可能让客户端查不到对象。
    # 现改为: 32 个女孩 × 全部合法场景号, created_at 用固定历史时间(不参与判定, 只用于排序显示)。
    if path == "/v1/photospot" and (method or "GET") == "GET":
        _psl = []
        # created_at 只是排序/显示用, 不参与解锁判定。用 2018 年的固定值: 远离 normalize_dates
        # 的 RECENT_DAYS(2700天) 窗口, 不会被改写成"今天"(否则 704 条全挤在同一天)。
        _ts_sp = "2018-01-01 00:00:00"
        for _g in sorted(GIRL_MASTER_MAP):
            for _sid in _photospot_all_ids():
                _psl.append({"photo_spot_mid": _sid, "girl_mid": _g, "created_at": _ts_sp})
        return {"photo_spot_list": _psl}
    # /v1/owner 返回当前主女孩
    if path == "/v1/owner" or path == "/v1/owner/updatelogin":
        # 2026-11-12: 客户端"更改岛主名 / 岛名 / 留言"实际发的是 PUT /v1/owner,
        # body 形如 {"name":"x"} / {"island_name":"y"} / {"message":"z"}。
        # 旧实现无视 method 直接回放快照 -> 改了不生效。这里先落盘再回写。
        if method == "PUT" and isinstance(req, dict):
            _op = STATE.get("owner_profile")
            if not isinstance(_op, dict):
                _op = STATE["owner_profile"] = {}
            _chg = False
            for _f in OWNER_PROFILE_FIELDS:
                if _f in req and req[_f] is not None:
                    _v = str(req[_f])[:50]
                    if _v != _op.get(_f):
                        _op[_f] = _v
                        _chg = True
            if _chg:
                _save_state()
        # 2026-09-11 修复: 浅拷贝会改原始 REAL_RESPONSES, 改用 deepcopy
        import copy as _copy_own
        base = _copy_own.deepcopy(REAL_RESPONSES.get(path, {"owner": {}}))
        owner = base.get("owner", {})
        if isinstance(owner, dict):
            owner["main_girl_mid"] = STATE.get("main_girl_mid", 3)
            owner["level"] = 300; owner["license_level"] = 99; owner["license_point"] = 999999
            owner["checked_license_level"] = 99; owner["stamina"] = 999
            _apply_owner_profile(owner)
        elif isinstance(owner, list):
            for o in owner:
                o["main_girl_mid"] = STATE.get("main_girl_mid", 3)
                o["level"] = 300; o["license_level"] = 99; o["license_point"] = 999999
                o["checked_license_level"] = 99; o["stamina"] = 999
                _apply_owner_profile(o)
        # owner_list 型 (updatelogin 的真实结构, 实测): 逐个注入 STATE 主女孩
        # 2026-09-10 修复: 此前只处理 owner, 漏 owner_list → 返回原始 main=3 → 客户端进岛回退穗香
        olist = base.get("owner_list")
        if isinstance(olist, list):
            for o in olist:
                if isinstance(o, dict):
                    o["main_girl_mid"] = STATE.get("main_girl_mid", 3)
                    o["level"] = 300; o["license_level"] = 99; o["license_point"] = 999999
                    o["checked_license_level"] = 99; o["stamina"] = 999
                    _apply_owner_profile(o)
        # 2026-11-07: last_logged_at 必须是"真实的 UTC 现在" — 客户端按 UTC 解析后算"距上次登录多久".
        # 旧实现用 game_today_str()(游戏日标签) + 本地时分 -> 北京 15:00 时写出 "D 15:00" = 客户端眼中的
        # D 23:00 (未来 16 小时) -> 判定未来日期 -> 走未实现的跨日回归分支 -> 卡死。
        _ll_today = game_now_str()
        if isinstance(owner, dict):
            owner["last_logged_at"] = _ll_today
        elif isinstance(owner, list):
            for o in owner:
                if isinstance(o, dict):
                    o["last_logged_at"] = _ll_today
        if isinstance(olist, list):
            for o in olist:
                if isinstance(o, dict):
                    o["last_logged_at"] = _ll_today
        return base
    # /v1/room 及所有子路径 (如 /v1/room/girl/friendly) 注入当前主女孩
    if path == "/v1/room" or path.startswith("/v1/room/"):
        # 用动态响应池或 REAL_RESPONSES 的 room 响应作为基底
        eps = SERVER_DB.get("endpoints", {})
        pool = eps.get(path) or eps.get("/v1/room")
        base = None
        if pool:
            base, _ = _pick_rotate(pool, path)
        if not base:
            base = dict(REAL_RESPONSES.get("/v1/room", {"owner_room": {}}))
        import copy as _copy
        resp = _copy.deepcopy(base)
        # 递归找 owner_room 字段
        _or_st = STATE.get("owner_room") or {}
        def _patch(obj):
            if isinstance(obj, dict):
                if "owner_room" in obj and isinstance(obj["owner_room"], dict):
                    obj["owner_room"]["main_girl_mid"] = STATE.get("main_girl_mid", 3)
                    # 2026-11-11b: 副女孩也以 STATE 为准 (池里是抓包时的旧副女孩, 换过不同步)
                    if _or_st.get("sub_girl_mid"):
                        obj["owner_room"]["sub_girl_mid"] = _or_st["sub_girl_mid"]
                for v in obj.values():
                    _patch(v)
            elif isinstance(obj, list):
                for x in obj:
                    _patch(x)
        _patch(resp)
        return resp
    # /v1/girl 女孩列表叠加装备状态
    if path == "/v1/girl":
        eps = SERVER_DB.get("endpoints", {})
        pool = eps.get(path)
        base_resp = None
        if pool:
            base_resp, _ = _pick_rotate(pool, path)
        if not base_resp:
            base_resp = REAL_RESPONSES.get(path, {"girl_list": []})
        import copy as _copy
        resp = _copy.deepcopy(base_resp)
        for g in resp.get("girl_list", []):
            apply_girl_state(g)
        # 2026-09-16: 解锁所有女孩 — /v1/girl 响应默认只有20个, 从 girl_master 构造所有缺失女孩
        # 2026-11-11: 改用 _build_girl_from_master 的自洽对象 (旧实现是"模板改 mid",
        #   残留模板女孩的发型/视觉字段, 客户端点进这些女孩的主页会白屏/闪退)
        _existing_gmids = {g.get("girl_mid") for g in resp.get("girl_list", [])}
        for _ugm in sorted(GIRL_MASTER_MAP):
            if _ugm not in _existing_gmids:
                _tmpl = _build_girl_from_master(_ugm)
                if _tmpl is None:
                    continue
                apply_girl_state(_tmpl)
                resp.setdefault("girl_list", []).append(_tmpl)
        global GIRL_RESP_ORDER
        GIRL_RESP_ORDER = [_venus_int(_g.get("girl_mid"))
                           for _g in resp.get("girl_list", []) if _venus_int(_g.get("girl_mid"))]
        return resp
    # ===== 2026-11-13: 维纳斯图板 (Venus Board) =====
    # 真服端点(二进制字符串实证): status / panel / update/status / open / open/list / exchange
    if path.startswith("/v1/venus_board/"):
        _vst = venus_state()
        _vreq_g = 0
        if isinstance(req, dict):
            try:
                _vreq_g = int(req.get("girl_mid") or 0)
            except (TypeError, ValueError):
                _vreq_g = 0
        _vgirl = _vreq_g or int(_vst.get("current_girl") or 0) or int(STATE.get("main_girl_mid", 3))
        if GIRL_MASTER_MAP and _vgirl not in GIRL_MASTER_MAP:
            _vgirl = int(STATE.get("main_girl_mid", 3))
            if _vgirl not in GIRL_MASTER_MAP:
                _vgirl = sorted(GIRL_MASTER_MAP)[0]

        # GET /v1/venus_board/status → 当前图板女孩 (真服抓包只回一条)
        if path == "/v1/venus_board/status" and method == "GET":
            _vst["current_girl"] = _vgirl
            return {"venus_board_status_list": [{"girl_mid": _vgirl}]}

        # POST /v1/venus_board/update/status {girl_mid} → 记录当前图板女孩
        if path == "/v1/venus_board/update/status" and method == "POST":
            _vst["current_girl"] = _vgirl
            _save_state()
            return {"venus_board_status_list": [{"girl_mid": _vgirl}]}

        # GET /v1/venus_board/panel → 所有女孩已解锁面板 (客户端据此绘制亮起的看板)
        if path == "/v1/venus_board/panel" and method == "GET":
            return {"venus_board_girl_panel_list": venus_panel_list()}

        # POST /v1/venus_board/open {content_mid, panel_id} → 解锁一块看板并领取该看板奖励
        if path == "/v1/venus_board/open" and method == "POST":
            _vc = _venus_int((req or {}).get("content_mid"))
            _vp = _venus_int((req or {}).get("panel_id"))
            _res = venus_open_one(_vgirl, _vc, _vp)
            if _res is None:
                print(f"[venus] open 未知看板 girl={_vgirl} content={_vc} panel={_vp}")
                return venus_progress_payload(_vgirl, [], [])
            # 已开过的看板也回填到 panel_list: 客户端据此判定"这块是亮的",
            # 避免重复点击时拿到空列表 → 误判成领取失败 / 看板又变暗。
            _payload = venus_progress_payload(_vgirl, [_res["row"]], _res["granted"])
            if _res["newly"]:
                print(f"[venus] girl={_vgirl} 解锁 {_vc}:{_vp} "
                      f"奖励={[(g['item_mid'], g['count']) for g in _res['granted']][:8]}")
            return _payload

        # open/list: POST=批量解锁(面板 "全部领取"); GET=已解锁清单
        if path == "/v1/venus_board/open/list":
            if method == "GET":
                _lst = venus_panel_list()
                _grouped = {}
                for _x in _lst:
                    _grouped.setdefault((_x["girl_mid"], _x["content_mid"]), []).append(_x["panel_id"])
                return {
                    "venus_board_girl_panel_list": _lst,
                    "venus_board_open_list": [
                        {"girl_mid": _gk[0], "content_mid": _gk[1], "panel_id_list": _pl}
                        for _gk, _pl in sorted(_grouped.items())
                    ],
                }
            _vpids = (req or {}).get("panel_id_list") or []
            if not isinstance(_vpids, list):
                _vpids = [_vpids]
            _vc = _venus_int((req or {}).get("content_mid"))
            _rows, _granted, _seen = [], [], set()
            _seen_rows = set()
            for _p in _vpids:
                _r = venus_open_one(_vgirl, _vc, _venus_int(_p))
                if _r is None:
                    continue
                _pk = venus_panel_key(_r["row"])
                if _pk not in _seen_rows:
                    _seen_rows.add(_pk)
                    _rows.append(_r["row"])
                for _it in _r["granted"]:
                    _k2 = (_it.get("item_mid"), _it.get("count"))
                    if _k2 not in _seen:
                        _seen.add(_k2)
                        _granted.append(_it)
            if _rows:
                print(f"[venus] girl={_vgirl} 批量解锁 {len(_rows)} 块 (open/list)")
            return venus_progress_payload(_vgirl, _rows, _granted)

    # ===== 2026-11-13: 亲爱度报酬领取 (POST /v1/affection_reward {content_mid, girl_mid}) =====
    # 真服响应必须同时含 4 个字段, 少一个客户端就"领取成功但列表空白":
    #   affection_levelup_reward_list  弹窗逐条奖励 (逐级一行, 这才是"获得奖励"列表的数据源)
    #   girl_status_progress           四维 before/gain/after
    #   affection_level_reward_list    accepted_level (决定"领取"按钮是否还亮)
    #   girl_list                      该女孩最新数据
    # ===== 2026-11-13: 亲爱度报酬「已领到第几级」查询 (GET /v1/affection_reward) =====
    # 2026-11-13 二次修复: GET 原来落到静态抓包(accepted_level 恒 0) → 客户端认为还没领,
    #   领完按钮还亮着, 再点一次没有任何新条目 → 弹窗空白。必须按 STATE 回真实进度。
    # 2026-11-13 七次修复(决定性证据: real_responses.json 的真服样本):
    #   真服 affection_level_reward_list **只含「仍有未领报酬」的女孩**, 领完的整条消失
    #   —— 样本里 girl 3 只出现在"未领"快照(accepted_level=0), 已领到 LV.2 的
    #   11/13/15/18 在后续快照里才带 accepted_level=2, 而 girl 3 已不在列表里。
    #   之前一律回全量 32 条 → 客户端永远能在列表里找到当前女孩 → 按钮/红点常亮,
    #   可以无限重复领取; 再点又命中"回退历史全量条目"→ "重复领取居然有奖励"。
    #   正确语义: 逐女孩过滤, 全部领完 → 空数组 → 按钮自然消失。
    def _aff_pending(girls):
        _acc = STATE.get("affection_accepted") or {}
        _out = []
        for _g in girls:
            # apply_girl_state 无条件把 affection_level 设为 CAP, 这里直接用常量即可
            _acp = min(_venus_int(_acc.get(str(_g))), _AFFECTION_LEVEL_CAP)
            if _AFFECTION_LEVEL_CAP > 1 and _acp < _AFFECTION_LEVEL_CAP:
                _out.append({"content_mid": 1, "girl_mid": _g,
                             "accepted_level": _acp})
        return _out

    if path == "/v1/affection_reward" and method == "GET":
        _ag_one = _venus_int((req or {}).get("girl_mid")) if isinstance(req, dict) else 0
        _ag_list = [_ag_one] if _ag_one else affection_girl_order()
        return {"affection_level_reward_list": _aff_pending(_ag_list)}

    if path == "/v1/affection_reward" and method == "POST":
        _ar_g = _venus_int((req or {}).get("girl_mid")) or int(STATE.get("main_girl_mid", 3))
        # 2026-11-13 七次修复: 真服"逐条领取"会在请求里带 level(=被点的那一级)。
        #   之前完全忽略它 → 点任意一行都回全部等级 → 用户看到"逐个点击也显示全部领取"。
        _ar_req_lv = _venus_int((req or {}).get("level"))
        _ar_acc = STATE.setdefault("affection_accepted", {})
        _ar_girl = girl_obj_from_db(_ar_g)
        if _ar_girl:
            apply_girl_state(_ar_girl)
        # 2026-11-13 六次修复: 等级封顶 300 (客户端「亲爱度报酬」页只认 LV.300)
        _ar_lv = min(int(_ar_girl.get("affection_level", 1)) if _ar_girl else 1,
                     _AFFECTION_LEVEL_CAP)
        _ar_key = str(_ar_g)

        # 逐级发奖台账: 防止"重置/重进"后重复发奖 (与维纳斯图板的 granted 同思路)
        _ar_gr = STATE.get("affection_granted")
        if not isinstance(_ar_gr, dict):
            # 首次建立: 老存档的 accepted_level 已经推到了 339, 把历史等级记成"已发"
            _ar_gr = {}
            for _gk2, _gv2 in list(_ar_acc.items()):
                _ar_gr[_gk2] = list(range(1, _venus_int(_gv2) + 1))
            STATE["affection_granted"] = _ar_gr
            # 一次性把"已领等级"归零, 让玩家重新点「全部领取」就能看到奖励列表,
            # 已发过的等级靠 _ar_gr 拦住不会重复进包。
            for _gk2 in list(_ar_acc):
                _ar_acc[_gk2] = 0
        _ar_prev = _venus_int(_ar_acc.get(_ar_key))
        _ar_done = set(_ar_gr.get(_ar_key) or [])
        # 待处理等级: 带 level = 只领这一级(逐条领取); 不带 = 所有未领等级(全部领取)
        if _ar_req_lv:
            _ar_targets = [_ar_req_lv] if 2 <= _ar_req_lv <= _ar_lv else []
        else:
            _ar_targets = [_lv for _lv in range(2, _ar_lv + 1) if _lv not in _ar_done]
        _ar_entries, _ar_pairs, _ar_new = [], {}, []
        for _lv in _ar_targets:
            if _lv in _ar_done:
                # 已领过的等级不再回内容 —— 这正是"重复领取还能看到奖励"的来源
                continue
            _entry = affection_entry(_ar_g, _lv)
            _ar_new.append(_lv)
            if not _entry:
                continue            # 该级无道具奖励(报酬表只有 31 个等级有), 不留全 0 空行
            _ar_entries.append(_entry)
            for _im, _cn in ((_entry["item_mid1"], _entry["item_count1"]),
                             (_entry["item_mid2"], _entry["item_count2"]),
                             (_entry["voice_mid"], 1 if _entry["voice_mid"] else 0)):
                if _im and _cn:
                    _ar_pairs[_im] = _ar_pairs.get(_im, 0) + _cn
        if _ar_new:
            if _ar_pairs:
                venus_grant_items(sorted(_ar_pairs.items()))
            _ar_done |= set(_ar_new)
            _ar_gr[_ar_key] = sorted(_ar_done)
            # accepted_level = 已领到的最高等级 (逐条领取时可能跳跃, 未领的低等级仍可领)
            _ar_acc[_ar_key] = min(max(_ar_done), _ar_lv)
            _save_state()
        log_write(f"  [affection] girl={_ar_g} req_level={_ar_req_lv} "
                  f"亲爱度报酬 LV.{_ar_prev}->{_ar_acc.get(_ar_key)} "
                  f"条目={len(_ar_entries)} 新发等级={len(_ar_new)} 奖励={_ar_pairs}\n")
        _flush_log()

        _gsp = {}
        for _sf, _bk in (("power", "additional_power"), ("technic", "additional_technic"),
                         ("stamina", "additional_stamina"), ("appeal", "additional_appeal")):
            _bv = _venus_int((_ar_girl or {}).get(_bk))
            _gsp[f"{_sf}_before"] = _bv
            _gsp[f"{_sf}_gain"] = 0
            _gsp[f"{_sf}_after"] = _bv
        return {
            "affection_levelup_reward_list": _ar_entries,
            "girl_status_progress": _gsp,
            # 2026-11-13 七次修复: 与 GET 同语义 —— 领完(或本次领完)后该女孩不再出现在
            #   列表里, 客户端据此熄灭按钮/红点; 之前回全量 32 条 → 永远可领。
            "affection_level_reward_list": _aff_pending([_ar_g]),
            "girl_list": [_ar_girl] if _ar_girl else [],
        }

    # 2026-09-14: GET /v1/girl/{mid} 单女孩详情动态化 (像私服版, 从DB构建+装备状态, 不走静态REAL_RESPONSES)
    _m_girl_get = re.match(r"^/v1/girl/(\d+)$", path)
    if _m_girl_get and method == "GET":
        _gm_g = int(_m_girl_get.group(1))
        _girl_g = girl_obj_from_db(_gm_g)
        if _girl_g:
            apply_girl_state(_girl_g)
            return {"girl_list": [_girl_g]}
        return {"girl_list": []}
    # /v1/girl/equipment: 从 STATE inventory 构建实例ID (避免静态实例ID不在inventory→0x2CE79C9归属冲突)
    if path == "/v1/girl/equipment":
        import copy as _cp_ge
        base = _cp_ge.deepcopy(REAL_RESPONSES.get(path, {"girl_equipment_list": []}))
        gel = base.get("girl_equipment_list", [])
        state_ge = STATE.get("girl_equipment", {})
        inv = STATE.get("equipment_inventory", [])
        _im2id = {}
        for _e in inv:
            _im = _e.get("item_mid") if isinstance(_e, dict) else None
            if _im and _im not in _im2id:
                _im2id[_im] = _e.get("id", 0)
        for _g in gel:
            _gm = str(_g.get("girl_mid", 0))
            _sg = state_ge.get(_gm, {})
            for _eq_f, _girl_f in (("swimsuit_equipment_item_id","swimsuit_item_mid"),
                                   ("accessory_head_equipment_item_id","accessory_head_item_mid"),
                                   ("accessory_face_equipment_item_id","accessory_face_item_mid"),
                                   ("accessory_arm_equipment_item_id","accessory_arm_item_mid"),
                                   ("hair_equipment_item_id","hair_item_mid"),
                                   ("ring_equipment_item_id","ring_item_mid")):
                _im = _sg.get(_girl_f)
                if _im and _im in _im2id:
                    _g[_eq_f] = _im2id[_im]
                elif _g.get(_eq_f):
                    _g[_eq_f] = 0
        # 2026-11-08 修复: 原实现直接复用抓包静态列表(只有 20 个女孩), 而 /v1/girl 返回 32 个
        #   → 缺 17/19/20/24/25/27/28/29/30/31/32/33 的装备记录, 进这些女孩的打扮/主页时
        #     客户端查不到记录(空指针/越界风险)。此处按女孩主数据补齐全量.
        _have_gm = set()
        for _g in gel:
            try:
                _have_gm.add(int(_g.get("girl_mid", 0)))
            except (TypeError, ValueError):
                pass
        _added_ge = 0
        for _gm_a in sorted(GIRL_MASTER_MAP.keys()):
            if _gm_a in _have_gm:
                continue
            _entry_a = {"owner_id": OWNER_ID, "girl_mid": _gm_a,
                        "swimsuit_equipment_item_id": 0,
                        "accessory_head_equipment_item_id": 0,
                        "accessory_face_equipment_item_id": 0,
                        "accessory_arm_equipment_item_id": 0,
                        "hair_equipment_item_id": 0,
                        "ring_equipment_item_id": 0,
                        "created_at": "2019-03-28 11:15:12",
                        "updated_at": server_now_str()}
            _sg_a = state_ge.get(str(_gm_a), {})
            for _eq_f, _girl_f in (("swimsuit_equipment_item_id","swimsuit_item_mid"),
                                   ("accessory_head_equipment_item_id","accessory_head_item_mid"),
                                   ("accessory_face_equipment_item_id","accessory_face_item_mid"),
                                   ("accessory_arm_equipment_item_id","accessory_arm_item_mid"),
                                   ("hair_equipment_item_id","hair_item_mid"),
                                   ("ring_equipment_item_id","ring_item_mid")):
                _im_a = _sg_a.get(_girl_f)
                if _im_a and _im_a in _im2id:
                    _entry_a[_eq_f] = _im2id[_im_a]
            # 没有穿戴记录的女孩 → 用 girl_master 的默认泳装/发型 (避免"光着"或渲染异常)
            _gmm_a = GIRL_MASTER_MAP.get(_gm_a) or {}
            if not _entry_a["swimsuit_equipment_item_id"]:
                _ds = _gmm_a.get("swimsuit")
                if _ds and _ds in _im2id:
                    _entry_a["swimsuit_equipment_item_id"] = _im2id[_ds]
            if not _entry_a["hair_equipment_item_id"]:
                _dh = _gmm_a.get("hair")
                if _dh and _dh in _im2id:
                    _entry_a["hair_equipment_item_id"] = _im2id[_dh]
            gel.append(_entry_a)
            _added_ge += 1
        if _added_ge:
            print(f"[girl/equipment] 补全缺失女孩记录 {_added_ge} 个 (共 {len(gel)} 个)")
        return base
    # /v1/item/equipment/type/*: 从 STATE 装备库返回 (2026-09-14: 不再合并 REAL_RESPONSES, STATE 是唯一数据源)
    if path.startswith("/v1/item/equipment/type/"):
        _m = re.match(r"^/v1/item/equipment/type/(\d+)$", path)
        _etype = int(_m.group(1)) if _m else 0
        # 2026-11-08 修复: type/0 不是"全部", 而是 type/11 (发型饰品).
        #   抓包铁证: /v1/item/equipment/type/0 与 type/11 返回完全相同的 4 件, type 全为 11.
        #   原代码把 0 当通配符返回全库 22902 件 (含封印69/家具67/道具37/70...) →
        #   客户端列表巨大(卡顿), 且这些非法类型会被当成可佩戴饰品 → 佩戴后闪退.
        if _etype == 0:
            _etype = 11
        _lst = []
        for _e in STATE.get("equipment_inventory", []):
            if isinstance(_e, dict) and _e.get("type", 0) == _etype:
                _lst.append(_e)
        return {"item_equipment_list": _lst}
    # /v1/furniture/: 家具背包 (2026-09-27: 从 STATE equipment_inventory 聚合 type=67)
    # 原 REAL_RESPONSES 静态快照仅 11 件, GM 播种的 656 件家具客户端看不到; 现动态聚合全量
    if path == "/v1/furniture" or path == "/v1/furniture/":
        _fbl = _furniture_blocklist()   # 2026-11-08: 屏蔽名单里的家具不给客户端 (防"装上就闪退")
        _fcnt = {}
        for _e in STATE.get("equipment_inventory", []):
            if isinstance(_e, dict) and _e.get("type", 0) == 67:
                _im = _e.get("item_mid", 0)
                if _im in _fbl:
                    continue
                _fcnt[_im] = _fcnt.get(_im, 0) + 1
        _fl = [{"item_mid": _im, "count": _c} for _im, _c in _fcnt.items()]
        _fl.sort(key=lambda x: x["item_mid"])
        return {"item_furniture_list": _fl}
    # /v1/furniture/myset + myset/home: 家具摆放布局 (2026-09-27: 从STATE读, 持久化用户摆放)
    # POST /v1/furniture/layout 保存到 STATE["furniture_myset_home"]; 无则走 REAL_RESPONSES 静态兜底
    if path == "/v1/furniture/myset" or path == "/v1/furniture/myset/home":
        _layout = STATE.get("furniture_myset_home")
        if _layout is not None:
            # 2026-09-27: 过滤 item_mid=0 (取下/清空的家具), 只返回有效布局 (抓包自Steam私服版)
            # 2026-11-08: 再加三重兜底, 因为带脏 id 的布局条目会让客户端查表拿到 0 → 闪退
            #   (a) 不在屏蔽名单 (b) 该 item_mid 确有真实实例 (c) 实例 id 能被解析, 摆位在合法区间
            _valid = _valid_furniture_layout(_layout)
            if path == "/v1/furniture/myset":
                return {"furniture_myset_list": _valid}
            return {"home_furniture_myset_list": _valid}
        return None  # 不处理, 走 REAL_RESPONSES 静态
    # /v1/fes_deck/equipment_list: 挑战赛卡组装备 (2026-11-08: 改从 STATE 当前穿戴构建)
    #   旧 bug: STATE 存的是 *_item_mid, 这里却拿 *_equipment_item_id 去匹配 → 覆盖从不生效,
    #   返回的永远是抓包账号的静态装备; 且 deck_position=2 是"随便找的第一个非主女孩"。
    #   客户端若优先读卡组装备, 换装后比赛里就会用回旧装备/旧技能。
    if path == "/v1/fes_deck/equipment_list":
        _im2e_deck = _item_mid_to_instance()
        _tm_deck = _current_quest_team()
        _g1 = _tm_deck.get(0) or STATE.get("main_girl_mid", 3)
        _g2 = _tm_deck.get(1) or 0
        if not _g2:
            _gel_deck = (REAL_RESPONSES.get("/v1/girl/equipment", {}) or {}).get("girl_equipment_list", []) or []
            for _g_deck in _gel_deck:
                if isinstance(_g_deck, dict) and _g_deck.get("girl_mid") and _g_deck.get("girl_mid") != _g1:
                    _g2 = _g_deck.get("girl_mid")
                    break
        _deck = []
        for _pos, _gm_deck in ((1, _g1), (2, _g2)):
            if not _gm_deck:
                continue
            _sg_deck = STATE.get("girl_equipment", {}).get(str(_gm_deck), {}) or {}
            _entry_deck = {"deck_position": _pos}
            # 只输出真服卡组的 7 个标准字段; hair/ring 无抓包依据, 2026-11-08 已移除
            for _out_f, _in_f in (("swimsuit_equipment_item_id", "swimsuit_item_mid"),
                                  ("accessory_head_equipment_item_id", "accessory_head_item_mid"),
                                  ("accessory_face_equipment_item_id", "accessory_face_item_mid"),
                                  ("accessory_arm_equipment_item_id", "accessory_arm_item_mid")):
                _im_deck = _sg_deck.get(_in_f) or 0
                _inst_deck = _im2e_deck.get(_im_deck) if _im_deck else None
                _entry_deck[_out_f] = _deck_instance_id(_inst_deck)
            # 无穿戴记录的女孩用 girl_master 默认泳装兜底
            if not _entry_deck["swimsuit_equipment_item_id"]:
                _ds_deck = (GIRL_MASTER_MAP.get(int(_gm_deck)) or {}).get("swimsuit")
                if _ds_deck:
                    _entry_deck["swimsuit_equipment_item_id"] = _deck_instance_id(_im2e_deck.get(_ds_deck))
            _entry_deck.update({"main_seal_id": 0, "sub1_seal_id": 0, "sub2_seal_id": 0})
            _deck.append(_entry_deck)
        return {"fes_deck_girl_equipment_list": _deck}
    # /v1/pvp_fes_deck/equipment_list_all: PvP 装备 (3 位置: forward/back/sub)
    #   2026-11-08: 与 fes_deck 同源修正; 旧实现完全只读抓包静态装备, 换装后 PvP 也不生效
    if path == "/v1/pvp_fes_deck/equipment_list_all":
        _im2e_pvp = _item_mid_to_instance()
        _tm_pvp = _current_quest_team()
        _pvp_girls = [_tm_pvp.get(0) or STATE.get("main_girl_mid", 3)]
        if _tm_pvp.get(1):
            _pvp_girls.append(_tm_pvp[1])
        else:
            _gel_pvp = (REAL_RESPONSES.get("/v1/girl/equipment", {}) or {}).get("girl_equipment_list", []) or []
            for _g_pvp in _gel_pvp:
                if (isinstance(_g_pvp, dict) and _g_pvp.get("girl_mid")
                        and _g_pvp.get("girl_mid") != _pvp_girls[0]):
                    _pvp_girls.append(_g_pvp["girl_mid"])
                    break
        _pvp_deck = []
        for _pos_pvp, _gm_pvp in enumerate(_pvp_girls, start=1):
            _sg_pvp = STATE.get("girl_equipment", {}).get(str(_gm_pvp), {}) or {}
            _entry_pvp = {"deck_position": _pos_pvp}
            # 只输出真服卡组的 7 个标准字段; hair/ring 无抓包依据, 2026-11-08 已移除
            for _out_f, _in_f in (("swimsuit_equipment_item_id", "swimsuit_item_mid"),
                                  ("accessory_head_equipment_item_id", "accessory_head_item_mid"),
                                  ("accessory_face_equipment_item_id", "accessory_face_item_mid"),
                                  ("accessory_arm_equipment_item_id", "accessory_arm_item_mid")):
                _im_pvp = _sg_pvp.get(_in_f) or 0
                _inst_pvp = _im2e_pvp.get(_im_pvp) if _im_pvp else None
                _entry_pvp[_out_f] = _deck_instance_id(_inst_pvp)
            if not _entry_pvp["swimsuit_equipment_item_id"]:
                _ds_pvp = (GIRL_MASTER_MAP.get(int(_gm_pvp)) or {}).get("swimsuit")
                if _ds_pvp:
                    _entry_pvp["swimsuit_equipment_item_id"] = _deck_instance_id(_im2e_pvp.get(_ds_pvp))
            _entry_pvp.update({"main_seal_id": 0, "sub1_seal_id": 0, "sub2_seal_id": 0})
            _pvp_deck.append(_entry_pvp)
        return {"pvp_fes_deck_girl_equipment_full_list": _pvp_deck}
    # /v1/girl/ring/list: 每个女孩当前佩戴的戒指 (2026-11-07: 从 STATE 构建)
    #   原来返回抓包账号的静态 30 条(item_mid 全 0) → 你给女孩戴上戒指后, 戒指页仍显示"未佩戴"
    if path == "/v1/girl/ring/list" and method == "GET":
        _base_rings = REAL_RESPONSES.get("/v1/girl/ring/list", {}).get("girl_ring_item_mid_list", [])
        _ring_gms = [g.get("girl_mid") for g in _base_rings if isinstance(g, dict) and g.get("girl_mid")]
        if not _ring_gms:
            _ring_gms = sorted(GIRL_MASTER_MAP)
        _ge_all = STATE.get("girl_equipment", {})
        _rings = []
        for _rgm in _ring_gms:
            _rsg = _ge_all.get(str(_rgm), {}) or {}
            _rings.append({"girl_mid": int(_rgm), "item_mid": int(_rsg.get("ring_item_mid") or 0)})
        return {"girl_ring_item_mid_list": _rings}
    # /v1/girl/{mid}/head/accessory/switch/{item_mid}: 头饰显示开关
    #   2026-11-07: 原来落兜底 {"status":"success"}, 真实响应是 head_accessary_switch_list
    #   → 客户端读不到字段, 头饰"戴/摘"图标点了不变
    _m_hsw = re.match(r"^/v1/girl/(\d+)/head/accessory/switch/(\d+)$", path)
    if _m_hsw:
        _hgm = int(_m_hsw.group(1))
        _hmid = int(_m_hsw.group(2))
        _hsw = STATE.setdefault("head_accessory_switch", {})
        _hkey = f"{_hgm}:{_hmid}"
        _hcur = _hsw.get(_hkey)
        if method == "POST":
            _hflag = not bool(_hcur.get("switch", True)) if isinstance(_hcur, dict) else False
            _hsw[_hkey] = {"switch": _hflag, "at": server_now_str()}
            _save_state()
        else:
            _hflag = bool(_hcur.get("switch", True)) if isinstance(_hcur, dict) else True
        return {"head_accessary_switch_list": [{
            "girl_mid": _hgm, "switch": _hflag,
            "created_at": (_hcur.get("at") if isinstance(_hcur, dict) else server_now_str())}]}
    if path == "/v1/girl/head/accessory/switch/list" and method == "GET":
        _hsw_all = STATE.get("head_accessory_switch", {})
        _hlist = []
        for _hk, _hv in _hsw_all.items():
            if not isinstance(_hv, dict):
                continue
            try:
                _hgm2 = int(str(_hk).split(":")[0])
            except (ValueError, IndexError):
                continue
            _hlist.append({"girl_mid": _hgm2, "switch": bool(_hv.get("switch", True)),
                           "created_at": _hv.get("at") or ""})
        return {"head_accessary_switch_list": _hlist}
    # /v1/girl/private: 私人套装物品列表 (2026-09-14: 从 STATE 返回, 不再合并 REAL_RESPONSES)
    if path == "/v1/girl/private":
        _pi_lst = [dict(_p) for _p in STATE.get("private_items", [])]
        return {"private_item_list": _pi_lst}
    # /v1/girl/{mid}/private/favorite/{type} 和 /v1/girl/private/favorite/{type}: 收藏物品列表
    # 2026-09-14: 从 STATE 装备库查询 (不再用 REAL_RESPONSES, STATE 是唯一数据源)
    _m_fav = re.match(r"^/v1/girl/(?:\d+/)?private/favorite/(\d+)$", path)
    if _m_fav and method != "POST":
        # 2026-09-13: POST 放行给 _build_dynamic (写 favorite 字段), 此处只处理 GET
        _fav_type = int(_m_fav.group(1))
        _m_fav_girl = re.match(r"^/v1/girl/(\d+)/private/favorite/", path)
        _fav_gm = int(_m_fav_girl.group(1)) if _m_fav_girl else 0
        # ---- 2026-11-08 14:30: 姿势卡(37)/表情卡(81) 的 favorite = 纯星标, 必须持久化 ----
        #   用户实证(14:26 日志): 连点 6 次 POST /v1/girl/3/private/favorite/37 取消星标, 重启后又变回星标。
        #   两个 bug: ① 上一版把 37/81 直接返回"全集"→ 客户端认为每张卡都已被星标, 取消也白取消;
        #             ② POST 只写 equipment_inventory(里面根本没有 type37/81 的实例) → 取消从未落库。
        #   现在: 星标存 STATE["pose_expr_favorite"]={"girl:type": [mids]}, GET 只回真正标记过的。
        # ---- 2026-11-08 15:10: 姿势(37)/表情(81) —— 这里才是真正的"可用列表" ----
        # 【为什么不是 private_item_list】实测: 客户端兑换 555 张后, 服务器已把
        #   {girl_mid,item_mid} 全部写进 private_item_list 并在响应里回给它, 但姿势菜单依旧全空。
        #   而上一版把 37/81 在这里返回全集时, girl 3 的姿势菜单立刻显示出一大堆(用户原话:
        #   "你把所有女孩的姿势都加给了这一个女孩") —— 说明菜单读的就是这个端点。
        #   (真服样本 favorite/37 是空的, 因为那个测试账号确实一张姿势卡都没买过, 不是反证。)
        # 【内容】= 映射表里属于这个女孩的卡 ∪ 用户额外加过的 - 用户删掉的。
        #   带 girl 的 /v1/girl/{id}/private/favorite/37 → 只回该女孩(约 40 条)
        #   不带 girl 的 /v1/girl/private/favorite/37      → 回全部(3239 条 / 约 250KB, 安全)
        if _fav_type in (37, 81):
            _pe_add = STATE.get("pose_expr_favorite", {})
            _pe_del = STATE.get("pose_expr_removed", {})
            _pe_out = []
            _pe_girls = [_fav_gm] if _fav_gm else sorted(GIRL_MASTER_MAP)
            _pe_map = _pose_owner_map_cached()
            _pe_uni = _pose_universal_items() if _fav_type == 37 else set()
            for _pe_g in _pe_girls:
                # v4: 映射是多对多 (item -> {girls}); 通用卡人人都有
                _pe_set = {_m for _m, _gs in _pe_map.items()
                           if _pe_g in _gs and EQUIP_TYPE_MAP.get(_m) == _fav_type}
                _pe_set |= {int(_x) for _x in _pe_add.get(f"{_pe_g}:{_fav_type}", [])}
                _pe_set -= {int(_x) for _x in _pe_del.get(f"{_pe_g}:{_fav_type}", [])}
                for _pe_m in sorted(_pe_set):
                    _pe_out.append({"girl_mid": _pe_g, "type": _fav_type, "item_mid": _pe_m})
            _pose_trace(_fav_gm, _fav_type, len(_pe_out))
            return {"favorite_private_item_list": _pe_out}
        _type_map = {1: 1, 22: 22, 23: 23, 24: 24}
        _eq_type = _type_map.get(_fav_type)
        _fav_lst = []
        if _eq_type is not None:
            _seen_mids = set()
            for _e_fav in STATE.get("equipment_inventory", []):
                # 2026-09-13 修复: 只返回 favorite=1 的 (旧逻辑返回全量持有 → 新抽到默认被标记, 取消无效)
                if isinstance(_e_fav, dict) and _e_fav.get("type", 0) == _eq_type and _e_fav.get("favorite", 0):
                    _im_fav = _e_fav.get("item_mid", 0)
                    if _im_fav and _im_fav not in _seen_mids:
                        _seen_mids.add(_im_fav)
                        _target_girls = [_fav_gm] if _fav_gm else _ALL_GIRL_MIDS
                        for _agm_fav in _target_girls:
                            _fav_lst.append({"girl_mid": _agm_fav, "type": _fav_type, "item_mid": _im_fav})
        return {"favorite_private_item_list": _fav_lst}
    return None

# 2026-09-14: 追踪用户当前浏览的女孩 (exchange 请求不含 girl_mid, 用此值作为购买目标)
_LAST_BROWSE_GIRL = None

# 2026-09-15: 维纳斯商店购买共享逻辑 (单买/批量买共用)
#   返回 (iel, otl, icl, pcl, pil, spl_entry) 或 None(未知商品)
#   iel=item_equipment_list, otl=order_ticket_list, icl=item_consume_list,
#   pcl=pose_card_item_list, pil=private_item_list, spl_entry=shop_purchase_list条目
def _alloc_equip_ids(n):
    """分配 n 个全局唯一的装备实例 id。

    2026-11-07 修复: 旧实现 _base_id = (毫秒时间戳 % 1e9) + 4e9, 同一毫秒内的多次购买
    (bulk_exchange 一次买多件时必然发生) 会算出相同 _base_id, 内层 _i 又从 0 开始
    → 多个实例共用同一个 id。客户端把 id 当主键, 同 id 会被当成同一件:
    换装换错人、强化加到别件、分解串台, 严重时归属冲突崩溃 0x2CE79C9。
    改为按衣橱现有最大 id 递增, 天然唯一。
    """
    if n <= 0:
        return []
    cur = 0
    for _e in (STATE.get("equipment_inventory") or []):
        if isinstance(_e, dict):
            try:
                cur = max(cur, int(_e.get("id") or 0))
            except (TypeError, ValueError):
                pass
    cur = max(cur, 4200000000)
    return list(range(cur + 1, cur + 1 + n))


def _process_shop_exchange(pmid, count, mgm, inv, spi, pi_keys, ic):
    _details = SHOP_DETAIL_MAP.get(pmid, [])
    if not _details:
        return None
    _iel, _otl, _icl, _pcl, _pil = [], [], [], [], []
    _ids = _alloc_equip_ids(len(_details))
    for _i, (_did, _cnt) in enumerate(_details):
        _etype = EQUIP_TYPE_MAP.get(_did, 1)
        _real_cnt = int(_cnt) * int(count)
        if _etype == 67:
            # ===== 2026-11-08: 家具单独分支 =====
            # 岛主房间的家具来自 /v1/furniture/ (从 equipment_inventory 聚合 type=67)。
            # 旧逻辑把家具当消耗品写 item_counts → 家具库里永远不出现 → "房间道具没解锁"。
            # 家具也不该进 private_items(那是女孩专属泳装) 和 order_ticket, 所以单列一支。
            # 同款家具允许多件(摆多把椅子), 上限 20 防止刷爆。
            _eid = _ids[_i]
            _ie = {"id": _eid, "item_mid": _did, "type": 67, "level": 1, "experience": 0,
                   "girl_mid": 0, "favorite": 0, "in_lock": 0, "unlock_count": 0,
                   "upgrade_count": 0, "combine_count": 0}
            _iel.append(_ie)
            _inv_n = sum(1 for _e2 in inv if isinstance(_e2, dict) and _e2.get("item_mid") == _did)
            _need = max(0, min(max(1, _real_cnt), 20 - _inv_n))
            if _need:
                if _inv_n == 0:
                    inv.append(dict(_ie))          # 第一件用本请求已分配的 id
                    _need -= 1
                for _nid in _alloc_equip_ids(_need):
                    _e_new = dict(_ie)
                    _e_new["id"] = _nid
                    inv.append(_e_new)
            continue
        if _etype in (0, 1, 11, 22, 23, 24, 56, 82):
            # 装备类: 入装备库(去重) + private_item + order_ticket
            _eid = _ids[_i]
            _ie = {"id": _eid, "item_mid": _did, "type": _etype, "level": 1, "experience": 0,
                   "girl_mid": 0, "favorite": 0, "in_lock": 1, "unlock_count": 0,
                   "upgrade_count": 0, "combine_count": 0}
            _iel.append(_ie)
            # 2026-11-07 修复: 旧逻辑同 item_mid 只保留 1 份, 但响应照旧声称发货 → 重登后物品消失(假发货)
            #   改为同款最多 3 个实例(各自唯一 id), 与真实服"同款泳装可以有多件"一致
            _inv_n = sum(1 for _e2 in inv if isinstance(_e2, dict) and _e2.get("item_mid") == _did)
            if _inv_n < 3:
                inv.append(dict(_ie))
            # STATE: 给当前浏览女孩
            if (mgm, _did) not in pi_keys:
                spi.append({"girl_mid": mgm, "item_mid": _did})
                pi_keys.add((mgm, _did))
            _pil.append({"girl_mid": mgm, "item_mid": _did})
            _otl.append({"item_mid": _did, "count": 0, "type": 29, "updated_at": None,
                         "created_at": server_now_str()})
        else:
            # 消耗品类: 入 item_counts + item_consume_list (+pose_card for type37)
            # 2026-11-07 修复: 旧代码写 str 键, 与其它路径的 int 键并存 → 同一件物品两条记录/数量被拆开
            ic[_did] = ic.get(_did, 0) + _real_cnt
            _now_c = server_now_str()
            _icl.append({"item_mid": _did, "count": _real_cnt, "type": _etype,
                         "updated_at": None, "created_at": _now_c})
            if _etype == 37:
                _pcl.append({"item_mid": _did, "count": _real_cnt, "type": _etype,
                             "updated_at": None, "created_at": _now_c})
    _spl_entry = {"owner_id": OWNER_ID, "product_mid": pmid, "limit_count": 1,
                  "total_count": count, "created_at": server_now_str(),
                  "updated_at": server_now_str()}
    return _iel, _otl, _icl, _pcl, _pil, _spl_entry

# ============ 温泉/送礼/岛主房间工作 动态持久化 (2026-09-15, 抓包私服版确认) ============
# 请求体来源: temp\capture_20260915_private_server\*_req.json
#   温泉 entry/slot:{slot_entry_list:[{girl_mid,is_entry,slot_id}]}  item/use/{mid}:{quality_mid}  update/quality:{quality_mid}  reward:{}
#   送礼 present:{is_checked_at} (服务器自主选: girl=main_girl_mid, gift=背包type20道具)
#   工作 end:{girl_mid1,girl_mid2,request_mid}  girls:{同end}  start:{空,用girls设状态}

def _onsen_info(onsen, now):
    """构造 onsen_info_list 单个温泉状态"""
    return {"onsen_mid": 0, "status": 0, "quality_mid": onsen.get("quality_mid", 1),
            "gauge_updated_at": now, "gauge": onsen.get("gauge", 0), "reward_stock_second": 0,
            "reward_count": onsen.get("reward_count", 91), "created_at": "2023-05-24 06:38:19", "updated_at": now}

def _onsen_slots(onsen, now):
    """构造 onsen_slot_list 4个槽位"""
    return [{"onsen_mid": 0, "slot_id": s["slot_id"], "girl_mid": s["girl_mid"],
             "exp_updated_at": now, "created_at": "2023-05-24 06:38:19", "updated_at": now} for s in onsen.get("slots", [])]

def _build_onsen(path, req, method="POST"):
    """温泉动态持久化: GET查询 / reward领奖(递减+经验) / entry_slot换女孩 / item_use加gauge / update_quality"""
    onsen = STATE.setdefault("onsen", {})
    onsen.setdefault("slots", [{"slot_id": 0, "girl_mid": 15}, {"slot_id": 1, "girl_mid": 16},
                               {"slot_id": 2, "girl_mid": 4}, {"slot_id": 3, "girl_mid": 3}])
    onsen.setdefault("reward_count", 91); onsen.setdefault("gauge", 0)
    onsen.setdefault("quality_mid", 1); onsen.setdefault("girl_exp", {})
    now = server_now_str()
    if path == "/v1/onsen" and method == "GET":
        return {"onsen_info_list": [_onsen_info(onsen, now)],
                "onsen_slot_list": _onsen_slots(onsen, now), "onsen_quality_stash_list": []}
    if path == "/v1/onsen/0/reward" and method == "POST":
        gain = 1590; exp_list = []; gexp = onsen.setdefault("girl_exp", {})
        for s in onsen["slots"]:
            gm = s["girl_mid"]; b = gexp.get(gm, 0); a = b + gain; gexp[gm] = a
            exp_list.append({"girl_mid": gm, "experience_gain": gain, "experience_before": b,
                             "experience_after": a, "level_gain": 0, "level_before": 1, "level_after": 1})
        if onsen.get("reward_count", 0) > 0:
            onsen["reward_count"] -= 1
        _save_state()
        return {"onsen_info_list": [_onsen_info(onsen, now)], "onsen_slot_list": _onsen_slots(onsen, now),
                "onsen_girl_experience_list": exp_list, "onsen_girl_levelup_reward_list": [],
                "onsen_slot_entry_result_list": [], "onsen_reward": {"onsen_mid": 0, "onsen_reward_list": []}}
    if path == "/v1/onsen/0/entry/slot" and method == "POST":
        import copy as _cp_os
        src = {g.get("girl_mid"): g for g in REAL_RESPONSES.get("/v1/girl", {}).get("girl_list", [])}
        result_slots = []; exp_list = []; entry_results = []; girls = []
        for e in req.get("slot_entry_list", []):
            sid = e.get("slot_id"); gm = e.get("girl_mid"); is_entry = e.get("is_entry", False)
            for s in onsen["slots"]:
                if s["slot_id"] == sid:
                    old_gm = s["girl_mid"]
                    s["girl_mid"] = gm if is_entry else -1  # is_entry=false 移除(girl=-1), true 设置
                    result_slots.append({"onsen_mid": 0, "slot_id": sid, "girl_mid": s["girl_mid"],
                                         "exp_updated_at": now, "created_at": "2023-05-24 06:38:19", "updated_at": now})
                    entry_results.append({"onsen_mid": 0, "slot_id": sid, "exp_pass_second": 0})
                    ref_gm = gm if is_entry else old_gm  # 经验/girl_list 引用被操作的女孩
                    if ref_gm and ref_gm in src:
                        ng = _cp_os.deepcopy(src[ref_gm])
                        exp_list.append({"girl_mid": ref_gm, "experience_gain": 0,
                                         "experience_before": ng.get("experience", 0), "experience_after": ng.get("experience", 0),
                                         "level_gain": 0, "level_before": ng.get("level", 1), "level_after": ng.get("level", 1)})
                        girls.append(ng)
                    break
        _save_state()
        return {"onsen_slot_list": result_slots, "onsen_girl_experience_list": exp_list,
                "onsen_girl_levelup_reward_list": [], "onsen_slot_entry_result_list": entry_results,
                "girl_list": girls}
    if path.startswith("/v1/onsen/0/item/use/") and method == "POST":
        onsen["gauge"] = onsen.get("gauge", 0) + 480
        tail = path.rsplit("/", 1)[-1]; item_mid = int(tail) if tail.isdigit() else 0
        _save_state()
        return {"onsen_info_list": [_onsen_info(onsen, now)],
                "item_consume_list": [{"item_mid": item_mid, "count": 0, "type": 98, "updated_at": now, "created_at": "2023-05-24 05:36:57"}]}
    if path == "/v1/onsen/0/update/quality" and method == "POST":
        onsen["quality_mid"] = req.get("quality_mid", onsen.get("quality_mid", 1))
        _save_state()
        return {"status": "success"}
    return None

def _build_present(path, req, method="POST"):
    """送礼动态持久化: 请求体仅{is_checked_at}, 服务器自主选礼物(看板娘+背包type20), 扣1加经验125"""
    if path != "/v1/present" or method != "POST":
        return None
    gm = STATE.get("main_girl_mid", 3); gain = 125
    gexp = STATE.setdefault("girl_exp", {}); b = gexp.get(gm, 0); a = b + gain; gexp[gm] = a
    gift_mid = None; ic = STATE.get("item_counts", {})
    for imid, cnt in list(ic.items()):
        try:
            if cnt > 0 and ITEM_TYPE_MAP.get(int(imid)) == 20:
                gift_mid = int(imid); break
        except Exception:
            continue
    consume = []
    if gift_mid is not None:
        ic[gift_mid] = max(0, ic.get(gift_mid, 0) - 1)
        consume = [{"item_mid": gift_mid, "count": ic[gift_mid], "type": 20, "updated_at": server_now_str(), "created_at": "2020-03-24 13:15:29"}]
    girls = []
    for g in REAL_RESPONSES.get("/v1/girl", {}).get("girl_list", []):
        if g.get("girl_mid") == gm:
            import copy as _cp_g; ng = _cp_g.deepcopy(g)
            ng["experience"] = a; ng["updated_at"] = server_now_str(); girls = [ng]; break
    _save_state()
    return {"present_result": {"reward_list": [],
            "girl_progress": {"girl_mid": gm, "experience_gain": gain, "experience_before": b,
                              "experience_after": a, "level_gain": 0, "level_before": 1, "level_after": 1},
            "girl_levelup_reward_list": []},
            "honor_list": [], "girl_list": girls, "item_consume_list": consume}

def _build_room_request(path, req, method="POST"):
    """岛主房间工作动态持久化: girls设置 / start开始 / end完成发奖+记历史+加好感 / list历史 / friendly / cancel"""
    rr = STATE.setdefault("room_request", {})
    rr.setdefault("current", None); rr.setdefault("log", []); rr.setdefault("girls", None)
    STATE.setdefault("friendly_value", []); now = server_now_str()
    if path == "/v1/room" and method in ("GET", "POST"):
        oroom = STATE.get("owner_room") or {"owner_id": OWNER_ID, "main_girl_mid": STATE.get("main_girl_mid", 3), "sub_girl_mid": 15, "set_no": 0}
        _oroom = dict(oroom)
        # 2026-11-11: 与 /v1/owner 对齐, 不再返回 owner_room 里过期的 main_girl_mid
        #   (切换主界面看板娘后此处曾是旧值 3, 客户端两个界面拿到不同女孩)
        _oroom["main_girl_mid"] = STATE.get("main_girl_mid", 3)
        return {"owner_room": _oroom}
    if path == "/v1/room/request" and method in ("GET", "POST"):
        cur = rr["current"]
        if cur:
            return {"custom_room_request_list": [{"owner_id": OWNER_ID, "request_mid": cur["request_mid"],
                    "girl_mid1": cur["girl_mid1"], "girl_mid2": cur["girl_mid2"], "trend_status": 0,
                    "created_at": "2020-03-30 06:49:51", "updated_at": cur["started_at"],
                    "started_at": cur["started_at"], "end_at": cur["end_at"]}]}
        return {"custom_room_request_list": []}
    if path == "/v1/room/request/list" and method == "GET":
        return {"custom_room_request_log_list": [{"request_mid": l["request_mid"], "clear_rank": l["clear_rank"]} for l in rr["log"]]}
    if path == "/v1/room/girls" and method == "POST":
        # 2026-09-18 抓包铁证: 换房间显示女孩请求体是 {main_girl_mid, sub_girl_mid}
        # (9/15 抓包的 {girl_mid1, girl_mid2, request_mid} 是设工作女孩, 同端点不同动作). 兼容两种.
        gm1 = req.get("main_girl_mid")
        if gm1 is None:
            gm1 = req.get("girl_mid1")
        gm2 = req.get("sub_girl_mid")
        if gm2 is None:
            gm2 = req.get("girl_mid2")
        log_write(f"  [ROOM-GIRLS] req={req} gm1={gm1} gm2={gm2}\n")
        rr["girls"] = {"girl_mid1": req.get("girl_mid1"), "girl_mid2": req.get("girl_mid2"), "request_mid": req.get("request_mid")}
        # 持久化岛主房间女孩 (main_girl=girl_mid1, sub_girl=girl_mid2) — 退出重进保持
        # 2026-09-18: guard None — req 空(girl_mid1 缺失)时不覆盖, 防止写 None 污染 owner_room 导致房间女孩丢失
        if gm1 is not None:
            try:
                _gm1i = int(gm1)
            except (TypeError, ValueError):
                _gm1i = None
            if _gm1i is not None and (not GIRL_MASTER_MAP or _gm1i in GIRL_MASTER_MAP):
                try:
                    _gm2i = int(gm2) if gm2 is not None else None
                except (TypeError, ValueError):
                    _gm2i = None
                if _gm2i is not None and GIRL_MASTER_MAP and _gm2i not in GIRL_MASTER_MAP:
                    _gm2i = None   # 2026-11-11b: 非法副女孩 ID 不落盘
                _or3 = STATE.get("owner_room") or {}
                STATE["owner_room"] = {"owner_id": OWNER_ID, "main_girl_mid": _gm1i,
                                      "sub_girl_mid": _gm2i if _gm2i is not None else _or3.get("sub_girl_mid", 15),
                                      "set_no": _or3.get("set_no", 0)}
                STATE["main_girl_mid"] = _gm1i
            else:
                # 2026-11-11: 非法女孩 ID 不落盘, 保持主女孩; 只更新房间副女孩
                log_write(f"  [ROOM-GIRLS] 拒绝非法 gm1={gm1}, 保持 {STATE.get('main_girl_mid', 3)}\n")
                _or2 = STATE.get("owner_room")
                if isinstance(_or2, dict):
                    _or2["main_girl_mid"] = STATE.get("main_girl_mid", 3)
                    try:
                        _gm2j = int(gm2) if gm2 is not None else None
                    except (TypeError, ValueError):
                        _gm2j = None
                    if _gm2j is not None and (not GIRL_MASTER_MAP or _gm2j in GIRL_MASTER_MAP):
                        _or2["sub_girl_mid"] = _gm2j   # 2026-11-11b: 只接受合法副女孩
            _save_state()
            _flush_state()   # 2026-11-11: 女孩是关键状态, 立即落盘
        else:
            log_write(f"  [ROOM-GIRLS] gm1=None, 跳过写入(防污染), 当前 owner_room={STATE.get('owner_room')}\n")
        _or = STATE.get("owner_room") or {"owner_id": OWNER_ID, "main_girl_mid": STATE.get("main_girl_mid", 3), "sub_girl_mid": 15, "set_no": 0}
        _or["main_girl_mid"] = STATE.get("main_girl_mid", 3)   # 2026-11-11b: 与 /v1/room GET 对齐
        return {"owner_room": dict(_or)}
    if path == "/v1/room/request/start" and method == "POST":
        g = rr.get("girls") or {}
        from datetime import timedelta
        end = (game_now() + timedelta(minutes=20)).strftime("%Y-%m-%d %H:%M:%S")
        cur = {"request_mid": g.get("request_mid", 2), "girl_mid1": g.get("girl_mid1", 3),
               "girl_mid2": g.get("girl_mid2", 15), "started_at": now, "end_at": end}
        rr["current"] = cur; _save_state()
        return {"custom_room_request_list": [{"owner_id": OWNER_ID, "request_mid": cur["request_mid"],
                "girl_mid1": cur["girl_mid1"], "girl_mid2": cur["girl_mid2"], "trend_status": 0,
                "created_at": "2020-03-30 06:49:51", "updated_at": now, "started_at": now, "end_at": end}]}
    if path == "/v1/room/request/end" and method == "POST":
        gm1 = req.get("girl_mid1", 3); gm2 = req.get("girl_mid2", 15); rmid = req.get("request_mid", 2)
        clear_rank = 3; rr["log"].append({"request_mid": rmid, "clear_rank": clear_rank}); rr["current"] = None
        fv = STATE["friendly_value"]; found = None
        for f in fv:
            if f.get("girl_mid") == gm1 and f.get("friendly_girl_mid") == gm2:
                found = f; break
        if not found:
            found = {"girl_mid": gm1, "friendly_girl_mid": gm2, "value": 0, "level": 1, "unlock_count": 0}; fv.append(found)
        fb = found["value"]; found["value"] = fb + 25
        # 2026-11-08: friendly 已拉满(FRIENDLY_MAX_LEVEL)的组合不再涨级, 防止 level 无限增长
        lvl_gain = 1 if (found["value"] >= 100 and found.get("level", 1) < FRIENDLY_MAX_LEVEL) else 0
        found["level"] = found.get("level", 1) + lvl_gain
        _save_state()
        return {"wallet": STATE.get("wallet", {}), "item_equipment_list": [], "item_consume_list": [],
                "custom_room_request_list": [],
                "custom_room_request_result": {"clear_rank": clear_rank, "trend_status": 0,
                    "friendly_progress": {"friendly_gain": 25, "friendly_before": fb, "friendly_after": fb + 25,
                        "level_gain": lvl_gain, "level_before": found["level"] - lvl_gain, "level_after": found["level"]},
                    "friendly_levelup_reward_list": [], "trend_reward": {"friendly_value": 0, "item_list": []},
                    "clear_rank_count_list": [{"clear_rank": clear_rank, "count": 1}], "clear_rank_reward_item_list": []},
                "custom_room_request_reward_list": [], "sp_fan_item_list": [], "sp_timestop_item_list": [],
                "pose_card_item_list": [], "sp_order_item_list": [], "order_ticket_list": [], "sp_reaction_mic_item_list": [],
                "custom_room_request_log_list": [{"request_mid": rmid, "clear_rank": clear_rank}],
                "friendly_value_list": [{"girl_mid": gm1, "friendly_girl_mid": gm2, "value": found["value"], "level": found["level"], "unlock_count": 0}],
                "seal_base_list": [], "wallet_list": [STATE.get("wallet", {})]}
    if path == "/v1/room/request/cancel" and method == "POST":
        rr["current"] = None; _save_state(); return {"status": "success"}
    if path == "/v1/room/girl/friendly" and method == "GET":
        return {"friendly_value_list": STATE.get("friendly_value", [])}
    return None

def _build_special_order_exchange(path, req, method="POST"):
    """特殊订单兑换: 泳装(3574) 或 姿势卡(order_item_type=37)。
    2026-11-08 14:45: 补上姿势卡分支。
      实证(full_server.log 14:37:21): 客户端兑换姿势卡时发
        {"girl_mid":21, "is_present":true, "item_mid_list":[56404], "order_item_type":37}
      → 说明姿势卡是 **per-girl** 兑换的, 目标女孩在请求里。旧实现只认 3574(泳装),
        姿势卡请求被当成泳装兑换, 扣券且把 3574 塞进 private_items —— 什么都没发对。
      现在: 按 girl_mid + item_mid_list 精确入账该女孩的 private_items。
    """
    if path != "/v1/special_order/exchange" or method != "POST":
        return None
    # ---- 分支①: 姿势卡 / 表情卡 (order_item_type=37) ----
    if int(req.get("order_item_type") or 0) == 37:
        try:
            _gm = int(req.get("girl_mid") or STATE.get("main_girl_mid", 3))
        except (TypeError, ValueError):
            _gm = STATE.get("main_girl_mid", 3)
        _mids = []
        for _m in (req.get("item_mid_list") or []):
            try:
                _mids.append(int(_m))
            except (TypeError, ValueError):
                continue
        _spi = STATE.setdefault("private_items", [])
        _have = set()
        for _p in _spi:
            if isinstance(_p, dict):
                try:
                    _have.add((int(_p.get("girl_mid")), int(_p.get("item_mid"))))
                except (TypeError, ValueError):
                    continue
        _new = []
        for _m in _mids:
            if (_gm, _m) in _have:
                continue
            _spi.append({"girl_mid": _gm, "item_mid": _m})
            _have.add((_gm, _m))
            _new.append(_m)
        _save_state()
        _now_o = server_now_str()
        # 兑换成功的卡同时记进"拥有"白名单: 映射表没覆盖到的卡(184 张姿势/318 张表情)
        # 只能靠用户自己兑一次才拿得到, 记下来下次 GET favorite/37 就能回给它。
        _pe_add = STATE.setdefault("pose_expr_favorite", {})
        _pe_del = STATE.setdefault("pose_expr_removed", {})
        for _m in _mids:
            _tt = EQUIP_TYPE_MAP.get(_m)
            if _tt not in (37, 81):
                _tt = 37
            _k = f"{_gm}:{_tt}"
            _add = set(int(x) for x in _pe_add.get(_k, []))
            _del = set(int(x) for x in _pe_del.get(_k, []))
            _add.add(_m)
            _del.discard(_m)
            _pe_add[_k] = sorted(_add)
            _pe_del[_k] = sorted(_del)
        _save_state()
        print(f"[special_order/exchange] 姿势卡 girl={_gm} 请求 {_mids} 新增 {_new}")
        return {
            "pose_card_item_list": [{"item_mid": _m, "count": 1, "type": 37,
                                     "updated_at": None, "created_at": _now_o} for _m in _mids],
            "private_item_list": [{"girl_mid": _gm, "item_mid": _m} for _m in _mids],
            "order_ticket_exchange_list": [],
            "order_ticket_list": [],
        }
    # ---- 分支②: 兑换券换泳装 (固定 3574) ----
    gm = STATE.get("main_girl_mid", 3)
    ITEM_MID = 3574  # 兑换券=泳装 (capture 5次 special_order/exchange 确认固定 3574, type29)
    ic = STATE.get("item_counts", {})
    cnt = ic.get(ITEM_MID, 0)
    if cnt <= 0:
        cnt = 7; ic[ITEM_MID] = 7  # 初始7张兑换券(像私服版 capture count=7)
    ic[ITEM_MID] = cnt - 1  # 扣1
    spi = STATE.setdefault("private_items", [])
    entry = {"girl_mid": gm, "item_mid": ITEM_MID}
    if entry not in spi:
        spi.append(entry)  # 泳装进私人套装(去重)
    _save_state()
    now = server_now_str()
    return {"order_ticket_exchange_list": [{"girl_mid": gm, "item_mid": ITEM_MID}],
            "order_ticket_list": [{"item_mid": ITEM_MID, "count": ic[ITEM_MID], "type": 29,
                                   "updated_at": now, "created_at": "2026-09-12 14:27:13"}],
            "private_item_list": [{"girl_mid": gm, "item_mid": ITEM_MID}]}

def _build_dynamic(path, req, method="POST"):
    """动态响应引擎: 处理有状态的操作型端点, 其余用轮换"""
    global LAST_DRAW_RESP, STATE, _LAST_BROWSE_GIRL
    eps = SERVER_DB.get("endpoints", {})
    req = req or {}

    # 2026-09-14: 发型自动回退确认 — 收到任何请求=游戏没崩=确认上次发型变更
    if STATE.get("_hair_revert"):
        STATE.pop("_hair_revert", None)
        _save_state()

    # 2026-09-15 修复: 只从 /v1/girl/{mid}/private 追踪浏览女孩 (更衣室请求)
    #   旧逻辑匹配所有 /v1/girl/{mid}/* → 游戏在两次购买间发 girl/3/equipment 请求 → 覆盖成 girl 3 → 物品给错女孩
    #   新逻辑只匹配 /private → 只有用户进入更衣室才更新 → 购买时仍是正确的女孩
    _m_track = re.match(r"^/v1/girl/(\d+)/private", path)
    if _m_track:
        _LAST_BROWSE_GIRL = int(_m_track.group(1))

    # ---- 2026-09-27: 家具摆放持久化 (/v1/furniture/layout/{set_no}) ----
    # 客户端 POST update_furniture_list 保存布局; 原走兜底{status:success}没存STATE→重登丢失
    # 2026-11-08 重写: 原实现给 id=0 的条目分配"库存最大 id+1", 而库存最大 id 已是 45 亿级的
    #   泳装实例 id → 造出 4528388208 这类**不存在的家具实例 id**, 客户端按它查表得到 0 →
    #   sub_142DA2F40 解引用空指针 → 0xc0000005 闪退("装上家具就卡住闪退"的根因)。
    #   现在改为: 只认本人真实持有的 type67 实例 id; id 缺失/伪造则分配该家具的空闲实例;
    #   屏蔽名单/未持有/非法摆位/撞位 的条目直接丢弃并记入隔离区。
    if path.startswith("/v1/furniture/layout/") and method == "POST":
        _ufl = req.get("update_furniture_list", []) if isinstance(req, dict) else []
        _fbl = _furniture_blocklist()
        _finst = _furniture_instances()
        _slots_used, _ids_used = set(), set()
        _clean, _quar = [], []
        for _it in _ufl:
            if not isinstance(_it, dict):
                continue
            try:
                _mid = int(_it.get("item_mid") or 0)
                _lm = int(_it.get("layout_mid") or 0)
                _ry = int(_it.get("rot_y") or 0)
                _oid = int(_it.get("id") or 0)
            except (TypeError, ValueError):
                continue
            # item_mid=0 = 客户端"取下该位家具", 原样回显但不必落库
            if _mid == 0:
                _clean.append({"id": _oid, "item_mid": 0, "layout_mid": _lm, "rot_y": _ry})
                continue
            _why = None
            if _mid in _fbl:
                _why = "blocked"
            elif EQUIP_TYPE_MAP.get(_mid) != 67:
                _why = "not_furniture"
            elif not _finst.get(_mid):
                _why = "not_owned"
            elif not (0 <= _lm < MAX_LAYOUT_SLOT):
                _why = "layout_out_of_range"
            elif _lm in _slots_used:
                _why = "duplicate_slot"
            if _why:
                _quar.append({"id": _oid, "item_mid": _mid, "layout_mid": _lm, "reason": _why})
                continue
            _free = [i for i in _finst[_mid] if i not in _ids_used]
            if not _free:
                _quar.append({"id": _oid, "item_mid": _mid, "layout_mid": _lm,
                              "reason": "no_free_instance"})
                continue
            _nid = _oid if _oid in _free else _free[0]
            _ids_used.add(_nid)
            _slots_used.add(_lm)
            _clean.append({"id": _nid, "item_mid": _mid, "layout_mid": _lm, "rot_y": _ry})
        STATE["furniture_myset_home"] = [x for x in _clean if x.get("item_mid")]
        _save_state()
        # 2026-09-27: 真实响应格式(抓包自Steam私服版): owner_room + furniture_myset_list(含全部, item_mid=0为取下)
        # 原{"status":"success"}客户端不认→布局没保存到客户端→"无效"
        _or = STATE.get("owner_room") or {"owner_id": OWNER_ID, "main_girl_mid": STATE.get("main_girl_mid", 3), "sub_girl_mid": 15, "set_no": 0}
        _or["main_girl_mid"] = STATE.get("main_girl_mid", 3)   # 2026-11-11b: 家具响应里的房间也用当前主女孩
        log_write(f"  [FURNITURE] 布局保存 {len(_clean)} 件 (丢弃 {len(_quar)})\n")
        for _q in _quar:
            log_write(f"    丢弃 item_mid={_q['item_mid']} layout={_q['layout_mid']} 原因={_q['reason']}\n")
        if _quar:
            _qlog = list(STATE.get("furniture_quarantine") or []) + _quar
            STATE["furniture_quarantine"] = _qlog[-100:]
            _save_state()
        return {"owner_room": dict(_or), "furniture_myset_list": _clean}

    # ---- 2026-09-14: bar/bell 酒吧摇铃 (消耗item_mid×count, 更新库存/bell_at/wallet; 奖励用模板) ----
    if path == "/v1/bar/bell" and method == "POST":
        _pool = eps.get(path, [])
        import copy as _bb_cp
        _base, _ = _pick_rotate(_pool, path) if _pool else ({}, True)
        _r = _bb_cp.deepcopy(_base) if _base else {}
        _count = req.get("count", 1)
        _im = req.get("item_mid")
        if _im is not None:
            _, _left_bb = ic_take(_im, _count)
            for _ic_l in _r.get("item_consume_list", []):
                if _ic_l.get("item_mid") == _im:
                    _ic_l["count"] = _left_bb
                    _ic_l["updated_at"] = server_now_str()
        _w = STATE.get("wallet", {})
        for _wl in _r.get("wallet_list", []):
            if isinstance(_wl, dict) and _w:
                _wl.update(_w)
        _now = server_now_str()
        for _bs in _r.get("bar_set_list", []):
            if isinstance(_bs, dict):
                _bs["bell_at"] = _now
        _save_state()
        return _r

    # ---- 2026-11-07 商店修复 ②: 购买前校验 POST /v1/shop/purchase/check ----
    #   原实现缺失 → 落兜底 {"status":"success"} → 客户端拿不到 purchase_check 字段
    #   → 购买确认流程异常(点了没反应/判定失败)。
    #   响应结构来自抓包库 9 份样本, 恒为 {"purchase_check":{"purchase":true,"total_price":0}}
    if path == "/v1/shop/purchase/check" and method == "POST":
        print(f"[shop/purchase/check] {req}")
        return {"purchase_check": {"purchase": True, "total_price": 0}}

    # ---- 2026-09-15: 维纳斯商店批量购买 POST /v1/shop/bulk_exchange ----
    #   请求体: {"bulk_exchange_list":[{"count":1,"product_mid":33353},{"count":1,"product_mid":43144}]}
    #   之前未实现此端点 → 兜底返回 {"status":"success"} → 物品不进背包！
    #   修复: 遍历 bulk_exchange_list, 逐个商品调用 _process_shop_exchange, 聚合所有结果
    if path == "/v1/shop/bulk_exchange" and method == "POST":
        _bulk_list = req.get("bulk_exchange_list", [])
        _inv = STATE.setdefault("equipment_inventory", [])
        _spi = STATE.setdefault("private_items", [])
        _pi_keys = {(_p.get("girl_mid", 0), _p.get("item_mid", 0)) for _p in _spi}
        _ic = STATE.setdefault("item_counts", {})
        _mgm = _LAST_BROWSE_GIRL or STATE.get("main_girl_mid", 3)
        _sp = STATE.setdefault("shop_purchased", {})
        _iel_all, _otl_all, _icl_all, _pcl_all, _pil_all, _spl_all = [], [], [], [], [], []
        for _item in _bulk_list:
            _pmid = int(_item.get("product_mid", 0))
            # 2026-11-07: count 缺省/为 0 时兜底 1 —— 原来 int(_item.get("count", 1)) 若客户端发 0,
            #   会真的按 0 件发货, 响应里 count 全是 0, 表现就是"购买成功但数量 0"
            try:
                _cnt = int(_item.get("count", 1) or 1)
            except (TypeError, ValueError):
                _cnt = 1
            _cnt = max(1, _cnt)
            if not _pmid:
                continue
            _result = _process_shop_exchange(_pmid, _cnt, _mgm, _inv, _spi, _pi_keys, _ic)
            if _result is None:
                print(f"[!] shop/bulk_exchange 未知商品 product_mid={_pmid} 已跳过")
                continue
            _iel, _otl, _icl, _pcl, _pil, _spl_entry = _result
            _iel_all.extend(_iel)
            _otl_all.extend(_otl)
            _icl_all.extend(_icl)
            _pcl_all.extend(_pcl)
            _pil_all.extend(_pil)
            _spl_all.append(_spl_entry)
            _sp[str(_pmid)] = _sp.get(str(_pmid), 0) + 1
            STATE.setdefault("shop_purchased_at", {})[str(_pmid)] = server_now_str()
        _save_state()
        print(f"[shop/bulk_exchange] req={req} -> 装备{len(_iel_all)}件 消耗品{len(_icl_all)}条 "
              f"{[(e.get('item_mid'), e.get('count')) for e in _icl_all][:8]}")
        _w = STATE.get("wallet", {})
        _resp = {
            "shop_purchase_list": _spl_all,
            "wallet_list": [_w] if _w else [],
        }
        if _iel_all:
            _resp["order_ticket_list"] = _otl_all
            _resp["item_equipment_list"] = _iel_all
            _resp["private_item_list"] = _pil_all
        if _icl_all:
            _resp["item_consume_list"] = _icl_all
            if _pcl_all:
                _resp["pose_card_item_list"] = _pcl_all
        return _resp

    # ---- 2026-09-14: 维纳斯商店单买 POST /v1/shop/exchange/{product_mid} ----
    #   2026-09-15 重构: 提取共享逻辑到 _process_shop_exchange, 单买/批量买共用
    #   2026-09-15 新增: limit_count 检查 (已购买的商品跳过, 像私服版)
    #   2026-09-15 新增: equipment_inventory 去重 (同 item_mid 只保留一份实例, 防归属冲突崩溃)
    _m_ex = re.match(r"^/v1/shop/exchange/(\d+)$", path)
    if _m_ex and method == "POST":
        _pmid = int(_m_ex.group(1))
        _sp = STATE.setdefault("shop_purchased", {})
        _inv = STATE.setdefault("equipment_inventory", [])
        _spi = STATE.setdefault("private_items", [])
        _pi_keys = {(_p.get("girl_mid", 0), _p.get("item_mid", 0)) for _p in _spi}
        _ic = STATE.setdefault("item_counts", {})
        _mgm = _LAST_BROWSE_GIRL or STATE.get("main_girl_mid", 3)
        _result = _process_shop_exchange(_pmid, 1, _mgm, _inv, _spi, _pi_keys, _ic)
        if _result is None:
            # 2026-11-07: 加日志 (商品不在 ShopItemDetail.csv 里 → 无法判断该发什么, 走兜底假成功)
            print(f"[!] shop/exchange 未知商品 product_mid={_pmid} (ShopItemDetail 无映射)")
            return None  # 未知商品交给上层
        _iel, _otl, _icl, _pcl, _pil, _spl_entry = _result
        _sp[str(_pmid)] = _sp.get(str(_pmid), 0) + 1
        STATE.setdefault("shop_purchased_at", {})[str(_pmid)] = server_now_str()
        _save_state()
        # 2026-11-07 诊断: 购买发货明细打日志, 方便对"买完数量0"这类问题定位
        print(f"[shop/exchange] product_mid={_pmid} req={req} "
              f"| 装备{len(_iel)}件 {[(e.get('item_mid'), e.get('type')) for e in _iel]} "
              f"| 消耗品{len(_icl)}条 {[(e.get('item_mid'), e.get('count')) for e in _icl]} "
              f"| 姿势卡{len(_pcl)}条 {[(e.get('item_mid'), e.get('count')) for e in _pcl]}")
        _w = STATE.get("wallet", {})
        _resp = {
            "shop_purchase_list": [_spl_entry],
            "wallet_list": [_w] if _w else [],
        }
        if _iel:
            _resp["order_ticket_list"] = _otl
            _resp["item_equipment_list"] = _iel
            _resp["private_item_list"] = _pil
        if _icl:
            _resp["item_consume_list"] = _icl
            if _pcl:
                _resp["pose_card_item_list"] = _pcl
        return _resp

    # ---- 切换主界面看板娘: 构造自洽 girl 对象并持久化 (2026-11-11 重写) ----
    if path == "/v1/owner/main_girl":
        mid = req.get("main_girl_mid")
        if mid is None:
            return None
        try:
            mid = int(mid)
        except (TypeError, ValueError):
            return None
        # ① 合法性校验: 只接受 girl_master 里真实存在的女孩, 非法 mid 一律不落盘
        if mid not in GIRL_MASTER_MAP:
            log_write(f"  [MAIN-GIRL] 拒绝非法 girl_mid={mid}, 保持 {STATE.get('main_girl_mid', 3)}\n")
            return None
        girl = girl_obj_from_db(mid)
        if girl is None:
            # ② 构造失败宁可放弃切换, 也不再用"拿别的女孩改 girl_mid"的混血兜底
            log_write(f"  [MAIN-GIRL] girl {mid} 构造失败, 放弃切换\n")
            return None
        apply_girl_state(girl)
        # ③ 同步 owner_room: 否则 /v1/owner 返回新看板娘而 /v1/room 仍是旧的,
        #    客户端主界面与岛主房间拿到两个不同女孩 -> 资源/场景状态互相打架
        _or = STATE.get("owner_room")
        if isinstance(_or, dict):
            _or["main_girl_mid"] = mid
        STATE["main_girl_mid"] = mid
        _save_state()
        _flush_state()   # ④ 切换是关键状态, 立即落盘, 不等 2 秒去抖窗口 (防崩溃时丢失/回退)
        log_write(f"  [MAIN-GIRL] 切换并落盘 girl_mid={mid} "
                  f"hair={girl.get('hair_item_mid')} swimsuit={girl.get('swimsuit_item_mid')}\n")
        # 构造完整响应 (girl + owner_partner_list + girl_list 结构)
        partner = {"owner_id": OWNER_ID, "main_girl_mid": mid, "lend_girl_mid": 21,
                   "updated_at": server_now_str()}
        return {"girl": girl, "owner_partner_list": [partner], "girl_list": [girl]}

    # ---- 换装 (girl/{mid}/equipment): 记录状态并回显请求的装备ID ----
    # 2026-09-10 修复: 仅 POST 才写 STATE(换装动作), GET(读取)不写; 且过滤 0 值, 防止污染覆盖已存装备
    m_eq = re.match(r"^/v1/girl/(\d+)/equipment$", path)
    if m_eq:
        gm = m_eq.group(1)
        # 2026-11-07 修复: GET 直接返回落库的真实装备(实例ID + 实例详情), 不再回显空请求体
        if method == "GET":
            return _build_girl_equipment_one(int(gm))
        # 请求里的装备字段 (item_id 型)
        eq_map = {
            "swimsuit_equipment_item_id": req.get("swimsuit_equipment_item_id", 0),
            "accessory_head_equipment_item_id": req.get("accessory_head_equipment_item_id", 0),
            "accessory_face_equipment_item_id": req.get("accessory_face_equipment_item_id", 0),
            "accessory_arm_equipment_item_id": req.get("accessory_arm_equipment_item_id", 0),
            "addition_accessory_equipment_item_id": req.get("addition_accessory_equipment_item_id", 0),
            "hair_equipment_item_id": req.get("hair_equipment_item_id", 0),
            "ring_equipment_item_id": req.get("ring_equipment_item_id", 0),
        }
        if method == "POST":
            # 2026-09-11 修复(四次): 合并 + 仅处理请求中显式包含的字段 (同 private 分支)
            _eq = STATE.setdefault("girl_equipment", {}).setdefault(gm, {})
            _inv = STATE.get("equipment_inventory", [])
            _id2mid = {e.get("id"): e.get("item_mid") for e in _inv if isinstance(e, dict) and e.get("id")}
            for _k, _v in eq_map.items():
                if _k not in req:
                    continue
                _mid_field = _k.replace("_equipment_item_id", "_item_mid")
                if _v:
                    _mid = _id2mid.get(_v, 0)
                    if _mid:
                        _eq[_mid_field] = _mid
                    _eq.pop(_k, None)
                else:
                    _eq.pop(_mid_field, None)
                    _eq.pop(_k, None)
            _save_state()
            # 保存后回真实落库结果 (客户端据此刷新, 回显请求值会在"卸下装备"时给出脏数据)
            return _build_girl_equipment_one(int(gm))
        return {"girl_equipment_list": [dict({"owner_id": OWNER_ID, "girl_mid": int(gm)}, **eq_map)]}

    # ---- 换装实际请求: POST /v1/girl/{mid}/private (实测: 客户端换装走此路径, 带 item_mid 型字段) ----
    # 2026-09-09 实测铁证: 单机版与私服版换装都发 POST /v1/girl/{mid}/private,
    #   body 如 {"swimsuit_item_mid":75,"accessory_head_item_mid":0,...}
    #   服务器之前未处理此路径 -> 提交的装备被丢弃 -> 重启后不持久化. 现保存进 STATE.
    m_pv = re.match(r"^/v1/girl/(\d+)/private$", path)
    # GET /v1/girl/{mid}/private: 返回女孩当前装备状态 (2026-09-14: 动态从 STATE 构建)
    if m_pv and method == "GET":
        _gm_pv = int(m_pv.group(1))
        _LAST_BROWSE_GIRL = _gm_pv  # 追踪当前浏览女孩 (供 exchange 购买时使用)
        _girl_pv = girl_obj_from_db(_gm_pv)
        if _girl_pv is not None:
            apply_girl_state(_girl_pv)
            return {"girl_list": [_girl_pv]}
        return {"girl_list": []}
    if m_pv and method == "POST":
        gm = m_pv.group(1)
        eq_map = {
            "swimsuit_item_mid": req.get("swimsuit_item_mid", 0),
            "accessory_head_item_mid": req.get("accessory_head_item_mid", 0),
            "accessory_face_item_mid": req.get("accessory_face_item_mid", 0),
            "accessory_arm_item_mid": req.get("accessory_arm_item_mid", 0),
            "hair_item_mid": req.get("hair_item_mid", 0),
            "ring_item_mid": req.get("ring_item_mid", 0),
        }
        # 2026-09-10 归属校验: 装备实例若专属他女孩(如 face=10044 归属girl13), 换装保存会污染STATE
        #   → 客户端构建该女孩子表时归属冲突 → 子表空 → 进大厅崩溃 0x2CE79C9. 冲突装备置0拒绝.
        _omap = _equipment_owner_map()
        _gmid = int(gm)
        for _f in eq_map:
            if not _validate_equipment_owner(_gmid, eq_map[_f], _omap):
                print(f"[private] 归属校验拒绝: girl{gm} 装备 {_f}={eq_map[_f]} 归属冲突, 置0")
                eq_map[_f] = 0
        # 2026-09-11 修复(四次): 合并 + 仅处理请求中显式包含的字段
        #   客户端发部分字段请求(如换发型只发 {"hair_item_mid":367}),
        #   不在请求中的字段不能动(否则 pop 会清掉已存泳装/饰品).
        #   在请求中: 非0=穿戴→更新, 0=取下→pop; 不在请求中→跳过.
        _eq = STATE.setdefault("girl_equipment", {}).setdefault(gm, {})
        # 2026-09-14: 记录旧发型 (供崩溃自动回退)
        _old_hair = _eq.get("hair_item_mid")
        for _k, _v in eq_map.items():
            if _k not in req:
                continue
            if _v:
                _eq[_k] = _v
            else:
                _eq.pop(_k, None)
        _save_state()
        # 2026-09-14: 如果换了发型, 记录回退点 (崩溃=游戏不再发请求=_hair_revert留存→重启回退)
        if "hair_item_mid" in req and req.get("hair_item_mid") and _old_hair != req.get("hair_item_mid"):
            STATE.setdefault("_hair_revert", {})[gm] = _old_hair
            _save_state()
            print(f"[private] girl{gm} 发型变更: {_old_hair} -> {req.get('hair_item_mid')} (已记录回退点)")
        girl = girl_obj_from_db(int(gm))
        if girl is None:
            # 2026-09-18: 不在响应池的女孩(如17/19/20/24/25/27-31) 同 PUT /v1/girl/{mid} 回退:
            # 从 GIRL_MASTER_MAP + 模板构建. 否则返回空 girl_list → 客户端换发型不刷新(切服装才刷新)
            import copy as _pgc2
            _gmm2 = GIRL_MASTER_MAP.get(int(gm), {})
            _src2 = None
            for _r2 in SERVER_DB.get("endpoints", {}).get("/v1/girl", []):
                for _g2 in _r2.get("girl_list", []):
                    _src2 = _g2; break
                if _src2: break
            girl = _pgc2.deepcopy(_src2) if _src2 else {"owner_id": OWNER_ID}
            girl["girl_mid"] = int(gm)
            girl["power"] = _gmm2.get("power", 1000)
            girl["technic"] = _gmm2.get("technic", 800)
            girl["stamina"] = _gmm2.get("stamina", 1000)
            girl["appeal"] = _gmm2.get("appeal", 20)
            girl["swimsuit_item_mid"] = _gmm2.get("swimsuit", 0)
            girl["hair_item_mid"] = _gmm2.get("hair", 0)
            girl["created_at"] = "2023-05-24 06:02:14"
            girl["updated_at"] = "2023-05-24 06:02:14"
        if girl is not None:
            apply_girl_state(girl)
        # 私服版实测返回 girl_list 结构; 保存后回显新装备
        return {"girl_list": [girl] if girl else []}

    # ---- 最爱标记: POST /v1/girl/{mid}/private/favorite/{type} (2026-09-13: 动态化, 写STATE) ----
    # 之前: overlay 不区分 method 提前拦截 POST → body 被丢 → 取消无效
    #       GET 把全量持有当最爱 (无 favorite 字段过滤) → 新抽到默认被标记
    # 修复: POST 写 equipment_inventory.favorite 字段并 _save_state, GET 只返回 favorite=1 的
    m_fav_post = re.match(r"^/v1/girl/(\d+)/private/favorite/(\d+)$", path)
    if m_fav_post and method == "POST":
        _fp_gm = int(m_fav_post.group(1))
        _fp_type = int(m_fav_post.group(2))
        # 2026-11-08 14:30: type37(姿势卡)/81(表情卡) 的星标单独存 STATE["pose_expr_favorite"]
        #   (equipment_inventory 里没有这两类的实例, 旧代码对它们完全空转 → 取消星标重启即复原)
        if _fp_type in (37, 81):
            # GET 现在回"拥有的卡"(映射表), 所以取消星标必须记进 removed 黑名单才能真的消失,
            # 否则下次 GET 又把它从映射里取回来 —— 这正是用户之前"取消后重启又复原"的根因。
            _pe_add = STATE.setdefault("pose_expr_favorite", {})
            _pe_del = STATE.setdefault("pose_expr_removed", {})
            _pek = f"{_fp_gm}:{_fp_type}"
            _add_set = set(int(x) for x in _pe_add.get(_pek, []))
            _del_set = set(int(x) for x in _pe_del.get(_pek, []))
            for _it in (req.get("item_list") or []):
                _fp_im = _it.get("item_mid")
                if _fp_im is None:
                    continue
                _fp_im = int(_fp_im)
                if _it.get("is_favorite", 0):
                    _add_set.add(_fp_im)
                    _del_set.discard(_fp_im)
                else:
                    _add_set.discard(_fp_im)
                    _del_set.add(_fp_im)
            _pe_add[_pek] = sorted(_add_set)
            _pe_del[_pek] = sorted(_del_set)
            _save_state()
            print(f"[favorite] girl={_fp_gm} type={_fp_type} 额外加 {len(_add_set)} 张, 移除 {len(_del_set)} 张")
            _fp_map = _pose_owner_map_cached()
            _fp_uni = _pose_universal_items() if _fp_type == 37 else set()
            _fp_set = {_m for _m, _gs in _fp_map.items()
                       if _fp_gm in _gs and EQUIP_TYPE_MAP.get(_m) == _fp_type}
            _fp_set |= _fp_uni
            _fp_set = (_fp_set | _add_set) - _del_set
            return {"favorite_private_item_list": [
                {"girl_mid": _fp_gm, "type": _fp_type, "item_mid": _m} for _m in sorted(_fp_set)]}
        _fp_type_map = {1: 1, 22: 22, 23: 23, 24: 24}
        _fp_eq_type = _fp_type_map.get(_fp_type)
        for _it in (req.get("item_list") or []):
            _fp_im = _it.get("item_mid")
            _fp_val = _it.get("is_favorite", 0)
            if _fp_im is None:
                continue
            for _e_fp in STATE.get("equipment_inventory", []):
                if isinstance(_e_fp, dict) and _e_fp.get("item_mid") == _fp_im:
                    _e_fp["favorite"] = 1 if _fp_val else 0
        _save_state()
        _fp_ret = []
        if _fp_eq_type is not None:
            _fp_seen = set()
            for _e_fp in STATE.get("equipment_inventory", []):
                if isinstance(_e_fp, dict) and _e_fp.get("type", 0) == _fp_eq_type and _e_fp.get("favorite", 0):
                    _fp_im = _e_fp.get("item_mid", 0)
                    if _fp_im and _fp_im not in _fp_seen:
                        _fp_seen.add(_fp_im)
                        _fp_ret.append({"girl_mid": _fp_gm, "type": _fp_type, "item_mid": _fp_im})
        return {"favorite_private_item_list": _fp_ret}

    # ---- 换装后更新: PUT /v1/girl/{mid} (visual_state/sunburn/wet 等) ----
    # 2026-09-09 实测: 每次换装后客户端还发 PUT /v1/girl/{mid} 更新状态, 之前未处理落默认
    m_pg = re.match(r"^/v1/girl/(\d+)$", path)
    if m_pg and method == "PUT":
        gm = m_pg.group(1)
        # 2026-09-14: 持久化 visual_state/sunburn/wet/hip_swing 等 (泳装滑落/护肤状态, 之前重启丢失)
        _vs_fields = ("sunburn","wet","hip_swing","hip_press","bust_swing","bust_press",
                      "hip_swing_lock","hip_press_lock","bust_swing_lock","bust_press_lock",
                      "visual_state_flag_a","visual_state_flag_b","visual_state_flag_c","visual_state_flag_d","mood")
        _vs = STATE.setdefault("girl_visual_state", {}).setdefault(gm, {})
        for _f in _vs_fields:
            if _f in req:
                _vs[_f] = req[_f]
        _save_state()
        girl = girl_obj_from_db(int(gm))
        if girl is None:
            # 2026-09-17: GM加的女孩(如girl24)不在响应池→girl_obj_from_db返回None→PUT回空girl_list
            # →客户端切visual_state后拿不到更新对象, 服装视觉不变. 用GIRL_MASTER_MAP+模板构建(同GET /v1/girl)
            import copy as _pgc
            _gmm = GIRL_MASTER_MAP.get(int(gm), {})
            _src = None
            for _r in SERVER_DB.get("endpoints", {}).get("/v1/girl", []):
                for _g in _r.get("girl_list", []):
                    _src = _g; break
                if _src: break
            girl = _pgc.deepcopy(_src) if _src else {"owner_id": OWNER_ID}
            girl["girl_mid"] = int(gm)
            girl["power"] = _gmm.get("power", 1000)
            girl["technic"] = _gmm.get("technic", 800)
            girl["stamina"] = _gmm.get("stamina", 1000)
            girl["appeal"] = _gmm.get("appeal", 20)
            girl["swimsuit_item_mid"] = _gmm.get("swimsuit", 0)
            girl["hair_item_mid"] = _gmm.get("hair", 0)
            girl["created_at"] = "2023-05-24 06:02:14"
            girl["updated_at"] = "2023-05-24 06:02:14"
        apply_girl_state(girl)
        return {"girl_list": [girl]}
    # 2026-09-14备注: visual_state(sunburn/wet/hip_swing等)已通过上面 m_pg PUT 持久化(STATE.girl_visual_state),
    # 覆盖以下端点(均静态可接受,无需单独动态化):
    #   - 泳装滑落 dishevelment GET(查看状态,visual_state已持久化,GET静态返回快照可接受)
    #   - 护肤 skin_care/lock(visual_state已持久化;锁定逻辑待抓PUT req,但状态已保存)
    #   注: 防晒油未发现单独端点(可能属skin_care或消耗品使用,待确认)

    # ---- 装备锁定: PUT /v1/item/equipment/list/lock (2026-09-13 修复卡死) ----
    # 客户端抽卡/获得装备后发此请求锁定新装备(item_id=服务器生成的实例id),
    # 服务器须回显请求的 item_id + in_lock, 否则客户端收不到匹配响应疯狂重试卡死
    if path == "/v1/item/equipment/list/lock" and method == "PUT":
        _lock_req = req.get("lock_equipment_item_id_list", []) or []
        _resp_lock = []
        _resp_update = []
        _inv = STATE.get("equipment_inventory", [])
        _inv_by_id = {_e.get("id"): _e for _e in _inv if isinstance(_e, dict)}
        for _lk in _lock_req:
            _iid = _lk.get("item_id")
            _ilock = _lk.get("in_lock", 1)
            _resp_lock.append({"item_id": _iid, "in_lock": _ilock})
            _eq = _inv_by_id.get(_iid)
            if _eq:
                _eq["in_lock"] = _ilock
                _resp_update.append({"id": _iid, "item_mid": _eq.get("item_mid", 0), "in_lock": _ilock})
            else:
                _resp_update.append({"id": _iid, "item_mid": 0, "in_lock": _ilock})
        _save_state()
        return {"item_equipment_lock_list": _resp_lock, "item_update_lock_equipment_list": _resp_update}

    # ---- 抽卡: 按 draw_count 从单抽/十连池轮换 (2026-09-13 阶段2: 增加扣费持久化) ----
    if path == "/v1/gacha/draw":
        # 2026-09-13 故障1根因确认: 客户端十连请求 draw_count 仍=1, 靠 paid_kind 区分!
        # paid_kind: 1=免费单抽 2=vstone单抽 3=vstone十连 5=券单抽 6=券十连
        print(f"[gacha/draw] REQ={json.dumps(req, ensure_ascii=False)[:500]}")
        _dc_raw = req.get("draw_count") or 1
        try:
            dc = int(_dc_raw)
        except (ValueError, TypeError):
            dc = 1
        _pk = req.get("paid_kind")
        _pk = int(_pk) if isinstance(_pk, (int, str)) and str(_pk).isdigit() else 0
        _is_ten = dc >= 10 or _pk in (3, 5, 6)   # 十连判断: draw_count>=10 或 paid_kind 为十连类型(3/5/6)
        if _is_ten:
            dc = 10   # 十连实际抽卡次数
        # 真随机: 按 (gacha_mid, step) 查对应卡池奖池, 按配置爆率+保底逻辑随机选
        import random as _grand
        import copy as _gcopy
        _gm_draw = req.get("gacha_mid")
        _gm_draw = int(_gm_draw) if isinstance(_gm_draw, (int, str)) and str(_gm_draw).isdigit() else 0
        # 2026-09-14: 卡池元数据验证 (type/时间范围)
        if _gm_draw:
            _gtype = _gacha_type(_gm_draw)
            if _gtype == 1:
                print(f"[gacha/draw] WARNING: gacha_mid={_gm_draw} 是 type=1 测试池")
            if not _gacha_is_active(_gm_draw):
                print(f"[gacha/draw] WARNING: gacha_mid={_gm_draw} 已过期或未开始 (type={_gtype})")
        # 方案C: 从保底状态读当前阶梯, 传给 _random_gacha_items
        _draw_step = STATE.get("gacha_pity", {}).get(_gacha_pity_key(_gm_draw), {}).get("current_step", 1) if _gm_draw else 1
        if _gm_draw:
            _random_items = _random_gacha_items(_gm_draw, dc, _draw_step)
        elif _GACHA_RANDOM_POOL["items"]:
            _random_items = _grand.choices(_GACHA_RANDOM_POOL["items"],
                                            weights=_GACHA_RANDOM_POOL["weights"], k=dc)
        else:
            _random_items = []
        if _random_items:
            _base_pool = SERVER_DB.get("gacha_draw_10" if _is_ten else "gacha_draw_1", [])
            _base_tmpl = _gcopy.deepcopy(_base_pool[0]) if _base_pool else {}
            _base_tmpl["gacha_draw_list"] = [{"item_mid": im} for im in _random_items]
            if _gm_draw:
                _base_tmpl["gacha_list"] = {"gacha_mid": _gm_draw}  # 修复bug1: draw resp 加 gacha_list, reward 才能从 LAST_DRAW_RESP 取 gacha_mid
            resp = _base_tmpl
            ok = True
        else:
            pool = SERVER_DB.get("gacha_draw_10" if _is_ten else "gacha_draw_1", [])
            if not pool:
                pool = eps.get(path, [])
            resp, ok = _pick_rotate(pool, path)
        if ok:
            LAST_DRAW_RESP = resp
            # 阶段2: 扣费持久化 — 优先用请求 gacha_mid 查 GachaStepup, 回退到 draw 响应的 item_consume_list
            _gm = req.get("gacha_mid")
            _gm = int(_gm) if isinstance(_gm, (int, str)) and str(_gm).isdigit() else None
            _cfg = GACHA_STEPUP_MAP.get(_gm) if _gm is not None else None
            _consume_im = _cfg["consume_item_mid"] if _cfg else 0
            if _consume_im:
                # 用抽卡券: 扣 dc 张
                _cur, _left_tk = ic_take(_consume_im, dc)
                print(f"[gacha/draw] gacha_mid={_gm} 扣券 item_mid={_consume_im} -{dc} (剩 {_left_tk})")
            else:
                # 用 vstone: 优先 stepup price, 否则默认 单抽3000/十连27000(九折)
                _price = _cfg["price"] if _cfg and _cfg.get("price") else 3000
                _cost = _price * (dc - 1) if dc >= 10 else _price * dc
                _w = STATE.setdefault("wallet", {})
                _free = _w.get("free_vstone", 0)
                _paid = _w.get("paid_vstone", 0)
                if _free + _paid >= _cost:
                    if _free >= _cost:
                        _w["free_vstone"] = _free - _cost
                    else:
                        _w["free_vstone"] = 0
                        _w["paid_vstone"] = _free + _paid - _cost
                    print(f"[gacha/draw] gacha_mid={_gm} 扣vstone -{_cost} (free={_w.get('free_vstone')} paid={_w.get('paid_vstone')})")
            # 阶段4: 记录抽卡进度到 STATE.gacha_draw_counts
            if _gm is not None:
                _gdc = STATE.setdefault("gacha_draw_counts", {})
                _gdc[_gm] = _gdc.get(_gm, 0) + dc
            _save_state()
            return resp
        return None

    # ---- 抽卡领取: 基于 LAST_DRAW_RESP 构造, 与 draw 一一对应 (2026-09-13 阶段1修复) ----
    # 原缺陷: reward 从独立池轮换, 与 draw 实际抽到的不一致 → 抽A领B
    # 修复: 基于 LAST_DRAW_RESP.gacha_draw_list 构造完整 reward 响应, 保证抽什么领什么
    if path == "/v1/gacha/reward":
        if LAST_DRAW_RESP is not None:
            import copy as _rcopy
            import time as _rtime
            rpool = eps.get(path, [])
            base = _rcopy.deepcopy(rpool[0]) if rpool else {}
            # draw 抽到的 item_mid 列表 (reward 必须与之对应)
            drawn = [d.get("item_mid") for d in LAST_DRAW_RESP.get("gacha_draw_list", []) if d.get("item_mid") is not None]
            # 方案C: SSR 自动锁定 — 查 gacha_mid 的 SSR 物品集, 配置开启则 in_lock=1
            _gm_rw = None
            _gl_rw = LAST_DRAW_RESP.get("gacha_list")
            if isinstance(_gl_rw, dict) and "gacha_mid" in _gl_rw:
                _gm_rw = _gl_rw["gacha_mid"]
            _ssr_set = set()
            _auto_lock = False
            if _gm_rw:
                try:
                    _gm_rw = int(_gm_rw)
                except (ValueError, TypeError):
                    _gm_rw = None
            if _gm_rw:
                _rw_step = STATE.get("gacha_pity", {}).get(_gacha_pity_key(_gm_rw), {}).get("current_step", 1)
                _rw_pool = _gacha_effective_pool(_gm_rw, _rw_step, _get_gacha_pool(_gm_rw, _rw_step))
                _ssr_set = {im for im, _ in _rw_pool.get("SSR", [])}
                _auto_lock = _get_gacha_config(_gm_rw).get("ssr_auto_lock", False)
            # 生成唯一装备实例 id (大整数, 4B 量级避开抓包 3.1B 区间)
            _base_id = (int(_rtime.time() * 1000) % 1000000000) + 4000000000
            riel = []
            iel = []
            otl = []
            icl = []
            _ic = STATE.setdefault("item_counts", {})
            for _i, _im in enumerate(drawn):
                if EQUIP_TYPE_MAP.get(_im) is None:
                    # 消耗品: 主数据(Equipment_Parameter)无此 item_mid 的装备类型映射 → 进 item_consume_list
                    # 2026-09-13 修复: 旧逻辑 `>=35000` 阈值把真泳装(如57434/59254等高item_mid泳装)误判为消耗品
                    _ctype = ITEM_TYPE_MAP.get(_im, 12)
                    _cnt_new = ic_add(_im, 1)
                    icl.append({"item_mid": _im, "count": _cnt_new, "type": _ctype,
                                "updated_at": server_now_str(), "created_at": server_now_str()})
                else:
                    # 装备 (泳装/配饰): 进 equipment list, type 从主数据查 (1泳装/22头/23脸/24臂)
                    _eid = _base_id + _i
                    _etype = EQUIP_TYPE_MAP.get(_im, 1)
                    _lock_val = 1 if (_auto_lock and _im in _ssr_set) else 0
                    riel.append({"id": _eid, "item_mid": _im, "level": 1, "combine_count": 0})
                    iel.append({"id": _eid, "item_mid": _im, "type": _etype, "level": 1, "experience": 0,
                                "girl_mid": 0, "favorite": 0, "in_lock": _lock_val, "unlock_count": 0,
                                "upgrade_count": 0, "combine_count": 0})
                    otl.append({"item_mid": _im, "count": 0, "type": 29, "updated_at": None,
                                "created_at": server_now_str()})
            base["reward_item_equipment_list"] = riel
            base["item_equipment_list"] = iel
            base["order_ticket_list"] = otl
            base["item_consume_list"] = icl
            # 2026-09-14: private_item_list — 抽到的装备加入私人套装列表 (为每个可用女孩添加记录)
            _avail_girls = [2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,26,27,29,30,31,32]
            _pil = []
            for _e in iel:
                for _agm in _avail_girls:
                    _pil.append({"girl_mid": _agm, "item_mid": _e["item_mid"]})
            if _pil:
                base["private_item_list"] = _pil
            # gacha_mid: 优先取 draw 的 gacha_list, 否则保留基底
            _gl = LAST_DRAW_RESP.get("gacha_list")
            if isinstance(_gl, dict) and "gacha_mid" in _gl:
                base["gacha_mid"] = {"gacha_mid": _gl["gacha_mid"]}
            # wallet/wallet_list 由 _inject_state_wallet 统一覆盖
            # 阶段3: 装备入库持久化 — 抽到的装备实例写入 STATE.equipment_inventory
            _inv = STATE.setdefault("equipment_inventory", [])
            # 同时写入 STATE.private_items (私人套装列表, 为每个女孩去重)
            _spi = STATE.setdefault("private_items", [])
            _spi_keys = {(_p.get("girl_mid", 0), _p.get("item_mid", 0)) for _p in _spi}
            _avail_girls2 = [2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,26,27,29,30,31,32]
            for _e in iel:
                _inv.append(_rcopy.deepcopy(_e))
                for _agm2 in _avail_girls2:
                    _pk2 = (_agm2, _e["item_mid"])
                    if _pk2 not in _spi_keys:
                        _spi.append({"girl_mid": _agm2, "item_mid": _e["item_mid"]})
                        _spi_keys.add(_pk2)
            # 修复bug2: SSR 泳装解锁女孩 — 抽到 in_lock=1 的 type=1 泳装, 解锁 girl 28 (girl_master.csv 属性: swimsuit=4172/hair=4173/power=1100)
            _ssr_swim = [e for e in iel if e.get("in_lock") == 1 and e.get("type") == 1]
            if _ssr_swim and 28 not in _ALL_GIRL_MIDS:
                _ALL_GIRL_MIDS.append(28)
                base["girl_list"] = [{"owner_id": OWNER_ID, "girl_mid": 28, "mood": 0, "experience": 0, "level": 1,
                    "power": 1100, "additional_power": 0, "technic": 880, "additional_technic": 0,
                    "stamina": 1040, "additional_stamina": 0, "appeal": 20, "appeal_up": 0, "additional_appeal": 0,
                    "hair_item_mid": 4173, "ring_item_mid": 0, "addition_accessory_item_mid": 0,
                    "swimsuit_item_mid": 4172, "accessory_head_item_mid": 0, "accessory_face_item_mid": 0,
                    "accessory_arm_item_mid": 0, "visual_state_flag_a": 0, "visual_state_flag_b": 0,
                    "visual_state_flag_c": 0, "visual_state_flag_d": 0, "sunburn": 0, "wet": 0,
                    "hip_swing": 0, "hip_press": 0, "bust_swing": 0, "bust_press": 0,
                    "hip_swing_lock": 0, "hip_press_lock": 0, "bust_swing_lock": 0, "bust_press_lock": 0,
                    "panel_experience": 0, "display_coordinate": 0, "affection_level": 1, "affection_point": 0,
                    "venus_memory": 0, "girly": 0, "skin_color": 0, "nail_color": 0, "partner_count": 0,
                    "created_at": server_now_str(), "updated_at": None}]
            _save_state()
            return base
        # 兜底: draw 无记录时回退原轮换
        pool = eps.get(path, [])
        resp, ok = _pick_rotate(pool, path)
        if ok:
            return resp
        return None

    # ---- 2026-11-08: 最近队伍动态化 (换女孩后不再返回抓包账号的 11/13) ----
    #   重要: 客户端请求体用 65535/0xffff 表示"无替补", 真服 latest/team 一律规范成 -1。
    #   直接回显 65535 会让客户端拿它当 girl_mid 查女孩对象 → 返回 nullptr →
    #   DOAX_VV.exe+0x240dd1b 处 movzx edx,[rax+0x98] 空指针崩溃 (0xc0000005)。
    if path == "/v1/quest/latest/team":
        _tmpl_lt = (REAL_RESPONSES.get(path, {}) or {}).get("quest_latest_team", {}) or {}
        _lt = dict(_tmpl_lt)
        _t = STATE.get("quest_team") or {}
        _valid_girls = set(GIRL_MASTER_MAP.keys())
        for _k in ("girl_mid_forward", "girl_mid_back", "girl_mid_substitute"):
            if _k not in _t:
                continue
            try:
                _v = int(_t[_k])
            except (TypeError, ValueError):
                continue
            if _k == "girl_mid_substitute":
                _lt[_k] = _v if _v in _valid_girls else -1
            elif _v in _valid_girls:
                _lt[_k] = _v
        # quest_mid 必须是客户端能在 quest/list 里查到的关卡, 否则同样会查表落空
        _known_q = set()
        for _o in SERVER_DB.get("endpoints", {}).get("/v1/quest/list", []):
            for _q in (_o.get("quest_list") or []):
                try:
                    _known_q.add(int(_q.get("quest_mid")))
                except (TypeError, ValueError):
                    pass
        for _qk in (STATE.get("cleared_quests") or {}):
            try:
                _known_q.add(int(_qk))
            except (TypeError, ValueError):
                pass
        try:
            _vm_i = int(_t.get("quest_mid"))
        except (TypeError, ValueError):
            _vm_i = 0
        if _vm_i in _known_q:
            _lt["quest_mid"] = _vm_i
        for _k in ("quest_mid", "girl_mid_forward", "girl_mid_back", "girl_mid_substitute"):
            try:
                _lt[_k] = int(_lt[_k])
            except (TypeError, ValueError, KeyError):
                pass
        _lt["owner_id"] = OWNER_ID
        return {"quest_latest_team": _lt}

    # ---- 挑战赛开始: 按 quest_mid 分组推进 phase 状态机 ----
    if path == "/v1/quest/start":
        mid = str(req.get("quest_mid")) if req.get("quest_mid") is not None else None
        by_mid = SERVER_DB.get("quest_start_by_mid", {})
        seq = by_mid.get(mid) if mid is not None else None
        mid_sub = None  # 2026-09-12: 兜底时需回填请求的 quest_mid (避免 quest_mid 错配 → -603)
        if not seq and by_mid:
            # 未知 quest_mid 不再掉包成别的 quest, 用模板序列 + 回填请求的 mid
            mid_sub = mid
            mid = sorted(by_mid.keys())[0]
            seq = by_mid[mid]
        if not seq:
            seq = eps.get(path, [])
        if not seq:
            return None
        idx = _quest_start_idx(mid)
        resp = seq[idx % len(seq)]
        # 2026-09-12 debug
        _qs_dbg = resp.get("quest_start", {})
        print(f"[QUEST-START-DBG] req_mid={mid_sub} fallback_mid={mid} idx={idx} resp_mid={_qs_dbg.get('quest_mid')} phase={_qs_dbg.get('phase')} cont={_qs_dbg.get('is_continue')}", flush=True)
        if mid_sub is not None:
            import copy as _copy
            resp = _copy.deepcopy(resp)
            _qs = resp.get("quest_start", {})
            if _qs:
                try:
                    _qs["quest_mid"] = int(mid_sub)
                except (ValueError, TypeError):
                    _qs["quest_mid"] = mid_sub
                # 2026-09-12: 也替换 match_point 等 quest 配置字段 (从 CSV 查正确值)
                _r = _qs.get("result")
                if isinstance(_r, dict):
                    try:
                        _qm_csv = int(mid_sub)
                        if _qm_csv in _QUEST_MATCH:
                            _r["match_point"] = _QUEST_MATCH[_qm_csv]
                    except (ValueError, TypeError):
                        pass
        # 一个关卡打完(最后一响应)后重置, 下一局重新 phase 1
        if (idx % len(seq)) == len(seq) - 1:
            _set_quest_start_idx(mid, 0)
        else:
            _set_quest_start_idx(mid, idx + 1)
        # 2026-09-12: 新一局 quest/start 时重置 quest/end 游标,
        # 确保 this 局首调 quest/end 返回 phase 1 (否则跨局游标累积 → phase 错位 → -603)
        _set_quest_end_idx(mid, 0)
        _save_state()
        # 2026-11-08: 挑战赛换女孩/换衣服动态化 (全套装备 + 技能, 不再只改 girl_mid 和泳装编号)
        #   旧实现只覆盖泳装 item_mid, skill_list/饰品/回合技能仍是抓包账号的 → 比赛技能不随换装变化
        import copy as _qs_c2
        resp = _qs_c2.deepcopy(resp)
        _team = {}
        for _pos, _key in ((0, "girl_mid_forward"), (1, "girl_mid_back"), (6, "girl_mid_substitute")):
            _v = req.get(_key)
            if _v:
                try:
                    _iv = int(_v)
                except (TypeError, ValueError):
                    continue
                # 65535/0xffff 等是"无替补"哨兵, 不能当 girl_mid 下发, 否则客户端查表落空崩溃
                if _iv in GIRL_MASTER_MAP:
                    _team[_pos] = _iv
        if _team:
            _saved_team = STATE.setdefault("quest_team", {})
            for _pos, _key in ((0, "girl_mid_forward"), (1, "girl_mid_back")):
                if _pos in _team:
                    _saved_team[_key] = _team[_pos]
            # 存档统一用真服的 -1 表示无替补
            _saved_team["girl_mid_substitute"] = _team.get(6, -1)
            _saved_team["quest_mid"] = mid_sub or mid
            try:
                _saved_team["quest_mid"] = int(_saved_team["quest_mid"])
            except (TypeError, ValueError):
                pass
            _save_state()
        _qs_r2 = resp.get("quest_start", {}).get("result")
        if isinstance(_qs_r2, dict) and isinstance(_qs_r2.get("girl_list"), list):
            _sync_battle_girls(_qs_r2["girl_list"], _team or None)
        # 2026-09-12: phase 3 (is_continue=false) 时初始化比赛状态 (动态生成排球回合用)
        _qs_init = resp.get("quest_start", {})
        if _qs_init.get("phase") == 3 and _qs_init.get("is_continue") is False:
            _result = _qs_init.get("result") or {}
            _init_match(_qs_init.get("quest_mid"), _result.get("match_point", 3))
        return resp

    # ---- 比赛回合: 2026-09-12 改为动态生成 (替代静态轮换, 解决 round_number 乱序 → -603) ----
    if path in ("/v1/quest/volley/round/start", "/v1/quest/volley/round/end",
                "/v1/quest/volley/skip"):
        resp = _build_volley_dynamic(path, eps)
        if resp is not None:
            return resp
        # 无比赛状态时回退到轮换
        pool = eps.get(path, [])
        resp, ok = _pick_rotate(pool, path)
        if ok:
            return resp
        return None
    if path == "/v1/quest/volley/run":
        pool = eps.get(path, [])
        resp, ok = _pick_rotate(pool, path)
        if ok:
            return resp
        return None

    # ---- 挑战赛结算: 按 quest_mid 推进 phase 1->2->3->4->5, 结束后重置 ----
    if path == "/v1/quest/end":
        mid = str(req.get("quest_mid")) if req.get("quest_mid") is not None else None
        pool = eps.get(path, [])
        if not pool:
            return None
        # 分组: 同一 quest_mid 的响应序列 (按出现顺序 = phase 序列)
        if mid is None:
            resp, ok = _pick_rotate(pool, path)
            return resp if ok else None
        by_mid = {}
        for obj in pool:
            qm = obj.get("quest_end", {}).get("quest_mid")
            by_mid.setdefault(str(qm) if qm is not None else "?", []).append(obj)
        mid_sub = None  # 2026-09-12: 兜底时需回填请求的 quest_mid (避免 quest_mid 错配 → -603)
        seq = by_mid.get(mid)
        if not seq and by_mid:
            # 未知 quest_mid 不再掉包成别的 quest, 用模板序列 + 回填请求的 mid
            mid_sub = mid
            mid = sorted(by_mid.keys())[0]
            seq = by_mid[mid]
        if not seq:
            return None
        idx = _quest_end_idx(mid)
        resp = seq[idx % len(seq)]
        if mid_sub is not None:
            import copy as _copy
            resp = _copy.deepcopy(resp)
            _qe = resp.get("quest_end", {})
            if _qe:
                try:
                    _qe["quest_mid"] = int(mid_sub)
                except (ValueError, TypeError):
                    _qe["quest_mid"] = mid_sub
        # 结束(phase5 continue=False)后重置, 下一局从 phase1 开始
        # 2026-11-08: 下面要改写结算女孩, 先脱离响应池, 避免污染 SERVER_DB 静态数据
        import copy as _qe_cp
        resp = _qe_cp.deepcopy(resp)
        qe = resp.get("quest_end", {})
        # 2026-11-08: 通关经验/升级应发给当前出战的两个女孩, 旧快照是抓包账号的 11/13
        _lr = qe.get("levelup_reward")
        if isinstance(_lr, dict) and isinstance(_lr.get("girl_list"), list):
            _tm_end = _current_quest_team()
            _ordered_end = [_tm_end[p] for p in (0, 1) if p in _tm_end]
            for _i, _g_end in enumerate(_lr["girl_list"]):
                if _i < len(_ordered_end) and isinstance(_g_end, dict):
                    _g_end["girl_mid"] = _ordered_end[_i]
        # 2026-09-12 debug: 确认 mid_substitution 是否生效
        print(f"[QUEST-END-DBG] req_mid={mid_sub} fallback_mid={mid} idx={idx} resp_mid={qe.get('quest_mid')} phase={qe.get('phase')} cont={qe.get('is_continue')}", flush=True)
        if qe.get("is_continue") is False or qe.get("phase") == 5:
            _set_quest_end_idx(mid, 0)
            # 2026-09-12: 记录通关状态 (用于 quest/list 叠加 quest_clear)
            _qm_end = qe.get("quest_mid")
            _now_str = server_now_str()
            _cleared = STATE.setdefault("cleared_quests", {})
            _cleared[str(_qm_end)] = {
                "quest_clear": True,
                "quest_new": False,
                "clear_rank": 1,
                "high_score": _MATCH_STATE.get("acc_pa", 3000),
                "first_cleared_at": _now_str,
                "srank_cleared_at": _now_str,
                "arank_cleared_at": None,
            }
            # 记录每日挑战通关 (category=3 = 每日/活动)
            try:
                _qm_int = int(_qm_end) if _qm_end else 0
                if _qm_int in _QUEST_CATEGORY and _QUEST_CATEGORY[_qm_int] == 3:
                    _today = game_today_str()
                    if STATE.get("daily_quest_date") != _today:
                        STATE["daily_quest_date"] = _today
                        STATE["daily_quest_count"] = 0
                    STATE["daily_quest_count"] = STATE.get("daily_quest_count", 0) + 1
            except (ValueError, TypeError):
                pass
        else:
            _set_quest_end_idx(mid, idx + 1)
        _save_state()
        return resp

    # ---- 2026-09-12: quest/list 叠加通关状态 (quest_clear) ----
    if path == "/v1/quest/list":
        pool = eps.get(path, [])
        resp, ok = _pick_rotate(pool, path)
        if ok:
            import copy as _copy
            resp = _copy.deepcopy(resp)
            cleared = STATE.get("cleared_quests", {})
            ql = resp.get("quest_list", [])
            existing = set()
            for q in ql:
                _qm_s = str(q.get("quest_mid"))
                existing.add(_qm_s)
                if _qm_s in cleared:
                    q.update(cleared[_qm_s])
            for _qm_s, info in cleared.items():
                if _qm_s not in existing:
                    try:
                        ql.append({"quest_mid": int(_qm_s), **info})
                    except (ValueError, TypeError):
                        pass
            resp["quest_list"] = ql
            return resp
        return resp if ok else None

    # ---- 2026-09-12: quest/fes/info 叠加每日挑战通关计数 ----
    if path == "/v1/quest/fes/info":
        pool = eps.get(path, [])
        resp, ok = _pick_rotate(pool, path)
        if ok:
            import copy as _copy
            resp = _copy.deepcopy(resp)
            _today = game_today_str()
            if STATE.get("daily_quest_date") != _today:
                STATE["daily_quest_date"] = _today
                STATE["daily_quest_count"] = 0
            _dc = STATE.get("daily_quest_count", 0)
            if _dc > 0:
                resp["quest_daily_info_list"] = [
                    {"group_id": 1, "count": _dc, "expired_at": _today + " 18:59:59"}
                ]
            else:
                resp["quest_daily_info_list"] = []
            return resp
        return resp if ok else None

    # ---- 2026-09-13 阶段4: gacha/ticket 叠加 STATE 抽卡券真实库存 ----
    if path == "/v1/gacha/ticket":
        pool = eps.get(path, [])
        resp, ok = _pick_rotate(pool, path)
        if ok:
            import copy as _copy
            resp = _copy.deepcopy(resp)
            _ic = STATE.get("item_counts", {})
            for _t in resp.get("gacha_ticket_list", []):
                _im = _t.get("item_mid")
                if _im is not None and _im in _ic:
                    _t["count"] = _ic[_im]
            return resp
        return resp if ok else None

    # ---- 2026-09-13 阶段4: gacha/list 叠加 STATE 抽卡进度 ----
    if path == "/v1/gacha/list":
        pool = eps.get(path, [])
        resp, ok = _pick_rotate(pool, path)
        if ok:
            import copy as _copy
            resp = _copy.deepcopy(resp)
            _gdc = STATE.get("gacha_draw_counts", {})
            for _g in resp.get("gacha_info_list", []):
                _gm = _g.get("gacha_mid")
                if _gm is not None:
                    _cnt = _gdc.get(_gm) or _gdc.get(str(_gm))
                    if _cnt:
                        _g["count_drew_gacha_free"] = _cnt
                        _g["gacha_drew_before"] = True
            # GM 控制可见卡池: gacha_visible_pools 非 None 时只返回列表内的卡池
            _vis = STATE.get("gacha_visible_pools")
            # None / [] 都表示「全部显示」；GM 面板用哨兵 mid 表达「一个都不显示」。
            # 口径必须与 /gm/api/gacha/visible 的回读一致，否则空列表会把卡池全过滤掉。
            if _vis:
                _vis_set = {int(v) for v in _vis}
                resp["gacha_info_list"] = [g for g in resp.get("gacha_info_list", []) if g.get("gacha_mid") in _vis_set]
            return resp
        return resp if ok else None

    # ========================================================================
    # 2026-11-07 背包修复③: 物品操作端点真实化
    #   背景: 这些端点在 SERVER_DB 里只有"别的账号"的静态快照, 走到下面的响应池轮换后:
    #     分解 → 回一堆不属于本账号的装备 id, 点了没删件、点数也不加;
    #     封印 → 回别人的封印列表, 贴上去必然失败。
    #   做: 用本账号真实存档(item_counts / equipment_inventory)生成响应并落盘。
    # ========================================================================

    # ---- 分解/回收套装: POST /v1/item/equipment/decompose ----
    #   请求: {"item_equipment_id_list": [实例id, ...]}
    #   真实响应: item_equipment_decompose_list(每件一条, source_item_mid + decompose_list)
    #             + deleted_item_equipment_list + wallet_list   (抓包样本 3 份一致)
    #   奖励: 维纳斯点数 35083, 泳装(1) 2 点/件, 其它装备 1 点/件 —— 与抓包中 271/320 两件一致
    if path == "/v1/item/equipment/decompose" and method == "POST":
        _req_ids = req.get("item_equipment_id_list", []) or []
        _req_set = set()
        for _x in _req_ids:
            try:
                _req_set.add(int(_x))
            except (TypeError, ValueError):
                pass
        _inv = STATE.get("equipment_inventory", [])
        _keep_inv = []
        _gone = []
        for _e in _inv:
            if isinstance(_e, dict) and _e.get("id") in _req_set:
                _gone.append(_e)
            else:
                _keep_inv.append(_e)
        _dec_list, _del_list = [], []
        _gain = 0
        _now_dec = game_now_str()
        for _e in _gone:
            _mid_d = int(_e.get("item_mid") or 0)
            _pt = 2 if _e.get("type") == 1 else 1
            _gain += _pt
            _dec_list.append({"source_item_mid": _mid_d,
                              "decompose_list": [{"item_mid": 35083, "count": _pt}]})
            _del_list.append({"id": _e.get("id"), "item_mid": _mid_d,
                              "level": _e.get("level", 1),
                              "combine_count": _e.get("combine_count", 0),
                              "created_at": _e.get("created_at") or _now_dec})
        if _gone:
            STATE["equipment_inventory"] = _keep_inv
            if _gain:
                ic_add(35083, _gain)
            _save_state()
        print(f"[decompose] 请求 {len(_req_set)} 件, 实际删除 {len(_gone)} 件, 返还 35083 x{_gain}")
        return {"item_equipment_decompose_list": _dec_list,
                "deleted_item_equipment_list": _del_list,
                "wallet_list": [dict(STATE.get("wallet", {}), owner_id=OWNER_ID)]}

    # ---- 封印列表: GET /v1/seal ----
    #   原走静态快照(别的账号的 100+ 个封印) → 客户端显示一堆没有的封印, 贴/拆都失败。
    #   改为从衣橱 type=69 实例生成。
    if path == "/v1/seal" and method == "GET":
        _seal_l = []
        for _e in STATE.get("equipment_inventory", []):
            if isinstance(_e, dict) and _e.get("type") == 69:
                _seal_l.append({
                    "id": _e.get("id"),
                    "item_mid": _e.get("item_mid", 0),
                    "type": 69,
                    "base_mid": _e.get("base_mid", 0),
                    "pvp_base_mid": _e.get("pvp_base_mid", 0),
                    "in_lock": _e.get("in_lock", 0),
                    "skill_level": _e.get("skill_level", _e.get("level", 1)),
                    "cost": _e.get("cost", 20),
                    "rarity": _e.get("rarity", 2),
                    "experience": _e.get("experience", 0),
                })
        return {"item_seal_list": _seal_l}

    # ---- 待实现: 强化/合成/界限突破 —— 先只记录请求体, 拿到真实字段名后再做 ----
    #   这三个目前仍返回抓包静态快照(里面的实例 id 不属于本账号), 点了会"有动画但属性不变"。
    #   缺的是请求体真实字段名, 客户端点一次这里就会打日志, 下次照日志实现。
    if path in ("/v1/item/equipment/combine", "/v1/item/equipment/limitbreak",
                "/v1/item/equipment/upgrade/consume") and method == "POST":
        print(f"[item-op待实现] {path} REQ={json.dumps(req, ensure_ascii=False)[:400]}")

    # ---- 其余端点: 有响应池则轮换, 否则交给上层 REAL_RESPONSES ----
    pool = eps.get(path)
    if pool:
        resp, ok = _pick_rotate(pool, path)
        if ok:
            # 2026-09-11 修复: 对含 girl_list 的响应叠加 STATE
            # affection_reward/present/onsen/venus_board 等端点返回 girl_list 但不走 apply_girl_state
            # → 客户端收到 DB 默认泳装 → 本地状态被覆盖 → 后续换装发送错误值 → "服装中途被换"
            if isinstance(resp, dict) and "girl_list" in resp:
                import copy as _copy
                resp = _copy.deepcopy(resp)
                for g in resp.get("girl_list", []):
                    apply_girl_state(g)
            return resp
    return None

def rsa_decrypt_session_key(ct):
    for name, pad in [("PKCS1v15", padding.PKCS1v15()),
                      ("OAEP-SHA256", padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))]:
        try:
            return PRIV.decrypt(ct, pad)
        except Exception:
            continue
    return None

def aes_cbc_decrypt(key, iv, ct):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = d.update(ct) + d.finalize()
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad])*pad:
        pt = pt[:-pad]
    return pt

def aes_cbc_encrypt(key, iv, pt):
    pad = 16 - (len(pt) % 16)
    pt = pt + bytes([pad])*pad
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(pt) + e.finalize()

# 日期归一化(2026-09-05, 彻底版): 把响应里"过去N天内"的日期统一替换为今天, 模拟"今日已登录"
# 原理: 游戏按"距上次登录天数"判断登录流程分支; 快照日期若过时(如last_logged_at=3天前)会走未实现的"跨日回归"分支卡死
# 改进(v2): 不再用硬编码正则(2026-09-0x), 改为按"日期距今天的天数"判断 — 任意月份/日期的近期日期都会被归一化, 避免复发
# 规则: 过去 RECENT_DAYS(默认14)天内的日期 → 替换为今天; 未来日期/更早历史日期 → 不动
RECENT_DAYS = 2700

def normalize_dates(data):
    try:
        txt = data.decode("utf-8", "replace")
        # 2026-11-07 REA 修正: 响应体里的日期串是 UTC (官方服务器如此, 客户端按 UTC 解析),
        #   所以"今天/窗口"也必须用 UTC 计算。旧实现用本地 now -> 写出的时间比客户端"现在"快 8 小时,
        #   等于给客户端一堆"未来时间", 北京 19:00 之后必然踩到 (19:00 本地 = 客户端眼中的次日 03:00)。
        now = utc_now()
        today_d = game_today_str()
        # 完整时间戳 -> 真实 UTC 现在 (必须 >= 客户端算出的日界 "D 19:00:00", 否则被判"不是今天")
        today = now.strftime("%Y-%m-%d %H:%M:%S")
        cutoff = now - datetime.timedelta(days=RECENT_DAYS)

        def repl_full(m):
            try:
                d = datetime.datetime.strptime(m.group(0), "%Y-%m-%d %H:%M:%S")
            except Exception:
                return m.group(0)
            if cutoff <= d <= now:
                return today
            return m.group(0)

        def repl_date(m):
            try:
                d = datetime.datetime.strptime(m.group(0), "%Y-%m-%d")
            except Exception:
                return m.group(0)
            if cutoff <= d <= now:
                return today_d
            return m.group(0)

        # 完整时间戳 (YYYY-MM-DD HH:MM:SS)
        txt = re.sub(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', repl_full, txt)
        # 纯日期 (YYYY-MM-DD, 不带时间)
        # 注意: 必须排除"后面跟着 空格+时分"的情况, 否则会把上一轮刚写好的完整时间戳
        # "2026-11-07 08:15:32" 的日期段又改回游戏日 -> 整条时间戳落后一天 ->
        # 客户端认为"今天还没签到"(received_at=昨天) -> 无限重跑登录序列 -> 白屏循环
        txt = re.sub(r'(?<!\d)\d{4}-\d{2}-\d{2}(?![\d\-]|[T ]\d{2}:)', repl_date, txt)
        return txt.encode("utf-8")
    except Exception:
        return data

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # 每个请求后关闭连接, 避免单线程阻塞
    def log_message(self, fmt, *args): pass

    def _handle(self, method):
        global SESSION_KEY
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length > 0 else b""
        p = self.path.split("?")[0]
        enc_hdr = self.headers.get("X-DOAXVV-Encrypted", "")

        log_write(f"\n[{now_ts()}] {method} {p} len={length} Host={self.headers.get('Host','?')}\n")

        # ---- CSV 文件下载（独立路径）----
        if "/production/csv/" in p:
            self._serve_csv(p)
            return

        # ---- 资源下载（独立路径, 代理到真实服务器或本地缓存）----
        if "/production/resource_data/" in p:
            self._serve_resource(p)
            return

        # ---- 公告网页 (/production/html/...): 返回简单HTML, 让WebView加载成功 ----
        # 2026-09-05: 游戏公告弹窗用WebView加载 html_page_url, 之前无处理返回JSON导致白屏卡公告
        if "/production/html/" in p:
            title = p.split("/")[-1][:60]
            html = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    "<title>DOAXVV</title><style>body{background:#fff;color:#333;font-family:sans-serif;padding:20px}"
                    "</style></head><body>"
                    f"<h2>DOAXVV 公告</h2><p>页面: {title}</p>"
                    "<p>单机版公告占位页</p></body></html>").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            self.wfile.flush()
            return

        # ---- GM 管理面板 (明文, 无加密, localhost 专用) ----
        if p.startswith("/gm"):
            self._handle_gm(p, method, body)
            return

        # ---- 2026-09-10: 启动器内嵌浏览器页面 (game.doaxvv.com 的非 API 路径) ----
        # 劫持后本地无法提供官网页面 → 启动器 WebView 拿到 JSON 会报 WebAplManager 错误
        # 处理: 直接代理回真实官网 (维护状态仍由本地 /v1/maintenance 控制)
        if (not p.startswith("/v1/")) and (not p.startswith("/production/")) \
           and self.headers.get("Host", "").startswith("game."):
            if self._proxy_real_page(p):
                return

        status = 200
        resp_body = b"{}"
        headers = {"Content-Type": "application/json"}

        if p == "/v1/session" and method == "POST":
            resp_body = json.dumps({"auth": True, "owner_id": OWNER_ID, "owner_status": 3}).encode()
            # ServerTime 用真实当前时间 (存档已同步为今天登录状态)
            headers.update({
                "X-DOAXVV-Access-Token": TOKEN,
                "X-DOAXVV-Status": "200",
                "X-DOAXVV-ServerTime": str(int(game_now().timestamp())),  # 2026-09-12: 游戏日对齐(19点后+1天), 与normalize_dates同源, 避免"归一化日期>ServerTime"的未来日期不一致
                "X-DOAXVV-ApplicationVersion": "82300",
                "X-DOAXVV-MasterVersion": "10",
                "X-DOAXVV-ResourceVersion": "82300,0,82300",
                "Set-Cookie": "PINKSID=" + uuid.uuid4().hex[:24] + "; path=/",
            })
        elif p == "/v1/session/key" and method == "GET":
            resp_body = json.dumps({"encrypt_key": PUB_PEM}).encode()
            headers.update({"X-DOAXVV-Status": "200", "X-DOAXVV-MasterVersion": "10"})
        elif p == "/v1/session/key" and method == "PUT":
            try:
                req = json.loads(body)
                ek = req.get("encrypt_key", "").replace("\r", "").replace("\n", "")
                ct = base64.b64decode(ek)
                sk = rsa_decrypt_session_key(ct)
                if sk and len(sk) == 32:
                    SESSION_KEY = sk
                    log_write(f"  [PUT] 会话密钥解出\n")
            except Exception as e:
                log_write(f"  [PUT] 失败: {e}\n")
            resp_body = json.dumps({"session": "encrypt key saved"}).encode()
            headers.update({"X-DOAXVV-Status": "200", "X-DOAXVV-MasterVersion": "10"})
        # ---- 2026-09-10 启动器后端接口 (Host=api01.doaxvv.com, 明文请求, 无加密握手) ----
        # 实测真实服务器响应:
        #   GET /v1/maintenance -> 200 + 空 body      (无维护)
        #   GET /v1/gamestart   -> 200 + {"gamestart":true}  (允许启动)
        # 用 Host 前缀限定, 不影响游戏本体 (api.doaxvv.com) 的加密响应流程
        elif self.headers.get("Host", "").startswith("api01.") and p == "/v1/maintenance":
            # 真实结构: {"maintenance":bool,"maintenance_datetime":"..."} (2026-09-10 实测)
            # 单机版永远回 false → 启动器不弹维护窗、不报 STATUS:2 解析错误
            resp_body = json.dumps({"maintenance": False, "maintenance_datetime": ""}).encode()
        elif self.headers.get("Host", "").startswith("api01.") and p == "/v1/gamestart":
            resp_body = json.dumps({"gamestart": True}).encode()
        elif self.headers.get("Host", "").startswith("api01.") and p == "/v1/resource/list":
            # 2026-09-10: 资源清单本地构造 (过滤到本地版本, 防启动器触发更新下载)
            rl = _build_resource_list()
            if rl is not None:
                resp_body = json.dumps(rl).encode()
            elif self._proxy_api01(p, method, body):
                return
            else:
                resp_body = b"{}"
        elif self.headers.get("Host", "").startswith("api01."):
            # 2026-09-10: 启动器后端其余接口 (resource/list 等) → 通用代理回真实后端
            if self._proxy_api01(p, method, body):
                return
            resp_body = b"{}"
        else:
            if SESSION_KEY and enc_hdr:
                resp_plain = None
                if len(body) > 0:
                    try:
                        iv = base64.b64decode(enc_hdr)
                        pt = aes_cbc_decrypt(SESSION_KEY, iv, body)
                        plain = zlib.decompress(pt)
                        req = json.loads(plain)
                        log_write(f"  [ENC] 请求: {plain.decode('utf-8','replace')[:500]}\n")
                        with STATE_LOCK:
                            _rd = _inject_state_wallet(self._build_response(p, req, method))
                        _cap(method, p, req, _rd)
                        resp_plain = json.dumps(_rd).encode()
                        if p != "/v1/owner/checkedat":
                            resp_plain = normalize_dates(resp_plain)
                    except Exception as e:
                        log_write(f"  [ENC] 解密失败: {e}\n")
                        resp_plain = b"{}"
                else:
                    with STATE_LOCK:
                        _rd = _inject_state_wallet(self._build_response(p, {}, method))
                    _cap(method, p, {}, _rd)
                    resp_plain = json.dumps(_rd).encode()
                    if p != "/v1/owner/checkedat":
                        resp_plain = normalize_dates(resp_plain)
                resp_iv = os.urandom(16)
                if p == "/v1/csv/list" and REAL_CSVLIST_BIN:
                    # 用真实服务器的压缩体(level1 zlib)完全复刻
                    ct_resp = aes_cbc_encrypt(SESSION_KEY, resp_iv, REAL_CSVLIST_BIN)
                    log_write(f"  <<< csv/list 用真实压缩体({len(REAL_CSVLIST_BIN)}B)\n")
                else:
                    ct_resp = aes_cbc_encrypt(SESSION_KEY, resp_iv, zlib.compress(resp_plain))
                resp_body = ct_resp
                headers = {
                    "Content-Type": "application/octet-stream",
                    "X-DOAXVV-Encoding": "deflate",
                    "X-DOAXVV-Encrypted": base64.b64encode(resp_iv).decode(),
                    "X-DOAXVV-Status": "200",
                    "X-DOAXVV-MasterVersion": "10",
                }
                log_write(f"  <<< 响应: {resp_plain.decode('utf-8','replace')[:300]}\n")   # 2026-09-11 性能优化: 4000→300 减小日志放大
            else:
                resp_body = b"{}"

        # ---- 2026-09-10: 启动器后端会话 (真实服务器下发 Set-Cookie: DOAXVVSID + no-cache) ----
        if self.headers.get("Host", "").startswith("api01."):
            try:
                _hl = {k: v for k, v in self.headers.items()
                       if k.lower() in ("cookie", "user-agent", "accept",
                                        "x-doaxvv-applicationversion", "x-doaxvv-masterversion",
                                        "x-doaxvv-resourceversion")}
                log_write("  [LAUNCHER] hdrs=" + str(_hl) + "\n")
            except Exception:
                pass
            headers["Set-Cookie"] = "DOAXVVSID=" + uuid.uuid4().hex[:26] + "; path=/"
            headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            headers["Pragma"] = "no-cache"
            headers["Expires"] = "Thu, 19 Nov 1981 08:52:00 GMT"

        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)
        self.wfile.flush()

    def _serve_csv(self, p):
        global SESSION_KEY
        parts = p.rstrip("/").split("/")
        hash_val = parts[-1] if parts else ""
        hash_val = hash_val.split("?")[0]
        name = HASH_TO_NAME.get(hash_val, "")
        data = CSV_DATA.get(name)
        gz = gzip.compress(data, 3) if data else gzip.compress(b"", 3)   # 2026-09-11 性能优化: 9→3, 本地传输重速度轻压缩比
        log_write(f"  [CSV] hash={hash_val} -> {name} ({len(data) if data else 0}B, gzip {len(gz)}B)\n")
        # CSV 解密: AES-256-CBC(密钥=ASCII '93c3bd75452506888d98dbae7a900a9c', IV=文件hash, 数据=gzip)
        try:
            key = b"93c3bd75452506888d98dbae7a900a9c"  # 32字节
            iv = bytes.fromhex(hash_val) if len(hash_val) == 32 else b"\x00" * 16
            # CBC 需要16倍数padding(PKCS7)
            pad = 16 - (len(gz) % 16)
            gz_pad = gz + bytes([pad]) * pad
            e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            ct = e.update(gz_pad) + e.finalize()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(ct)))
            self.end_headers()
            self.wfile.write(ct)
            self.wfile.flush()
            log_write(f"  [CSV] AES-CBC(固定密钥, IV=hash) 加密响应: {len(ct)}B\n")
        except Exception as ex:
            log_write(f"  [CSV] 加密失败: {ex}\n")
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.wfile.flush()

    def _proxy_api01(self, p, method, req_body=b""):
        """2026-09-10: 启动器后端 (api01.doaxvv.com) 通用代理。
        /v1/maintenance 与 /v1/gamestart 已本地定制(无维护/允许启动),
        其余接口 (resource/list 等) 代理回真实后端, 无需逐一硬编码结构。
        """
        import socket as _sock, ssl as _ssl
        _ips = ("54.178.128.246", "52.193.93.101")
        for ip in _ips:
            try:
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                raw = _sock.create_connection((ip, 443), timeout=10)
                ss = ctx.wrap_socket(raw, server_hostname="api01.doaxvv.com")
                hdrs = ["Host: api01.doaxvv.com",
                        "User-Agent: " + (self.headers.get("User-Agent", "DOAX_VV/82300"))]
                ck = self.headers.get("Cookie", "")
                if ck:
                    hdrs.append("Cookie: " + ck)
                ct = self.headers.get("Content-Type", "")
                if ct:
                    hdrs.append("Content-Type: " + ct)
                for h in ("X-DOAXVV-ApplicationVersion", "X-DOAXVV-MasterVersion",
                          "X-DOAXVV-ResourceVersion", "X-DOAXVV-Status"):
                    v = self.headers.get(h, "")
                    if v:
                        hdrs.append(h + ": " + v)
                req = (method + " " + p + " HTTP/1.1\r\n" + "\r\n".join(hdrs) +
                       "\r\nContent-Length: " + str(len(req_body)) +
                       "\r\nConnection: close\r\n\r\n")
                ss.sendall(req.encode())
                if req_body:
                    ss.sendall(req_body)
                buf = b""
                while True:
                    ch = ss.recv(65536)
                    if not ch:
                        break
                    buf += ch
                try:
                    ss.close()
                except Exception:
                    pass
                head, _, body = buf.partition(b"\r\n\r\n")
                if not head:
                    continue
                if b"transfer-encoding: chunked" in head.lower():
                    body = _decode_chunked(body)
                try:
                    status = int(head.split(b"\r\n")[0].split()[1])
                except Exception:
                    status = 200
                self.send_response(status)
                for line in head.split(b"\r\n")[1:]:
                    ln = line.lower()
                    if ln.startswith(b"content-type:") or ln.startswith(b"set-cookie:"):
                        val = line.split(b":", 1)[1].strip()
                        self.send_header("Content-Type" if ln.startswith(b"content-type:")
                                         else "Set-Cookie", val.decode("latin1", "replace"))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                log_write(f"  [API01-PROXY] {method} {p} -> {status} ({len(body)}B)\n")
                return True
            except Exception as e:
                log_write(f"  [API01-PROXY] {p} ip={ip} 失败: {e}\n")
        return False

    def _proxy_real_page(self, p):
        """2026-09-10: 启动器内嵌浏览器页面代理。
        劫持后 game.doaxvv.com 指向本机, 但本机只提供 /v1 API → 启动器 WebView
        拿不到官网页面 (表现为 WebAplManager STATUS 错误)。
        这里直连真实官网 (Akamai, 绕过 hosts) 取回页面原文返回。
        """
        import socket as _sock, ssl as _ssl
        _ips = ("104.109.143.26", "104.109.143.30")
        _path = p
        for _hop in range(3):
            _ok = False
            for ip in _ips:
                try:
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    raw = _sock.create_connection((ip, 443), timeout=8)
                    ss = ctx.wrap_socket(raw, server_hostname="game.doaxvv.com")
                    req = ("GET " + _path + " HTTP/1.1\r\nHost: game.doaxvv.com\r\n"
                           "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                           "Accept: */*\r\nConnection: close\r\n\r\n")
                    ss.sendall(req.encode())
                    buf = b""
                    while True:
                        ch = ss.recv(65536)
                        if not ch:
                            break
                        buf += ch
                    try:
                        ss.close()
                    except Exception:
                        pass
                    head, _, body = buf.partition(b"\r\n\r\n")
                    if not head:
                        continue
                    try:
                        status = int(head.split(b"\r\n")[0].split()[1])
                    except Exception:
                        status = 0
                    if status in (301, 302, 303, 307, 308):
                        loc = ""
                        for line in head.split(b"\r\n")[1:]:
                            if line.lower().startswith(b"location:"):
                                loc = line.split(b":", 1)[1].strip().decode("latin1", "replace")
                        if loc.startswith("https://game.doaxvv.com"):
                            _path = loc[len("https://game.doaxvv.com"):] or "/"
                            _ok = True
                        break
                    if status != 200 or not body:
                        continue
                    ctype = "text/html; charset=utf-8"
                    for line in head.split(b"\r\n")[1:]:
                        if line.lower().startswith(b"content-type:"):
                            ctype = line.split(b":", 1)[1].strip().decode("latin1", "replace")
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    self.wfile.flush()
                    log_write(f"  [PAGE] 代理真实官网 {_path} -> 200 ({len(body)}B, {ctype})\n")
                    return True
                except Exception as e:
                    log_write(f"  [PAGE] {ip} 代理失败: {e}\n")
            if not _ok:
                return False
        return False

    def _proxy_fetch(self, url_path, cache_file, max_retries=2):
        """代理下载资源 (2026-09-14 修复版) —— 只负责取回数据, 不写缓存(由调用方原子写)。

        修复内容:
          A3  VPN IP 列表化 + 成功率排序 + 失败计数 (替代旧单值覆盖, 抗 VPN 虚拟 IP 抖动)
          A4  VPN 段全失败后追加 Akamai 真实 IP 直连兜底 (HTTPS, 不依赖 VPN)
          B2  外层指数退避重试 (替代旧"一次失败即 404")
        原有机制保留:
          1) 按成功率降序尝试 VPN 已知 IP (明文 HTTP:80, Host=game.doaxvv.com)
          2) 全失败则并发扫描 198.18.0.3-64 段, 内容校验排除假响应(欢迎页/HTML)
          3) 命中后回写 vpn_ip.txt (JSON 列表格式)
        """
        import http.client as _hc, ssl as _ssl
        from concurrent.futures import ThreadPoolExecutor

        VALID_HEADERS = {"Host": "game.doaxvv.com", "User-Agent": "DOAX_VV/82300", "Accept": "*/*"}

        def looks_valid(d):
            """内容校验: 排除 VPN 段上其他服务的欢迎页/HTML/空响应"""
            if not d or len(d) < 16:
                return False
            head = d[:32]
            if b"Welcome" in head or b"<html" in d[:128] or b"<!DOCTYPE" in d[:128]:
                return False
            if d[:4] in (b"HTTP", b"ERR ", b"FAIL"):
                return False
            return True

        def try_one(ip, timeout=5, port=80, use_tls=False):
            """单IP尝试, 返回 (成功?, 数据)。use_tls=True 走 HTTPS 直连 Akamai。"""
            try:
                if use_tls:
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    raw = _sockmod.create_connection((ip, port), timeout=timeout)
                    ss = ctx.wrap_socket(raw, server_hostname="game.doaxvv.com")
                    req = ("GET " + url_path + " HTTP/1.1\r\n"
                           "Host: game.doaxvv.com\r\n"
                           "User-Agent: DOAX_VV/82300\r\n"
                           "Accept: */*\r\n"
                           "Connection: close\r\n\r\n").encode()
                    ss.sendall(req)
                    buf = bytearray()
                    while True:
                        ch = ss.recv(65536)
                        if not ch:
                            break
                        buf.extend(ch)
                    try:
                        ss.close()
                    except Exception:
                        pass
                    head_b, _, body = buf.partition(b"\r\n\r\n")
                    if not head_b or not body:
                        return False, None
                    try:
                        status = int(head_b.split(b"\r\n")[0].split()[1])
                    except Exception:
                        return False, None
                    if status == 200 and looks_valid(body):
                        return True, bytes(body)
                    return False, None
                else:
                    conn = _hc.HTTPConnection(ip, port, timeout=timeout)
                    conn.request("GET", url_path, headers=VALID_HEADERS)
                    r = conn.getresponse()
                    d = r.read()
                    conn.close()
                    if r.status == 200 and looks_valid(d):
                        return True, d
                    return False, None
            except Exception:
                return False, None

        # 0) VPN 可达性探测: 不通则跳过 VPN 段直连 Akamai (避免无 VPN 时空耗 ~40s/次重试)
        vpn_up = _vpn_probe()
        if not vpn_up:
            log_write(f"  [RES] VPN 段不可达, 跳过 VPN 回源, 直连 Akamai\n")

        for attempt in range(1, max_retries + 2):       # 1 次正常 + max_retries 次重试
            if attempt > 1:
                backoff = 0.5 * (2 ** (attempt - 1))    # 1s, 2s
                log_write(f"  [RES] 重试 {attempt}/{max_retries + 1} (退避 {backoff:.1f}s)...\n")
                time.sleep(backoff)

            if vpn_up:
                # 1) VPN 已知 IP (成功率降序; 单次最多试 VPN_KNOWN_TRY_MAX 个, 其余交给并发扫描)
                known_ips = _load_vpn_ips()[:VPN_KNOWN_TRY_MAX]
                for ip in known_ips:
                    ok, d = try_one(ip, 5)
                    if ok:
                        _record_vpn_ip(ip, True)
                        log_write(f"  [RES] 代理成功(HTTP {ip}): {len(d)}B, IP已记录\n")
                        return d
                    _record_vpn_ip(ip, False)
                    log_write(f"  [RES] 已知IP {ip} 未返回有效资源\n")

                # 2) 全失败: 快速扫描 198.18.0.x 段 (缩小范围+短超时, 避免卡死游戏)
                log_write(f"  [RES] 已知IP全部失败, 快速扫描 198.18.0.3-64 段...\n")
                known_set = set(known_ips)
                scan_ips = [f"198.18.0.{i}" for i in VPN_SCAN_RANGE if f"198.18.0.{i}" not in known_set]
                found = None
                with ThreadPoolExecutor(max_workers=32) as ex:
                    for ip, (ok, d) in zip(scan_ips, ex.map(lambda ip: try_one(ip, 1), scan_ips)):
                        if ok:
                            found = (ip, d)
                            break
                if found:
                    ip, d = found
                    _record_vpn_ip(ip, True)
                    log_write(f"  [RES] ✅ 扫描发现真实IP {ip}: {len(d)}B\n")
                    return d
                log_write(f"  [RES] 扫描未找到可用IP\n")

            # 3) A4: Akamai 真实 IP 直连兜底 (不依赖 VPN)
            for ip in _get_akamai_fallback_ips():
                ok, d = try_one(ip, 15, 443, use_tls=True)
                if ok:
                    log_write(f"  [RES] ✅ Akamai直连成功({ip}): {len(d)}B\n")
                    return d
                log_write(f"  [RES] Akamai直连 {ip} 失败\n")

        log_write(f"  [RES] 全部重试耗尽, 未找到可用IP\n")
        return None

    def _res_download_dedup(self, hash_val, url_path, cache_file, max_attempts=2):
        """带并发去重的回源下载 (A1)。
        同 hash 只允许一个线程回源, 其余线程等待后重读缓存; 缓存仍缺则自己接管重试。
        避免 ThreadingHTTPServer 下同一 hash 的 N 个并发 Range 请求各跑一遍 IP 扫描。
        """
        for attempt in range(1, max_attempts + 1):
            data = _res_read_cache(cache_file)          # 先复查(可能有其他线程刚写好)
            if data:
                return data
            is_owner, ev = _res_begin_download(hash_val)
            if is_owner:
                try:
                    log_write(f"  [RES] 代理下载(所有者 attempt={attempt}): {hash_val[:16]}...\n")
                    data = self._proxy_fetch(url_path, cache_file)
                    if data is not None:
                        _res_write_cache_atomic(cache_file, data)   # C3 原子写
                finally:
                    _res_end_download(hash_val, ev)
                return data                                  # 可能 None → 调用方 404
            # 非所有者: 其他线程正在回源, 等待
            log_write(f"  [RES] 去重等待(非所有者 attempt={attempt}): {hash_val[:16]}...\n")
            ev.wait(timeout=_RES_OWNER_WAIT)
        return None

    def _serve_resource(self, p):
        """服务资源下载: /production/resource_data/<ver>/<q>/<hash>
        本地缓存有就返回, 没有则(并发去重)代理下载真实服务器"""
        import urllib.request, ssl as sslmod
        # 记录请求头(调试Range分块下载)
        rng = self.headers.get("Range", "")
        ref = self.headers.get("Referer", "")
        ua = self.headers.get("User-Agent", "")
        log_write(f"  [RES] 请求头: Range='{rng}' UA='{ua[:30]}'\n")
        # 提取资源 hash
        parts = p.rstrip("/").split("/")
        hash_val = parts[-1] if parts else ""
        hash_val = hash_val.split("?")[0]
        cache_dir = os.path.join(TOOL, "resources")
        cache_file = os.path.join(cache_dir, hash_val)
        os.makedirs(cache_dir, exist_ok=True)

        data = _res_read_cache(cache_file)
        if data:
            log_write(f"  [RES] 本地缓存: {hash_val[:16]}... ({len(data)}B)\n")
        else:
            data = self._res_download_dedup(hash_val, p, cache_file)

        if data is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.wfile.flush()
            return

        # 支持 Range 分块下载 (游戏用 Range 头切块下载大资源)
        rng = self.headers.get("Range", "")
        if rng.startswith("bytes="):
            try:
                range_spec = rng[6:].split(",")[0].strip()
                if "-" in range_spec:
                    start_s, end_s = range_spec.split("-", 1)
                    start = int(start_s) if start_s else 0
                    end = int(end_s) if end_s else len(data) - 1
                    if start < 0:
                        # suffix range: bytes=-N (最后N字节)
                        start = max(0, len(data) + start)
                        end = len(data) - 1
                    end = min(end, len(data) - 1)
                    if start <= end and start < len(data):
                        chunk = data[start:end + 1]
                        self.send_response(206)
                        self.send_header("Content-Type", "application/octet-stream")
                        self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
                        self.send_header("Accept-Ranges", "bytes")
                        self.send_header("Content-Length", str(len(chunk)))
                        self.end_headers()
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        log_write(f"  [RES] Range {start}-{end}/{len(data)} -> {len(chunk)}B\n")
                        return
            except Exception as ex:
                log_write(f"  [RES] Range解析失败: {ex}\n")

        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
        except (ssl.SSLEOFError, BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass  # 客户端断开资源下载(取消/切场景), 忽略避免 SSLEOFError 刷屏

    def _handle_gm(self, p, method, body):
        with STATE_LOCK:
            return self._handle_gm_impl(p, method, body)

    def _handle_gm_impl(self, p, method, body):
        """GM 管理面板: 明文 HTTP, 直接操作内存 STATE, 即时生效"""
        # GET /gm/ 或 /gm/index.html → 返回 HTML 面板
        if (p == "/gm" or p == "/gm/") and method == "GET":
            try:
                with open(GM_HTML, "rb") as f:
                    html = f.read()
            except Exception:
                html = b"<html><body><h1>gm_panel.html not found</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            self.wfile.flush()
            return

        # 解析 JSON 请求体 (POST)
        req = {}
        if method == "POST" and body:
            try:
                req = json.loads(body)
            except Exception:
                req = {}

        # ---- GET/POST /gm/api/gm_session → GM 会话开关 (托盘「启动GM / 关闭GM」) ----
        # GET  : 页面心跳, 返回 {"active": bool}; 面板据此显示/隐藏「GM 已关闭」遮罩
        # POST : {"active": true/false} 由托盘点「启动GM / 关闭GM」调用
        if p == "/gm/api/gm_session":
            if method == "POST":
                _v = req.get("active", None)
                if isinstance(_v, bool):
                    GM_SESSION["active"] = _v
            data = json.dumps({"ok": True, "active": GM_SESSION["active"]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # GM 会话关闭期间, 其余 GM 接口一律 403 —— 真正"断开", 不只是遮一层界面
        if not GM_SESSION["active"] and p.startswith("/gm/api/"):
            data = json.dumps({"ok": False, "error": "gm_closed"}).encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- GET /gm/api/names → GM 专属名称修正表 (纯展示层, 不动原始主数据) ----
        if p == "/gm/api/names" and method == "GET":
            _nm = _gm_names_read()
            resp = {"ok": True, "file": "GM/gm_names.csv",
                    "items": _nm["items"], "groups": _nm["groups"], "types": _nm["types"],
                    "count": len(_nm["items"]) + len(_nm["groups"]) + len(_nm["types"])}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- POST /gm/api/name → 修改/恢复名称 (name 为空 = 删除该条修正) ----
        if p == "/gm/api/name" and method == "POST":
            _kind = str(req.get("kind", "") or "").strip().lower()
            _key = str(req.get("key", "") or "").strip()
            _name = str(req.get("name", "") or "").strip()
            if _kind not in ("item", "group", "type") or not _key:
                resp = {"ok": False, "error": "kind 必须是 item/group/type, key 不能为空"}
            elif len(_name) > 60:
                resp = {"ok": False, "error": "名称过长（上限 60 字）"}
            else:
                try:
                    # 2026-11-12: 幂等 —— 与已保存值完全相同时不重复写盘, 直接回 ok+unchanged
                    _cur = _gm_names_read()
                    _bucket = {"item": _cur["items"], "group": _cur["groups"], "type": _cur["types"]}[_kind]
                    if _name and _bucket.get(_key) == _name:
                        resp = {"ok": True, "unchanged": True, "items": _cur["items"],
                                "groups": _cur["groups"], "types": _cur["types"],
                                "count": len(_cur["items"]) + len(_cur["groups"]) + len(_cur["types"])}
                    else:
                        _nm = _gm_names_write(_kind, _key, _name, req.get("original", ""))
                        resp = {"ok": True, "items": _nm["items"], "groups": _nm["groups"], "types": _nm["types"],
                                "count": len(_nm["items"]) + len(_nm["groups"]) + len(_nm["types"]),
                                "removed": not _name}
                except Exception as e:
                    resp = {"ok": False, "error": str(e)}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- GET /gm/api/state → 返回 STATE 摘要 ----
        if p == "/gm/api/state" and method == "GET":
            gb_total = 0
            try:
                _eps = SERVER_DB.get("endpoints", {})
                for _v in _eps.get("/v1/giftbox", []):
                    _gl = _v.get("giftbox_list", [])
                    if _gl:
                        gb_total = len(_gl)
                        break
            except Exception:
                pass
            resp = {
                "main_girl_mid": STATE.get("main_girl_mid", 3),
                "girl_equipment": STATE.get("girl_equipment", {}),
                "wallet": STATE.get("wallet", {}),
                "item_counts": STATE.get("item_counts", {}),
                "giftbox_claimed": STATE.get("giftbox_claimed", []),
                "giftbox_total": gb_total + len(STATE.get("custom_mails", [])),
                "giftbox_custom": len(STATE.get("custom_mails", [])),
                "custom_mails": STATE.get("custom_mails", []),
                "monthly_claimed": STATE.get("monthly_claimed", {}),
                "read_information": STATE.get("read_information", []),
                "venus_board": venus_stats(),
            }
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- POST /gm/api/wallet → 修改钱包 ----
        if p == "/gm/api/wallet" and method == "POST":
            w = STATE.setdefault("wallet", {})
            changed = []
            for k in ("zack_money", "free_vstone", "guest_point",
                       "vip_point", "paid_vstone", "vip_coin"):
                if k in req:
                    w[k] = int(req[k])
                    changed.append(k)
            _save_state()
            resp = {"ok": True, "changed": changed}
            data = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- POST /gm/api/girl → 切换看板娘 / 修改装备 ----
        if p == "/gm/api/girl" and method == "POST":
            if "main_girl_mid" in req:
                try:
                    _gm_mid = int(req["main_girl_mid"])
                except (TypeError, ValueError):
                    _gm_mid = None
                if _gm_mid is not None and (not GIRL_MASTER_MAP or _gm_mid in GIRL_MASTER_MAP):
                    _gm_or = STATE.get("owner_room")
                    if isinstance(_gm_or, dict):
                        _gm_or["main_girl_mid"] = _gm_mid
                    STATE["main_girl_mid"] = _gm_mid
                else:
                    log_write(f"  [MAIN-GIRL] GM 拒绝非法 girl_mid={req['main_girl_mid']}, "
                              f"保持 {STATE.get('main_girl_mid', 3)}\n")
            if "girl_mid" in req and "equipment" in req:
                gm = str(req["girl_mid"])
                eq = STATE.setdefault("girl_equipment", {})
                cur = eq.setdefault(gm, {})
                for k in ("swimsuit_item_mid", "accessory_arm_item_mid",
                          "accessory_head_item_mid"):
                    if k in req["equipment"]:
                        if req["equipment"][k] is None or req["equipment"][k] == "":
                            cur.pop(k, None)
                        else:
                            cur[k] = int(req["equipment"][k])
            _save_state()
            _flush_state()   # 2026-11-11: 看板娘是关键状态, 立即落盘
            resp = {"ok": True, "main_girl_mid": STATE["main_girl_mid"]}
            data = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- POST /gm/api/items → 发放/删除物品 ----
        if p == "/gm/api/items" and method == "POST":
            mid = int(req.get("item_mid", 0))
            count = int(req.get("count", 1))
            action = req.get("action", "add")
            ic = STATE.setdefault("item_counts", {})
            if action == "add":
                ic[mid] = ic.get(mid, 0) + count
            elif action == "set":
                # 2026-11-13: 设为 0 视为移出库存, 不留 0 值条目
                # (GM 面板「当前库存」按数量 > 0 过滤, 0 值条目会变成隐形垃圾数据)
                if count > 0:
                    ic[mid] = count
                else:
                    ic.pop(mid, None)
            elif action == "remove":
                ic.pop(mid, None)
            _save_state()
            resp = {"ok": True, "item_mid": mid, "count": ic.get(mid, 0)}
            data = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- POST /gm/api/reset → 重置模块 ----
        if p == "/gm/api/reset" and method == "POST":
            mod = req.get("module", "")
            if mod == "giftbox":
                # 2026-11-12 用户要求: 「重置邮箱」= 清空邮箱 + 清空历史领取记录。
                # claimed 清空后内置 25 封会重新出现, 所以同时置 hide_builtin 把内置邮件隐藏,
                # 并把 custom_mails 一并清空 -> 邮箱真正变空。
                STATE["giftbox_claimed"] = []
                STATE["custom_mails"] = []
                STATE["giftbox_hide_builtin"] = True
            elif mod == "login_bonus":
                STATE["monthly_claimed"] = {}
                STATE.pop("daily_quest_date", None)
                STATE.pop("daily_quest_count", None)
            elif mod == "information":
                STATE["read_information"] = []
            elif mod == "all":
                STATE["giftbox_claimed"] = []
                STATE["custom_mails"] = []
                STATE["giftbox_hide_builtin"] = True
                STATE["monthly_claimed"] = {}
                STATE["read_information"] = []
            else:
                resp = {"ok": False, "error": "unknown module: " + mod}
            if mod in ("giftbox", "login_bonus", "information", "all"):
                _save_state()
                resp = {"ok": True, "module": mod}
            data = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- POST /gm/api/giftbox/send → 发送自定义邮件 (GM 发放物品) ----
        if p == "/gm/api/giftbox/send" and method == "POST":
            cm = STATE.setdefault("custom_mails", [])
            # 2026-11-12 修复: 之前用 900000001+len(cm) 分配 id, 领取后 custom_mails 里的
            # 邮件仍在、但清空/重建后 len 归零 -> 新邮件复用已领取的旧 id -> 一发出就被
            # giftbox_claimed 判定为"已领"而过滤掉, 游戏邮箱里看不到。改为取所有已知 id
            # (现存邮件 + 已领取记录) 的最大值 +1, 保证永不复用。
            _claimed_ids = set(int(c) for c in (STATE.get("giftbox_claimed") or []) if isinstance(c, int))
            _known = [900000000] + [int(m.get("id") or 0) for m in cm] + \
                     [c for c in _claimed_ids if c >= 900000000]
            _next_id = max(_known) + 1
            while _next_id in _claimed_ids:
                _next_id += 1
            mail = {
                "id": _next_id,
                "sender_id": OWNER_ID,
                "sender_name": "GM",
                "item_mid": int(req.get("item_mid", 0)),
                "count": int(req.get("count", 1)),
                "message_type": int(req.get("message_type", 10)),
                "message": req.get("message", "GM发放"),
                "parameter1": 0,
                "created_at": game_now().strftime("%Y-%m-%d %H:%M:%S"),
                # 2026-11-12: 有效期 +1年 → +30天。真实邮件全是 30 天窗口
                # (created 2026-09-03 / expired 2026-10-03), 客户端对异常期限的邮件
                # 会直接发 force_accepted 强制领取, 导致邮件无法正常查看。
                "expired_at": (game_now() + datetime.timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S"),
                "accepted_at": None,
            }
            cm.append(mail)
            _save_state()
            resp = {"ok": True, "mail": mail, "custom_total": len(cm)}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- POST /gm/api/giftbox/clear → 清除所有自定义邮件 ----
        if p == "/gm/api/giftbox/clear" and method == "POST":
            STATE["custom_mails"] = []
            # 同时清除自定义邮件的领取记录
            _claimed = STATE.get("giftbox_claimed", [])
            STATE["giftbox_claimed"] = [c for c in _claimed if c < 900000000]
            _save_state()
            resp = {"ok": True, "cleared": True}
            data = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- GET/POST /gm/api/owner_profile → 岛主资料 (岛主名 / 岛名 / 留言) ----
        # 2026-11-12: 游戏内改名走 PUT /v1/owner 且有前置校验, 改名门槛高;
        # GM 侧直接读写 STATE["owner_profile"], /v1/owner 与 updatelogin 统一套覆盖层。
        if p == "/gm/api/owner_profile":
            op = STATE.get("owner_profile")
            if not isinstance(op, dict):
                op = {}
            if method == "POST":
                _src = dict(op)
                if req.get("reset"):
                    STATE.pop("owner_profile", None)
                    _save_state()
                    resp = {"ok": True, "owner_profile": {}, "prev": _src, "reset": True}
                    data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    self.wfile.flush()
                    return
                op2 = dict(op)
                for _f in OWNER_PROFILE_FIELDS:
                    if _f in req and req[_f] is not None:
                        op2[_f] = str(req[_f]).strip()[:50]
                STATE["owner_profile"] = op2
                _save_state()
                resp = {"ok": True, "owner_profile": op2, "prev": _src}
            else:
                # 默认值取抓包快照, 方便面板显示"当前实际生效的值"
                _def = {}
                try:
                    _snap = REAL_RESPONSES.get("/v1/owner", {})
                    _o = _snap.get("owner")
                    if isinstance(_o, dict):
                        _def = _o
                    elif isinstance(_o, list) and _o:
                        _def = _o[0]
                except Exception:
                    _def = {}
                cur = {_f: (op.get(_f) if _f in op else _def.get(_f, "")) for _f in OWNER_PROFILE_FIELDS}
                builtin = {_f: _def.get(_f, "") for _f in OWNER_PROFILE_FIELDS}
                resp = {"ok": True, "owner_profile": cur, "builtin": builtin,
                        "overridden": sorted(k for k in op if k in OWNER_PROFILE_FIELDS)}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- POST /gm/api/giftbox/restore → 恢复被抓包内置邮件 (撤销 hide_builtin) ----
        if p == "/gm/api/giftbox/restore" and method == "POST":
            STATE.pop("giftbox_hide_builtin", None)
            _save_state()
            resp = {"ok": True, "restored": True}
            data = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- GET /gm/api/log → 返回服务器日志 (最后100行) ----
        if p == "/gm/api/log" and method == "GET":
            log_text = ""
            try:
                _flush_log()
                with open(LOG, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                log_text = "".join(lines[-100:])
            except Exception as e:
                log_text = f"(读取日志失败: {e})"
            resp = {"log": log_text}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- GET /gm/api/gacha/groups → 卡池分组(banner 组) ----
        if p == "/gm/api/gacha/groups" and method == "GET":
            _vis = STATE.get("gacha_visible_pools")
            _vis_set = set(int(v) for v in _vis) if _vis else None
            _gc = STATE.get("gacha_group_config", {})
            _gnm = _gm_names_read().get("groups", {})   # GM 名称修正 (仅展示)
            _groups = []
            for _g in GACHA_GROUPS.get("groups", []):
                _mids = _g.get("mids", [])
                _one = {k: _g[k] for k in ("group_id", "pop_id", "has_banner", "tabs",
                                           "types", "start_time", "end_time", "label") if k in _g}
                _one["mids"] = _mids
                _one["pools"] = _g.get("pools", {})
                _one["visible"] = True if _vis_set is None else any(m in _vis_set for m in _mids)
                _one["config"] = _gc.get(_g.get("group_id"), {})
                _lbl = _gnm.get(str(_one.get("group_id")))
                if _lbl:
                    _one["label_default"] = _one.get("label")
                    _one["label"] = _lbl
                _groups.append(_one)
            resp = {"groups": _groups,
                    "visible_group_count": GACHA_GROUPS.get("visible_group_count", 0),
                    "mid_count": GACHA_GROUPS.get("mid_count", 0)}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- POST /gm/api/gacha/group → 按卡池组设置/清除爆率 ----
        if p == "/gm/api/gacha/group" and method == "POST":
            _gc = STATE.setdefault("gacha_group_config", {})
            try:
                _gid = str(req.get("group_id") or "")
                _g = GACHA_GROUP_BY_ID.get(_gid)
                if not _g:
                    raise ValueError("unknown group_id: " + _gid)
                if req.get("action") == "clear":
                    _gc.pop(_gid, None)
                    _act = "cleared"
                else:
                    _cfg_in = req.get("config")
                    if not isinstance(_cfg_in, dict):
                        raise ValueError("config must be an object")
                    _clean = {}
                    if "rarity_weights" in _cfg_in:
                        _rw = _cfg_in["rarity_weights"]
                        if not isinstance(_rw, dict):
                            raise ValueError("rarity_weights must be an object")
                        _vals = {}
                        for _r in ("SSR", "SR", "R"):
                            _v = int(_rw.get(_r, 0))
                            if _v < 0:
                                raise ValueError("rarity_weights must be non-negative")
                            _vals[_r] = _v
                        if sum(_vals.values()) != 100:
                            raise ValueError("SSR + SR + R must equal 100")
                        _clean["rarity_weights"] = _vals
                    for _k in ("hard_pity", "soft_pity_start", "soft_pity_increment"):
                        if _k in _cfg_in:
                            _v = int(_cfg_in[_k])
                            if _v < 0:
                                raise ValueError(_k + " must be non-negative")
                            _clean[_k] = _v
                    if "item_weights" in _cfg_in:
                        _iw = _cfg_in["item_weights"]
                        if not isinstance(_iw, dict):
                            raise ValueError("item_weights must be an object")
                        _clean["item_weights"] = {str(k): max(int(v), 1) for k, v in _iw.items()}
                    for _k in ("enable_stepup", "ssr_auto_lock", "use_group_fill"):
                        if _k in _cfg_in:
                            _clean[_k] = bool(_cfg_in[_k])
                    _gc[_gid] = _clean
                    # 组内旧的单 mid 覆盖会干扰组配置，清掉 STATE 中的残留
                    _po = STATE.setdefault("gacha_config", {}).setdefault("pool_overrides", {})
                    for _m in _g.get("mids", []):
                        _po.pop(str(_m), None)
                    _act = "saved"
            except (ValueError, TypeError) as _ge:
                data = json.dumps({"error": str(_ge)}, ensure_ascii=False).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                self.wfile.flush()
                return
            _save_state()
            resp = {"ok": True, "group_id": _gid, "action": _act,
                    "config": _gc.get(_gid, {}), "mids": _g.get("mids", [])}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- GET /gm/api/gacha/config → 返回扭蛋配置 (文件默认+STATE覆盖合并) ----
        if p == "/gm/api/gacha/config" and method == "GET":
            _fd = _GACHA_CONFIG_FILE.get("defaults", {})
            _fo = _GACHA_CONFIG_FILE.get("pool_overrides", {})
            _sc = STATE.get("gacha_config", {})
            _sd = _sc.get("defaults", {})
            _so = _sc.get("pool_overrides", {})
            _md = {**_fd, **_sd}
            _mo = {}
            for _k in set(list(_fo.keys()) + list(_so.keys())):
                _mo[_k] = {**_fo.get(_k, {}), **_so.get(_k, {})}
            resp = {"defaults": _md, "pool_overrides": _mo}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- POST /gm/api/gacha/config → 设置全局默认配置 (写入STATE, 即时生效) ----
        if p == "/gm/api/gacha/config" and method == "POST":
            _sc = STATE.setdefault("gacha_config", {})
            _sd = _sc.setdefault("defaults", {})
            for _k in ("rarity_weights", "use_csv_rarity", "hard_pity", "soft_pity_start",
                        "soft_pity_increment", "enable_stepup", "step_increment",
                        "step_cap_behavior", "max_step_bonus", "ssr_auto_lock",
                        "use_group_fill"):
                if _k in req:
                    _sd[_k] = req[_k]
            _save_state()
            _invalidate_gacha_pool_cache()
            resp = {"ok": True, "defaults": _sd}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- GET /gm/api/gacha/pool?gacha_mid=X → 返回卡池详情(物品权重+保底+配置) ----
        if p == "/gm/api/gacha/pool" and method == "GET":
            from urllib.parse import urlparse as _ul_urlparse, parse_qs as _ul_parseqs
            _qs = _ul_parseqs(_ul_urlparse(self.path).query)
            _gm_q = _qs.get("gacha_mid", ["0"])[0]
            try:
                _gm_q = int(_gm_q)
            except ValueError:
                _gm_q = 0
            if not _gm_q:
                resp = {"error": "gacha_mid required"}
                data = json.dumps(resp).encode()
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                self.wfile.flush()
                return
            _full = GACHA_STEPUP_FULL.get(_gm_q, {})
            _max_step = max(_full.keys()) if _full else 1
            _pity = STATE.get("gacha_pity", {}).get(_gacha_pity_key(_gm_q), {})
            _cur_step = _pity.get("current_step", 1)
            _pool = _get_gacha_pool(_gm_q, _cur_step)
            _cfg = _get_gacha_config(_gm_q)
            _iw = _cfg.get("item_weights", {})
            _pool_detail = {}
            for _rarity in ("SSR", "SR", "R"):
                _items = []
                for _im, _w in _pool.get(_rarity, []):
                    _ow = _iw.get(str(_im))
                    _items.append({"item_mid": _im, "default_weight": _w, "override_weight": _ow})
                _pool_detail[_rarity] = _items
            # 返回按卡池覆盖配置 (合并文件+STATE), 非全局默认
            _po_file = _GACHA_CONFIG_FILE.get("pool_overrides", {}).get(str(_gm_q), {})
            _po_state = STATE.get("gacha_config", {}).get("pool_overrides", {}).get(str(_gm_q), {})
            _po_merged = {**_po_file, **_po_state}
            _gid_q = _gacha_group_of(_gm_q)
            if _gid_q:
                _po_merged = {**_po_merged, **STATE.get("gacha_group_config", {}).get(_gid_q, {})}
            _pool_info = GACHA_INFO_MAP.get(_gm_q, {})
            resp = {
                "gacha_mid": _gm_q, "max_step": _max_step, "group_id": _gid_q,
                "type": _pool_info.get("type", 3),
                "active": _gacha_is_active(_gm_q),
                "start_time": _pool_info.get("start_time", ""),
                "end_time": _pool_info.get("end_time", ""),
                "paired_gacha_mid": _gacha_paired(_gm_q),
                "pity": {"current_step": _cur_step,
                         "total_draws": _pity.get("total_draws", 0),
                         "draws_since_ssr": _pity.get("draws_since_ssr", 0)},
                "pool": _pool_detail,
                "config": _po_merged,
            }
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- POST /gm/api/gacha/pool → 设置按卡池配置覆盖 (写入STATE, 即时生效) ----
        if p == "/gm/api/gacha/pool" and method == "POST":
            _gm_p = req.get("gacha_mid")
            try:
                _gm_p = int(_gm_p)
            except (ValueError, TypeError):
                _gm_p = 0
            if not _gm_p:
                resp = {"error": "gacha_mid required"}
                data = json.dumps(resp).encode()
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                self.wfile.flush()
                return
            _sc = STATE.setdefault("gacha_config", {})
            _po = _sc.setdefault("pool_overrides", {})
            # action=clear → 删除该卡池的覆盖配置
            if req.get("action") == "clear":
                _po.pop(str(_gm_p), None)
                _save_state()
                _invalidate_gacha_pool_cache(_gm_p)
                resp = {"ok": True, "gacha_mid": _gm_p, "cleared": True}
                data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                self.wfile.flush()
                return
            _po_gm = _po.setdefault(str(_gm_p), {})
            for _k in ("rarity_weights", "hard_pity", "soft_pity_start", "soft_pity_increment",
                        "enable_stepup", "ssr_auto_lock", "item_weights"):
                if _k in req:
                    _po_gm[_k] = req[_k]
            _save_state()
            _invalidate_gacha_pool_cache(_gm_p)
            resp = {"ok": True, "gacha_mid": _gm_p, "config": _po_gm}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- POST /gm/api/gacha/pity/reset → 重置保底计数 (指定卡池或全部) ----
        if p == "/gm/api/gacha/pity/reset" and method == "POST":
            _gm_r = req.get("gacha_mid")
            _pity = STATE.setdefault("gacha_pity", {})
            if _gm_r is not None:
                try:
                    _gm_r = int(_gm_r)
                except (ValueError, TypeError):
                    _gm_r = None
            _gid_r = req.get("group_id")
            if _gid_r and str(_gid_r) in GACHA_GROUP_BY_ID:
                _pk = "g:" + str(_gid_r)
                _pity[_pk] = {"draws_since_ssr": 0, "total_draws": 0, "current_step": 1}
                resp = {"ok": True, "reset": _pk}
            elif _gm_r:
                _pk = _gacha_pity_key(_gm_r)
                _pity[_pk] = {"draws_since_ssr": 0, "total_draws": 0, "current_step": 1}
                resp = {"ok": True, "reset": _pk}
            else:
                for _pk in _pity:
                    _pity[_pk] = {"draws_since_ssr": 0, "total_draws": 0, "current_step": 1}
                resp = {"ok": True, "reset": "all"}
            _save_state()
            data = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- GET /gm/api/gacha/search?q=X → 搜索卡池 (按 gacha_mid 前缀匹配) ----
        if p == "/gm/api/gacha/search" and method == "GET":
            from urllib.parse import urlparse as _ul_urlparse, parse_qs as _ul_parseqs
            _qs = _ul_parseqs(_ul_urlparse(self.path).query)
            _q = _qs.get("q", [""])[0]
            _pools = []
            _sc_overrides = STATE.get("gacha_config", {}).get("pool_overrides", {})
            _file_overrides = _GACHA_CONFIG_FILE.get("pool_overrides", {})
            for _gm_s, _sf in GACHA_STEPUP_FULL.items():
                _s = str(_gm_s)
                if _q and _s.find(_q) == -1:
                    continue
                _max_s = max(_sf.keys()) if _sf else 1
                _has_ov = _s in _sc_overrides or _s in _file_overrides
                _info = GACHA_INFO_MAP.get(_gm_s, {})
                _pools.append({
                    "gacha_mid": _gm_s, "max_step": _max_s, "has_override": _has_ov,
                    "type": _info.get("type", 3),
                    "active": _gacha_is_active(_gm_s),
                    "start_time": _info.get("start_time", ""),
                    "end_time": _info.get("end_time", ""),
                })
                if len(_pools) >= 100:
                    break
            resp = {"pools": _pools}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- GET/POST /gm/api/gacha/visible → 卡池开关(GM控制游戏显示哪些卡池) ----
        # GET: 返回所有卡池+可见状态; POST: visible_pools=[mid,...]设置可见, action=reset=全部显示
        if p == "/gm/api/gacha/visible" and method in ("GET", "POST"):
            if method == "GET":
                _vis = STATE.get("gacha_visible_pools")
                # None / [] = 全部显示；非空列表 = 只显示列表内的卡池
                _vis_set = set(int(v) for v in _vis) if _vis else None
                _gl = SERVER_DB.get("endpoints", {}).get("/v1/gacha/list", [])
                _snap = _gl[0].get("gacha_info_list", []) if _gl else []
                _pools = []
                for _g in _snap:
                    _gm_v = _g.get("gacha_mid")
                    if _gm_v is None:
                        continue
                    _info = GACHA_INFO_MAP.get(_gm_v, {})
                    _pools.append({"gacha_mid": _gm_v, "type": _info.get("type", 3),
                                   "group_id": _gacha_group_of(_gm_v),
                                   "visible": True if _vis_set is None else (int(_gm_v) in _vis_set)})
                resp = {"visible_pools": _vis, "pools": _pools}
            else:
                if req.get("action") == "reset":
                    STATE["gacha_visible_pools"] = None
                else:
                    # 只接受整数列表；传 null / 字符串时报错，而不是静默变成「全部显示」
                    _vp = req.get("visible_pools")
                    if not isinstance(_vp, list):
                        data = json.dumps({"error": "visible_pools must be a list"}).encode()
                        self.send_response(400)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers(); self.wfile.write(data); self.wfile.flush()
                        return
                    try:
                        STATE["gacha_visible_pools"] = [int(v) for v in _vp]
                    except (TypeError, ValueError):
                        data = json.dumps({"error": "visible_pools must contain numbers"}).encode()
                        self.send_response(400)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers(); self.wfile.write(data); self.wfile.flush()
                        return
                _save_state()
                resp = {"ok": True, "gacha_visible_pools": STATE["gacha_visible_pools"]}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- POST /gm/api/venus_coin → 发放维纳斯货币 (item_counts[item_mid] += count) ----
        if p == "/gm/api/venus_coin" and method == "POST":
            try:
                _vr = json.loads(body) if body else {}
            except Exception:
                _vr = {}
            try:
                _im = int(_vr.get("item_mid", 0))
                _cnt = int(_vr.get("count", 0))
            except (ValueError, TypeError):
                _im, _cnt = 0, 0
            if _im and _cnt > 0:
                _new_cnt = ic_add(_im, _cnt)
                _save_state()
                resp = {"ok": True, "item_mid": _im, "count": _new_cnt}
            else:
                resp = {"ok": False, "error": "invalid item_mid or count"}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # ---- GET/POST /gm/api/venus_board → 维纳斯图板全解锁 / 重置 ----
        if p == "/gm/api/venus_board" and method in ("GET", "POST"):
            if method == "GET":
                resp = {"ok": True}
                resp.update(venus_stats())
            else:
                _vact = (req or {}).get("action")
                if _vact == "unlock_all":
                    _vnew = venus_unlock_all(grant=True)
                    resp = {"ok": True, "new_panels": _vnew}
                    resp.update(venus_stats())
                elif _vact == "reset":
                    _vst2 = venus_state()
                    _vst2["opened"] = {}
                    _vst2["seen"] = {}
                    # 注意: 不重置 granted —— 重开面板不应重复发奖
                    _vst2["maxed_at"] = None
                    _vst2["rewards_granted"] = False
                    _save_state()
                    resp = {"ok": True}
                    resp.update(venus_stats())
                else:
                    resp = {"ok": False, "error": "unknown action"}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return

        # 未知 GM 路径
        resp = {"error": "unknown gm path: " + p}
        data = json.dumps(resp).encode()
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()

    def _build_response(self, path, req, method="POST"):
        # 2026-09-14: 各功能GET查看时更新对应红点checked_at (像私服版, 查看后红点灭; 内存更新不每次写盘)
        if method == "GET":
            _ckf = _ENDPOINT_CHECKED_MAP.get(path)
            if _ckf:
                STATE.setdefault("checked_at", {})[_ckf] = server_now_str()
        # 2026-09-14: owner/checkedat 红点系统动态化 (像私服版, 从STATE返回真实已读时间, 不写死旧值)
        if path == "/v1/owner/checkedat":
            import copy as _ck_cp
            _ck = _ck_cp.deepcopy(STATE.get("checked_at", {}))
            _ck["updated_at"] = server_now_str()
            return {"owner_checked_at": _ck}
        # 2026-09-14: casino/chip 赌场筹码动态化 (像私服版, 从STATE返回真实值; 赌场play时更新筹码)
        if path == "/v1/casino/chip":
            import copy as _chip_cp
            _chip = _chip_cp.deepcopy(STATE.get("casino_chip", {}))
            if _chip:
                _chip["updated_at"] = server_now_str()
                return {"casino_chip": _chip}
        # 2026-09-14: casino/game 赌场统计动态化 (像私服版, 从STATE返回; 赌场play时play_count++/win_count++)
        if path == "/v1/casino/game":
            import copy as _cg_cp
            _cg = _cg_cp.deepcopy(STATE.get("casino_game", []))
            if _cg:
                return {"casino_game_list": _cg}
        # 2026-09-14: 维纳斯商店购买记录叠加 (像私服版, shop/list 返回历史+本次购买记录; 买后商品显示已购/售罄)
        #   铁证 captured_diff_private4: 购买43143后 GET /v1/shop/list 响应从10017B→10207B, 43143追加到 shop_purchase_list 末尾
        #   之前 shop/list 走静态 REAL_RESPONSES (53条旧记录), 新购买的43143/33345未叠加 → 商品买后仍显示可购买
        if path == "/v1/shop/list":
            # ===== 2026-11-07 修复(核心): 不再返回抓包账号的 52 条历史购买记录 =====
            # 病根: real_responses.json 里这份 shop_purchase_list 是别人账号 2020~2026 年的购买史,
            #   而 normalize_dates 的窗口 RECENT_DAYS=2700 天, 会把它们的 created_at 全部改写成"现在"。
            #   客户端因此认为这些商品"今天刚买过", 每日/限购商品的可购买数量直接算成 0
            #   → 表现就是"商品显示数量 0 / 买不了", 买完也显示 0。
            # 正确做法: 购买记录只来自本存档 (STATE.shop_purchased), 没买过就是没买过。
            _shop_pl = []
            _shop_pur = STATE.get("shop_purchased", {})
            _shop_time = STATE.setdefault("shop_purchased_at", {})
            for _pmid, _cnt in _shop_pur.items():
                try:
                    _pmid_i = int(_pmid)
                    _c = int(_cnt)
                except (TypeError, ValueError):
                    continue
                if _c <= 0:
                    continue
                # 历史购买(旧存档无时间戳)统一给 2019-01-01: 这个日期在 normalize_dates 的
                #   2700 天窗口之外, 不会被改写成"今天", 客户端才会按"不是今天"处理每日限购。
                _shop_pl.append({
                    "owner_id": OWNER_ID, "product_mid": _pmid_i,
                    "limit_count": max(1, _c), "total_count": _c,
                    "created_at": _shop_time.get(str(_pmid_i), "2019-01-01 00:00:00"),
                    "updated_at": None
                })
            return {"shop_purchase_list": _shop_pl}
        # 特殊处理: special_order/37 = "已解锁的姿势卡列表" —— 这才是姿势/表情菜单的真正解锁载体
        #   2026-11-08 14:20 重大修正: 此前硬编码返回 [] 导致除自带基础 6 张外全部锁死。
        #   条目格式照抄同族端点 /v1/special_order/29 的 order_ticket_list:
        #     {"item_mid":..,"count":1,"type":37,"updated_at":null,"created_at":"2019-03-28 11:13:59"}
        #   全集: Equipment_Parameter type37=1325 张姿势卡 + type81=2416 张表情卡 = 3741 条 ≈ 180KB
        #   (远低于 private_items 5.19MB 的安全水位, 不会 OOM)。
        if path == "/v1/special_order/37" and _POSE_CARD_ORDER_ENABLED:
            _pc_lst = [{"item_mid": _pc_m, "count": 1, "type": 37,
                        "updated_at": None, "created_at": _POSE_CARD_TS}
                       for _pc_m in POSE_ITEM_MIDS]
            if _POSE_CARD_INCLUDE_EXPR:
                _pc_lst.extend({"item_mid": _pc_m, "count": 1, "type": 81,
                                "updated_at": None, "created_at": _POSE_CARD_TS}
                               for _pc_m in EXPR_ITEM_MIDS)
            _pose_trace(0, 37, len(_pc_lst))
            return {"pose_card_item_list": _pc_lst}
        # 表情的独立入口(客户端目前在日志里没请求, 保留以防某些界面按 type 单独拉)
        if path == "/v1/special_order/81" and _POSE_CARD_ORDER_ENABLED:
            _pe_lst = [{"item_mid": _pc_m, "count": 1, "type": 81,
                        "updated_at": None, "created_at": _POSE_CARD_TS}
                       for _pc_m in EXPR_ITEM_MIDS]
            _pose_trace(0, 81, len(_pe_lst))
            return {"pose_card_item_list": _pe_lst}
        if path == "/v1/special_order/37":
            return {"pose_card_item_list": []}
        # 2026-09-17: tutorial flag 对齐私服版(抓包铁证) — 补上私服独占bit, 解锁滑落等功能
        # 私服 event_mid=0 有 bit25+bit14(0x2004000), event_mid=100000 有 bit22+bit14(0x408000); 单机缺 -> 补
        if path == "/v1/tutorial":
            import copy as _cp_tut
            _tut = _cp_tut.deepcopy(REAL_RESPONSES.get("/v1/tutorial", {"tutorial_list": []}))
            _tl = _tut.setdefault("tutorial_list", [])
            _tf = {t.get("event_mid"): t for t in _tl if isinstance(t, dict)}
            if 0 in _tf:
                _tf[0]["flag"] = int(_tf[0].get("flag", 0)) | 0x2004000
            if 100000 in _tf:
                _tf[100000]["flag"] = int(_tf[100000].get("flag", 0)) | 0x408000
            for _em in (386, 388):
                if _em not in _tf:
                    _tl.append({"owner_id": OWNER_ID, "event_mid": _em, "flag": 4,
                                "created_at": "2019-03-28 11:10:39", "updated_at": None})
            return _tut
        # 关键: 公告弹窗 — 2026-09-05 改为返回真实公告, 让游戏正常显示公告弹窗
        # 2026-09-07 方案C: 已读持久化 — PUT information 记录已读, 已读公告 read=true 不再弹
        # 效果: 第一次弹公告, 关闭记录已读, 之后点按钮不再弹 (模拟私服版)
        if path == "/v1/information/global":
            if INFORMATION_GLOBAL and INFORMATION_GLOBAL.get("information_list"):
                import copy as _copy_info
                resp_info = _copy_info.deepcopy(INFORMATION_GLOBAL)
                read_list = STATE.setdefault("read_information", [])
                for info in resp_info.get("information_list", []):
                    if info.get("information_id") in read_list:
                        info["read"] = True
                return resp_info
            return {"information_list": []}
        # 公告已读标记 (PUT /v1/information): 返回标记成功 + information_id
        # 2026-09-07 修复: 私服版返回 {"information_mark_as_read":{"information_id":16263}}
        # 缺 information_id 导致客户端关闭公告时访问违例闪退 (昨天已定位修复, 今天在9/5代码上重新应用)
        if path == "/v1/information" and method == "PUT":
            info_id = req.get("information_id", 16263)
            # 记录已读 (方案C): 下次 information/global 返回 read=true, 不再弹
            read_list = STATE.setdefault("read_information", [])
            if info_id not in read_list:
                read_list.append(info_id)
            _save_state()
            return {"information_mark_as_read": {"information_id": info_id}}
        # 签到弹窗相关: 保持空(游戏跳过签到弹窗)
        if path == "/v1/login_bonus/shared/check":
            return {"login_bonus_shared_bonus_id_list": []}
        # 关键: matching_pvp/active 必须始终返回空列表
        # 否则响应池轮换到含"进行中比赛"的变体时, 游戏自动开打竞技场PVP并卡死, 永不进主岛
        if path == "/v1/matching_pvp/active":
            return {"matching_pvp_active_list": []}
        # 关键: countlogin 登录计数与私服版一致(6), 客户端可能据此判断"是否首次登录/每日登录流程"
        # 2026-09-05 测试: 私服版9/5实测 login_count=2, 改回2尝试修复白屏复现
        if path == "/v1/owner/countlogin":
            return {"login_count": 2}
        # 2026-09-05: login_bonus/monthly 按方法区分:
        #   POST -> 领月度签到奖, 返回真实发奖(login_monthly_reward + 物品进背包) [私服版48856ms]
        #   GET  -> 查询月度签到状态 (monthly_login); 领过奖后返回 collect=1
        if path == "/v1/login_bonus/monthly":
            if method == "POST":
                if LOGIN_BONUS_MONTHLY_REWARD:
                    STATE.setdefault("monthly_claimed", {})
                    STATE["monthly_claimed"]["monthly"] = game_today_str()
                    _save_state()
                    return LOGIN_BONUS_MONTHLY_REWARD
            lbm = REAL_RESPONSES.get(path, {})
            lbm = dict(lbm)
            ml = dict(lbm.get("monthly_login", {}))
            ml["monthly_login_count"] = 3
            # 09-25: 改用游戏日(game_today_str)判 collect — 日切后(游戏日=明天) claimed_date(昨天) != 明天 -> collect=0(可领) -> 客户端领 -> collect=1 -> 过. 旧用日历日->日切后 collect=1(已领昨天)客户端不认->反复GET死循环.
            claimed_date = STATE.get("monthly_claimed", {}).get("monthly")
            today = game_today_str()
            ml["monthly_login_collect"] = 1 if claimed_date == today else 0
            lbm["monthly_login"] = ml
            return lbm
        # 关键: login_bonus 按请求方法区分阶段:
        #   GET  -> 读签到列表 (login_bonus_list)   [私服版 40626ms]
        #   POST -> 领取奖励, 返回空奖励结构        [私服版 46352ms, login_bonus_after.json]
        # 否则游戏 POST 领奖收到"列表"会认为还有奖励要领 -> 无限循环 -> 白屏
        # 2026-09-05 v3: 第一次 POST 返回完整发奖(玩家领奖), 之后(客户端二次检查)返回"已领完"
        #   - 第一次: login_bonus_reward_list 有5条奖励 + complite标记领完 -> 签到弹窗领奖
        #   - 之后:   reward_list 空 + login_bonus_list complite=count -> 客户端确认已领完, 进 shared/check
        if path == "/v1/login_bonus":
            global LOGIN_BONUS_COUNT
            LOGIN_BONUS_COUNT += 1
            # 09-25: 撤销 v2 动态签到, 回原始静态. 私服版抓包铁证: 日常 complite=6<count=24(可领), 不是领完.
            # v2 把 complite 改成 count(领完)→客户端没法领→更卡. 月度循环真因是 collect=1(已领), 清 claimed 即可.
            if method == "GET":
                import copy as _copy_get
                resp = _copy_get.deepcopy(LOGIN_BONUS_FIRST)
                if CONFIG.get("skip_daily_login_bonus"):
                    for lb in resp.get("login_bonus_list", []):
                        lb["complite"] = lb.get("count", 0)
                return resp
            if CONFIG.get("skip_daily_login_bonus") or not (LOGIN_BONUS_REWARD and LOGIN_BONUS_COUNT == 2):
                import copy as _copy2b
                resp = dict(LOGIN_BONUS_AFTER)
                resp["login_bonus_list"] = _copy2b.deepcopy(LOGIN_BONUS_REWARD.get("login_bonus_list", []))
                for lb in resp.get("login_bonus_list", []):
                    lb["complite"] = lb.get("count", 0)
                return resp
            import copy as _copy2
            resp = _copy2.deepcopy(LOGIN_BONUS_REWARD)
            for lb in resp.get("login_bonus_list", []):
                lb["complite"] = lb.get("count", 0)
            return resp
        # ---- 邮箱完整逻辑 (2026-09-07 复活版): 领取持久化, 已领邮件从列表移除 ----
        # 源码依据: 客户端不读 accepted_at 判断已领 → 已领邮件必须从列表移除 → 红点消失
        if path.startswith("/v1/giftbox"):
            gb = _build_giftbox(path, req, method)
            if gb is not None:
                return gb
        # ---- 2026-09-12: 钱包/消耗品库存返回 STATE 追踪值 (与 giftbox accept 一致) ----
        # 领取货币邮件后钱包变化, 领取消耗品邮件后库存变化, /v1/wallet 和 /v1/item/consume 需同步
        if path == "/v1/wallet" and method == "GET":
            w = STATE.get("wallet", {})
            if w:
                import copy as _cp_w
                return {"wallet": _cp_w.deepcopy(w)}
        if path == "/v1/item/consume" and method == "GET":
            ic = STATE.get("item_counts", {})
            if ic:
                # 从原始 /v1/item/consume 响应为基础, 叠加 STATE 追踪的库存变化
                import copy as _cp_ic
                base_ic = _cp_ic.deepcopy(SERVER_DB.get("endpoints", {}).get("/v1/item/consume", [{}])[0])
                _lst_ic = base_ic.setdefault("item_consume_list", [])
                # 2026-11-07 修复①b: 旧逻辑只"覆盖"已有条目, 从不"追加"新物品
                #   实证: 抓包 base 只有 290 种, STATE 实际 367 种 → 77 种物品永远不返回
                #   (含 15 种 999999 货币 + 购买/领取的道具) → 客户端显示 0 / 背包里没有 / 道具无法使用
                #   这里统一用 int 键归一化(历史代码有 str 键写入) 并补齐缺失条目。
                _icn = {}
                for _kx, _vx in ic.items():
                    try:
                        _icn[int(_kx)] = int(_vx)
                    except (TypeError, ValueError):
                        continue
                _seen_ic = set()
                # 2026-11-07 修复②b: 输出前过滤两类脏数据
                #   ① count<=0 —— 真实服务器不会把"数量 0"的物品放进背包; 客户端拿到 0 会
                #      显示成"有这件但数量 0", 既用不了也丢不掉(用户反馈的"数量不对")。
                #   ② 装备表(Equipment_Parameter)里的 item_mid —— 属于衣橱实例,
                #      同时出现在背包会让同一件东西被算两次。
                _out_ic = []
                for item in _lst_ic:
                    mid = item.get("item_mid")
                    if mid is None:
                        continue
                    _seen_ic.add(mid)
                    _cnt_now = _icn.get(mid, item.get("count", 0) or 0)
                    if _cnt_now <= 0 or mid in EQUIP_TYPE_MAP:
                        continue
                    item["count"] = _cnt_now
                    _out_ic.append(item)
                _now_ic = game_now_str()
                _appended = 0
                for _mid2, _cnt2 in _icn.items():
                    if _mid2 in _seen_ic:
                        continue
                    if _cnt2 <= 0 or _mid2 in EQUIP_TYPE_MAP:
                        continue
                    _out_ic.append({"item_mid": _mid2, "count": _cnt2,
                                    "type": ITEM_TYPE_MAP.get(_mid2, 0),
                                    "updated_at": None, "created_at": _now_ic})
                    _appended += 1
                base_ic["item_consume_list"] = _out_ic
                if _appended:
                    print(f"[/v1/item/consume] 追加缺失库存 {_appended} 条 (总 {len(_out_ic)})")
                return base_ic
        # ---- 任务全部标记完成 (2026-09-07 复活版): 让"新任岛主应援"看板任务面板关闭 ----
        # 原理: 客户端读 mission_list 的 progress 判断任务状态, progress=3 视为完成
        # 目标: "新任岛主应援"任务(13447/13449/13450/18028/18034) 全部 progress=3 → 面板关闭
        # 副作用: 日常/每周任务也被标记完成 (用户暂接受)
        if path.startswith("/v1/mission") and method in ("GET", "POST"):
            import copy as _cp_mission

            def _sanitize_mission_list(_ml):
                # 2026-11-11: 剔除会让客户端任务面板空指针闪退的条目
                #   ① 黑名单 (13446, 见 MISSION_MID_BLOCKLIST 注释)
                #   ② mission_mid 非法: <=0 / 非整数 / 不在 MissionData 主数据里
                #      抓包池 /v1/mission/7 每份最后一条都是 mission_mid=0, 必剔
                if not isinstance(_ml, list):
                    return _ml
                _kept, _drop = [], []
                for _t in _ml:
                    if not isinstance(_t, dict):
                        continue
                    if _mission_mid_ok(_t.get("mission_mid")):
                        _kept.append(_t)
                    else:
                        _drop.append(_t.get("mission_mid"))
                if _drop:
                    log_write(f"  [MISSION] {path} 剔除非法任务 {len(_drop)} 条 "
                              f"{_drop[:5]} (总 {len(_ml)} → {len(_kept)})\n")
                return _kept

            # 2026-11-11b: 领奖请求结构只记一次 (现在 /mission/reward 仍走抓包轮换,
            #   返回的奖励与实际领的任务无关且不落库; 记下真实请求体后再做成"按任务发奖")
            if path == "/v1/mission/reward" and req and not STATE.get("_mission_reward_req_logged"):
                STATE["_mission_reward_req_logged"] = True
                log_write(f"  [MISSION] reward 请求样本: "
                          f"{json.dumps(req, ensure_ascii=False)[:500]}\n")

            # 2026-11-11e: /v1/mission/multiple 必须按请求里的 mission_ids 逐面板合并!
            #   客户端的 mission_ids 是【面板号】不是类别号, 一次要一批面板:
            #     "1,2" → /mission/1 + /mission/2 = 69 条, "3,4" → 162, "5,6" → 82, "7" → 1011。
            #   旧实现用写死的 {"1,2":0,"3,4":1,"5,6":2,"7":3} 索引取样本: 任何别的组合
            #   (如 "8,9"、"1,2,3"、"7,8" 或空参数) 都会掉进 _build_dynamic 的固定 pool[0]
            #   (69 条, 只含 category 1/2/3/6, 永远不含 category=9 的 27 条) → 客户端
            #   "新任岛主应援"看板查状态缺键 → 空指针闪退 (0x274e73b / Rdx=13446)。
            #   现改为按面板号合并对应单端点 pool[0], 任意组合都能给出完整列表。
            if path == "/v1/mission/multiple":
                _ids = ""
                if isinstance(req, dict):
                    _ids = str(req.get("mission_ids") or "")
                _toks = [t.strip() for t in _ids.replace("，", ",").split(",") if t.strip()]
                if not _toks:
                    # 没带 mission_ids 时给全集, 宁可多给也不能缺(缺键=闪退)
                    _toks = ["1", "2", "3", "4", "5", "6", "7", "8", "9"]
                _merged_ml = _sanitize_mission_list(_mission_panel_list(_toks))
                if not _merged_ml:
                    # 面板号全不认识 → 返回空数组是"缺键=闪退"的同款危险情形, 退化为全集
                    _toks = ["1", "2", "3", "4", "5", "6", "7", "8", "9"]
                    _merged_ml = _sanitize_mission_list(_mission_panel_list(_toks))
                for _t in _merged_ml:
                    _t["progress"] = 3
                _base_ml = {"mission_list": _merged_ml}
                # 合并结果若与某份抓包样本的 mid 集合完全一致, 用它做底以保留
                # owner_checked_at_list 等附加字段(面板 "1,2" 的样本就带这个键)
                _mset = {t["mission_mid"] for t in _merged_ml}
                for _s in ((SERVER_DB.get("endpoints", {}) or {}).get(path) or []):
                    if not isinstance(_s, dict):
                        continue
                    _sm = {x.get("mission_mid") for x in (_s.get("mission_list") or [])
                           if isinstance(x, dict)}
                    if _sm - {0} == _mset and len(_sm) - (1 if 0 in _sm else 0) == len(_mset):
                        _base_ml = _cp_mission.deepcopy(_s)
                        _base_ml["mission_list"] = _merged_ml
                        break
                _mid2cat_pl = {}
                for _c, _lst in MISSION_BY_CAT.items():
                    for _mid, _s2, _e2 in _lst:
                        _mid2cat_pl[_mid] = _c
                _cstat = {}
                for _t in _merged_ml:
                    _c = _mid2cat_pl.get(_t["mission_mid"], "?")
                    _cstat[_c] = _cstat.get(_c, 0) + 1
                log_write(f"  [MISSION] multiple ids={_ids or '∅'} → {len(_merged_ml)} 条 "
                          f"(类别 {dict(sorted(_cstat.items(), key=lambda x: str(x[0])))})\n")
                if not STATE.get("_mission_selfcheck_done"):
                    STATE["_mission_selfcheck_done"] = True
                    _mission_selfcheck()
                return _base_ml

            # 2026-11-11c: /v1/mission/8 /v1/mission/9 的抓包快照都是 [] (真实服务器对该账号
            #   没有这两类常驻任务), 但客户端任务面板会去遍历本地 csv 的 category=8/9 任务
            #   mid 并查内部状态表 → 全落空 → 第一个元素就空指针闪退(13446 是 category=9 首个)。
            #   这里按主数据把所有该类任务以 progress=3(已完成) 下发, 把状态表补满。
            if path in ("/v1/mission/8", "/v1/mission/9"):
                _cat = path.rsplit("/", 1)[-1]
                _gl = _gen_mission_list_by_category(_cat)
                if _gl:
                    log_write(f"  [MISSION] {path} 按类别 {_cat} 补全 {len(_gl)} 条任务"
                              f" (首条 mid={_gl[0]['mission_mid']})\n")
                    return {"mission_list": _gl}

            dyn = _build_dynamic(path, req, method)
            if dyn is not None:
                # 2026-11-11b: /mission/8 /mission/9 的抓包本身就是 list([]), 直接原样返回;
                #   原实现只认 dict, 非 dict 会掉到下面的 REAL_RESPONSES 分支,
                #   对 list 调 .get() → AttributeError → 客户端收到空 {} (接口语义错)
                if not isinstance(dyn, dict):
                    return dyn
                ml = dyn.get("mission_list")
                if isinstance(ml, list):
                    resp2 = _cp_mission.deepcopy(dyn)
                    resp2["mission_list"] = _sanitize_mission_list(resp2.get("mission_list", []))
                    for t in resp2["mission_list"]:
                        t["progress"] = 3  # 全部标记完成
                    return resp2
                return dyn
            if path in REAL_RESPONSES:
                base = _cp_mission.deepcopy(REAL_RESPONSES[path])
                if not isinstance(base, dict):
                    # 同上: /mission/8 在 REAL_RESPONSES 里是 list, 不能再 .get()
                    return base
                ml = base.get("mission_list")
                if isinstance(ml, list):
                    base["mission_list"] = _sanitize_mission_list(ml)
                    for t in base["mission_list"]:
                        if isinstance(t, dict):
                            t["progress"] = 3
                    return base
                return base
        # ---- 好友红点测试 (2026-09-07): 3787646 updated_at 改2019, 验证"红点=近期更新好友数" ----
        # 假设: 红点数字 = friendship_list 里 updated_at 较新的好友数 (3好友中3787646最新→红点1)
        if path == "/v1/friendship" and method == "GET":
            import copy as _cp_fr
            base_fr = _cp_fr.deepcopy(REAL_RESPONSES.get(path, {"friendship_list": []}))
            for f in base_fr.get("friendship_list", []):
                if f.get("friend_id") == 3787646:
                    f["updated_at"] = "2019-01-01 00:00:00"
            return base_fr
        # 2026-09-18: 回忆-写真(bromide) 全部已读 — count>=1=已读(同episode机制)
        # 原走静态快照部分 count=0=未读(亮"新"). 改为快照基础上全部 count=1.
        if path == "/v1/bromide" and method == "GET":
            import copy as _cp_br
            _br_base = _cp_br.deepcopy(REAL_RESPONSES.get("/v1/bromide", {"bromide_list": []}))
            for _b in _br_base.get("bromide_list", []):
                if _b.get("count", 0) < 1:
                    _b["count"] = 1
            return _br_base
        # 2026-09-16: 泳装滑落开启 — swimsuit_arrange_flag switch=1(所有女孩) + dishevelment 全部已滑落
        # 子路径/PUT 按抓包真实结构返回 (单机无他人->other列表空; PUT强制switch=1始终开启), 避免落兜底
        if path.startswith("/v1/swimsuit_arrange_flag"):
            _sp = path.strip("/").split("/")  # ["v1","swimsuit_arrange_flag", maybe id]
            if len(_sp) == 3 and method == "GET":
                # /v1/swimsuit_arrange_flag/<owner_id> 查别人的 arrange flag — 单机无他人
                return {"swimsuit_arrage_flag_other_list": []}
            if len(_sp) == 3 and method == "PUT":
                # PUT /v1/swimsuit_arrange_flag/<girl_mid> 切换泳装形态/配色 (7.5周年新功能)
                # 2026-11-08: 之前伪造 variation=2/switch=1 固定值 — 客户端切形态后收不到自己提交的值
                #   → 模型切回默认形态, 表现就是"点了模式箭头没变化"。
                # 正确做法: 回显请求体里的 variation/switch, 并持久化到 STATE, GET 时返回。
                _gm_put = 0
                try:
                    _gm_put = int(_sp[2])
                except Exception:
                    pass
                _af_var = req.get("variation", 0) if isinstance(req, dict) else 0
                _af_sw = req.get("switch", 0) if isinstance(req, dict) else 0
                try:
                    _af_var = int(_af_var); _af_sw = int(_af_sw)
                except (TypeError, ValueError):
                    _af_var = 0; _af_sw = 0
                _af_now = server_now_str()
                # 2026-11-08: 列表条目结构由 IDA 实证 (sub_14236F7F0) = {item_mid, variation, created_at}
                #   → 必须记下"切换时她穿的泳装 item_mid", 重启后客户端靠它把形态套回具体泳装.
                _af_gear = STATE.get("girl_equipment") or {}
                _af_g = _af_gear.get(str(_gm_put)) or _af_gear.get(_gm_put) or {}
                _af_item = 0
                try:
                    _af_item = int(_af_g.get("swimsuit_item_mid", 0) or 0)
                except (TypeError, ValueError):
                    _af_item = 0
                _af_state = STATE.setdefault("swimsuit_arrange_flags", {})
                _af_state[str(_gm_put)] = {"variation": _af_var, "switch": _af_sw,
                                           "item_mid": _af_item,
                                           "updated_at": _af_now}
                _save_state()
                print(f"[swimsuit_arrange_flag] girl={_gm_put} item={_af_item} "
                      f"variation={_af_var} switch={_af_sw}")
                _arrange_trace("PUT", girl=_gm_put, item=_af_item,
                               variation=_af_var, switch=_af_sw,
                               body=json.dumps(req, ensure_ascii=False)[:200])
                return {"swimsuit_arrage_flag": {"owner_id": OWNER_ID, "girl_mid": _gm_put,
                        "variation": _af_var, "switch": _af_sw,
                        "created_at": "2026-09-16 00:00:00", "updated_at": _af_now}}
            # GET /v1/swimsuit_arrange_flag — 回放已保存形态
            #   2026-11-08: 实测回放 {item_mid:59983, variation:74} 会让客户端在收到响应瞬间崩溃
            #   (ucrtbase 0xc0000409 快速失败, 疑似 variation 被当作变体数组下标 → 越界抛异常 → abort)
            #   → 默认关闭回放, 恢复"空列表"的安全行为, 待确认 variation 的真实语义后再开.
            if not _ARRANGE_REPLAY_ENABLED:
                _arrange_trace("GET", replay="off",
                               saved=json.dumps(STATE.get("swimsuit_arrange_flags") or {},
                                                ensure_ascii=False)[:300])
                return {"swimsuit_arrage_flag_list": []}
            _af_dirty = False
            _af_own = set()
            for _e_af in STATE.get("equipment_inventory", []):
                if isinstance(_e_af, dict) and _e_af.get("type") == 1:
                    _af_own.add(_e_af.get("item_mid", 0))
            _af_out = []
            _af_seen = set()
            for _k_af, _v_af in (STATE.get("swimsuit_arrange_flags") or {}).items():
                if not isinstance(_v_af, dict):
                    continue
                try:
                    _im_af = int(_v_af.get("item_mid", 0) or 0)
                except (TypeError, ValueError):
                    _im_af = 0
                if not _im_af:
                    # 旧记录 (无 item_mid) → 用该女孩当前穿的泳装回填
                    _g_af = (STATE.get("girl_equipment") or {}).get(str(_k_af)) or {}
                    try:
                        _im_af = int(_g_af.get("swimsuit_item_mid", 0) or 0)
                    except (TypeError, ValueError):
                        _im_af = 0
                    if _im_af:
                        _v_af["item_mid"] = _im_af
                        _af_dirty = True
                if not _im_af or _im_af in _af_seen or _im_af not in _af_own:
                    continue
                _af_seen.add(_im_af)
                # ============================================================================
                # 【勿再尝试 · 2026-11-08 已两次实测失败, 用户决定暂时搁置】
                # 目标: 让"泳装模式(多形态/多配色)"在完全退出游戏后仍保持切换结果。
                #
                # 已验证的事实 (arrange_trace.log):
                #   1. 客户端点模式箭头**确实会发** PUT /v1/swimsuit_arrange_flag/{girl},
                #      body 恒为 {"switch": 0 或 1, "variation": 74}, 连点 7 次 variation 全是 74,
                #      只有 switch 在 0/1 交替 → variation 是"这件泳装自己的固定标识", switch 才是形态开关。
                #      (注: 曾误判"点箭头 0 请求", 那是 logutil 16KB 缓冲 + bat 启动看不到 print 造成的假象)
                #   2. GET /v1/swimsuit_arrange_flag 是客户端**启动时**拉取的(每次启动一次, 在登录流程很早的位置)。
                #   3. 该列表条目结构由 IDA 反编译实证(sub_14236F7F0) = {item_mid, variation, created_at}。
                #
                # 两次失败的尝试 (都会让客户端 ucrtbase.dll 0xc0000409 快速失败 → 进程 abort):
                #   A. 回放 {item_mid: 59983, variation: 74} → 崩
                #   B. 回放 {item_mid: 59983, variation: 1}  → 也崩 (1 是 /v1/dishevelment 在真实抓包里的常用值)
                #   → 结论: 问题不在 variation 取值, 而是"非空列表"本身缺少客户端必需的配套数据
                #     (极可能 item_mid 不是泳装 mid, 或条目要配合一张客户端内置的变体表才能解析)。
                #
                # 要真正修好, 唯一可靠路径: 在能正常切形态的正版/私服环境里,
                #   切完形态后抓一次 **非空** 的 GET /v1/swimsuit_arrange_flag 响应, 照抄结构。
                #   靠反编译只能看到字段名, 看不到"哪些字段必须有值/取值范围", 这正是两次都栽在同一处的原因。
                #
                # 现状(可接受): 开关 _ARRANGE_REPLAY_ENABLED = False → 返回空列表,
                #   形态切换在**游戏内**正常(会话内即时生效), 只是完全重启后回到默认形态。不影响正常游玩。
                # ============================================================================
                try:
                    _af_on = 1 if int(_v_af.get("switch", 0) or 0) else 0
                except (TypeError, ValueError):
                    _af_on = 0
                if not _af_on:
                    _arrange_trace("SKIP-SWITCH-OFF", girl=_k_af, item=_im_af)
                    continue
                # 兜底保护: 值域仍限制在 0..CAP (1 必然通过; 只防未来手改数据)
                if _af_on < 0 or _af_on > _ARRANGE_VARIATION_CAP:
                    _arrange_trace("SKIP-OUT-OF-RANGE", girl=_k_af, item=_im_af,
                                   variation=_af_on, cap=_ARRANGE_VARIATION_CAP)
                    continue
                _af_out.append({"item_mid": _im_af, "variation": _af_on,
                                "created_at": _v_af.get("updated_at") or server_now_str()})
            if _af_dirty:
                _save_state()
            _arrange_trace("GET", replay="on", count=len(_af_out),
                           items=[(e["item_mid"], e["variation"]) for e in _af_out][:10])
            if _af_out:
                print(f"[swimsuit_arrange_flag] GET 回放 {len(_af_out)} 条: "
                      f"{[(e['item_mid'], e['variation']) for e in _af_out]}")
            return {"swimsuit_arrage_flag_list": _af_out}
        # 2026-09-17: max_combine 动态化 — 客户端用此列表判"技能觉醒到最大限度"以解锁泳装滑落
        # 原走 REAL_RESPONSES 静态快照(只含私服6件 426/431/434/493/558/2980), GM 泳装不在列表→滑落按钮灰.
        # 抓包铁证: 客户端 GET /v1/max_combine 后, 查 worn swimsuit 是否在 max_combine_swimsuit_list 里.
        # 改为返回全部 type=1 泳装(同 dishevelment 逻辑), 让 GM 加的泳装也"觉醒到上限".
        if path == "/v1/max_combine" and method == "GET":
            _mc_list = []
            _seen_mc = set()
            for _e in STATE.get("equipment_inventory", []):
                if isinstance(_e, dict) and _e.get("type") == 1:
                    _im_mc = _e.get("item_mid", 0)
                    if _im_mc and _im_mc not in _seen_mc:
                        _mc_list.append({"item_mid": _im_mc, "variation": 1, "created_at": "2026-09-16 00:00:00"})
                        _seen_mc.add(_im_mc)
            return {"max_combine_swimsuit_list": _mc_list}
        # 2026-09-17: 回忆菜单(写真视频/主要剧情/性感照板块/活动剧情/女孩剧情/额外剧情)全部解锁+已读
        # 客户端 GET /v1/owner/episode 用 episode_list 判解锁(在列表=解锁), count>=1 判已读.
        # 原走静态快照只178条(私服抓的部分), 其余2530个看不到. 改为返回 EpisodeList 全集(2708) count=1.
        # 写真视频/性感照板块(type1, 320个GravurePanel关联)也含在全集中, 一并解锁.
        if path == "/v1/owner/episode" and method == "GET":
            _ep_list = [{"episode_mid": _em, "count": 1, "created_at": "2026-09-17 00:00:00"}
                        for _em in EPISODE_MIDS]
            return {"episode_list": _ep_list}
        if path.startswith("/v1/owner/episode/") and method in ("PUT", "POST"):
            # PUT=注册解锁(count=0); POST=观看(count+1+给经验). 单机已全解锁全已读, 都回 count=1.
            _sp_ep = path.strip("/").split("/")  # ["v1","owner","episode", mid]
            _em_act = 0
            if len(_sp_ep) >= 4:
                try:
                    _em_act = int(_sp_ep[3])
                except ValueError:
                    pass
            if method == "PUT":
                return {"episode_list": [{"episode_mid": _em_act, "count": 1,
                        "created_at": "2026-09-17 00:00:00"}]}
            # POST: 抓包完整结构 episode_result(episode+owner) + owner_list + episode_list
            # 缺 owner_list/episode_result.owner → 客户端访问空字段闪退 (2026-09-18 episode 1003180 实测)
            import copy as _cp_ep
            _own_src = _cp_ep.deepcopy(REAL_RESPONSES.get("/v1/owner", {"owner": {}})).get("owner", {})
            if isinstance(_own_src, dict):
                _own_src["main_girl_mid"] = STATE.get("main_girl_mid", 3)
                _lvl_ep = _own_src.get("level", 1)
                _exp_ep = _own_src.get("experience", 0)
            else:
                _own_src = {}; _lvl_ep = 1; _exp_ep = 0
            return {
                "episode_result": {
                    "episode": {"episode_mid": _em_act, "count": 1},
                    "owner": {"experience_before": _exp_ep, "experience_gain": 0,
                              "experience_after": _exp_ep, "level_before": _lvl_ep,
                              "level_gain": 0, "level_after": _lvl_ep}},
                "owner_list": [_own_src] if _own_src else [],
                "episode_list": [{"episode_mid": _em_act, "count": 1,
                        "created_at": "2026-09-17 00:00:00"}]}
        if path.startswith("/v1/dishevelment") and method == "GET":
            _sp = path.strip("/").split("/")  # ["v1","dishevelment", maybe owner, item]
            if len(_sp) == 4:
                # /v1/dishevelment/<owner_id>/<item_mid> 查别人某泳装滑落状态 — 单机 dishevelment=0(未滑落)
                _ow = 0
                _im = 0
                try:
                    _ow = int(_sp[2]); _im = int(_sp[3])
                except Exception:
                    pass
                return {"dishevelment_other": {"owner_id": _ow, "item_mid": _im, "variation": 1, "dishevelment": 0}}
            # GET /v1/dishevelment — 自己的滑落泳装列表(全部已滑落, 从装备库 type=1 去重)
            _dis_list = []
            _seen_dis = set()
            for _e in STATE.get("equipment_inventory", []):
                if isinstance(_e, dict) and _e.get("type") == 1:
                    _im_dis = _e.get("item_mid", 0)
                    if _im_dis and _im_dis not in _seen_dis:
                        _dis_list.append({"item_mid": _im_dis, "variation": 1, "created_at": "2026-09-16 00:00:00"})
                        _seen_dis.add(_im_dis)
            return {"dishevelment_swimsuit_list": _dis_list}
        # ---- 2026-09-15: 温泉/送礼/岛主房间工作 动态持久化 (抓包确认, 在状态叠加前拦截) ----
        if path.startswith("/v1/onsen"):
            _r = _build_onsen(path, req, method)
            if _r is not None:
                return _r
        if path == "/v1/present" and method == "POST":
            _r = _build_present(path, req, method)
            if _r is not None:
                return _r
        if path == "/v1/special_order/exchange" and method == "POST":
            _r = _build_special_order_exchange(path, req, method)
            if _r is not None:
                return _r
        if path.startswith("/v1/room/request") or path == "/v1/room/girls" or path == "/v1/room/girl/friendly" or path == "/v1/room":
            _r = _build_room_request(path, req, method)
            if _r is not None:
                return _r
        # ---- 状态叠加: 主女孩 / 房间 / 女孩列表注入当前STATE ----
        ov = _apply_state_overlay(path, method, req)
        if ov is not None:
            return ov
        # 动态响应引擎: 私服版全量抓取的 295 个端点 (main_girl/gacha/quest/任务/商店等)
        dyn = _build_dynamic(path, req, method)
        if dyn is not None:
            return dyn
        # 优先用真实抓取的数据 (大厅家具会触发资源下载, 服务器已实现资源代理)
        if path in REAL_RESPONSES:
            resp = REAL_RESPONSES[path]
            # 2026-09-11 修复: 对含 girl_list 的响应叠加 STATE (同 _build_dynamic 通用回退)
            if isinstance(resp, dict) and "girl_list" in resp:
                import copy as _copy_rr
                resp = _copy_rr.deepcopy(resp)
                for g in resp.get("girl_list", []):
                    apply_girl_state(g)
            return resp
        if path.startswith("/v1/item/equipment/type/"):
            return {"item_equipment_list": []}
        if path.startswith("/v1/item/consume/negative"):
            return {"item_negative_consume_list": []}
        if path == "/v1/steam/currencyinfo":
            return {"status": "success", "steam_id": req.get("steam_id", "")}
        if path == "/v1/steam/timeoutcheck":
            return {"status": "success"}
        if path == "/v1/shop/paymentlog/incomplete":
            return {"payment_log_list": []}
        if path == "/v1/csv/list":
            # 真实结构: csv_file_list 含所有文件名->hash, 末尾含 file_encrypt_key
            return {"csv_file_list": CSV_MAP}
        return {"status": "success"}

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_PUT(self): self._handle("PUT")
    def do_DELETE(self): self._handle("DELETE")

def _ensure_tls_cert():
    """缺失时自动生成自签名 TLS 证书 (doaxvv_cert.pem / doaxvv_key.pem)。
    客户端经 hosts 劫持连本机, 不校验证书, 故自签名即可。"""
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    print("[*] TLS 证书缺失, 自动生成自签名证书...")
    _k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _n = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "doaxvv.local")])
    _now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    _cert = (x509.CertificateBuilder().subject_name(_n).issuer_name(_n)
             .public_key(_k.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(_now)
             .not_valid_after(_now + datetime.timedelta(days=3650))
             .sign(_k, hashes.SHA256()))
    with open(KEY, "wb") as _f:
        _f.write(_k.private_bytes(serialization.Encoding.PEM,
                 serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(CERT, "wb") as _f:
        _f.write(_cert.public_bytes(serialization.Encoding.PEM))

def run(port):
    _ensure_tls_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"[*] 完整单机服务器已启动: {port}")
    print(f"[*] CSV列表: {len(CSV_MAP)} 个, 已加载 {len(CSV_DATA)} 个")
    print(f"[*] 日志: {LOG}")
    httpd.serve_forever()

if __name__ == "__main__":
    if os.path.exists(LOG): os.remove(LOG)
    _load_quest_tables()   # 2026-09-12: 加载 quest 配置表 (match_point, 评级阈值)
    # 2026-11-13: 首次启动自动把每个女孩的维纳斯图板解锁到最大, 并把看板奖励写进背包。
    #   只执行一次 (bootstrap_done); 之后用 GM 面板「解锁全部 / 重置进度」控制。
    try:
        if VENUS_PANEL_ROWS and not venus_state().get("bootstrap_done"):
            print("[venus] 首次启动: 解锁全部女孩图板并发放看板奖励 ...")
            _vn_first = venus_unlock_all(grant=True)
            venus_state()["bootstrap_done"] = True
            _flush_state()
            print(f"[venus] 完成: 新增 {_vn_first} 块看板")
    except Exception as _vn_ex:
        print(f"[venus] 自动解锁失败: {_vn_ex}")
    # 2026-11-13: 亲爱度报酬一次性迁移。
    #   旧存档里 accepted_level 已推进到 339, 但客户端弹窗没有奖励列表(响应缺 affection_levelup_reward_list)。
    #   这里把"已发等级"记进 affection_granted 并把 accepted_level 归零, 让玩家重新点「全部领取」
    #   就能看到完整的奖励列表, 已发过的等级不会重复进包。
    try:
        if STATE.get("affection_accepted") and not isinstance(STATE.get("affection_granted"), dict):
            _mig_gr = {}
            for _mg_k, _mg_v in list(STATE["affection_accepted"].items()):
                _mig_gr[_mg_k] = list(range(1, int(_mg_v or 0) + 1))
            STATE["affection_granted"] = _mig_gr
            STATE["affection_accepted"] = {}
            _save_state()      # 标记 dirty
            _flush_state()     # 立即落盘, 方便核对
            print(f"[affection] 迁移完成: {len(_mig_gr)} 个女孩已发等级已记账, accepted_level 归零")
    except Exception as _mg_ex:
        print(f"[affection] 迁移失败: {_mg_ex}")

    run(443)
