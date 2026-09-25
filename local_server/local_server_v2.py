"""
local_server_v2.py — 完整本地单机服务器 (CSV版)
实现:
  1. 完整协议 + RSA握手 + AES-256-CBC加密 (B2)
  2. /v1/csv/list 返回真实 csv_file_list (zlib压缩)
  3. /production/csv/<ver>/<hash> 返回 gzip 压缩的 CSV 明文
"""
import os, json, ssl, datetime, uuid, base64, zlib, gzip, re, time, threading, socket as _sockmod
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509

from paths import OUT, CERT, KEY, LOG, GM_HTML, RSA_PUB, RSA_PRIV, TOOL, CSV_LIST_JSON, CSV_MASTER

# 鉴权凭据 (敏感: 原硬编码 Token/owner_id 已移除, 改为从环境变量读取; 见 README)
TOKEN = os.environ.get("DOAXVV_TOKEN", "")                          # 设置环境变量 DOAXVV_TOKEN 为你的鉴权 Token
OWNER_ID = int(os.environ.get("DOAXVV_OWNER_ID", "0") or "0")       # 设置环境变量 DOAXVV_OWNER_ID 为你的游戏 owner_id
SESSION_KEY = None

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

# ===== 服务器时间 (本地时间 + 时间偏移, 与客户端探针共用同一偏移) =====
# 时间偏移从 time_offset_config.json 读取 (clamp_offset.py 写入, frida 探针也读同一文件)
#   19点后 clamp_offset 写偏移(回到18:00), 服务器+客户端都偏移相同量 → 双方时间一致 → 不触发19点白屏
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
    # 09-25: 动态重读 time_offset_config (配合后台定时 clamp_offset 刷新, 服务器不用重启也跟着钳)
    _d, _h, _m, _s = _load_time_offset()
    return datetime.timedelta(days=_d, hours=_h, minutes=_m, seconds=_s)

def server_now():
    """服务器当前时间 (本地时间 + 时间偏移, 与客户端探针一致). 注: .timestamp() 已自动转 UTC epoch,
    故 X-DOAXVV-ServerTime = str(int(game_now().timestamp())) 本就是正确 UTC epoch (2026-09-25 实测:
    now().timestamp()==time.time(), utcnow().timestamp() 反而偏 -8h). 09-24「utcnow 修复时间错位」推断已被证伪."""
    return datetime.datetime.now() + time_offset_delta()

def server_now_str(fmt="%Y-%m-%d %H:%M:%S"):
    return server_now().strftime(fmt)

# ===== 游戏日 (19点日切) — 2026-09-12 19点白屏修复 =====
# 机制: 客户端以 19:00 (北京时间) 为"游戏日"分界, 19点后视为次日;
#       服务器原先用日历日(午夜翻日)判断 monthly collect, 19:00~24:00 窗口内与客户端游戏日错位一天,
#       客户端认为"月度签到未随新游戏日刷新" -> 大厅初始化序列无限循环 -> 白屏/黑屏 (铁证: 10_错误日志 序号2/3/4)
# 修复: monthly collect 比较 + POST 领取写日期 都用 game_today_str(), 与客户端游戏日对齐
# 开关: server_config.json "game_day_boundary_hour": 19 (默认=19, 修复开启); 设为 -1 则回退日历日(修复前行为)
# 注: CONFIG 在本函数定义之后才初始化(L391), 但 Python 在调用时才解析全局名, 请求处理阶段 CONFIG 已存在
def game_today_str():
    """当前"游戏日"日期字符串 (%Y-%m-%d). 边界小时(默认19,可配)之后算次日, 与客户端游戏日一致"""
    try:
        boundary = int(CONFIG.get("game_day_boundary_hour", 19))
    except (TypeError, ValueError):
        boundary = 19
    now = server_now()
    if boundary >= 0 and now.hour >= boundary:
        now = now + datetime.timedelta(days=1)
    return now.strftime("%Y-%m-%d")

def game_now():
    """raw 当前时间 (不 shift). 09-25 真修复: 之前 game_now 在 boundary 后 +1天 → X-DOAXVV-ServerTime=明天
    → 客户端 srvOff=+86400 → 19点后死循环(探针实证). 改回 raw server_now → ServerTime=今天 → srvOff=0.
    游戏日 shift 只保留在 game_today_str (签到/月度/last_logged_at), 此处不 shift."""
    return server_now()

def load_rsa():
    """加载服务器 RSA 密钥对; 若缺失则自动生成 2048 位新密钥对并落盘。
    握手机制: GET /v1/session/key 把本公钥下发给客户端, 客户端用它加密 AES 会话密钥,
    故任意新生成的密钥对均可工作, 不含任何个人/原版密钥 (原密钥已作为敏感数据移除)。"""
    if not (os.path.exists(RSA_PUB) and os.path.exists(RSA_PRIV)):
        print("[*] RSA 密钥对缺失, 自动生成新 2048 位密钥对...")
        _k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(RSA_PRIV, "wb") as _f:
            _f.write(_k.private_bytes(serialization.Encoding.PEM,
                     serialization.PrivateFormat.PKCS8,
                     serialization.NoEncryption()))
        with open(RSA_PUB, "wb") as _f:
            _f.write(_k.public_key().public_bytes(serialization.Encoding.PEM,
                     serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(RSA_PUB, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    with open(RSA_PRIV, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    pub_pem = open(RSA_PUB, "r").read()
    return pub, priv, pub_pem

PUB, PRIV, PUB_PEM = load_rsa()

def load_csv_list():
    """加载 CSV 列表; 若 real_csv_list.json 缺失则返回空映射, 降级运行 (不下发任何 CSV, 游戏无数据表)。
    CSV 列表与 csv_master 数据表为版权游戏数据, 不随仓库分发 — 自行获取后放入 TOOL 目录, 见 README。"""
    if not os.path.exists(CSV_LIST_JSON):
        print("[!] CSV 列表 (real_csv_list.json) 缺失 — 降级运行 (无 CSV 数据表, 见 README)")
        return {}, ""
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
    """检查卡池是否在有效时间范围内 — 单机版放宽: 时间钳制会导致限定池(type=3)判定过期, 单机版不限制卡池时间"""
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

def _get_gacha_config(gm=None):
    """解析扭蛋配置. 优先级(低→高): 文件默认 → STATE全局 → 文件按卡池 → STATE按卡池.
    gm=None 返回全局默认(文件+STATE合并)."""
    # 1. 全局: 文件默认 + STATE 全局 (STATE 覆盖文件)
    _cfg = dict(_GACHA_CONFIG_FILE.get("defaults", {}))
    _sc = STATE.get("gacha_config", {})
    _cfg.update(_sc.get("defaults", {}))
    # 2. 按卡池: 文件覆盖 + STATE 覆盖 (per-pool 始终优先于 global)
    if gm is not None:
        _cfg.update(_GACHA_CONFIG_FILE.get("pool_overrides", {}).get(str(gm), {}))
        _cfg.update(_sc.get("pool_overrides", {}).get(str(gm), {}))
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
    return _cfg

def _random_gacha_items(gm, count, step=1):
    """从 (gacha_mid, step) 卡池按配置爆率+保底逻辑随机选 count 个 item_mid.
    保底: 硬保底(N抽必出SSR) + 软保底(接近N抽SSR权重递增). per-pool 计数持久化到 STATE."""
    pool = _get_gacha_pool(gm, step)
    cfg = _get_gacha_config(gm)
    import random as _grand

    # 无奖池数据 → 回退常驻池
    if not any(pool[r] for r in ("SSR", "SR", "R")):
        _items = _GACHA_RANDOM_POOL["items"]
        _weights = _GACHA_RANDOM_POOL["weights"]
        return _grand.choices(_items, weights=_weights, k=count)

    # 保底状态 (per-pool)
    _pity = STATE.setdefault("gacha_pity", {})
    _pk = str(gm)
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
              "owner_id": OWNER_ID, "chip_normal": 0, "chip_gold": 0,
              "limit_chip_gold": 0, "gold_chip_mid": 73, "dealer_chip_count": 0,
              "created_at": "2021-04-04 03:07:30", "updated_at": "2026-09-13 11:17:53"},
          "casino_game": [   # 2026-09-14: 赌场统计 (像私服版, 初始真实值; 赌场play时play_count++/win_count++)
              {"game": 2, "play_count": 0, "win_count_total": 0, "win_count_series": 0, "win_count_series_max": 0},
              {"game": 1, "play_count": 0, "win_count_total": 0, "win_count_series": 0, "win_count_series_max": 0}],
          # 2026-09-15: 温泉/送礼/岛主房间工作 动态持久化 (抓包私服版确认的端点+请求体)
          "onsen": {                       # 温泉: 槽位女孩/领奖计数/gauge/品质/女孩经验
              "slots": [{"slot_id": 0, "girl_mid": 15}, {"slot_id": 1, "girl_mid": 16},
                        {"slot_id": 2, "girl_mid": 4}, {"slot_id": 3, "girl_mid": 3}],
              "reward_count": 0, "gauge": 0, "quality_mid": 1, "girl_exp": {}},
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
    return st

_STATE_DIRTY = False  # IO优化: 去抖标记, _save_state 只设dirty, 后台线程定时写盘

def _save_state():
    """标记 dirty, 后台线程定时写盘 (去抖: 44个调用点不再每次fsync 500KB, 大幅减少IO卡顿)"""
    global _STATE_DIRTY
    _STATE_DIRTY = True

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

# 2026-09-13: 归一化 item_counts key 为整数 (JSON 加载后 key 变字符串, 导致 int 查找失败)
_ic_raw = STATE.get("item_counts", {})
if _ic_raw:
    STATE["item_counts"] = {int(k): v for k, v in _ic_raw.items()}

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
else:
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
    return girl_obj

# 2026-09-11 性能优化: 装备归属映射缓存 (REAL_RESPONSES 启动后不变, 只构建一次, 供所有女孩/请求复用)
_EQUIP_OWNER_CACHE = None

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

def girl_obj_from_db(mid):
    """从 /v1/girl 响应池找某女孩的完整对象 (46字段), 找不到返回None"""
    eps = SERVER_DB.get("endpoints", {})
    for resp in eps.get("/v1/girl", []):
        for g in resp.get("girl_list", []):
            if g.get("girl_mid") == mid:
                return dict(g)
    # 兜底: main_girl 池
    pool = SERVER_DB.get("main_girl_by_mid", {})
    if str(mid) in pool:
        return dict(pool[str(mid)].get("girl", {}))
    return None

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

def _pick_rotate(pool, key):
    """从响应池轮换取一个, 返回 (resp, 是否成功)"""
    if not pool:
        return None, False
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

        not_accept = []
        history = []
        item_consume = []
        now_ts = "2026-09-06 09:00:00"
        wallet = STATE.setdefault("wallet", {})
        item_counts = STATE.setdefault("item_counts", {})
        for mid in accept_ids:
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
            # else: 特殊物品 (不在 Consume_Parameter, 如装备/泳装) → 两边都不加
        _save_state()

        # 钱包: 返回当前 STATE 钱包 (而非静态模板)
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

def _apply_state_overlay(path, method=None):
    """状态叠加: /v1/owner /v1/room /v1/girl 注入当前主女孩和装备状态。
    返回响应或 None(不处理)。
    2026-09-13: 增加 method 参数, 让 favorite 等 POST 端点放行给 _build_dynamic 处理"""
    # /v1/owner 返回当前主女孩
    if path == "/v1/owner" or path == "/v1/owner/updatelogin":
        # 2026-09-11 修复: 浅拷贝会改原始 REAL_RESPONSES, 改用 deepcopy
        import copy as _copy_own
        base = _copy_own.deepcopy(REAL_RESPONSES.get(path, {"owner": {}}))
        owner = base.get("owner", {})
        if isinstance(owner, dict):
            owner["main_girl_mid"] = STATE.get("main_girl_mid", 3)
        elif isinstance(owner, list):
            for o in owner:
                o["main_girl_mid"] = STATE.get("main_girl_mid", 3)
        # owner_list 型 (updatelogin 的真实结构, 实测): 逐个注入 STATE 主女孩
        # 2026-09-10 修复: 此前只处理 owner, 漏 owner_list → 返回原始 main=3 → 客户端进岛回退穗香
        olist = base.get("owner_list")
        if isinstance(olist, list):
            for o in olist:
                if isinstance(o, dict):
                    o["main_girl_mid"] = STATE.get("main_girl_mid", 3)
        # 2026-09-25: 动态把 last_logged_at 改成"游戏日今天" — 静态 last_logged_at(2026-09-02)
        # 超过 RECENT_DAYS 窗口时不会被 normalize_dates 刷新→游戏"距上次登录>阈值"走未实现的
        # 跨日回归分支→卡死。这里强制写今天, 与 normalize_dates 的 today 同源(game_today_str + now),
        # 下限不再依赖 RECENT_DAYS, 任取值都不卡(只要 < 上限 created_at 年龄~2730天)。
        _ll_today = game_today_str() + " " + server_now().strftime("%H:%M:%S")
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
        def _patch(obj):
            if isinstance(obj, dict):
                if "owner_room" in obj and isinstance(obj["owner_room"], dict):
                    obj["owner_room"]["main_girl_mid"] = STATE.get("main_girl_mid", 3)
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
        _existing_gmids = {g.get("girl_mid") for g in resp.get("girl_list", [])}
        for _ugm in sorted(GIRL_MASTER_MAP):
            if _ugm not in _existing_gmids:
                _gmm = GIRL_MASTER_MAP[_ugm]
                _tmpl = _copy.deepcopy(resp["girl_list"][0]) if resp.get("girl_list") else {"owner_id": OWNER_ID}
                _tmpl["girl_mid"] = _ugm
                _tmpl["power"] = _gmm.get("power", 1000)
                _tmpl["technic"] = _gmm.get("technic", 800)
                _tmpl["stamina"] = _gmm.get("stamina", 1000)
                _tmpl["appeal"] = _gmm.get("appeal", 20)
                _tmpl["swimsuit_item_mid"] = _gmm.get("swimsuit", 0)
                _tmpl["hair_item_mid"] = _gmm.get("hair", 0)
                _tmpl["experience"] = 0
                _tmpl["level"] = 1
                _tmpl["affection_level"] = 1
                _tmpl["created_at"] = "2023-05-24 06:02:14"
                _tmpl["updated_at"] = "2023-05-24 06:02:14"
                apply_girl_state(_tmpl)
                resp.setdefault("girl_list", []).append(_tmpl)
        return resp
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
        return base
    # /v1/item/equipment/type/*: 从 STATE 装备库返回 (2026-09-14: 不再合并 REAL_RESPONSES, STATE 是唯一数据源)
    if path.startswith("/v1/item/equipment/type/"):
        _m = re.match(r"^/v1/item/equipment/type/(\d+)$", path)
        _etype = int(_m.group(1)) if _m else 0
        _lst = []
        for _e in STATE.get("equipment_inventory", []):
            if isinstance(_e, dict) and (_etype == 0 or _e.get("type", 0) == _etype):
                _lst.append(_e)
        return {"item_equipment_list": _lst}
    # /v1/fes_deck/equipment_list: 挑战赛卡组装备 (2026-09-14: 从 girl_equipment 构建 deck 格式)
    # 结构: [{deck_position, swimsuit_equipment_item_id, accessory_head/face/arm_equipment_item_id, main/sub1/sub2_seal_id}]
    if path == "/v1/fes_deck/equipment_list":
        _ge = REAL_RESPONSES.get("/v1/girl/equipment", {})
        _gel = _ge.get("girl_equipment_list", []) if isinstance(_ge, dict) else []
        _main_girl = STATE.get("main_girl_mid", 3)
        # STATE 中保存的装备覆盖静态数据 (POST /v1/girl/{mid}/equipment 保存的)
        _state_ge = STATE.get("girl_equipment", {})
        # 找主女孩和第二女孩的装备配置
        _deck = []
        _positions = [(_main_girl, 1)]
        for _g in _gel:
            _gm = _g.get("girl_mid")
            if _gm and _gm != _main_girl:
                _positions.append((_gm, 2))
                break
        for _gm, _pos in _positions:
            _eq = {}
            for _g in _gel:
                if _g.get("girl_mid") == _gm:
                    _eq = dict(_g)
                    break
            # STATE 覆盖: 用 girl_equipment 中保存的装备 ID 覆盖静态值
            _sg = _state_ge.get(str(_gm), {})
            if _sg:
                for _fld in ("swimsuit_equipment_item_id", "accessory_head_equipment_item_id",
                             "accessory_face_equipment_item_id", "accessory_arm_equipment_item_id",
                             "hair_equipment_item_id", "ring_equipment_item_id",
                             "addition_accessory_equipment_item_id"):
                    if _fld in _sg:
                        _eq[_fld] = _sg[_fld]
            _entry = {
                "deck_position": _pos,
                "swimsuit_equipment_item_id": _eq.get("swimsuit_equipment_item_id", 0),
                "accessory_head_equipment_item_id": _eq.get("accessory_head_equipment_item_id", 0),
                "accessory_face_equipment_item_id": _eq.get("accessory_face_equipment_item_id", 0),
                "accessory_arm_equipment_item_id": _eq.get("accessory_arm_equipment_item_id", 0),
                "main_seal_id": 0,
                "sub1_seal_id": 0,
                "sub2_seal_id": 0,
            }
            _deck.append(_entry)
        return {"fes_deck_girl_equipment_list": _deck}
    # /v1/pvp_fes_deck/equipment_list_all: PvP 装备 (3 位置: forward/back/sub)
    if path == "/v1/pvp_fes_deck/equipment_list_all":
        _ge2 = REAL_RESPONSES.get("/v1/girl/equipment", {})
        _gel2 = _ge2.get("girl_equipment_list", []) if isinstance(_ge2, dict) else []
        _main_girl2 = STATE.get("main_girl_mid", 3)
        _pvp_deck = []
        _pvp_positions = [(_main_girl2, 1)]
        _count = 0
        for _g in _gel2:
            _gm = _g.get("girl_mid")
            if _gm and _gm != _main_girl2:
                _pvp_positions.append((_gm, _count + 2))
                _count += 1
                if _count >= 2:
                    break
        for _gm, _pos in _pvp_positions:
            _eq2 = {}
            for _g in _gel2:
                if _g.get("girl_mid") == _gm:
                    _eq2 = _g
                    break
            _pvp_deck.append({
                "deck_position": _pos,
                "swimsuit_equipment_item_id": _eq2.get("swimsuit_equipment_item_id", 0),
                "accessory_head_equipment_item_id": _eq2.get("accessory_head_equipment_item_id", 0),
                "accessory_face_equipment_item_id": _eq2.get("accessory_face_equipment_item_id", 0),
                "accessory_arm_equipment_item_id": _eq2.get("accessory_arm_equipment_item_id", 0),
                "main_seal_id": 0,
                "sub1_seal_id": 0,
                "sub2_seal_id": 0,
            })
        return {"pvp_fes_deck_girl_equipment_full_list": _pvp_deck}
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
def _process_shop_exchange(pmid, count, mgm, inv, spi, pi_keys, ic):
    _details = SHOP_DETAIL_MAP.get(pmid, [])
    if not _details:
        return None
    _iel, _otl, _icl, _pcl, _pil = [], [], [], [], []
    _base_id = (int(datetime.datetime.now().timestamp() * 1000) % 1000000000) + 4000000000
    for _i, (_did, _cnt) in enumerate(_details):
        _etype = EQUIP_TYPE_MAP.get(_did, 1)
        _real_cnt = int(_cnt) * int(count)
        if _etype in (0, 1, 11, 22, 23, 24, 56, 82):
            # 装备类: 入装备库(去重) + private_item + order_ticket
            _eid = _base_id + _i
            _ie = {"id": _eid, "item_mid": _did, "type": _etype, "level": 1, "experience": 0,
                   "girl_mid": 0, "favorite": 0, "in_lock": 1, "unlock_count": 0,
                   "upgrade_count": 0, "combine_count": 0}
            _iel.append(_ie)
            # 2026-09-15 去重: 同 item_mid 的装备实例只保留一份 (避免重复播种/重复购买导致归属冲突崩溃 0x2CE79C9)
            _inv_has = any(isinstance(_e2, dict) and _e2.get("item_mid") == _did for _e2 in inv)
            if not _inv_has:
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
            ic[str(_did)] = ic.get(str(_did), 0) + _real_cnt
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
        return {"owner_room": dict(oroom)}
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
            STATE["owner_room"] = {"owner_id": OWNER_ID, "main_girl_mid": gm1,
                                  "sub_girl_mid": gm2 if gm2 is not None else 15, "set_no": 0}
            STATE["main_girl_mid"] = gm1
            _save_state()
        else:
            log_write(f"  [ROOM-GIRLS] gm1=None, 跳过写入(防污染), 当前 owner_room={STATE.get('owner_room')}\n")
        _or = STATE.get("owner_room") or {"owner_id": OWNER_ID, "main_girl_mid": STATE.get("main_girl_mid", 3), "sub_girl_mid": 15, "set_no": 0}
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
        lvl_gain = 1 if found["value"] >= 100 else 0; found["level"] = found.get("level", 1) + lvl_gain
        _save_state()
        return {"wallet": STATE.get("wallet", {}), "item_equipment_list": [], "item_consume_list": [],
                "custom_room_request_list": [],
                "custom_room_request_result": {"clear_rank": clear_rank, "trend_status": 0,
                    "friendly_progress": {"friendly_gain": 25, "friendly_before": fb, "friendly_after": fb + 25,
                        "level_gain": lvl_gain, "level_before": 1, "level_after": 1},
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
    """特殊订单兑换(送泳装进私人套装): 请求{is_checked_at}, item_mid=3574固定(capture 5次确认), girl=main_girl, 扣兑换券(初始7)+进private_items"""
    if path != "/v1/special_order/exchange" or method != "POST":
        return None
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

    # ---- 2026-09-14: bar/bell 酒吧摇铃 (消耗item_mid×count, 更新库存/bell_at/wallet; 奖励用模板) ----
    if path == "/v1/bar/bell" and method == "POST":
        _pool = eps.get(path, [])
        import copy as _bb_cp
        _base, _ = _pick_rotate(_pool, path) if _pool else ({}, True)
        _r = _bb_cp.deepcopy(_base) if _base else {}
        _count = req.get("count", 1)
        _im = req.get("item_mid")
        if _im is not None:
            _ic = STATE.setdefault("item_counts", {})
            _ic[_im] = max(0, _ic.get(_im, 0) - _count)
            for _ic_l in _r.get("item_consume_list", []):
                if _ic_l.get("item_mid") == _im:
                    _ic_l["count"] = _ic[_im]
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
            _cnt = int(_item.get("count", 1))
            if not _pmid:
                continue
            _result = _process_shop_exchange(_pmid, _cnt, _mgm, _inv, _spi, _pi_keys, _ic)
            if _result is None:
                continue
            _iel, _otl, _icl, _pcl, _pil, _spl_entry = _result
            _iel_all.extend(_iel)
            _otl_all.extend(_otl)
            _icl_all.extend(_icl)
            _pcl_all.extend(_pcl)
            _pil_all.extend(_pil)
            _spl_all.append(_spl_entry)
            _sp[str(_pmid)] = _sp.get(str(_pmid), 0) + 1
        _save_state()
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
            return None  # 未知商品交给上层
        _iel, _otl, _icl, _pcl, _pil, _spl_entry = _result
        _sp[str(_pmid)] = _sp.get(str(_pmid), 0) + 1
        _save_state()
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

    # ---- 切换主女孩: 从 /v1/girl 数据构造任意女孩响应, 并保存状态 ----
    if path == "/v1/owner/main_girl":
        mid = req.get("main_girl_mid")
        if mid is None:
            return None
        girl = girl_obj_from_db(int(mid))
        if girl is None:
            # 兜底: 用池里最近的一个响应改 girl_mid
            pool = SERVER_DB.get("main_girl_by_mid", {})
            if pool:
                girl = dict(list(pool.values())[0].get("girl", {}))
                girl["girl_mid"] = int(mid)
            else:
                return None
        # 叠加已保存的装备状态 + 更新主女孩
        apply_girl_state(girl)
        STATE["main_girl_mid"] = int(mid)
        _save_state()
        # 构造完整响应 (girl + owner_partner_list + girl_list 结构)
        partner = {"owner_id": OWNER_ID, "main_girl_mid": int(mid), "lend_girl_mid": 21,
                   "updated_at": server_now_str()}
        return {"girl": girl, "owner_partner_list": [partner], "girl_list": [girl]}

    # ---- 换装 (girl/{mid}/equipment): 记录状态并回显请求的装备ID ----
    # 2026-09-10 修复: 仅 POST 才写 STATE(换装动作), GET(读取)不写; 且过滤 0 值, 防止污染覆盖已存装备
    m_eq = re.match(r"^/v1/girl/(\d+)/equipment$", path)
    if m_eq:
        gm = m_eq.group(1)
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
        _draw_step = STATE.get("gacha_pity", {}).get(str(_gm_draw), {}).get("current_step", 1) if _gm_draw else 1
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
                _ic = STATE.setdefault("item_counts", {})
                _cur = _ic.get(_consume_im, 0)
                _ic[_consume_im] = max(0, _cur - dc)
                print(f"[gacha/draw] gacha_mid={_gm} 扣券 item_mid={_consume_im} -{dc} (剩 {_ic[_consume_im]})")
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
                _rw_step = STATE.get("gacha_pity", {}).get(str(_gm_rw), {}).get("current_step", 1)
                _rw_pool = _get_gacha_pool(_gm_rw, _rw_step)
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
                    _ic[_im] = _ic.get(_im, 0) + 1
                    icl.append({"item_mid": _im, "count": _ic[_im], "type": _ctype,
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
        # 2026-09-13: 挑战赛换女孩动态化 — team0 玩家方 girl_list 按 req 的 forward/back 改写 girl_mid+泳装
        # 之前: resp 是静态抓包数据, girl_mid 是抓包时的女孩(如15), 不反映用户选择 → 进比赛不是选的女孩
        import copy as _qs_c2
        resp = _qs_c2.deepcopy(resp)
        _qs_r2 = resp.get("quest_start", {}).get("result")
        if isinstance(_qs_r2, dict) and isinstance(_qs_r2.get("girl_list"), list):
            _fwd2 = req.get("girl_mid_forward")
            _bk2 = req.get("girl_mid_back")
            _pos_mid = {0: _fwd2, 1: _bk2}
            for _g2 in _qs_r2["girl_list"]:
                if _g2.get("team") != 0:
                    continue
                _nm2 = _pos_mid.get(_g2.get("position"))
                if _nm2:
                    _g2["girl_mid"] = _nm2
                    # 同步泳装: 从 STATE.girl_equipment 取该女孩当前泳装, 覆盖 equipment_list 的 type1
                    _ge2 = STATE.get("girl_equipment", {}).get(str(_nm2), {})
                    _sw2 = _ge2.get("swimsuit_item_mid")
                    if _sw2:
                        _el2 = _g2.get("equipment_list")
                        if isinstance(_el2, list):
                            for _e2 in _el2:
                                if isinstance(_e2, dict) and _e2.get("type") == 1:
                                    _e2["item_mid"] = _sw2
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
        qe = resp.get("quest_end", {})
        # 2026-09-12 debug: 确认 mid_substitution 是否生效
        print(f"[QUEST-END-DBG] req_mid={mid_sub} fallback_mid={mid} idx={idx} resp_mid={qe.get('quest_mid')} phase={qe.get('phase')} cont={qe.get('is_continue')}", flush=True)
        if qe.get("is_continue") is False or qe.get("phase") == 5:
            _set_quest_end_idx(mid, 0)
            # 2026-09-12: 记录通关状态 (用于 quest/list 叠加 quest_clear)
            _qm_end = qe.get("quest_mid")
            _now_str = server_now().strftime("%Y-%m-%d %H:%M:%S")
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
                    _today = server_now().strftime("%Y-%m-%d")
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
            _today = server_now().strftime("%Y-%m-%d")
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
            if _vis is not None:
                _vis_set = {int(v) for v in _vis}
                resp["gacha_info_list"] = [g for g in resp.get("gacha_info_list", []) if g.get("gacha_mid") in _vis_set]
            return resp
        return resp if ok else None

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
        now = server_now()
        # 2026-09-12 19点白屏修复: 归一化的"今天"用游戏日(19点后进位次日, game_today_str),
        # 与客户端游戏日对齐 — 否则19点后服务器写日历今天、客户端游戏日=次日, 日期错位→大厅初始化循环.
        # 只改替换目标日期; cutoff/window 仍用日历 now 判断"哪些日期在14天内"(不变).
        # 开关: server_config game_day_boundary_hour=-1 时 game_today_str() 回退日历日(=修复前行为)
        today_d = game_today_str()
        today = today_d + " " + now.strftime("%H:%M:%S")
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
        # 纯日期 (YYYY-MM-DD, 不带时间; 避免误匹配时间戳已被替换的部分)
        txt = re.sub(r'(?<!\d)\d{4}-\d{2}-\d{2}(?![\d\-])', repl_date, txt)
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
                STATE["main_girl_mid"] = int(req["main_girl_mid"])
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
                ic[mid] = count
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
                STATE["giftbox_claimed"] = []
            elif mod == "login_bonus":
                STATE["monthly_claimed"] = {}
                STATE.pop("daily_quest_date", None)
                STATE.pop("daily_quest_count", None)
            elif mod == "information":
                STATE["read_information"] = []
            elif mod == "all":
                STATE["giftbox_claimed"] = []
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
            import time as _time
            cm = STATE.setdefault("custom_mails", [])
            _next_id = 900000001 + len(cm)
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
                "expired_at": (game_now().replace(year=game_now().year + 1)).strftime("%Y-%m-%d %H:%M:%S"),
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
                        "step_cap_behavior", "max_step_bonus", "ssr_auto_lock"):
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
            _pity = STATE.get("gacha_pity", {}).get(str(_gm_q), {})
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
            _pool_info = GACHA_INFO_MAP.get(_gm_q, {})
            resp = {
                "gacha_mid": _gm_q, "max_step": _max_step,
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
            if _gm_r:
                _pk = str(_gm_r)
                _pity[_pk] = {"draws_since_ssr": 0, "total_draws": 0, "current_step": 1}
                resp = {"ok": True, "reset": str(_gm_r)}
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
                                   "visible": True if _vis_set is None else (int(_gm_v) in _vis_set)})
                resp = {"visible_pools": _vis, "pools": _pools}
            else:
                if req.get("action") == "reset":
                    STATE["gacha_visible_pools"] = None
                else:
                    STATE["gacha_visible_pools"] = req.get("visible_pools")
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
                _ic = STATE.setdefault("item_counts", {})
                _ic[_im] = _ic.get(_im, 0) + _cnt
                _save_state()
                resp = {"ok": True, "item_mid": _im, "count": _ic[_im]}
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
            import copy as _shop_cp
            _shop_base = REAL_RESPONSES.get("/v1/shop/list", {})
            _shop_pl = _shop_cp.deepcopy(_shop_base.get("shop_purchase_list", []))
            _shop_pur = STATE.get("shop_purchased", {})
            if _shop_pur:
                _shop_idx = {int(_e.get("product_mid", 0)): _e for _e in _shop_pl}
                for _pmid, _cnt in _shop_pur.items():
                    _pmid_i = int(_pmid)
                    if _pmid_i in _shop_idx:
                        _shop_idx[_pmid_i]["total_count"] = _shop_idx[_pmid_i].get("total_count", 0) + int(_cnt)
                        _shop_idx[_pmid_i]["updated_at"] = server_now_str()
                    else:
                        _shop_pl.append({
                            "owner_id": OWNER_ID, "product_mid": _pmid_i, "limit_count": 1,
                            "total_count": int(_cnt), "created_at": server_now_str(), "updated_at": None
                        })
            return {"shop_purchase_list": _shop_pl}
        # 特殊处理: special_order/37 的 pose card 物品在 PosecardShopItemList.csv 缺失, 返回空避免崩溃
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
                for item in base_ic.get("item_consume_list", []):
                    mid = item.get("item_mid")
                    if mid is not None and mid in ic:
                        item["count"] = ic[mid]
                return base_ic
        # ---- 任务全部标记完成 (2026-09-07 复活版): 让"新任岛主应援"看板任务面板关闭 ----
        # 原理: 客户端读 mission_list 的 progress 判断任务状态, progress=3 视为完成
        # 目标: "新任岛主应援"任务(13447/13449/13450/18028/18034) 全部 progress=3 → 面板关闭
        # 副作用: 日常/每周任务也被标记完成 (用户暂接受)
        if path.startswith("/v1/mission") and method in ("GET", "POST"):
            import copy as _cp_mission
            dyn = _build_dynamic(path, req, method)
            if dyn is not None and isinstance(dyn, dict):
                ml = dyn.get("mission_list")
                if isinstance(ml, list):
                    resp2 = _cp_mission.deepcopy(dyn)
                    for t in resp2.get("mission_list", []):
                        if isinstance(t, dict):
                            t["progress"] = 3  # 全部标记完成
                    return resp2
                return dyn
            if path in REAL_RESPONSES:
                base = _cp_mission.deepcopy(REAL_RESPONSES[path])
                ml = base.get("mission_list")
                if isinstance(ml, list):
                    for t in ml:
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
                # PUT /v1/swimsuit_arrange_flag/<girl_mid> 切换开关 — 单机强制 switch=1 始终开启
                _gm_put = 0
                try:
                    _gm_put = int(_sp[2])
                except Exception:
                    pass
                return {"swimsuit_arrage_flag": {"owner_id": OWNER_ID, "girl_mid": _gm_put, "variation": 2,
                        "switch": 1, "created_at": "2026-09-16 00:00:00", "updated_at": "2026-09-16 00:00:00"}}
            # GET /v1/swimsuit_arrange_flag — 私服版返回空(抓包铁证); 滑落由 visual_state_flag_b 控制, 不靠 arrange_flag
            # (原 switch=1+variation=2 是无效值, 会让打扮里滑落按钮变灰; 私服版空列表+按钮可点)
            return {"swimsuit_arrage_flag_list": []}
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
        ov = _apply_state_overlay(path, method)
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
    客户端经 hosts 劫持连本机, 不校验证书, 故自签名即可 (原用户证书已作为敏感数据移除)。"""
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
    run(443)
