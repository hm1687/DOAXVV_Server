# DOAXVV_Server — 死或生:维纳斯假期 本地模拟服务器

一个用 Python 实现的 **DOAXVV（Dead or Alive Xtreme Venus Vacation）本地单机模拟服务器**。
通过 hosts 劫持 + 自签证书 + Frida 探针，把游戏的 HTTPS 流量导向本机服务器，从而实现
**单机离线游玩、跳过签到弹窗、自定义扭蛋爆率/保底、GM 控制面板发奖** 等功能。

> ⚠️ **本项目仅供学习与协议研究。** 游戏客户端、CSV 数据表、二进制资源等版权内容归
> Koei Tecmo / 光荣特库摩 所有，**不包含在本仓库中**。请仅在本地对自己合法持有的游戏副本使用。

---

## 一、工作原理

```
游戏客户端 (DOAX_VV.exe)
   │  HTTPS (api.doaxvv.com / game.doaxvv.com / api01.doaxvv.com)
   │  hosts 劫持 → 127.0.0.1
   ▼
本地服务器 (local_server_v2.py, 监听 :443)
   │  1. RSA 握手: GET /v1/session/key 下发服务器公钥 → 客户端用它加密 AES 会话密钥
   │  2. AES-256-CBC 加密信封: 解密请求 / 加密响应
   │  3. /v1/csv/list (zlib) + /production/csv/<hash> (gzip) 下发数据表
   │  4. 14+ 动态端点: 扭蛋/装备/挑战赛/邮箱/商店/温泉/岛主房间… 优先级链响应
   │  5. 资源回源: 命中本地缓存则直发, 未命中经 VPN IP 探测回源官方并缓存
   ▼
GM 面板 (gm_panel.html) / 系统托盘 (tray_app.py)
```

**响应优先级链**（自上而下首个命中即返回）：
特殊硬编码 → information → login_bonus → giftbox → wallet → item/consume →
mission → friendship → `_apply_state_overlay`(STATE 叠加) → `_build_dynamic`(动态引擎) →
REAL_RESPONSES → 兜底 `{status:success}`。

---

## 二、目录结构（清理后）

```
DOAXVV_Server/
├── local_server/
│   ├── local_server_v2.py   # 主服务器 (4500+ 行): 加密/CSV/动态响应/资源代理/GM
│   ├── paths.py             # 路径常量
│   ├── logutil.py           # 日志缓冲写入
│   └── time_offset_config.json  # 时间偏移配置 (客户端探针+服务器共用)
├── GM/
│   └── gm_panel.html        # GM 控制面板
├── probe_smart_clamp.js     # Frida 智能时间钳制探针 (hook 客户端时间 API, 防跨日白屏)
├── clamp_offset.py          # 时间钳制偏移计算
├── attach_wait_forever.py   # 等待游戏进程并挂载探针
├── tray_app.py              # 系统托盘应用 (后台跑服务器+hosts, 右键菜单)
├── tray_dialogs.py          # 托盘弹窗 (状态/日志)
├── stop_all.py              # 一键关闭 (服务器+托盘+探针+hosts)
├── hosts_switch.ps1         # hosts 劫持/还原 (on/off/status)
├── server_config.json       # 服务器功能开关 (跳过签到/游戏日日切)
├── clamp_config.json        # 时间钳制配置
├── gacha_config.json        # 扭蛋爆率/保底配置
├── information_global.json  # 公告配置 (公开游戏页面 URL, 非敏感)
├── 一键启动.vbs / 一键启动.bat      # 启动托盘 (pythonw, 无窗口)
├── 一键关闭.vbs / 一键关闭.bat      # 关闭全部
├── 启动服务器.bat / 关闭服务器.bat   # 纯服务器启停
├── 开启单机版.bat / 关闭单机版.bat   # hosts 劫持开关
└── 查看hosts状态.bat
```

---

## 三、已删除的敏感数据（上传 GitHub 前清理记录）

为确保公开仓库不含任何个人/密钥/版权数据，以下内容已从仓库中删除。**它们不会随仓库分发**，
首次运行时由服务器自动生成，或需你自行获取后放入（见第四节）。

### 1. 密钥与证书（私钥，最高敏感级）— 已删除，改为首次启动自动生成

| 已删除文件 | 说明 | 现处理方式 |
|---|---|---|
| `local_server/rsa_server_priv.pem` | RSA 握手私钥 | 首次启动 `load_rsa()` 自动生成 2048 位新密钥对 |
| `local_server/rsa_server_pub.pem` | RSA 握手公钥 | 同上（握手把公钥下发给客户端，任意新密钥对均可工作） |
| `local_server/doaxvv_key.pem` | TLS 私钥 | 首次启动 `_ensure_tls_cert()` 自动生成自签名证书 |
| `local_server/doaxvv_cert.pem` | 自签名 TLS 证书 | 同上 |

> 嵌套重复副本 `local_server/local_server/`（含上述密钥的旧拷贝）整目录已删除。

### 2. 玩家个人存档 / 账号数据 — 已删除

| 已删除文件 | 敏感内容 |
|---|---|
| `server_state.json`（约 12.7MB） | 完整玩家存档：钱包余额、装备库、抽卡进度、女孩好感度、赌场筹码等 |
| `server_response_db.json`（约 22.7MB） | 抓取的全量动态响应数据库（含个人账号数据） |
| `real_responses.json` | 抓取的真实业务响应快照 |
| `login_bonus_first.json` | 含 `owner_id` + 签到历史 |
| `login_bonus_reward.json` | 含 `owner_id` + 钱包 |
| `login_bonus_reward_full.json` | 含 `owner_id` + 钱包 + 赌场筹码 + 背包 |
| `login_bonus_monthly_reward.json` | 含 `owner_id` + 月度奖励 + 钱包 |
| `login_bonus_after.json` | 抓包响应（空结构） |

### 3. 抓包 / 真实响应数据（版权 + 个人）— 已删除

| 已删除文件 | 说明 |
|---|---|
| `real_csvlist.bin` / `real_csv_list.json` | 官方服务器 CSV 列表及内容哈希 |
| `local_server/resource_list_real.json` | 官方资源清单 |
| `local_server/baseline_working.jsonl` 及 `baseline_*.jsonl` | 回归基线抓包流量 |

### 4. 运营 / 日志数据 — 已删除

| 已删除项 | 说明 |
|---|---|
| `vpn_ip.txt` | VPN IP 列表及成功率统计（个人运营数据） |
| `hosts_backup/` | hosts 文件历史备份 |
| `frida_logs/` | 探针 attach 日志（16 个） |
| `local_server/full_server.log` 等所有 `*.log` | 服务器运行日志 |
| `local_server/stdout*.txt` / `stderr*.txt` | 标准输出/错误重定向 |

### 5. 版权游戏数据 — 已删除（需自行获取）

| 已删除项 | 说明 |
|---|---|
| `csv_master/`（194 个 CSV，约 30–40MB） | 游戏数据表（装备/扭蛋/挑战赛/剧情等），版权内容 |
| `resources/`（451 个二进制文件） | 游戏资源补丁缓存（首次运行从回源自动重建） |

### 6. 代码内硬编码敏感常量 — 已脱敏

| 位置 | 原值 | 现处理 |
|---|---|---|
| `local_server_v2.py` `TOKEN` | 硬编码鉴权 Token `b3f165…` | 改为读环境变量 `DOAXVV_TOKEN`（默认空） |
| `local_server_v2.py` `OWNER_ID` | 硬编码 `60502`（个人账号 ID） | 改为读环境变量 `DOAXVV_OWNER_ID`（默认 0） |
| `DEFAULT_STATE` 模板 | `owner_id: 60502`、赌场筹码 7220/148、赌场战绩 176/73、温泉奖励计数 91 等个人值 | `owner_id` 改用 `OWNER_ID`，其余个人数值归零 |

### 7. 构建产物与重复目录 — 已删除

- `__pycache__/`、`local_server/__pycache__/`（字节码缓存）
- 嵌套重复目录 `csv_master/csv_master/`、`resources/resources/`、`GM/GM/`、`local_server/local_server/`

> 清理后全仓库已通过敏感模式扫描（账号 ID / Token / `BEGIN PRIVATE KEY` / 钱包余额等），**零残留**；
> `local_server_v2.py` 通过 `py_compile` 语法校验。`.gitignore` 已配置，防止上述运行时数据再次入库。

---

## 四、运行前的准备

### 1. 安装依赖

```powershell
# Python 3.10+ (项目用 3.12 开发)
pip install cryptography frida pystray Pillow
```

### 2. 设置鉴权凭据（环境变量）

服务器启动时会读取以下环境变量（取代原硬编码值）：

```powershell
# PowerShell（当前会话）
$env:DOAXVV_TOKEN      = "你的鉴权Token"     # 原 TOKEN
$env:DOAXVV_OWNER_ID   = "你的owner_id"      # 原 OWNER_ID (整数)
```

> 想永久生效，可在系统环境变量里设置，或写入 `启动服务器.bat` 的 `set` 行。

### 3. 密钥 / 证书 — 无需手动操作

首次启动服务器时，`load_rsa()` 与 `_ensure_tls_cert()` 会自动生成：
- `local_server/rsa_server_pub.pem` / `rsa_server_priv.pem`（RSA 2048）
- `local_server/doaxvv_cert.pem` / `doaxvv_key.pem`（自签名 TLS，10 年有效）

这些是新生成的随机密钥，不含任何原版/个人数据，已被 `.gitignore` 忽略。

### 4. 游戏数据（可选，但完整运行需要）

仓库**不包含**版权游戏数据。若要完整运行（下发数据表、扭蛋、挑战赛等），需自行从你的
游戏副本抓取/提取并放入：

| 数据 | 放置位置 | 作用 |
|---|---|---|
| CSV 数据表（194 个） | `csv_master/` | `/production/csv/<hash>` 下发、`_load_quest_tables` 评级 |
| CSV 列表（文件名→哈希） | `real_csv_list.json` | `/v1/csv/list` 下发清单 |
| 资源缓存 | `resources/`（首次运行自动从回源重建） | 二进制资源分发 |

> **未放入数据时服务器仍可启动**（降级模式：`load_csv_list` 返回空映射，各加载器检测到文件
> 缺失即跳过并使用默认值），但游戏内无数据表，部分功能不可用。

---

## 五、启动与关闭

| 方式 | 操作 |
|---|---|
| **一键启动（推荐）** | 双击 `一键启动.vbs`（或 `.bat`）→ 托盘程序后台拉起服务器 + hosts 劫持，无控制台窗口 |
| **纯服务器** | 双击 `启动服务器.bat`（仅服务器，不带探针/托盘） |
| **查看状态** | 托盘右键 → 状态 / 日志；或双击 `查看hosts状态.bat` |
| **GM 面板** | 托盘右键 → 打开控制台；服务器运行时访问 GM 面板 |
| **一键关闭** | 双击 `一键关闭.vbs`（或 `.bat`）→ 关服务器 + 托盘 + 探针 + 还原 hosts |

> hosts 劫持需管理员权限，首次会弹 UAC。`hosts_switch.ps1` 会把
> `api.doaxvv.com / game.doaxvv.com / api01.doaxvv.com` 指向 `127.0.0.1`。

---

## 六、核心配置文件

| 文件 | 作用 |
|---|---|
| `server_config.json` | `skip_daily_login_bonus` / `skip_monthly_login_bonus`（跳过签到）、`game_day_boundary_hour`（游戏日日切小时） |
| `gacha_config.json` | 扭蛋稀有度权重（SSR/SR/R）、保底、阶梯；GM 面板可运行时覆盖 |
| `clamp_config.json` | 时间钳制：`boundary_hour` 触发点、`clamp_hour/minute/second` 钳制目标、`clamp_end_hour` 跨午夜窗口 |
| `local_server/time_offset_config.json` | 统一时间偏移（客户端探针 + 服务器共用同一时间源） |

---

## 七、免责声明

- 本项目**仅用于协议学习与个人本地研究**，不提供、不分发任何游戏客户端或版权数据。
- 使用本项目产生的任何后果（账号、法律等）由使用者自行承担。
- 请遵守你所在地区法律与游戏服务条款；若你是游戏版权方且认为本项目侵犯权益，请联系仓库作者删除。