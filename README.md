# DOAXVV_Server — 死或生:维纳斯假期 本地模拟服务器

一个用 Python 实现的 **DOAXVV（Dead or Alive Xtreme Venus Vacation）本地单机模拟服务器**。
通过 hosts 劫持 + 自签证书，把游戏的 HTTPS 流量导向本机服务器，从而实现
**单机离线游玩、跳过签到弹窗、自定义扭蛋爆率/保底、GM 控制面板发奖、岛主房间家具与场景全解锁、挑战赛队伍与装备技能同步** 等功能。

> **v1.1（2026-11-11）**：合并 v1.0 之后 40 天的修复与维护，主服务器 4563 → 6726 行。完整更新日志见 `CHANGELOG.md`。

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
   │  4. 120+ 端点: 扭蛋/装备/挑战赛/邮箱/商店/温泉/岛主房间… 查询稳定+动作轮换
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
│   ├── local_server_v2.py   # 主服务器 (6700+ 行): 加密/CSV/动态响应/资源代理/战斗快照/GM
│   ├── paths.py             # 路径常量
│   ├── logutil.py           # 日志缓冲写入
│   └── time_offset_config.json  # 时间偏移配置 (v1.1 起恒为 0, 服务器依赖)
├── GM/
│   ├── gm_panel.html        # GM 控制面板
│   └── 启动GM.bat / 关闭GM.bat
├── _python_env.bat          # 启动脚本共用: 探测可导入 cryptography 的 Python
├── CHANGELOG.md             # 版本更新日志
├── tray_app.py              # 系统托盘应用 (后台跑服务器+hosts, 右键菜单)
├── tray_dialogs.py          # 托盘弹窗 (状态/日志)
├── stop_all.py              # 一键关闭 (服务器+托盘+hosts)
├── hosts_switch.ps1         # hosts 劫持/还原 (on/off/status)
├── server_config.json       # 服务器功能开关 (跳过签到/游戏日日切)
├── gacha_config.json        # 扭蛋爆率/保底配置
├── information_global.json  # 公告配置
├── 一键启动.vbs / 一键启动.bat
├── 一键关闭.vbs / 一键关闭.bat
├── 启动服务器.bat / 关闭服务器.bat
├── 开启单机版.bat / 关闭单机版.bat
└── 查看hosts状态.bat
```

---

## 三、已删除的敏感数据（上传 GitHub 前清理记录）

为确保公开仓库不含任何个人/密钥/版权数据，以下内容已从仓库中删除。**它们不会随仓库分发**，
首次运行时由服务器自动生成，或需你自行获取后放入（见第四节）。
> **哪些会影响运行、分别怎么恢复，见本节第 9 小节汇总表**（尤其是必须设置的鉴权凭据与必须保留的 CSV 密钥）。

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
| `local_server/arrange_trace.log` / `pose_trace.log` | 形态切换 / 姿势归属诊断日志 |
| `local_server/full_server.log` 等所有 `*.log` | 服务器运行日志 |
| `local_server/stdout*.txt` / `stderr*.txt` | 标准输出/错误重定向 |
| `local_server/pose_owner_map.json` / `pose_anchors.json` / `pose_real_private.json` | 姿势/表情归属映射（本地实证数据，缺失时代码自动降级到锚点算法） |
| `local_server/resource_list_real.json` | 官方资源清单（v1.1 新增忽略） |

### 5. 版权游戏数据 — 已删除（需自行获取）

| 已删除项 | 说明 |
|---|---|
| `csv_master/`（223 个 CSV，约 83MB） | 游戏数据表（装备/扭蛋/挑战赛/剧情等），版权内容 |
| `resources/`（421 个二进制文件，约 1.25GB） | 游戏资源补丁缓存（首次运行从回源自动重建） |

### 6. 代码内硬编码敏感常量 — 已脱敏

| 位置 | 原值 | 现处理 |
|---|---|---|
| `local_server_v2.py` `TOKEN` | 硬编码鉴权 Token | 改为读环境变量 `DOAXVV_TOKEN`（默认空） |
| `local_server_v2.py` `OWNER_ID` | 硬编码个人账号 ID | 改为读环境变量 `DOAXVV_OWNER_ID`（默认 0） |
| `DEFAULT_STATE` 模板 | 个人 `owner_id`、赌场筹码/战绩、温泉奖励计数等值 | `owner_id` 改用 `OWNER_ID`，其余个人数值归零 |

### 7. 构建产物与重复目录 — 已删除

- `__pycache__/`、`local_server/__pycache__/`（字节码缓存）
- 嵌套重复目录 `csv_master/csv_master/`、`resources/resources/`、`GM/GM/`、`local_server/local_server/`

> 清理后全仓库已通过敏感模式扫描：账号 ID / Token / `BEGIN PRIVATE KEY` / 钱包余额 / 存档 / 抓包 **均为零残留**；
> 主文件仍保留官方 CSV 加解密所需的固定 AES key（官方公开常量、功能必需，详见本节第 9 小节）；
> `local_server_v2.py` 通过 `py_compile` 语法校验。`.gitignore` 已配置，防止上述运行时数据再次入库。

### 8. v1.1 补充排查：配置 / 注释里的本机痕迹 — 已清理

v1.1 对上面 1–7 类**之外**又做了一次全盘扫描，额外发现并清理了：

| 位置 | 残留内容 | 处理 |
|---|---|---|
| `server_config.json` | 一个已废弃键的说明文字里写有本机绝对路径与本地归档目录名 | 删除整个废弃键（已无代码读取）；其余说明去掉对已停用探针脚本的引用 |
| `tray_app.py` / `local_server_v2.py` 注释 | 本机归档目录名、本机游戏根目录名 | 改为中性描述（「已整体停用并移出仓库」），不含任何路径 |
| `GM/启动GM.bat` | 错误提示引用了仓库中并不存在的存档 / 抓包文件 | 改为通用的端口 / 依赖提示 |

**保留但需知情**（非个人信息，v1.0 起即公开）：

- `local_server_v2.py` 内置 `VPN_KNOWN_DEFAULT` / `AKAMAI_FALLBACK_IPS` 及回源 IP：均为通用回源网络常量（`198.18.0.0/15` 为 RFC 2544 保留测试段，Akamai / AWS 为官方 CDN 地址），不含账号或设备信息；真正的个人运营数据 `vpn_ip.txt` 已按第 4 类删除。
- `information_global.json` 的官方公告页 URL（含资源哈希）、`hosts_switch.ps1` 的 `C:\Windows\System32\drivers\etc\hosts`：官方 / 系统公开常量。
- `local_server_v2.py::_serve_csv()` 的官方 CSV 加解密固定 AES key：官方客户端内置的公开常量、非个人凭据，v1.1 特意保留（删除后客户端解不开数据表），详见本节第 9 小节。

> 全盘扫描覆盖：凭据 / 密钥 / 账号 ID / 邮箱 / 手机号 / 本机路径 / 公网 IP / 带参 URL / 高熵串 / 抓包存档特征 / 运行时数据文件；发布副本**硬命中 0 项**。扫描脚本与逐项报告属本地校验材料，不随仓库分发。

### 9. 已删除数据对运行的影响与恢复方式（v1.1 汇总）

第三节 1–8 类的删除项并非都能「自动补回」。下表集中列出**移除后可能影响运行**的全部项目，
便于下载后逐项排查；表中未列出的（运行日志、`hosts_backup/`、`__pycache__/`、重复嵌套目录、
注释与错误提示文案、`.gitignore` 里本机专属的备份/归档规则）删除后**无任何影响**。

| 已删除 / 已脱敏项 | 是否影响运行 | 缺失后的表现 | 恢复 / 配置方式 |
|---|---|---|---|
| 硬编码 `TOKEN` / `OWNER_ID`（第 6 类） | **是，必须配置** | 鉴权失败，客户端报 `ERROR_NO: 10005` 或进不去游戏 | 设置环境变量 `DOAXVV_TOKEN` / `DOAXVV_OWNER_ID`（见第四节 2） |
| RSA 密钥对 / TLS 证书（第 1 类） | 否，自动重建 | 首次启动生成新密钥对并与客户端重新握手 | 无需操作（见第四节 3） |
| `server_state.json`（第 2 类） | 部分 | 存档按 `DEFAULT_STATE` 重新生成：钱包、装备、好感度、抽卡进度归零 | 首次运行自动生成新档；需要旧进度须自备存档 |
| `server_response_db.json` / `real_responses.json` / `login_bonus_*.json`（第 2、3 类） | **是，功能降级** | 抓包响应池为空，相关端点走模板或兜底 `{status:success}`；签到 / 商店 / 挑战赛等缺历史数据 | 需自行抓包后按同名文件放回；缺失时服务器仍可启动 |
| `real_csv_list.json` / `real_csvlist.bin` + `csv_master/`（第 3、5 类） | **是，最明显** | `/v1/csv/list` 返回空映射，客户端拿不到数据表；扭蛋 / 装备 / 挑战赛等依赖表的功能不可用 | 自行从游戏副本提取后放回（见第四节 4） |
| `resources/` + `local_server/resource_list_real.json`（第 3、5 类） | 部分 | 首次运行按内置回源 IP 探测并缓存；回源不通时资源缺失 | 自动重建，或自备缓存目录 |
| `vpn_ip.txt`（第 4 类） | 否 | 使用代码内置的通用回源 IP 常量兜底，运行时重新探测并写回 | 自动重建 |
| `pose_owner_map.json` / `pose_anchors.json` / `pose_real_private.json`（第 4 类） | **是，功能降级** | 姿势 / 表情归属自动降级到锚点算法：卡片数量明显减少、部分分类不精确，**不崩溃**，也不影响其他功能 | 自备实测数据放入 `local_server/`，或接受降级 |
| 4 个时间钳制脚本 + `server_config.json` 废弃键（第 8 类） | 否 | 机制整体停用，日切不再被钳制 | 无需操作；**切勿删除** `local_server/time_offset_config.json`（`server_now()` 依赖，v1.1 起恒为 0） |

> ⚠️ **务必保留主服务器里的 CSV 加解密固定密钥**：`local_server_v2.py::_serve_csv()` 内置的
> 32 字节 `AES-256-CBC` key 用于加密 `/production/csv/<hash>` 响应体（IV = 文件名哈希），
> 客户端用同一把钥匙解密。它是**官方客户端内置的公开固定常量**，不是任何人的私钥、Token 或账号数据；
> v1.1 全盘隐私清理时**特意保留**，发布校验也强制要求其存在。删除或改成随机值会让客户端解不开数据表，
> 表现为游戏卡在加载界面 / 数据表为空 —— 也就是「下载后没法用」。请勿按第 6 类的方式把它一并脱敏。

---

## 四、运行前的准备

### 1. 安装依赖

```powershell
# Python 3.10+ (项目用 3.12 开发)
pip install cryptography pystray Pillow
```

### 2. 设置鉴权凭据（环境变量）

服务器启动时会读取以下环境变量（取代原硬编码值）：

```powershell
# PowerShell（当前会话）
$env:DOAXVV_TOKEN      = "你的鉴权Token"     # 原 TOKEN
$env:DOAXVV_OWNER_ID   = "你的owner_id"      # 原 OWNER_ID (整数)
```

> 想永久生效，可在系统环境变量里设置，或写入 `启动服务器.bat` 的 `set` 行。
> **注意**：双击 `一键启动.vbs` / `.bat` 启动的进程**不会继承** PowerShell 会话里的 `$env:`，必须写成系统级环境变量或写入启动脚本。
> 出现 `ERROR_NO: 10005` 时优先检查这两项、hosts 是否切成功、443 是否被占用。

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
| CSV 数据表（223 个） | `csv_master/` | `/production/csv/<hash>` 下发、`_load_quest_tables` 评级 |
| CSV 列表（文件名→哈希） | `real_csv_list.json` | `/v1/csv/list` 下发清单 |
| 资源缓存 | `resources/`（首次运行自动从回源重建） | 二进制资源分发 |

> **未放入数据时服务器仍可启动**（降级模式：`load_csv_list` 返回空映射，各加载器检测到文件
> 缺失即跳过并使用默认值），但游戏内无数据表，部分功能不可用。
> **注意**：上述 CSV 响应体由服务器用内置的官方固定 AES key 加密（见第三节第 9 小节），该常量不需要、也不可以另行配置或删除；自备 CSV 数据表时同样要保留它，否则客户端解密失败。

---

## 五、启动与关闭

| 方式 | 操作 |
|---|---|
| **一键启动（推荐）** | 双击 `一键启动.vbs`（或 `.bat`）→ 托盘程序后台拉起服务器 + hosts 劫持，无控制台窗口 |
| **纯服务器** | 双击 `启动服务器.bat`（仅服务器，不带托盘） |
| **查看状态** | 托盘右键 → 状态 / 日志；或双击 `查看hosts状态.bat` |
| **GM 面板** | 托盘右键 → 打开控制台；服务器运行时访问 GM 面板 |
| **一键关闭** | 双击 `一键关闭.vbs`（或 `.bat`）→ 关服务器 + 托盘 + 还原 hosts |

> hosts 劫持需管理员权限，首次会弹 UAC。`hosts_switch.ps1` 会把
> `api.doaxvv.com / game.doaxvv.com / api01.doaxvv.com` 指向 `127.0.0.1`。

---

## 六、核心配置文件

| 文件 | 作用 |
|---|---|
| `server_config.json` | `skip_daily_login_bonus` / `skip_monthly_login_bonus`（跳过签到）、`game_day_boundary_hour`（游戏日日切小时） |
| `gacha_config.json` | 扭蛋稀有度权重（SSR/SR/R）、保底、阶梯；GM 面板可运行时覆盖 |
| `local_server/time_offset_config.json` | 统一时间偏移；**v1.1 起恒为 0**（服务器 `server_now()` 依赖此文件，时间钳制已停用，勿删） |

---

## 七、免责声明

- 本项目**仅用于协议学习与个人本地研究**，不提供、不分发任何游戏客户端或版权数据。
- 使用本项目产生的任何后果（账号、法律等）由使用者自行承担。
- 请遵守你所在地区法律与游戏服务条款；若你是游戏版权方且认为本项目侵犯权益，请联系仓库作者删除。

---

## 八、版本与更新日志

| 版本 | 日期 | 说明 |
|---|---|---|
| v1.0 | 2026-10-01 | 首个公开版本 |
| v1.1 | 2026-11-11 | 40 天修复合并版：商店/背包/女孩装备/岛主房间/姿势表情/挑战赛/稳定性，详见 `CHANGELOG.md` |
