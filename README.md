# DOAXVV_Server — 死或生:维纳斯假期 本地模拟服务器

一个用 Python 实现的 DOAXVV（Dead or Alive Xtreme Venus Vacation）本地单机模拟服务器。
通过 hosts 劫持 + 自签证书，把游戏的 HTTPS 流量导向本机，实现单机离线游玩、
跳过签到弹窗、自定义扭蛋爆率/保底、GM 面板发奖、维纳斯图板与岛主房间全解锁、挑战赛装备技能同步。

> **v1.2（2026-11-13）**：新增维纳斯图板全解锁、重做亲爱度报酬领取、GM 面板换成新版「玩家服务」UI、
> 整合 hosts 与服务器状态开关。完整更新日志见 `CHANGELOG.md` 与 Release Notes。

> ⚠️ **本项目仅供协议学习与个人本地研究。** 游戏客户端、CSV 数据表、二进制资源等版权内容归
> Koei Tecmo / 光荣特库摩 所有，**不包含在本仓库中**。请仅在本地对自己合法持有的游戏副本使用。

---

## 一、工作原理

```
游戏客户端 (DOAX_VV.exe)
   │  HTTPS (api.doaxvv.com / game.doaxvv.com / api01.doaxvv.com)
   │  hosts 劫持 → 127.0.0.1
   ▼
本地服务器 (local_server_v2.py, 监听 :443)
   │  RSA 握手 → AES-256-CBC 加密信封 → 解密请求 / 加密响应
   │  下发数据表 (/v1/csv/list + /production/csv/<hash>)
   │  120+ 端点：扭蛋 / 装备 / 挑战赛 / 邮箱 / 商店 / 温泉 / 岛主房间…
   │  资源命中本地缓存直发，未命中时回源并缓存
   ▼
GM 面板 (gm_panel.html) / 系统托盘 (tray_app.py)
```

---

## 二、目录结构

```
DOAXVV_Server/
├── local_server/
│   ├── local_server_v2.py       # 主服务器：加密 / CSV / 动态响应 / 资源代理 / GM
│   ├── paths.py                 # 路径常量
│   ├── logutil.py               # 日志写入
│   └── time_offset_config.json  # 时间偏移（恒为 0，服务器依赖，勿删）
├── GM/
│   ├── gm_panel.html            # GM 控制面板
│   ├── gm_names.csv             # GM 名称修正表
│   └── 启动GM.bat / 关闭GM.bat
├── CHANGELOG.md                 # 版本更新日志
├── _python_env.bat              # 启动脚本共用：探测可导入 cryptography 的 Python
├── tray_app.py / tray_dialogs.py / stop_all.py / gm_shutdown.py
├── hosts_switch.ps1             # hosts 后端 on/off/status（勿删）
├── server_config.json           # 功能开关（跳过签到 / 游戏日日切）
├── gacha_config.json / gacha_groups.json   # 扭蛋爆率 / 保底 / 卡池分组
├── information_global.json      # 公告配置
├── 一键启动.bat / 一键关闭.bat
└── 查看服务器状态.bat / 查看hosts状态.bat   # 状态 + 切换统一入口
```

---

## 三、Quick Start

1. `pip install cryptography pystray Pillow`（Python 3.10+；不再需要 frida）
2. 双击 `一键启动.bat`（托盘拉起服务器 + hosts 劫持，无窗口）
   > `TOKEN` / `OWNER_ID` 已内置无意义默认值，**开箱即用，无需手动配置**；需自定义时请设为系统级环境变量（`.bat` 不继承 PowerShell 会话的 `$env:`）。报 `ERROR_NO: 10005` 时优先查这两项、hosts 是否切成功、443 是否被占用。
3. 启动游戏（hosts 已指向 `127.0.0.1`）

> hosts 劫持需管理员权限，首次会弹 UAC。RSA 密钥对与自签名 TLS 证书在首次启动时自动生成，无需手动准备。

### 启动与关闭

| 方式 | 操作 |
|---|---|
| **一键启动（推荐）** | 双击 `一键启动.bat` → 托盘后台拉起服务器 + hosts 劫持；会闪一下 CMD 窗口，托盘本身无窗口 |
| **服务器状态 / 切换** | 双击 `查看服务器状态.bat`：显示 443 状态与 PID，`1` 启动 / `2` 关闭；15 秒无操作自动切到相反状态，执行完 5 秒自动关窗 |
| **hosts 状态 / 切换** | 双击 `查看hosts状态.bat`：显示当前状态，`1` 切 local / `2` 切 real；15 秒无操作自动切到相反状态，执行完 5 秒自动关窗 |
| **GM 面板** | 托盘右键 → 启动 GM；服务器运行时在浏览器打开控制台 |
| **一键关闭** | 双击 `一键关闭.bat`，或托盘右键「一键关闭」→ 断开 GM 会话 + 关服务器 + 托盘 + 还原 hosts；只在 Chrome 还有其他窗口时才关 GM 窗口 |

> `开启单机版.bat` / `关闭单机版.bat` 已整合进 `查看hosts状态.bat`；`hosts_switch.ps1` 保留为后端（`tray_app.py` / `stop_all.py` 仍依赖它的 `status` 输出，请勿删除）。

---

## 四、游戏数据需自备

仓库**不包含**版权游戏数据。要完整运行（下发数据表、扭蛋、挑战赛等），需自行从合法持有的游戏副本提取：

| 数据 | 放置位置 | 作用 |
|---|---|---|
| CSV 数据表 | `csv_master/` | `/production/csv/<hash>` 下发 |
| CSV 列表（文件名 → 哈希） | `real_csv_list.json` | `/v1/csv/list` 下发清单 |
| 资源缓存 | `resources/` | 二进制资源分发，首次运行自动回源重建 |

> 未放入数据时服务器**仍可启动**，但游戏内无数据表、部分功能不可用。
> 主服务器内置的 CSV 加解密常量是官方客户端的公开固定值，**请勿修改或删除**，否则客户端解不开数据表、会卡在加载界面。

---

## 五、配置文件

| 文件 | 作用 |
|---|---|
| `server_config.json` | `skip_daily_login_bonus` / `skip_monthly_login_bonus`、`game_day_boundary_hour` |
| `gacha_config.json` | 扭蛋稀有度权重、保底、阶梯；GM 面板可运行时覆盖 |
| `local_server/time_offset_config.json` | 统一时间偏移，恒为 0（`server_now()` 依赖，勿删） |

---

## 六、免责

- 本项目**仅用于协议学习与个人本地研究**，不提供、不分发任何游戏客户端或版权数据。
- 使用本项目产生的任何后果（账号、法律等）由使用者自行承担。
- 请遵守你所在地区法律与游戏服务条款；若你是游戏版权方且认为本项目侵犯权益，请联系仓库作者删除。

---

## 七、版本

| 版本 | 日期 | 说明 |
|---|---|---|
| v1.0 | 2026-10-01 | 首个公开版本 |
| v1.1 | 2026-11-11 | 40 天修复合并版：商店 / 背包 / 女孩装备 / 岛主房间 / 姿势表情 / 挑战赛 / 稳定性 |
| v1.2 | 2026-11-13 | 维纳斯图板全解锁、亲爱度报酬重做、新版 GM UI、状态开关整合，详见 `CHANGELOG.md` |
