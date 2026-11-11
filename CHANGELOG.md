## DOAXVV_Server v1.1 — 死或生:维纳斯假期 本地模拟服务器

Python 实现的 DOAXVV（Dead or Alive Xtreme Venus Vacation）本地单机模拟服务器。
通过 hosts 劫持 + 自签证书，把游戏 HTTPS 流量导向本机，实现单机离线游玩、跳过签到、自定义扭蛋爆率/保底、GM 控制面板发奖、岛主房间全解锁、挑战赛技能同步。

v1.1 合并 v1.0（2026-10-01）之后的修复与维护：主服务器 4563 → 6726 行、端点 87 → 123。

### 功能
- hosts 劫持 + RSA 握手 + AES-256-CBC 加密信封；首次启动自动生成 RSA/TLS 证书
- 120+ 端点：查询类稳定快照、动作类状态机轮换，优先级链响应
- 商店 / 背包 / 女孩换装 / 岛主房间：购买发货、装备齐全、家具与场景全解锁
- 姿势 / 表情按女孩分类、星标可持久化；挑战赛装备技能随穿戴同步
- 资源回源（缓存直发 / 未命中回源）、GM 面板、系统托盘、自定义扭蛋爆率

### 本次更新（v1.0 → v1.1）
- 修复登录日切白屏循环；整体停用 Frida 时间钳制，不再需要 frida
- 修复商店购买数量 0 / 限购误判 / 背包实例 ID 撞号 / 女孩装备查询全 0
- 修复家具不显示与家具闪退；场景、外出地点、亲密等级全解锁
- 修复姿势/表情串女孩、表情丢失、星标不持久；CDN 补齐 30 张 CSV
- 修复挑战赛换人换衣后技能仍旧、查询端点轮换跳变
- 修复 2 次客户端闪退（超大实例 ID、替补 65535 被当成女孩 ID）
- 全盘隐私复扫、开发中间文件归档；按 v1.0 附件格式重建发布包

### 内容
- local_server/local_server_v2.py（主服务器 6700+ 行：加密/CSV/动态响应/资源代理/GM）
- GM/gm_panel.html（GM 面板）+ tray_app.py / stop_all.py / hosts_switch.ps1（托盘/关闭/hosts）
- _python_env.bat（新增，解释器探测）/ CHANGELOG.md（本更新日志）
- 配置：server_config.json / gacha_config.json / information_global.json / time_offset_config.json
- 中文一键启动/关闭 .bat / .vbs；已移除 4 个时间钳制脚本

### Quick Start
1. pip install cryptography pystray Pillow（Python 3.10+；不再需要 frida）
2. set DOAXVV_TOKEN=你的Token  &  set DOAXVV_OWNER_ID=你的owner_id
   > 一键启动.vbs 不继承 PowerShell 会话的 $env:，请设为系统级环境变量；报 ERROR_NO: 10005 时优先查这两项。
3. 双击 一键启动.vbs（托盘拉起服务器 + hosts 劫持，无窗口）
4. 启动游戏（hosts 已指向 127.0.0.1）

### 敏感数据已清理
仓库已清理所有个人/密钥/版权数据（逐项及对运行的影响见 README.md 第三节，尤其第 9 小节）：
- RSA/TLS 密钥：首次启动自动生成（load_rsa() / _ensure_tls_cert()）
- TOKEN / OWNER_ID：改读环境变量 DOAXVV_TOKEN / DOAXVV_OWNER_ID
- 存档/抓包/CSV/资源/姿势归属数据：已删除（自行获取、首次运行重建或自动降级）
- 官方 CSV 加解密固定 AES key 为官方公开常量、非个人凭据，特意保留：删除后客户端解不开数据表，请勿移除

### 已知限制
PvP matching_pvp/* 仍为静态抓包；装备强化/合成/界限突破、战斗数值成长待实现；姿势/表情归属为实证近似。

### 免责
仅供协议学习与个人本地研究。游戏客户端、CSV 数据表、二进制资源版权归 Koei Tecmo / 光荣特库摩 所有，不包含在仓库中。
使用本项目产生的任何后果（账号、法律等）由使用者自行承担。

### Download
- DOAXVV_Server_v1.1.zip — 仓库快照（结构与 v1.0 附件一致，条目位于压缩包根目录），下载解压即用，游戏数据需自备。
